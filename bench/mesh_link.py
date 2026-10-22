"""Tactical mesh interface verification for the STS edge node.

Pre-flight check used before a forced sync / flush_now campaign: proves the
radio or mesh interface that carries traffic to Core Command is actually UP
and has peers, instead of discovering mid-campaign that the queue is draining
into a black hole.

Supported topologies (auto-detected per interface name):

  * batman-adv soft interfaces (bat0, bat1, mesh0...)
      - operstate must be up
      - originator table via ``batctl o`` (or /sys/class/net/<if>/batman-adv/
        originators) gives neighbor visibility + last-seen ages
      - gateway mode via ``batctl gwl`` (primary/backup electable)

  * 802.11s mesh point / station interfaces (wlan0, ath0, mwifi0...)
      - ``iw dev <if> link``          -> station association (AP link)
      - ``iw dev <if> station dump``  -> peer list (mesh peers show here too)
      - ``iw dev <if> survey dump``   -> channel activity (optional signal)

  * plain Ethernet backhaul (eth0, end0...)
      - carrier + operstate check only

Fallback chain semantics
------------------------
The edge node may physically rove between transports (mesh radio dies, driver
falls back to Ethernet dongle). ``verify_mesh_link`` therefore probes an ORDERED
candidate list (default: bat0, wlan0, eth0 -- override with $STS_MESH_IFACES or
--ifaces) and returns the first interface that passes; every other candidate is
still probed and reported so operators see WHY the primary was demoted.

Exit codes (usable directly in shell preflight scripts):
    0  at least one interface is ACTIVE with peers/carrier
    1  an interface is UP but has no peers yet (degraded: single-node mesh)
    2  all candidates down/missing   -> refuse forced sync
    3  tooling missing (iw/batctl not installed) -> fail closed

CLI examples
------------
    python3 bench/mesh_link.py                       # default candidates
    python3 bench/mesh_link.py --ifaces bat0 wlan0   # explicit order
    python3 bench/mesh_link.py --json | jq .active   # machine-readable

Integration: AnchorClient.flush_now(force=True) calls verify_mesh_link() and
refuses to burn ApprovalGate approvals on a dead radio.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict

# ---------------------------------------------------------------------------
# Tool resolution (same discipline as hardware_hooks._resolve_tool: absolute
# paths, merged-/usr fallback dirs, never trust PATH alone)
# ---------------------------------------------------------------------------
_TOOL_FALLBACK_DIRS = ("/usr/sbin", "/sbin", "/usr/bin", "/usr/local/bin")


def _resolve_tool(name: str):
    found = shutil.which(name)
    if found:
        return os.path.abspath(found)
    for d in _TOOL_FALLBACK_DIRS:
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return os.path.abspath(cand)
    return None


def _run(cmd: list[str], timeout: float = 5.0):
    """Run a probe command. Returns (rc, stdout) or (None, error string)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"{type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# Interface classification
# ---------------------------------------------------------------------------
def classify(ifname: str) -> str:
    """batman-adv soft iface vs wifi vs wired, from /sys when possible."""
    sysdir = f"/sys/class/net/{ifname}"
    if not os.path.isdir(sysdir):
        return "missing"
    if os.path.isdir(f"{sysdir}/batman-adv"):
        return "batman-adv"
    if os.path.exists(f"{sysdir}/wireless") or os.path.islink(f"{sysdir}/phy80211"):
        return "wifi"
    # udev-bus type 802_11 also marks wifi on some images
    try:
        with open(f"{sysdir}/type") as f:
            pass  # ARPHRD constants: 772=IEEE802_11
        with open(f"{sysdir}/uevent") as f:
            uev = f.read()
        if "DEVTYPE=wlan" in uev:
            return "wifi"
    except OSError:
        pass
    return "wired"


def _read_sysfs(ifname: str, rel: str) -> str | None:
    try:
        with open(f"/sys/class/net/{ifname}/{rel}") as f:
            return f.read().strip()
    except OSError:
        return None


@dataclass
class LinkReport:
    iface: str
    kind: str                      # batman-adv | wifi | wired | missing
    exists: bool
    operstate: str
    carrier: bool
    peers: int = 0
    peer_detail: list = field(default_factory=list)
    gateway: dict | None = None    # batman-adv gateway visibility
    state: str = "DOWN"            # ACTIVE | DEGRADED | DOWN
    notes: list = field(default_factory=list)

    def summary_line(self) -> str:
        extra = ""
        if self.kind == "batman-adv" and self.gateway:
            gw = self.gateway.get("primary")
            extra = f", gateway={'yes ' + gw if gw else 'NONE'}"
        return (f"{self.iface} [{self.kind}] {self.state}: "
                f"operstate={self.operstate or '?'}, carrier={'up' if self.carrier else 'down'}, "
                f"peers={self.peers}{extra}")


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------
def probe_wlan_iw(ifname: str, report: LinkReport, iw: str):
    """`iw dev <if> link` (station mode) then `iw dev <if> station dump` (mesh/AP peers)."""
    rc, out = _run([iw, "dev", ifname, "link"])
    if rc is None:
        report.notes.append(f"iw exec failed: {out}")
        return
    # Not-attached output looks like: "Not connected." (rc 0) -- treat as no link.
    m = re.search(r"Connected to ([0-9a-f:]{17})", out, re.I)
    if m:
        report.peer_detail.append({"mac": m.group(1), "via": "iw link"})
        ssid = re.search(r"SSID:\s*(.+)", out)
        freq = re.search(r"freq:\s*(\d+)", out)
        sig = re.search(r"signal:\s*(-?\d+)", out)
        if ssid:
            report.peer_detail[-1]["ssid"] = ssid.group(1).strip()
        if freq:
            report.peer_detail[-1]["freq"] = int(freq.group(1))
        if sig:
            report.peer_detail[-1]["signal_dbm"] = int(sig.group(1))

    rc2, out2 = _run([iw, "dev", ifname, "station", "dump"])
    if rc2 == 0:
        macs = re.findall(r"^Station\s+([0-9a-f:]{17})", out2, re.M | re.I)
        for mac in macs:
            if not any(p["mac"] == mac for p in report.peer_detail):
                report.peer_detail.append({"mac": mac, "via": "station dump"})
    elif "Command failed" in out2 and not report.peer_detail:
        report.notes.append("no station entries (unassociated / mesh idle)")

    report.peers = len(report.peer_detail)


def probe_batman(ifname: str, report: LinkReport, batctl: str | None):
    """Originator (neighbor) visibility + gateway election for a batman-adv soft iface."""
    origs = []
    ages = {}
    if batctl:
        rc, out = _run([batctl, "-i", ifname, "o"])
        if rc == 0:
            # Line format: "<last-seen>   <originator>   (<router>) ... * <- next hop"
            for line in out.splitlines():
                m = re.match(r"\s*([\d.]+)\s+([0-9a-f:]{17})\b(.*)", line, re.I)
                if m:
                    origs.append(m.group(2))
                    ages[m.group(2)] = float(m.group(1))
        rcg, outg = _run([batctl, "-i", ifname, "gwl"])
        if rcg == 0:
            gws = re.findall(r"=>\s*([0-9a-f:]{17})|->\s*([0-9a-f:]{17})", outg)
            primary = next((a or b for a, b in gws if (a or b).startswith(("=>", "->")) ), None)
            # simpler: => marks elected primary, -> backup
            pm = re.search(r"=>\s*([0-9a-f:]{17})", outg, re.I)
            bm = re.findall(r"->\s*([0-9a-f:]{17})", outg, re.I)
            report.gateway = {"primary": pm.group(1) if pm else None,
                              "backups": bm}
    if not origs:  # sysfs fallback (works without batctl, read-only)
        content = _read_sysfs(ifname, "batman-adv/originators")
        if content:
            for line in content.splitlines():
                m = re.match(r"\s*([0-9a-f:]{17}).*?last_seen:\s*([\d.]+)", line, re.I)
                if m:
                    origs.append(m.group(1))
                    ages[m.group(1)] = float(m.group(2))
    report.peer_detail = [{"mac": o, "last_seen_s": ages.get(o)} for o in origs]
    report.peers = len(origs)
    if not batctl and not origs:
        report.notes.append("batctl missing and no sysfs originator table")


# ---------------------------------------------------------------------------
# Main verification
# ---------------------------------------------------------------------------
DEFAULT_CANDIDATES = ("bat0", "wlan0", "eth0")


def verify_mesh_link(candidates=None, require_peers: bool = True) -> tuple[LinkReport | None, list[LinkReport]]:
    """Probe candidates in priority order.

    Returns (active_report_or_None, all_reports). ACTIVE means: exists,
    operstate up (or carrier up for wired), and peer count >= 1 when
    require_peers. A UP-but-peerless mesh is DEGRADED (single node island):
    usable locally, but a forced sync through it will queue until a peer
    appears -- callers should warn, not hard-fail.
    """
    if candidates:
        cands = list(candidates)
    else:
        cands = os.environ.get("STS_MESH_IFACES", "").split() or list(DEFAULT_CANDIDATES)
    iw = _resolve_tool("iw")
    batctl = _resolve_tool("batctl")

    reports: list[LinkReport] = []
    active: LinkReport | None = None

    for ifname in cands:
        kind = classify(ifname)
        oper = _read_sysfs(ifname, "operstate") or ""
        carrier_raw = _read_sysfs(ifname, "carrier")
        carrier = carrier_raw == "1"
        rep = LinkReport(iface=ifname, kind=kind, exists=kind != "missing",
                         operstate=oper, carrier=carrier)
        if kind == "missing":
            rep.state = "DOWN"
            rep.notes.append("interface does not exist on this host")
            reports.append(rep)
            continue

        if kind == "wifi":
            if iw:
                probe_wlan_iw(ifname, rep, iw)
            else:
                rep.notes.append("iw not installed; falling back to carrier-only check")
        elif kind == "batman-adv":
            probe_batman(ifname, rep, batctl)

        up = oper in ("up", "unknown") and (carrier or kind in ("batman-adv", "wifi"))
        if up and (rep.peers > 0 or not require_peers):
            rep.state = "ACTIVE"
            if active is None:
                active = rep
        elif up:
            rep.state = "DEGRADED"
        else:
            rep.state = "DOWN"
        reports.append(rep)

    return active, reports


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Verify tactical mesh/radio link before forced sync")
    ap.add_argument("--ifaces", nargs="*", default=None,
                    help=f"priority-ordered candidates (default {' '.join(DEFAULT_CANDIDATES)})")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--allow-single-node", action="store_true",
                    help="treat UP-with-no-peers as ACTIVE (single-node mesh island)")
    args = ap.parse_args(argv)

    iw_missing = _resolve_tool("iw") is None
    bat_missing = _resolve_tool("batctl") is None

    active, reports = verify_mesh_link(args.ifaces,
                                       require_peers=not args.allow_single_node)

    if args.json:
        print(json.dumps({
            "active": asdict(active) if active else None,
            "reports": [asdict(r) for r in reports],
            "tools": {"iw": not iw_missing, "batctl": not bat_missing},
        }, indent=2))
    else:
        for r in reports:
            print(("OK  " if r.state == "ACTIVE" else
                   "WARN" if r.state == "DEGRADED" else "FAIL") + " " + r.summary_line())
            for n in r.notes:
                print(f"       note: {n}")
            for p in r.peer_detail[:5]:
                print(f"       peer: {p}")
        if len(reports) > 1 and active and reports.index(active) > 0:
            skipped = ", ".join(x.iface for x in reports[:reports.index(active)])
            print(f"NOTE: primary candidates ({skipped}) unavailable -> using fallback {active.iface}")

    if active:
        return 0
    if any(r.state == "DEGRADED" for r in reports):
        print("Warning: link up but no peers visible (single-node island); "
              "forced sync will queue until mesh forms.", file=sys.stderr)
        return 1
    if iw_missing and bat_missing:
        print("Warning: neither iw nor batctl installed -- cannot prove RF peer "
              "visibility. Install wireless-tools/iw + batctl (fail-closed).",
              file=sys.stderr)
        return 3
    print("All mesh candidates down. Refusing forced sync; normal (gated) flush "
          "may still enqueue to quarantine.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
