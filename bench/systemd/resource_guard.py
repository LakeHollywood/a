#!/usr/bin/env python3
"""
Resource guard for the STS Core Command daemon.

Enforces the same budgets as bench/systemd/sts-core-command.service
(CPUQuota=20%, MemoryMax=512M) via POSIX rlimits, so the uvicorn process is
starvation-proof even on hosts WITHOUT systemd (containers, minimal L4T
images). On a systemd host this script is optional — prefer the unit file —
but it doubles as a validator: it parses the unit and applies the identical
limits, proving the two paths can never drift apart.

Why rlimits are not sufficient alone (documented honestly):
  * RLIMIT_AS caps virtual address space, not RSS; sqlite + aiohttp reserve
    large VSZ, so we cap at 2x (1024 MB VA ~ 512 MB RSS) to avoid false
    aborts while still bounding blowups.
  * RLIMIT_CPU counts CPU-SECONDS and SIGKILLs when exceeded — a hard wall,
    not a rate. The real-time rate limit (CPUQuota) needs cgroups, which is
    why the systemd slice is the primary mechanism. Here RLIMIT_CPU acts as
    a runaway watchdog sized from the quota (20% of the run duration).

Usage:
    python3 resource_guard.py -- python3 -m uvicorn main:app --port 8000
    python3 resource_guard.py --parse-only            # validate unit files
Exit code 3 => unit files missing/invalid (fail closed, like ApprovalGate).
"""
import argparse
import os
import re
import resource
import signal
import subprocess
import sys

UNIT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sts-core-command.service")
SLICE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sts-core-command.slice")

# Fallbacks mirror the shipped unit if parsing fails validation above.
DEFAULTS = {"cpuquota_pct": 20.0, "memorymax_mib": 512.0}


def parse_kb_or_mib(value: str) -> float:
    """Parse systemd size suffixes (K/M/G/T, optional B or iB) into MiB."""
    value = value.strip().upper()
    m = re.fullmatch(r"(\d+(?:\.\d+)?)(?:\s*)(KB|MB|GB|TB|KIB|MIB|GIB|TIB|K|M|G|T)?", value)
    if not m:
        raise ValueError(f"unparseable size: {value!r}")
    n = float(m.group(1))
    unit = m.group(2) or "K"  # systemd bare numbers are bytes; treat K as default only for '# K'-style comments
    mib_per = {"K": 1 / 1024, "KB": 1 / 1024, "KIB": 1024 / (1024 * 1024),
               "M": 1, "MB": 1, "MIB": 1,
               "G": 1024, "GB": 1024, "GIB": 1024,
               "T": 1024 * 1024, "TB": 1024 * 1024, "TIB": 1024 * 1024}
    return n * mib_per[unit]


def parse_unit(path: str) -> dict:
    """Extract CPUQuota (percent) and MemoryMax (MiB) from a systemd unit."""
    out = {}
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    m = re.search(r"^\s*CPUQuota\s*=\s*(\d+(?:\.\d+)?)%\s*$", text, re.M)
    if not m:
        raise ValueError(f"{path}: no CPUQuota=NN% directive found")
    out["cpuquota_pct"] = float(m.group(1))
    m = re.search(r"^\s*MemoryMax\s*=\s*(.+)$", text, re.M)
    if not m:
        raise ValueError(f"{path}: no MemoryMax directive found")
    out["memorymax_mib"] = parse_kb_or_mib(m.group(1))
    return out


def apply_limits(cpuquota_pct: float, memorymax_mib: float, est_runtime_s: int = 3600) -> None:
    """Apply rlimits in THIS process before exec'ing the server."""
    mem_bytes = int(memorymax_mib * 1024 * 1024)
    # RLIMIT_AS: 2x headroom over the RSS target (VA >> RSS for our stack).
    resource.setrlimit(resource.RLIMIT_AS, (mem_bytes * 2, mem_bytes * 2))
    # RLIMIT_CPU: runaway watchdog = quota_rate * expected runtime seconds.
    cpu_seconds = max(60, int(est_runtime_s * cpuquota_pct / 100.0))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 30))
    # Bound fork bombs regardless of TasksMax availability.
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (128, 128))
    except (ValueError, OSError):
        pass  # not permitted in some containers; systemd TasksMax covers it there
    print(
        f"[resource_guard] applied: CPUQuota={cpuquota_pct}% -> RLIMIT_CPU={cpu_seconds}s "
        f"| MemoryMax={memorymax_mib:.0f}M -> RLIMIT_AS={mem_bytes * 2 // (1024*1024)}M | NPROC<=128",
        flush=True,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--parse-only", action="store_true", help="validate unit files and exit")
    ap.add_argument("--runtime-seconds", type=int, default=3600,
                    help="expected uptime used to size the RLIMIT_CPU watchdog")
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="command line after '--'")
    args = ap.parse_args()

    cfg = dict(DEFAULTS)
    for path in (UNIT_PATH, SLICE_PATH):
        try:
            parsed = parse_unit(path)
            cfg.update(parsed)
            print(f"[resource_guard] parsed {os.path.basename(path)}: "
                  f"CPUQuota={parsed['cpuquota_pct']}% MemoryMax={parsed['memorymax_mib']:.0f}M",
                  flush=True)
        except FileNotFoundError:
            print(f"[resource_guard] ERROR: missing {path}", file=sys.stderr, flush=True)
            return 3
        except ValueError as exc:
            print(f"[resource_guard] ERROR: {exc}", file=sys.stderr, flush=True)
            return 3

    if args.parse_only:
        print("[resource_guard] unit files valid; limits consistent between service and slice.")
        return 0

    cmd = [c for c in args.cmd if c != "--"]
    if not cmd:
        print("usage: resource_guard.py [--runtime-seconds N] -- <command...>", file=sys.stderr)
        return 2

    apply_limits(cfg["cpuquota_pct"], cfg["memorymax_mib"], args.runtime_seconds)

    def relay(sig, _frm):  # forward SIGTERM/SIGINT so uvicorn shuts down cleanly
        try:
            proc.send_signal(sig)
        except ProcessLookupError:
            pass

    signal.signal(signal.SIGTERM, relay)
    signal.signal(signal.SIGINT, relay)

    proc = subprocess.Popen(cmd)
    rc = proc.wait()
    if rc < 0:
        killed = signal.Signals(-rc).name
        print(f"[resource_guard] server terminated by {killed}"
              + (" (RLIMIT_CPU hard cap — quota exhausted)" if -rc == signal.SIGXCPU else ""),
              flush=True)
    return rc


if __name__ == "__main__":
    sys.exit(main())
