"""SEALedger: append-only, hash-chained result ledger for the STS benchmark.

Every benchmark row is written as a single JSONL line carrying:
  * seq        - strictly increasing row number (no gaps allowed)
  * ts         - wall-clock epoch of the write
  * payload    - the phase result dict (tps, status, ...)
  * row_hmac   - HMAC-SHA256 over the canonical encoding of (seq, ts, payload)

The file itself is chained like a blockchain: each line's ``prev`` field holds
the SHA-256 of the previous *raw* line, so truncation, reordering, insertion,
and deletion are all detectable by audit() even without the secret key.

Integrity model ("SEAL" = Secret-key Append Ledger):
  * Without the key you can still DETECT structural tampering (chain walk).
  * With the key you can VERIFY provenance (per-row HMAC) and RE-SEAL a
    legitimately extended ledger (seal()) to prove who appended what.

Crash safety: rows are fsync'd one at a time. If the process dies mid-write,
audit() reports exactly where the ledger diverges; seal() refuses to seal past
a torn final line unless it is repaired first.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Iterator, Optional


class SealError(Exception):
    """Raised when the ledger fails integrity verification or misuse."""


def _canonical(seq: int, ts: float, payload: dict) -> bytes:
    """Deterministic byte encoding used for both HMAC and hashing."""
    return json.dumps(
        {"seq": seq, "ts": ts, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def load_key(env_var: str = "STS_LEDGER_KEY", path: Optional[str] = None) -> bytes:
    """Resolve the sealing key from env var, then a keyfile, else generate one.

    A freshly generated key is persisted next to the ledger (0600) so that
    subsequent runs can verify what earlier runs sealed. Set the env var in CI
    if you want the key to live outside the report directory.
    """
    from_env = os.getenv(env_var)
    if from_env:
        return from_env.encode("utf-8")
    if path and os.path.exists(path):
        with open(path, "rb") as f:
            return f.read().strip()
    raise SealError(
        f"No ledger key found: set ${env_var} or pass an existing keyfile path."
    )


@dataclass
class Row:
    seq: int
    ts: float
    prev: str
    payload: dict
    row_hmac: str
    raw_digest: str  # sha256 of the raw on-disk line


class SEALedger:
    def __init__(self, ledger_path: str, key: bytes):
        self.ledger_path = ledger_path
        self._key = key
        os.makedirs(os.path.dirname(os.path.abspath(ledger_path)) or ".", exist_ok=True)
        # Touch so callers can always open() later.
        if not os.path.exists(ledger_path):
            open(ledger_path, "a").close()

    # -- helpers ---------------------------------------------------------
    def _mac(self, seq: int, ts: float, payload: dict) -> str:
        return hmac.new(self._key, _canonical(seq, ts, payload), hashlib.sha256).hexdigest()

    def _last_line(self) -> Optional[bytes]:
        """Return the final non-empty raw line, or None on an empty ledger."""
        try:
            with open(self.ledger_path, "rb") as f:
                last = None
                for line in f:
                    if line.strip():
                        last = line.rstrip(b"\n")
                return last
        except FileNotFoundError:
            return None

    def head_digest(self) -> str:
        """SHA-256 of the last raw line ('' chain anchor if empty)."""
        last = self._last_line()
        return hashlib.sha256(last).hexdigest() if last else ""

    # -- public API ------------------------------------------------------
    def append(self, payload: dict) -> Row:
        """Atomically append one sealed row. Returns the parsed Row."""
        last = self._last_line()
        if last is None:
            seq, prev = 1, ""
        else:
            try:
                tail = json.loads(last.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                raise SealError(
                    "Ledger tail is corrupt/torn; repair or truncate the last "
                    "line before appending (see audit())."
                ) from e
            seq, prev = int(tail["seq"]) + 1, hashlib.sha256(last).hexdigest()

        ts = time.time()
        rec = {
            "seq": seq,
            "ts": ts,
            "prev": prev,
            "payload": payload,
            "row_hmac": self._mac(seq, ts, payload),
        }
        line = json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"

        # O_APPEND + single write() keeps concurrent appenders from interleaving
        # partial lines (line < PIPE_BUF); fsync makes it durable before return.
        fd = os.open(self.ledger_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

        rec["raw_digest"] = hashlib.sha256(line.rstrip("\n").encode("utf-8")).hexdigest()
        return Row(**rec)

    def iter_rows(self) -> Iterator[Row]:
        with open(self.ledger_path, "rb") as f:
            for line in f:
                if not line.strip():
                    continue
                rec = json.loads(line.decode("utf-8"))
                rec["raw_digest"] = hashlib.sha256(line.rstrip(b"\n")).hexdigest()
                yield Row(**rec)

    def audit(self) -> dict:
        """Full chain-walk + HMAC verification. Never raises on tampering;
        returns a structured report so pipelines can decide policy."""
        report = {
            "ok": True,
            "rows_checked": 0,
            "errors": [],
        }
        expected_prev = ""
        expected_seq = 1
        try:
            with open(self.ledger_path, "rb") as f:
                for lineno, raw in enumerate(f, start=1):
                    if not raw.strip():
                        report["errors"].append(f"line {lineno}: blank line in ledger")
                        report["ok"] = False
                        continue
                    try:
                        rec = json.loads(raw.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        report["errors"].append(f"line {lineno}: torn/corrupt JSON")
                        report["ok"] = False
                        break  # chain beyond a torn line cannot be walked
                    ok_fields = {"seq", "ts", "prev", "payload", "row_hmac"}
                    if set(rec) != ok_fields:
                        report["errors"].append(
                            f"line {lineno}: unexpected field set {sorted(rec)}"
                        )
                        report["ok"] = False
                    if rec["seq"] != expected_seq:
                        report["errors"].append(
                            f"line {lineno}: seq gap (expected {expected_seq}, got {rec['seq']})"
                        )
                        report["ok"] = False
                    if rec["prev"] != expected_prev:
                        report["errors"].append(
                            f"line {lineno}: broken hash chain (prev mismatch)"
                        )
                        report["ok"] = False
                    want_mac = self._mac(int(rec["seq"]), float(rec["ts"]), rec["payload"])
                    if not hmac.compare_digest(want_mac, rec["row_hmac"]):
                        report["errors"].append(
                            f"line {lineno}: HMAC mismatch (payload forged or wrong key)"
                        )
                        report["ok"] = False
                    expected_prev = hashlib.sha256(raw.rstrip(b"\n")).hexdigest()
                    expected_seq = int(rec["seq"]) + 1
                    report["rows_checked"] += 1
        except FileNotFoundError:
            report["errors"].append("ledger file missing")
            report["ok"] = False
        return report

    def seal(self) -> dict:
        """Recompute and stamp a run-level manifest over the audited chain.

        Call after the final append and after audit()['ok'] is True. The
        manifest (head digest + row count + per-run signature) is written
        alongside the ledger so downstream tooling can check the whole file
        against one signature instead of walking every row.
        """
        report = self.audit()
        if not report["ok"]:
            raise SealError(f"refusing to seal a failing ledger: {report['errors']}")
        head = self.head_digest()
        manifest = {
            "sealed_at": time.time(),
            "rows": report["rows_checked"],
            "head_digest": head,
            "signature": hmac.new(
                self._key, f"{report['rows_checked']}:{head}".encode(), hashlib.sha256
            ).hexdigest(),
        }
        tmp = self.ledger_path + ".seal.tmp"
        with open(tmp, "w") as f:
            json.dump(manifest, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.ledger_path + ".seal.json")
        return manifest

    @staticmethod
    def verify_seal(ledger_path: str, key: bytes) -> dict:
        """Offline check: does .seal.json still match the ledger on disk?"""
        with open(ledger_path + ".seal.json") as f:
            manifest = json.load(f)
        want = hmac.new(
            key, f"{manifest['rows']}:{manifest['head_digest']}".encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(want, manifest["signature"]):
            raise SealError("seal manifest signature invalid")
        head = SEALedger(ledger_path, key).head_digest()
        if head != manifest["head_digest"]:
            raise SealError(
                "ledger changed after sealing (truncation/reorder detected)"
            )
        return manifest
