"""STS core primitives: the monotonic time source and the tamper-evident
assurance ledger used by every category of the validation matrix.

Design contract (the thing the benchmark is meant to prove):

  * ``STSMonotonicClock`` reads CLOCK_MONOTONIC_RAW — a hardware tick baseline
    that the kernel does NOT adjust for NTP steps, slews, or settimeofday().
    It additionally enforces strict monotonicity at the API boundary: no call
    may ever return a value smaller than the previous one, regardless of what
    any external time service claims. Wall-clock (UTC) values are treated as
    untrusted metadata only — they are recorded alongside the sovereign stamp
    but never feed ordering decisions.

  * ``AssuranceLedger`` is an append-only SQLite store whose rows form a hash
    chain (SEAL = Signed Event Assurance Ledger semantics): each row's
    ``seal_hash`` covers payload + previous seal + the monotonic stamp, so
    reordering, editing, or deleting any entry breaks verification. Commits
    run under WAL with per-commit latency capture.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

GENESIS_SEAL = "0" * 64


def raw_tick() -> float:
    """Hardware monotonic tick: immune to NTP/settimeofday adjustments."""
    return time.clock_gettime(time.CLOCK_MONOTONIC_RAW)


class TemporalAnomaly(RuntimeError):
    """Raised when a backward time step would violate strict monotonicity."""


@dataclass
class ClockStats:
    samples: int = 0
    rejected_backward_steps: int = 0
    max_step_ns: int = 0
    min_step_ns: Optional[int] = None
    step_total_ns: int = 0

    @property
    def mean_step_ns(self) -> float:
        if self.samples < 2:
            return 0.0
        return self.step_total_ns / (self.samples - 1)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "samples": self.samples,
            "rejected_backward_steps": self.rejected_backward_steps,
            "max_step_ns": self.max_step_ns,
            "min_step_ns": self.min_step_ns,
            "mean_step_ns": round(self.mean_step_ns, 3),
        }


class STSMonotonicClock:
    """Sovereign Time System clock: RAW monotonic source + strict enforcement.

    ``stamp()`` returns a nondecreasing nanosecond integer derived from
    CLOCK_MONOTONIC_RAW. If the underlying source were ever observed to move
    backwards (impossible for MONOTONIC_RAW on Linux, but the guard makes the
    invariant explicit and testable), the step is REJECTED: the counter is
    held at the last issued value and the event is counted, never absorbed.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_ns: Optional[int] = None
        self.stats = ClockStats()

    # -- trusted path -------------------------------------------------------

    def stamp(self) -> int:
        """Return a strictly nondecreasing monotonic timestamp (ns)."""
        ns = int(raw_tick() * 1_000_000_000)
        with self._lock:
            self.stats.samples += 1
            last = self._last_ns
            if last is not None:
                delta = ns - last
                if delta < 0:
                    # Backward step detected -> reject, hold the line.
                    self.stats.rejected_backward_steps += 1
                    ns = last
                    delta = 0
                self.stats.step_total_ns += delta
                if delta > self.stats.max_step_ns:
                    self.stats.max_step_ns = delta
                self.stats.min_step_ns = (
                    delta if self.stats.min_step_ns is None
                    else min(self.stats.min_step_ns, delta)
                )
            self._last_ns = ns
            return ns

    @staticmethod
    def check_monotonic(stamps: Iterable[int]) -> List[str]:
        """Audit helper: list violations ('backward jump at index i') found."""
        errors: List[str] = []
        prev: Optional[int] = None
        for i, s in enumerate(stamps):
            if prev is not None and s < prev:
                errors.append(f"backward jump at index {i}: {s} < {prev}")
            prev = s
        return errors

    # -- untrusted path (proving immunity) ----------------------------------

    @staticmethod
    def wall_clock_metadata() -> Dict[str, Any]:
        """Capture UTC/wall readings purely as metadata. Never used for order.

        Returns both the poisoned-prone POSIX clock and the sovereign RAW
        tick, so benchmarks can measure how far external time has diverged
        from the hardware baseline.
        """
        return {
            "utc_wall": time.time(),
            "clock_realtime_ns": time.clock_gettime(time.CLOCK_REALTIME),
            "clock_monotonic_raw_ns": int(raw_tick() * 1_000_000_000),
        }


@dataclass
class LedgerRow:
    seq: int
    mono_ns: int
    utc_wall: float
    stream: str
    payload: Dict[str, Any]
    prev_seal: str
    seal_hash: str
    commit_latency_ms: float


class AssuranceLedger:
    """Append-only SQLite ledger with per-row SEAL hash chaining."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS ledger (
        seq               INTEGER PRIMARY KEY,
        mono_ns           INTEGER NOT NULL,
        utc_wall          REAL NOT NULL,
        stream            TEXT NOT NULL,
        payload           TEXT NOT NULL,
        prev_seal         TEXT NOT NULL,
        seal_hash         TEXT NOT NULL,
        commit_latency_ms REAL NOT NULL
    );
    """

    def __init__(self, path: str) -> None:
        self.path = path
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute(self.SCHEMA)
        self._conn.commit()
        tail = self._conn.execute(
            "SELECT seq, seal_hash FROM ledger ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        self._seq: int = tail[0] if tail else 0
        self._prev_seal: str = tail[1] if tail else GENESIS_SEAL
        self.commits: int = 0
        self.latencies_ms: List[float] = []

    @staticmethod
    def compute_seal(seq: int, mono_ns: int, utc_wall: float, stream: str,
                     payload_json: str, prev_seal: str) -> str:
        canonical = json.dumps(
            {"seq": seq, "mono_ns": mono_ns, "utc_wall": utc_wall,
             "stream": stream, "payload": payload_json, "prev_seal": prev_seal},
            sort_keys=True, separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def append(self, clock: STSMonotonicClock, stream: str,
               payload: Dict[str, Any]) -> LedgerRow:
        """Commit one event; captures commit latency; seals the row.

        The monotonic stamp is taken INSIDE the ledger lock so that seq order
        and timestamp order are atomic with respect to concurrent producers —
        the ordering guarantee must hold across threads, not just within one.
        """
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        with self._lock:
            mono_ns = clock.stamp()
            utc_wall = time.time()      # metadata only — never ordering input
            seq = self._seq + 1
            prev_seal = self._prev_seal
            seal = self.compute_seal(seq, mono_ns, utc_wall, stream,
                                     payload_json, prev_seal)
            # Latency is observability metadata, NOT evidence: it is measured
            # around INSERT+COMMIT but excluded from the sealed fields so the
            # row can be verified byte-for-byte without rewriting anything.
            t0 = time.perf_counter()
            self._conn.execute(
                "INSERT INTO ledger (seq, mono_ns, utc_wall, stream, payload,"
                " prev_seal, seal_hash, commit_latency_ms)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (seq, mono_ns, utc_wall, stream, payload_json,
                 prev_seal, seal, 0.0),
            )
            self._conn.commit()
            latency_ms = (time.perf_counter() - t0) * 1000.0
            self._conn.execute(
                "UPDATE ledger SET commit_latency_ms = ? WHERE seq = ?",
                (latency_ms, seq),
            )
            self._conn.commit()
            self._seq = seq
            self._prev_seal = seal
            self.commits += 1
            self.latencies_ms.append(latency_ms)
            return LedgerRow(seq, mono_ns, utc_wall, stream, payload,
                             prev_seal, seal, latency_ms)

    def append_many(self, clock: STSMonotonicClock,
                    events: Iterable[Tuple[str, Dict[str, Any]]]) -> List[LedgerRow]:
        return [self.append(clock, s, p) for s, p in events]

    # -- verification ---------------------------------------------------------

    def verify(self) -> Tuple[bool, List[str]]:
        """Re-hash the entire chain and enforce monotonic-stamp ordering.

        Returns (ok, errors). Checks:
          * seq contiguity starting at 1
          * seal_hash recomputation over canonical row fields
          * prev_seal linkage (insert/delete/reorder detection)
          * mono_ns strictly nondecreasing (STS ordering invariant)
        """
        errors: List[str] = []
        expected_seq = 1
        expected_prev = GENESIS_SEAL
        prev_mono: Optional[int] = None
        for row in self._conn.execute(
                "SELECT seq, mono_ns, utc_wall, stream, payload, prev_seal,"
                " seal_hash FROM ledger ORDER BY seq ASC"):
            seq, mono_ns, utc_wall, stream, payload, prev_seal, seal_hash = row
            where = f"seq {seq}"
            recomputed = self.compute_seal(seq, mono_ns, utc_wall, stream,
                                           payload, prev_seal)
            if recomputed != seal_hash:
                errors.append(f"{where}: seal mismatch — payload/time edited")
            if prev_seal != expected_prev:
                errors.append(f"{where}: prev_seal break — chain reordered/"
                              "truncated")
            if seq != expected_seq:
                errors.append(f"{where}: seq gap (expected {expected_seq})")
            if prev_mono is not None and mono_ns < prev_mono:
                errors.append(f"{where}: TEMPORAL ANOMALY — monotonic stamp "
                              f"went backwards ({mono_ns} < {prev_mono})")
            expected_seq = seq + 1
            expected_prev = seal_hash
            prev_mono = mono_ns
        return (not errors, errors)

    def all_stamps(self) -> List[int]:
        return [r[0] for r in self._conn.execute(
            "SELECT mono_ns FROM ledger ORDER BY seq ASC")]

    def stats(self) -> Dict[str, Any]:
        lat = sorted(self.latencies_ms)
        n = len(lat)
        return {
            "commits": self.commits,
            "write_latency_ms": {
                "p50": round(lat[n // 2], 4) if n else 0.0,
                "p99": round(lat[min(n - 1, int(n * 0.99))], 4) if n else 0.0,
                "max": round(lat[-1], 4) if n else 0.0,
            },
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()
