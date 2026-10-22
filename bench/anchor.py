"""SQLite/WAL anchoring engine for the STS ledger.

Generates deterministic, verifiable Merkle checkpoints over batches of
hash-chained ledger events and anchors them (conceptually) to an external
timestamping service (STS).

Design rules (the invariants that earlier revisions got wrong):

  * A batch is ``batch_size`` ACTUAL EVENTS, not a raw sequence-number span.
    Sparse logs (deletes, torn-write rollbacks, AUTOINCREMENT gaps after a
    failed transaction) must never silently drop or duplicate events.
  * Event selection happens inside ONE transaction with explicit
    ``ORDER BY seq ASC LIMIT n`` so the Merkle root is deterministic and the
    snapshot cannot change underneath us.
  * The public watermark (``last_anchored_seq``) advances ONLY on external
    ACK (:meth:`AnchorEngine.confirm_checkpoint`). Pending checkpoints are
    recorded but do not move the watermark, so nothing is ever anchored
    twice or skipped forever.
  * Concurrency is handled with SQLite WAL mode plus ``BEGIN IMMEDIATE``
    (write-lock first), which serialises checkpoint generation between
    competing workers; ``timeout`` avoids spurious ``database is locked``
    crashes under contention.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from typing import List, Optional

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Checkpoint:
    anchor_id: str
    ledger_id: str
    seq_start: int
    seq_end: int
    head_hash: str
    merkle_root: str
    sts_timestamp: float
    status: str  # 'pending', 'anchored', 'failed'
    event_count: int = 0  # actual number of leaves (robust to sparse seqs)
    prev_head_hash: str = ""  # head_hash of previous CONFIRMED batch ('' = genesis)


def compute_merkle_root(payload_hashes: List[str]) -> str:
    """SHA-256 Merkle root over hex-encoded leaf hashes.

    Deterministic: leaves are hashed in ascending-seq order; an odd node is
    paired with a duplicate of itself (Bitcoin-style). Inputs are normalised
    to lowercase hex strings so the same logical tree always yields the same
    root regardless of caller formatting.
    """
    if not payload_hashes:
        return hashlib.sha256(b"empty_batch").hexdigest()

    level = [bytes.fromhex(h.strip().lower()) for h in payload_hashes]
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            next_level.append(hashlib.sha256(left + right).digest())
        level = next_level
    return level[0].hex()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger_events (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL NOT NULL DEFAULT 0,
    payload      TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    hash         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checkpoints (
    anchor_id     TEXT PRIMARY KEY,
    ledger_id     TEXT,
    seq_start     INTEGER,
    seq_end       INTEGER,
    head_hash     TEXT,
    merkle_root   TEXT,
    sts_timestamp REAL,
    status        TEXT DEFAULT 'pending',
    event_count   INTEGER DEFAULT 0,
    prev_head_hash TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS engine_state (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

# executescript() implicitly COMMITs any open transaction, which breaks our
# explicit BEGIN IMMEDIATE handling; split the schema into plain statements.
_STATEMENTS = [s.strip() for s in _SCHEMA.split(";") if s.strip()]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class AnchorEngine:
    def __init__(self, db_path: str, ledger_id: str, batch_size: int = 1000):
        self.db_path = db_path
        self.ledger_id = ledger_id
        self.batch_size = batch_size
        # One long-lived WAL connection per engine instance. All of the
        # engine's own transactions run on it (guarded by _txlock for
        # in-process thread safety); SQLite's file lock still serialises
        # competing processes. Callers may also pass their own connection
        # into generate_checkpoint().
        # isolation_level=None => we drive BEGIN IMMEDIATE/COMMIT explicitly.
        self._conn = self._connect()
        self._txlock = threading.Lock()
        with self._tx() as conn:
            for stmt in _STATEMENTS:
                conn.execute(stmt)
            conn.commit()

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass

    def __enter__(self) -> "AnchorEngine":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- infrastructure ----------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        # Legacy transaction control (isolation_level=""): the sqlite3 module
        # implicitly COMMITs before DDL and defers DML, which would silently
        # break our explicit BEGIN IMMEDIATE handling. With isolation_level
        # = None we drive BEGIN IMMEDIATE / COMMIT / ROLLBACK by hand and
        # never mix in implicit transactions. check_same_thread=False lets
        # worker threads share this connection; _txlock serialises access.
        conn = sqlite3.connect(
            self.db_path, timeout=30.0, isolation_level=None,
            check_same_thread=False,
        )
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=30000;")
        return conn

    class _Tx:
        """Context manager: BEGIN IMMEDIATE ... COMMIT/ROLLBACK on one conn."""

        def __init__(self, engine: "AnchorEngine", external=None):
            self.e = engine
            self.external = external  # caller-supplied connection or None

        def __enter__(self):
            if self.external is not None:
                self.conn = self.external
                # A caller-supplied connection may already sit inside a
                # transaction of its own; join it instead of crashing with
                # "cannot start a transaction within a transaction".
                self.begun = not self.conn.in_transaction
                if self.begun:
                    self.conn.execute("BEGIN IMMEDIATE;")
            else:
                self.lock = self.e._txlock
                self.lock.acquire()
                self.conn = self.e._conn
                self.begun = True
                self.conn.execute("BEGIN IMMEDIATE;")
            return self.conn

        def __exit__(self, exc_type, exc, tb):
            if exc_type is not None and self.begun:
                try:
                    self.conn.rollback()
                except Exception:
                    pass
            if self.external is None:
                self.lock.release()
            return False

    def _tx(self, db_conn: Optional[sqlite3.Connection] = None) -> "AnchorEngine._Tx":
        return AnchorEngine._Tx(self, db_conn)

    def append_event(self, payload: dict | str, ts: Optional[float] = None) -> int:
        """Append one hash-chained event; returns its seq."""
        body = payload if isinstance(payload, str) else json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        )
        payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        ts = time.time() if ts is None else ts
        with self._tx() as conn:
            cur = conn.execute(
                "SELECT hash FROM ledger_events ORDER BY seq DESC LIMIT 1"
            )
            row = cur.fetchone()
            prev_hash = row[0] if row else ""
            chain_input = f"{prev_hash}|{ts:.6f}|{payload_hash}"
            hash_ = hashlib.sha256(chain_input.encode("utf-8")).hexdigest()
            cur = conn.execute(
                "INSERT INTO ledger_events (ts, payload, payload_hash, hash)"
                " VALUES (?, ?, ?, ?)",
                (ts, body, payload_hash, hash_),
            )
            seq = cur.lastrowid
            conn.commit()
            return seq

    # -- watermark helpers ---------------------------------------------------

    @staticmethod
    def _get_last_anchored_seq(conn: sqlite3.Connection) -> int:
        cur = conn.execute(
            "SELECT value FROM engine_state WHERE key = 'last_anchored_seq'"
        )
        row = cur.fetchone()
        return int(row[0]) if row else 0

    @staticmethod
    def _set_last_anchored_seq(conn: sqlite3.Connection, seq: int) -> None:
        conn.execute(
            "INSERT INTO engine_state (key, value) VALUES ('last_anchored_seq', ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(seq),),
        )

    # -- checkpoint generation ----------------------------------------------

    def generate_checkpoint(self, db_conn: Optional[sqlite3.Connection] = None) -> Optional[Checkpoint]:
        """Build a Merkle checkpoint over the next unanchored batch.

        Returns ``None`` (without touching state) when fewer than
        ``batch_size`` events remain. Never advances the watermark: that is
        :meth:`confirm_checkpoint`'s job after the external STS ACK.
        """
        # BEGIN IMMEDIATE takes the write lock up front: two racing
        # engines serialise here instead of producing overlapping,
        # non-deterministic batches.
        with self._tx(db_conn) as conn:
            last_seq = self._get_last_anchored_seq(conn)

            # Count ACTUAL events above the watermark — not the raw
            # seq span — so gaps can neither fake a full batch nor
            # hide real ones.
            cur = conn.execute(
                "SELECT COUNT(*) FROM ledger_events WHERE seq > ?", (last_seq,)
            )
            available = cur.fetchone()[0]
            if available < self.batch_size:
                conn.rollback()
                return None

            # Explicit ORDER BY + LIMIT: deterministic leaf order and
            # exactly batch_size rows even on a sparse log.
            cur = conn.execute(
                "SELECT seq, payload_hash, hash FROM ledger_events"
                " WHERE seq > ? ORDER BY seq ASC LIMIT ?",
                (last_seq, self.batch_size),
            )
            rows = cur.fetchall()
            if len(rows) < self.batch_size:  # defensive: changed under us
                conn.rollback()
                return None

            seq_start = rows[0][0]
            seq_end = rows[-1][0]
            payload_hashes = [r[1] for r in rows]
            head_hash = rows[-1][2]  # chain hash of the LAST selected row

            merkle_root = compute_merkle_root(payload_hashes)

            # Hash-chain linkage: reference the head of the previously
            # CONFIRMED batch so Core Command can detect forks/replays.
            cur = conn.execute(
                "SELECT head_hash FROM checkpoints"
                " WHERE ledger_id = ? AND status = 'anchored'"
                " ORDER BY seq_end DESC LIMIT 1",
                (self.ledger_id,),
            )
            prev_row = cur.fetchone()
            prev_head_hash = prev_row[0] if prev_row else ""

            checkpoint = Checkpoint(
                anchor_id=str(uuid.uuid4()),
                ledger_id=self.ledger_id,
                seq_start=seq_start,
                seq_end=seq_end,
                head_hash=head_hash,
                merkle_root=merkle_root,
                sts_timestamp=time.time(),
                status="pending",
                event_count=len(rows),
                prev_head_hash=prev_head_hash,
            )

            conn.execute(
                "INSERT INTO checkpoints (anchor_id, ledger_id, seq_start,"
                " seq_end, head_hash, merkle_root, sts_timestamp, status,"
                " event_count, prev_head_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    checkpoint.anchor_id,
                    checkpoint.ledger_id,
                    checkpoint.seq_start,
                    checkpoint.seq_end,
                    checkpoint.head_hash,
                    checkpoint.merkle_root,
                    checkpoint.sts_timestamp,
                    checkpoint.status,
                    checkpoint.event_count,
                    checkpoint.prev_head_hash,
                ),
            )
            # Watermark deliberately NOT advanced while pending.
            conn.commit()
            return checkpoint

    # -- lifecycle: anchored / failed ---------------------------------------

    def confirm_checkpoint(self, anchor_id: str) -> bool:
        """External STS ACK arrived: mark anchored and advance the watermark.

        Idempotent. Returns False for unknown/duplicate ACKs so callers can
        detect protocol errors.
        """
        with self._tx() as conn:
            cur = conn.execute(
                "SELECT status, seq_end FROM checkpoints WHERE anchor_id = ?",
                (anchor_id,),
            )
            row = cur.fetchone()
            if row is None or row[0] != "pending":
                conn.rollback()
                return False
            conn.execute(
                "UPDATE checkpoints SET status = 'anchored' WHERE anchor_id = ?",
                (anchor_id,),
            )
            last_seq = self._get_last_anchored_seq(conn)
            self._set_last_anchored_seq(conn, max(last_seq, int(row[1])))
            conn.commit()
            return True

    def mark_failed(self, anchor_id: str) -> bool:
        """STS submission failed: flag it. The watermark stays put, so the
        same events are re-batched by the next generate_checkpoint()."""
        with self._tx() as conn:
            cur = conn.execute(
                "UPDATE checkpoints SET status = 'failed'"
                " WHERE anchor_id = ? AND status = 'pending'",
                (anchor_id,),
            )
            conn.commit()
            return cur.rowcount > 0

    # -- verification / introspection ---------------------------------------

    def verify_checkpoint(self, anchor_id: str) -> bool:
        """Recompute the Merkle root from the ledger and compare."""
        cur = self._conn.execute(
            "SELECT seq_start, seq_end, merkle_root FROM checkpoints"
            " WHERE anchor_id = ?",
            (anchor_id,),
        )
        row = cur.fetchone()
        if row is None:
            return False
        seq_start, seq_end, stored = row
        cur = self._conn.execute(
            "SELECT payload_hash FROM ledger_events"
            " WHERE seq BETWEEN ? AND ? ORDER BY seq ASC",
            (seq_start, seq_end),
        )
        recomputed = compute_merkle_root([r[0] for r in cur.fetchall()])
        return recomputed == stored

    def get_checkpoint(self, anchor_id: str) -> Optional[Checkpoint]:
        cur = self._conn.execute(
            "SELECT anchor_id, ledger_id, seq_start, seq_end, head_hash,"
            " merkle_root, sts_timestamp, status, event_count, prev_head_hash"
            " FROM checkpoints WHERE anchor_id = ?",
            (anchor_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return Checkpoint(*row)

    @property
    def last_anchored_seq(self) -> int:
        return self._get_last_anchored_seq(self._conn)

    def pending_checkpoints(self) -> List[Checkpoint]:
        cur = self._conn.execute(
            "SELECT anchor_id, ledger_id, seq_start, seq_end, head_hash,"
            " merkle_root, sts_timestamp, status, event_count, prev_head_hash"
            " FROM checkpoints WHERE status = 'pending' ORDER BY seq_start"
        )
        return [Checkpoint(*row) for row in cur.fetchall()]

    def checkpoint_to_json(self, cp: Checkpoint) -> str:
        return json.dumps(asdict(cp), sort_keys=True)

# ---------------------------------------------------------------------------
# Quarantine queue: async flush to Core Command
# ---------------------------------------------------------------------------

import asyncio
import logging
import os

import aiohttp

logger = logging.getLogger("bench.anchor")

_QUARANTINE_SCHEMA = """
CREATE TABLE IF NOT EXISTS quarantine_queue (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    anchor_id    TEXT,
    payload      TEXT NOT NULL,
    status       TEXT DEFAULT 'PENDING',
    created_at   REAL NOT NULL DEFAULT 0,
    flushed_at   REAL
)
"""

_SYNC_ENDPOINT_ENV = "STS_SYNC_ENDPOINT"


class QuarantineQueue:
    """Buffer of checkpoint payloads awaiting delivery to Core Command.

    Entries live in the same SQLite database (WAL) as the ledger, so a crash
    between STS submission and ACK never loses an anchor: unflushed rows stay
    PENDING and are retried by :meth:`flush_quarantine_queue`.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        # isolation_level=None => we drive BEGIN/COMMIT explicitly; WAL keeps
        # edge writers and the flusher from blocking each other.
        self._conn = sqlite3.connect(
            db_path, timeout=30.0, isolation_level=None, check_same_thread=False,
        )
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute("PRAGMA busy_timeout=30000;")
        for stmt in [s.strip() for s in _QUARANTINE_SCHEMA.split(";") if s.strip()]:
            self._conn.execute(stmt)

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass

    def enqueue(self, anchor_id: str, payload: dict) -> int:
        """Persist one pending sync batch; returns its queue id."""
        cur = self._conn.execute(
            "INSERT INTO quarantine_queue (anchor_id, payload, status, created_at)"
            " VALUES (?, ?, 'PENDING', ?)",
            (anchor_id, json.dumps(payload, sort_keys=True), time.time()),
        )
        return cur.lastrowid

    def fetch_pending(self, limit: int = 100) -> List[tuple]:
        """Return up to ``limit`` (id, anchor_id, payload_dict) rows, oldest first."""
        cur = self._conn.execute(
            "SELECT id, anchor_id, payload FROM quarantine_queue"
            " WHERE status = 'PENDING' ORDER BY id ASC LIMIT ?",
            (limit,),
        )
        return [(row[0], row[1], json.loads(row[2])) for row in cur.fetchall()]

    def mark_synced(self, ack_ids: List[int]) -> int:
        """Mark flushed entries SYNCED (tuple() binding for the IN clause)."""
        if not ack_ids:
            return 0
        placeholders = ",".join("?" * len(ack_ids))
        cur = self._conn.execute(
            f"UPDATE quarantine_queue SET status = 'SYNCED', flushed_at = ?"
            f" WHERE id IN ({placeholders})",
            (time.time(), *tuple(ack_ids)),
        )
        return cur.rowcount

    async def flush_quarantine_queue(
        self,
        sync_endpoint: Optional[str] = None,
        headers: Optional[dict] = None,
        batch_limit: int = 100,
        timeout_s: float = 10.0,
    ) -> int:
        """POST pending batches to Core Command and mark ACKed ids SYNCED.

        Returns the number of entries confirmed synced. On non-200 responses
        or transport errors nothing is marked: the rows remain PENDING and
        are retried on the next flush (at-least-once delivery; Core-side
        dedupes by entry id).
        """
        sync_endpoint = sync_endpoint or os.environ.get(_SYNC_ENDPOINT_ENV)
        if not sync_endpoint:
            logger.warning("No sync endpoint configured; skipping flush.")
            return 0

        batch_rows = self.fetch_pending(batch_limit)
        if not batch_rows:
            return 0

        batch = [
            {"id": qid, "anchor_id": anchor_id, **payload}
            for qid, anchor_id, payload in batch_rows
        ]
        # Core Command's /anchors/batch contract is BatchRequest(batch=[...]);
        # posting a bare list would be rejected with 422 by FastAPI validation.
        body = {"batch": batch}
        headers = headers or {"Content-Type": "application/json"}

        conn = self._conn
        flushed = 0
        try:
            client_timeout = aiohttp.ClientTimeout(total=timeout_s)
            async with aiohttp.ClientSession(timeout=client_timeout) as session:
                async with session.post(
                    sync_endpoint, json=body, headers=headers
                ) as response:
                    if response.status == 200:
                        # FIX 1: Properly await the coroutine before accessing .get()
                        resp_data = await response.json()
                        ack_ids = [item["id"] for item in resp_data.get("acknowledged", [])]

                        # Core Command reports policy rejections (bad signature,
                        # sequence gap/overlap, unknown device). Those rows must
                        # NOT be retried forever: mark them REJECTED so an
                        # operator can intervene, and alert loudly.
                        rejected = resp_data.get("rejected", []) or []
                        rej_ids = [r["id"] for r in rejected if "id" in r]
                        if rej_ids:
                            reasons = {r.get("id"): r.get("reason", "?") for r in rejected}
                            placeholders_r = ",".join("?" * len(rej_ids))
                            conn.execute(
                                f"UPDATE quarantine_queue SET status = 'REJECTED'"
                                f" WHERE id IN ({placeholders_r})",
                                tuple(rej_ids),
                            )
                            conn.commit()
                            for rid in rej_ids:
                                logger.error(
                                    "Core Command permanently rejected anchor queue id=%s: %s"
                                    " -- possible compromise or data loss; operator review required.",
                                    rid, reasons.get(rid),
                                )

                        if ack_ids:
                            placeholders = ",".join("?" * len(ack_ids))
                            # FIX 2: Pass tuple(ack_ids) to satisfy sqlite3 parameter binding
                            conn.execute(
                                f"UPDATE quarantine_queue SET status = 'SYNCED'"
                                f" WHERE id IN ({placeholders})",
                                tuple(ack_ids),
                            )
                            conn.commit()
                            flushed = len(ack_ids)
                            logger.info(
                                f"Successfully flushed {flushed} anchors to Core Command."
                            )
                    else:
                        body = await response.text()
                        logger.warning(
                            "Sync endpoint returned %s; batch stays PENDING for retry: %s",
                            response.status, body[:200],
                        )
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            logger.error("Flush to Core Command failed; batch stays PENDING: %s", exc)
        return flushed


# ---------------------------------------------------------------------------
# AnchorClient: edge orchestrator (generate -> sign -> quarantine -> flush -> confirm)
# ---------------------------------------------------------------------------

class AnchorClient:
    """End-to-end edge-node orchestrator against STS Core Command.

    Pipeline per batch:
      1. ``AnchorEngine.generate_checkpoint`` builds a Merkle checkpoint over
         the next unanchored ledger events (watermark NOT advanced yet).
      2. The checkpoint dict is signed with the device's Ed25519 private key
         over the SAME canonical JSON the server verifies
         (json.dumps(sort_keys=True, separators=(',',':'))).
      3. The signed envelope is buffered in the quarantine queue (crash-safe).
      4. ``flush_quarantine_queue`` POSTs it to Core Command
         (default http://localhost:8000/anchors/batch).
      5. Only on ACK does the engine advance its watermark
         (confirm_checkpoint); permanent policy rejections mark the
         checkpoint 'failed' so it is retried/regenerated later.
    """

    DEFAULT_ENDPOINT = "http://localhost:8000/anchors/batch"

    def __init__(
        self,
        db_path: str,
        device_id: str,
        signing_key_b64: Optional[str] = None,
        keys_file: Optional[str] = None,
        endpoint: Optional[str] = None,
        batch_size: int = 1000,
    ):
        from nacl.signing import SigningKey

        if keys_file and not signing_key_b64:
            with open(keys_file) as fh:
                data = json.load(fh)
            device_id = data.get("device_id", device_id)
            signing_key_b64 = data["private_key_b64"]
        if not signing_key_b64:
            raise ValueError("Provide signing_key_b64 or keys_file")

        self._signing_key = SigningKey(base64.b64decode(signing_key_b64))
        self.device_id = device_id
        self.endpoint = endpoint or os.environ.get(_SYNC_ENDPOINT_ENV) or self.DEFAULT_ENDPOINT
        self.engine = AnchorEngine(db_path, ledger_id=device_id, batch_size=batch_size)
        self.quarantine = QuarantineQueue(db_path)
        logger.info(
            "AnchorClient %s ready (endpoint=%s, pubkey=%s)",
            device_id, self.endpoint,
            base64.b64encode(bytes(self._signing_key.verify_key)).decode(),
        )

    def close(self) -> None:
        self.engine.close()
        self.quarantine.close()

    def sign_checkpoint(self, cp_dict: dict) -> str:
        """Ed25519 signature over the canonical anchor payload.

        Uses validator.canonical_anchor_payload (whitelisted SIGNED_FIELDS,
        sort_keys, compact separators) — the EXACT function Core Command's
        /anchors/batch uses to reconstruct the signed message, so the two
        sides can never desynchronise on extra/renamed fields.
        """
        from validator import canonical_anchor_payload

        payload_bytes = canonical_anchor_payload(cp_dict)
        return base64.b64encode(self._signing_key.sign(payload_bytes).signature).decode()

    async def run_once(self) -> Optional[dict]:
        """One full anchor cycle; returns an outcome dict or None if no batch ready."""
        cp = self.engine.generate_checkpoint()
        if cp is None:
            logger.info("Not enough events for a batch of %d; nothing to anchor.",
                        self.engine.batch_size)
            return None

        cp_dict = asdict(cp)
        cp_dict.pop("status", None)
        signature = self.sign_checkpoint(cp_dict)
        envelope = {
            "payload": cp_dict,
            "signature": signature,
            "timestamp": time.time(),
        }
        qid = self.quarantine.enqueue(cp.anchor_id, envelope)
        logger.info(
            "Generated + signed checkpoint %s seq %d-%d (merkle=%s..., queued id=%d)",
            cp.anchor_id[:8], cp.seq_start, cp.seq_end, cp.merkle_root[:16], qid,
        )

        flushed = await self.quarantine.flush_quarantine_queue(sync_endpoint=self.endpoint)
        cur = self.quarantine._conn.execute(
            "SELECT status FROM quarantine_queue WHERE id = ?", (qid,)
        )
        row = cur.fetchone()
        status = row[0] if row else "?"

        if status == "SYNCED":
            self.engine.confirm_checkpoint(cp.anchor_id)
            logger.info(
                "Core Command ACKed %s; checkpoint ANCHORED, watermark advanced to seq %d.",
                cp.anchor_id[:8], self.engine.last_anchored_seq,
            )
            return {"anchor_id": cp.anchor_id, "seq": (cp.seq_start, cp.seq_end), "result": "ANCHORED"}

        if status == "REJECTED":
            self.engine.mark_failed(cp.anchor_id)
            logger.error("Core Command permanently rejected %s; checkpoint marked FAILED.",
                         cp.anchor_id[:8])
            return {"anchor_id": cp.anchor_id, "seq": (cp.seq_start, cp.seq_end), "result": "REJECTED"}

        # Still PENDING: transport failure / non-200 — retry on next flush.
        logger.warning("Flush incomplete for %s (queue status=%s); will retry.",
                       cp.anchor_id[:8], status)
        return {"anchor_id": cp.anchor_id, "seq": (cp.seq_start, cp.seq_end), "result": "PENDING_RETRY"}

    # -- ApprovalGate-aware forced flush -----------------------------------
    GATE_ENDPOINT_DEFAULT = "http://localhost:8000/approvalgate"

    def pending_count(self) -> int:
        cur = self.quarantine._conn.execute(
            "SELECT COUNT(*) FROM quarantine_queue WHERE status = 'PENDING'"
        )
        return cur.fetchone()[0]

    async def _check_approval_gate(
        self, forced: bool, override: Optional[dict] = None,
        gate_base: Optional[str] = None, timeout_s: float = 5.0,
    ) -> dict:
        """Ask Core Command's ApprovalGate whether this flush may proceed.

        Example (operator CLI):
            curl -s http://localhost:8000/approvalgate/risk_score | jq '.score'
            # If score > 75, require manual override or bundle approvals
            # before executing flush_now.

        Fail-closed policy: if the gate cannot be reached while forcing, we
        refuse the forced flush (a partitioned node must not stampede the
        WORM store unreviewed). Non-forced flushes never consult the gate.
        """
        if not forced:
            return {"allowed": True, "reason": "normal flush: gate not consulted"}
        gate_base = gate_base or os.environ.get(
            "APPROVALGATE_ENDPOINT", self.GATE_ENDPOINT_DEFAULT)
        body = {
            "device_id": self.device_id,
            "forced": True,
            "pending_queue": self.pending_count(),
        }
        if override:
            body["override"] = override
        try:
            timeout = aiohttp.ClientTimeout(total=timeout_s)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Report queue depth first so backlog feeds the risk model.
                await session.post(
                    f"{gate_base}/heartbeat",
                    json={"device_id": self.device_id,
                          "pending_queue": body["pending_queue"]},
                )
                async with session.post(f"{gate_base}/check_flush", json=body) as resp:
                    decision = await resp.json()
                    decision["allowed"] = decision.get("allowed", False) and resp.status == 200
                    return decision
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return {"allowed": False,
                    "reason": f"ApprovalGate unreachable while forcing flush ({exc}); fail-closed"}

    async def flush_now(
        self,
        force: bool = False,
        override: Optional[dict] = None,
        gate_base: Optional[str] = None,
    ) -> dict:
        """Flush the quarantine queue to Core Command.

        ``force=True`` is a *forced sync*: before touching the wire it checks
        the ApprovalGate risk score (GET /approvalgate/risk_score via
        POST /approvalgate/check_flush). If the score exceeds the threshold
        (>75 by default), the flush proceeds only with a valid signed
        operator override token or enough pre-registered bundle approvals;
        otherwise it is refused and nothing is sent.
        """
        gate = await self._check_approval_gate(force, override, gate_base)
        if not gate.get("allowed"):
            risk = (gate.get("risk") or {}).get("score", "?")
            logger.error(
                "flush_now BLOCKED by ApprovalGate (risk=%s): %s", risk,
                gate.get("reason"))
            return {"flushed": 0, "blocked": True, "gate": gate}

        # Mesh/radio preflight: a forced sync must not burn approvals or hit
        # the wire over a dead radio. DEGRADED (up, no peers) is allowed with
        # a warning; DOWN/missing across all candidates blocks the flush.
        link = None
        if force:
            try:
                from mesh_link import verify_mesh_link
            except ImportError:  # running as part of the bench package
                from bench.mesh_link import verify_mesh_link
            active, reports = verify_mesh_link(require_peers=True)
            link = {"active": active.iface if active else None,
                    "states": {r.iface: r.state for r in reports}}
            if active is None:
                degraded = [r.iface for r in reports if r.state == "DEGRADED"]
                if degraded:
                    logger.warning(
                        "flush_now: link up but no RF peers visible (%s); "
                        "proceeding with forced sync, batches will queue "
                        "until mesh forms.", ", ".join(degraded))
                else:
                    logger.error(
                        "flush_now BLOCKED by mesh preflight: all candidate "
                        "interfaces down/missing (%s). Nothing sent; gate "
                        "approvals untouched.",
                        ", ".join(f"{r.iface}:{r.state}" for r in reports))
                    return {"flushed": 0, "blocked": True, "gate": gate,
                            "link": link,
                            "block_reason": "mesh link down (no ACTIVE interface)"}
            else:
                logger.info("flush_now: mesh preflight OK via %s (peers=%d)",
                            active.iface, active.peers)

        flushed = await self.quarantine.flush_quarantine_queue(
            sync_endpoint=self.endpoint)
        # Reconcile engine checkpoint states from queue statuses.
        for outcome in self._reconcile_after_flush():
            logger.info("Reconciled %s -> %s", outcome["anchor_id"][:8],
                        outcome["result"])
        risk = (gate.get("risk") or {}).get("score", "-")
        logger.info("flush_now complete: %d anchors synced (forced=%s, gate risk=%s)",
                    flushed, force, risk)
        return {"flushed": flushed, "blocked": False, "gate": gate}

    def _reconcile_after_flush(self) -> List[dict]:
        """Move engine checkpoints to ANCHORED/FAILED based on queue status."""
        outcomes = []
        rows = self.quarantine._conn.execute(
            "SELECT anchor_id, status FROM quarantine_queue"
            " WHERE status IN ('SYNCED','REJECTED')"
        ).fetchall()
        for anchor_id, qstatus in rows:
            cp = self.engine.get_checkpoint(anchor_id) if hasattr(
                self.engine, "get_checkpoint") else None
            if cp is None or cp.status == "anchored":
                continue
            if qstatus == "SYNCED":
                self.engine.confirm_checkpoint(anchor_id)
                outcomes.append({"anchor_id": anchor_id, "result": "ANCHORED"})
            elif qstatus == "REJECTED" and cp.status == "pending":
                self.engine.mark_failed(anchor_id)
                outcomes.append({"anchor_id": anchor_id, "result": "FAILED"})
        return outcomes


def _orchestrator_main(argv=None) -> int:
    """python3 -m bench.anchor --run-orchestrator ..."""
    import argparse

    parser = argparse.ArgumentParser(prog="bench.anchor orchestrator")
    parser.add_argument("--db", default="edge_orchestrator.db")
    parser.add_argument("--keys-file", default=None)
    parser.add_argument("--device-id", default="orin-splinter-01")
    parser.add_argument("--endpoint", default=AnchorClient.DEFAULT_ENDPOINT)
    parser.add_argument("--events", type=int, default=0, help="Synthetic events to append first")
    parser.add_argument("--batch-size", type=int, default=1000)
    parser.add_argument("--cycles", type=int, default=1)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s: %(message)s")

    client = AnchorClient(
        db_path=args.db,
        device_id=args.device_id,
        keys_file=args.keys_file,
        endpoint=args.endpoint,
        batch_size=args.batch_size,
    )
    try:
        if args.events:
            logger.info("Appending %d synthetic telemetry events...", args.events)
            for i in range(args.events):
                client.engine.append_event({"sensor": "imu", "t": time.time(), "n": i})

        async def drive():
            outcomes = []
            for cycle in range(args.cycles):
                logger.info("--- orchestrator cycle %d ---", cycle + 1)
                outcome = await client.run_once()
                if outcome is None:
                    break
                outcomes.append(outcome)
            return outcomes

        outcomes = asyncio.run(drive())
        for o in outcomes:
            print(f"RESULT {o['result']}: anchor={o['anchor_id'][:8]} seq={o['seq'][0]}..{o['seq'][1]}")
        return 0 if all(o["result"] == "ANCHORED" for o in outcomes) else 1
    finally:
        client.close()
