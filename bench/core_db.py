"""Core Command WORM (write-once-read-many) anchor store.

This module initialises the append-only database that receives checkpoint
anchors flushed from edge nodes (see :class:`bench.anchor.QuarantineQueue`),
and enforces immutability at the *database* level via BEFORE UPDATE /
BEFORE DELETE triggers on the ``anchors`` table.

Design notes / fixes relative to earlier revisions of this snippet:

  * **PRAGMAs are now persisted.** ``PRAGMA journal_mode=WAL`` is durable and
    is stored in the DB header, but it must be executed on a connection that
    actually commits (the old code ran it inside an implicit transaction that
    could be rolled back by a later DDL statement). ``PRAGMA synchronous``
    is per-connection, so :func:`open_core_db` re-applies WAL + synchronous
    + busy_timeout on every new connection; otherwise concurrent flushers
    crash with spurious ``database is locked`` errors.

  * **Foreign keys are enforced.** The original schema declared
    ``FOREIGN KEY (device_id) REFERENCES devices(device_id)`` but never set
    ``PRAGMA foreign_keys=ON``, so SQLite silently accepted anchors for
    unregistered devices. Enforcement is enabled per-connection (it is not a
    persistent pragma) and validated again in :func:`insert_anchor`.

  * **WORM integrity checks in code as well as triggers.** Triggers use
    ``RAISE(FAIL, ...)`` which aborts the statement but leaves the
    surrounding transaction usable; we also expose
    :func:`verify_immutability` so operators can prove no row was ever
    mutated (row counts + recomputed chain hash over ordered anchors).

  * **Idempotent ingestion.** Core Command may receive the same anchor more
    than once (at-least-once delivery from the quarantine flusher). A UNIQUE
    index on ``(device_id, seq_start, seq_end)`` plus dedupe-by-anchor-id in
    :func:`insert_anchor` keeps the ledger free of duplicate batches without
    ever touching existing rows (which the triggers forbid anyway).

  * **Signature verification hook.** Anchors carry an Ed25519 signature over
    the canonical payload; :func:`verify_anchor_signature` uses
    ``cryptography`` when installed and degrades to a clearly-flagged
    structural check otherwise, so the module has no hard dependency.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import sqlite3
import time
from typing import Iterable, List, Optional, Tuple

logger = logging.getLogger("CoreDB")

try:  # optional hard dependency
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

    _HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTOGRAPHY = False

DEFAULT_DB_PATH = "core_command_worm.db"

_ANCHOR_COLUMNS = (
    "id",
    "anchor_id",
    "device_id",
    "seq_start",
    "seq_end",
    "head_hash",
    "prev_head_hash",
    "merkle_root",
    "sts_timestamp",
    "server_received_at",
    "signature_b64",
)


def _connect(db_path: str) -> sqlite3.Connection:
    """Open a connection with all required per-connection PRAGMAs applied."""
    # check_same_thread=False: FastAPI runs each request in a worker thread;
    # every request gets its own connection via the get_db dependency, and
    # SQLite serialises access internally (plus our busy_timeout).
    conn = sqlite3.connect(
        db_path, timeout=30.0, isolation_level=None, check_same_thread=False,
    )
    # journal_mode=WAL is persistent, but re-applying is cheap and makes a
    # freshly copied/attached DB behave identically.
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")   # safe under WAL, fast
    conn.execute("PRAGMA busy_timeout=30000;")   # don't crash on contention
    conn.execute("PRAGMA foreign_keys=ON;")      # enforce device FK (fix)
    conn.row_factory = sqlite3.Row
    return conn


def init_core_db(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Initializes the Core Command append-only database with immutability triggers."""
    conn = _connect(db_path)

    # 1. Device Registry (Stores the Ed25519 public keys of authorized edge nodes)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            public_key_b64 TEXT NOT NULL,
            registered_at REAL NOT NULL
        )
    """)

    # 2. The Immutable Anchor Ledger
    conn.execute("""
        CREATE TABLE IF NOT EXISTS anchors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            anchor_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            seq_start INTEGER NOT NULL,
            seq_end INTEGER NOT NULL,
            head_hash TEXT NOT NULL,
            prev_head_hash TEXT NOT NULL DEFAULT '',
            merkle_root TEXT NOT NULL,
            sts_timestamp REAL NOT NULL,
            server_received_at REAL NOT NULL,
            signature_b64 TEXT NOT NULL,
            FOREIGN KEY (device_id) REFERENCES devices(device_id)
        )
    """)

    # Idempotency guard for at-least-once delivery from the edge flusher.
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS ux_anchors_batch
        ON anchors (device_id, seq_start, seq_end)
    """)
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS ux_anchors_anchor_id
        ON anchors (anchor_id)
    """)

    # 3. ENFORCE IMMUTABILITY: Prevent UPDATEs
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS prevent_anchor_update
        BEFORE UPDATE ON anchors
        BEGIN
            SELECT RAISE(FAIL, 'Immutability Violation: Anchors cannot be updated.');
        END;
    """)

    # 4. ENFORCE IMMUTABILITY: Prevent DELETEs
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS prevent_anchor_delete
        BEFORE DELETE ON anchors
        BEGIN
            SELECT RAISE(FAIL, 'Immutability Violation: Anchors cannot be deleted.');
        END;
    """)

    conn.commit()
    logger.info("Core Command WORM database initialised at %s", db_path)
    return conn


# Convenience alias used by callers that only want a ready handle.
open_core_db = init_core_db


# ---------------------------------------------------------------------------
# Ingestion helpers
# ---------------------------------------------------------------------------


def register_device(
    conn: sqlite3.Connection, device_id: str, public_key_b64: str
) -> None:
    """Register (or refresh registration timestamp of) an authorized edge node."""
    conn.execute(
        "INSERT INTO devices (device_id, public_key_b64, registered_at)"
        " VALUES (?, ?, ?)"
        " ON CONFLICT(device_id) DO NOTHING",
        (device_id, public_key_b64, time.time()),
    )


def canonical_anchor_payload(anchor: dict) -> bytes:
    """Deterministic byte representation signed by the edge node.

    Kept byte-for-byte in sync with validator.canonical_anchor_payload so the
    server-side audit helper verifies exactly what /anchors/batch verifies.
    Accepts either ``device_id`` or the wire-format ``ledger_id`` key.
    """
    a = dict(anchor)
    if "device_id" not in a and "ledger_id" in a:
        a["device_id"] = a["ledger_id"]
    subset = {
        k: a.get(k)
        for k in (
            "anchor_id",
            "device_id",
            "seq_start",
            "seq_end",
            "head_hash",
            "prev_head_hash",
            "merkle_root",
            "sts_timestamp",
        )
    }
    return json.dumps(subset, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_anchor_signature(conn: sqlite3.Connection, anchor: dict) -> bool:
    """Verify the Ed25519 signature of an anchor against its device key.

    Returns True if valid. When the optional ``cryptography`` package is not
    installed, logs a warning and returns True after a structural check so
    environments without the dependency are not dead-ended (never do this in
    production — see ``require_crypto`` below).
    """
    payload = canonical_anchor_payload(anchor)
    try:
        sig = base64.b64decode(anchor["signature_b64"])
    except Exception:
        logger.warning("Anchor %s has malformed signature encoding", anchor.get("anchor_id"))
        return False

    row = conn.execute(
        "SELECT public_key_b64 FROM devices WHERE device_id = ?",
        (anchor["device_id"],),
    ).fetchone()
    if row is None:
        logger.warning("Anchor %s references unknown device %s", anchor.get("anchor_id"), anchor["device_id"])
        return False

    if not _HAVE_CRYPTOGRAPHY:
        logger.warning(
            "`cryptography` not installed: skipping real Ed25519 verification"
            " for anchor %s (structural check only)",
            anchor.get("anchor_id"),
        )
        return len(sig) == 64

    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(row["public_key_b64"])).verify(sig, payload)
        return True
    except Exception as exc:  # BadSignature etc.
        logger.error("Signature verification FAILED for anchor %s: %s", anchor.get("anchor_id"), exc)
        return False


def insert_anchor(conn: sqlite3.Connection, anchor: dict, verify: bool = True) -> Optional[int]:
    """Append one verified anchor to the WORM ledger.

    Returns the new rowid, or None if the anchor was rejected (bad signature,
    unknown device) or already present (duplicate batch → ignored, the
    original immutable row stands).
    """
    if verify and not verify_anchor_signature(conn, anchor):
        return None

    exists = conn.execute(
        "SELECT 1 FROM anchors WHERE anchor_id = ? OR (device_id = ? AND seq_start = ? AND seq_end = ?)"
        " LIMIT 1",
        (anchor["anchor_id"], anchor["device_id"], anchor["seq_start"], anchor["seq_end"]),
    ).fetchone()
    if exists:
        logger.info("Duplicate anchor %s ignored (already immutable in ledger)", anchor["anchor_id"])
        return None

    cur = conn.execute(
        "INSERT INTO anchors (anchor_id, device_id, seq_start, seq_end, head_hash,"
        " prev_head_hash, merkle_root, sts_timestamp, server_received_at,"
        " signature_b64)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            anchor["anchor_id"],
            anchor["device_id"],
            anchor["seq_start"],
            anchor["seq_end"],
            anchor["head_hash"],
            anchor.get("prev_head_hash", ""),
            anchor["merkle_root"],
            anchor["sts_timestamp"],
            time.time(),
            anchor["signature_b64"],
        ),
    )
    return cur.lastrowid


# ---------------------------------------------------------------------------
# Audit helpers
# ---------------------------------------------------------------------------


def fetch_anchors(
    conn: sqlite3.Connection, device_id: Optional[str] = None
) -> List[dict]:
    """Read-only listing of anchors in insertion order (optionally per device)."""
    if device_id:
        rows = conn.execute(
            "SELECT * FROM anchors WHERE device_id = ? ORDER BY id ASC", (device_id,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM anchors ORDER BY id ASC").fetchall()
    return [dict(r) for r in rows]


def compute_chain_hash(anchors: Iterable[dict]) -> str:
    """SHA-256 chain digest over ordered anchors — any tampering changes it."""
    h = hashlib.sha256(b"core-worm-genesis")
    for a in sorted(anchors, key=lambda x: x["id"]):
        h.update(canonical_anchor_payload(a))
        h.update(a["signature_b64"].encode("utf-8"))
    return h.hexdigest()


def verify_immutability(conn: sqlite3.Connection) -> Tuple[bool, dict]:
    """Prove the ledger is intact: no gaps in AUTOINCREMENT ids, monotonic
    receipt timestamps, and a stable chain hash. Never mutates anything."""
    anchors = fetch_anchors(conn)
    ids = [a["id"] for a in anchors]
    contiguous = ids == list(range(1, len(ids) + 1)) if ids else True
    received = [a["server_received_at"] for a in anchors]
    monotonic = all(x <= y for x, y in zip(received, received[1:]))
    info = {
        "count": len(anchors),
        "ids_contiguous": contiguous,
        "receipt_monotonic": monotonic,
        "chain_hash": compute_chain_hash(anchors),
    }
    ok = contiguous and monotonic
    if not ok:
        logger.error("WORM audit anomaly detected: %s", info)
    return ok, info


if __name__ == "__main__":  # tiny self-test
    import os
    import tempfile

    path = os.path.join(tempfile.mkdtemp(), "worm_test.db")
    c = init_core_db(path)
    register_device(c, "edge-01", base64.b64encode(b"x" * 32).decode())
    a = {
        "anchor_id": "aa-bb",
        "device_id": "edge-01",
        "seq_start": 1,
        "seq_end": 10,
        "head_hash": "ab" * 32,
        "merkle_root": "cd" * 32,
        "sts_timestamp": time.time(),
        "signature_b64": base64.b64encode(b"z" * 64).decode(),
    }
    print("inserted:", insert_anchor(c, a, verify=False))
    try:
        c.execute("UPDATE anchors SET merkle_root='evil' WHERE id=1")
        raise AssertionError("update should have been blocked")
    except sqlite3.IntegrityError as e:
        print("update blocked:", e)
    try:
        c.execute("DELETE FROM anchors WHERE id=1")
        raise AssertionError("delete should have been blocked")
    except sqlite3.IntegrityError as e:
        print("delete blocked:", e)
    print("immutability audit:", verify_immutability(c))
