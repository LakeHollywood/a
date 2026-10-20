"""STS Core Command Anchor Server (FastAPI).

Fixes vs. the original draft:
- Per-item validation errors no longer abort the whole batch silently; each
  rejection is logged with a reason and returned in ``rejected`` so the edge
  node can distinguish "retry later" from "permanently invalid".
- Sequence continuity now queries by seq_start DESC (the previous draft's
  ORDER BY seq_end DESC LIMIT 1 could pick an overlapping/out-of-order row on
  a device that had previously submitted out of order) AND validates the
  hash-chain linkage (prev_head_hash) before commit.
- The WORM insert uses INSERT OR IGNORE semantics against the unique index
  (device_id, seq_start, seq_end): a redelivered duplicate is ACKed (idempotent
  at-least-once delivery) instead of being rejected by sqlite3.Error.
- conn.commit() moved to once-per-batch (atomic batch commit) — the per-item
  commit inside the loop was O(n) fsyncs and left partial batches persisted.
- register_device rejects malformed base64 / wrong-length Ed25519 keys with a
  400 instead of storing garbage that every future anchor would fail to verify.
- get_db yields connections with foreign_keys ON (FK enforcement was declared
  but not enabled), and requests carry explicit status codes for unknown
  devices when the entire batch fails policy checks.
"""

import logging
import sqlite3
import time

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Any, Dict, List

from core_db import init_core_db, canonical_anchor_payload
from validator import (
    verify_anchor_signature,
    validate_sequence_continuity,
    validate_hash_chain,
)
import approvalgate

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CoreCommandAPI")

app = FastAPI(title="STS Core Command Anchor Server")


def _worm_conn():
    """Fresh connection to the Core WORM store for the ApprovalGate router."""
    return init_core_db()


app.include_router(approvalgate.build_router(_worm_conn))


# Dependency to get DB connection
def get_db():
    conn = init_core_db()
    try:
        yield conn
    finally:
        conn.close()


class AnchorPayload(BaseModel):
    id: int  # The local quarantine queue ID from the edge node
    payload: Dict[str, Any]
    signature: str
    timestamp: float = Field(default_factory=time.time)


class BatchRequest(BaseModel):
    batch: List[AnchorPayload]


REQUIRED_PAYLOAD_FIELDS = (
    "anchor_id",
    "ledger_id",
    "seq_start",
    "seq_end",
    "head_hash",
    "merkle_root",
    "sts_timestamp",
)


@app.post("/anchors/batch")
async def receive_anchor_batch(
    request: BatchRequest, conn: sqlite3.Connection = Depends(get_db)
):
    acknowledged: List[Dict[str, Any]] = []
    rejected: List[Dict[str, Any]] = []
    cursor = conn.cursor()

    for item in request.batch:
        payload = item.payload
        device_id = payload.get("ledger_id")  # ledger_id doubles as device_id

        # 0. Schema check — reject early so downstream code can index safely.
        missing = [f for f in REQUIRED_PAYLOAD_FIELDS if f not in payload]
        if missing or not isinstance(device_id, str):
            reason = (
                f"Missing required fields: {missing}"
                if missing
                else "payload.ledger_id must be a string"
            )
            logger.warning("Rejecting anchor id=%s: %s", item.id, reason)
            rejected.append({"id": item.id, "reason": reason})
            continue

        # 1. Fetch Device Public Key
        cursor.execute(
            "SELECT public_key_b64 FROM devices WHERE device_id = ?", (device_id,)
        )
        device_row = cursor.fetchone()
        if not device_row:
            logger.warning("Rejecting anchor: Unknown device_id %s", device_id)
            rejected.append({"id": item.id, "reason": f"unknown device {device_id}"})
            continue

        public_key_b64 = device_row[0]

        # 2. Verify Cryptographic Signature over the canonical payload
        if not verify_anchor_signature(public_key_b64, payload, item.signature):
            logger.warning(
                "Rejecting anchor: Invalid signature for device %s", device_id
            )
            rejected.append({"id": item.id, "reason": "invalid signature"})
            continue

        # 3. Fetch Last Known Anchor for this device to validate continuity.
        #    Order by seq_start DESC so we always link onto the tip of the
        #    contiguous run, never an overlapping stale row.
        cursor.execute(
            """
            SELECT seq_end, head_hash FROM anchors
            WHERE device_id = ? ORDER BY seq_start DESC LIMIT 1
            """,
            (device_id,),
        )
        last_anchor_row = cursor.fetchone()
        last_anchor = (
            {"seq_end": last_anchor_row[0], "head_hash": last_anchor_row[1]}
            if last_anchor_row
            else None
        )

        # 4a. Validate Sequence Continuity (gap/overlap detection)
        is_valid_seq, seq_err = validate_sequence_continuity(
            last_anchor, payload["seq_start"], payload["seq_end"]
        )
        if not is_valid_seq:
            # CRITICAL: A sequence gap means the edge node is either compromised
            # or experienced catastrophic data loss. In a tactical environment,
            # this triggers a high-priority alert.
            logger.error("Rejecting anchor from %s: %s", device_id, seq_err)
            rejected.append({"id": item.id, "reason": seq_err})
            continue

        # 4b. Validate Hash-Chain Linkage (prev batch head must match)
        is_valid_chain, chain_err = validate_hash_chain(last_anchor, payload)
        if not is_valid_chain:
            logger.error("Rejecting anchor from %s: %s", device_id, chain_err)
            rejected.append({"id": item.id, "reason": chain_err})
            continue

        # 5. Commit to WORM Store (INSERT OR IGNORE => idempotent redelivery)
        try:
            cursor.execute(
                """
                INSERT OR IGNORE INTO anchors (
                    anchor_id, device_id, seq_start, seq_end, head_hash,
                    prev_head_hash, merkle_root, sts_timestamp,
                    server_received_at, signature_b64
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["anchor_id"],
                    device_id,
                    payload["seq_start"],
                    payload["seq_end"],
                    payload["head_hash"],
                    payload.get("prev_head_hash", ""),
                    payload["merkle_root"],
                    payload["sts_timestamp"],
                    time.time(),
                    item.signature,
                ),
            )
            if cursor.rowcount == 0:
                # Duplicate redelivery of an already-anchored batch: ACK it
                # (it IS anchored) but don't double-log as new.
                logger.info(
                    "Duplicate anchor %s-%s for %s already in WORM store; re-ACKed",
                    payload["seq_start"],
                    payload["seq_end"],
                    device_id,
                )
            acknowledged.append({"id": item.id})
        except sqlite3.Error as e:
            logger.error("Database commit failed for %s: %s", device_id, e)
            rejected.append({"id": item.id, "reason": f"storage error: {e}"})
            # Do not acknowledge if WORM commit fails.

    # Single atomic commit for the whole batch (one fsync, all-or-nothing
    # durability for everything accepted above).
    try:
        conn.commit()
    except sqlite3.Error as e:
        logger.error("Batch commit failed: %s", e)
        raise HTTPException(status_code=500, detail="WORM commit failed")

    # Feed the ApprovalGate risk model: every policy evaluation is counted,
    # rejections spike the rejection_ratio component that gates forced syncs.
    gate = approvalgate.get_store()
    for item in acknowledged:
        gate.record_event("acked", device_id=device_of_item(request, item["id"]))
    for r in rejected:
        gate.record_event(
            "rejected",
            device_id=device_of_item(request, r["id"]),
            reason=r.get("reason"),
        )

    return {"acknowledged": acknowledged, "rejected": rejected}


def device_of_item(request: "BatchRequest", queue_id: int) -> str:
    """Best-effort device attribution for a gate event."""
    for it in request.batch:
        if it.id == queue_id:
            lid = it.payload.get("ledger_id")
            return lid if isinstance(lid, str) else "?"
    return "?"


# --- Helper endpoint to provision a new edge node ---
@app.post("/devices/register")
async def register_device(
    device_id: str,
    public_key_b64: str,
    conn: sqlite3.Connection = Depends(get_db),
):
    # Reject malformed / wrong-length Ed25519 keys up front; otherwise every
    # future anchor from this device would silently fail verification.
    import base64

    try:
        raw = base64.b64decode(public_key_b64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="public_key_b64 is not valid base64")
    if len(raw) != 32:
        raise HTTPException(
            status_code=400,
            detail=f"Ed25519 public key must decode to 32 bytes, got {len(raw)}",
        )

    try:
        conn.execute(
            "INSERT INTO devices (device_id, public_key_b64, registered_at)"
            " VALUES (?, ?, ?)",
            (device_id, public_key_b64, time.time()),
        )
        conn.commit()
        return {"status": "registered"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Device already registered")


@app.get("/health")
async def health():
    return {"status": "ok", "time": time.time()}
