"""ApprovalGate: server-side risk scoring + manual-override gate for forced syncs.

Core Command computes a composite risk score (0-100) from WORM-ledger health
and rejects any ``forced`` flush while the score exceeds the threshold, unless
an operator has pre-registered bundle approvals or issued a signed override
token. The edge node's ``flush_now`` consults this gate BEFORE forcing a sync
(defense in depth: the gate is enforced on BOTH sides).

Risk signals (weights sum to 100):
  * rejection_ratio    (35) - rejected / total policy evaluations; spikes when
                              an edge node is compromised or lost catastrophic
                              data (gaps, bad signatures, unknown devices).
  * chain_breaks       (25) - prev_head_hash linkage breaks inside each
                              device's contiguous anchor run.
  * stale_devices      (15) - registered devices with no anchors older than
                              STALE_DEVICE_S (default 900 s).
  * queue_backlog      (15) - PENDING quarantine entries reported by edge
                              heartbeat POSTs (delivery lag / partitioning).
  * clock_skew         (10) - |sts_timestamp - server_received_at| beyond 60 s.

Override mechanisms (either satisfies the gate):
  * Bundle approvals: N distinct approvers recorded via
    POST /approvalgate/approve -> required count = ceil(risk_score/25),
    capped at APPROVAL_REQUIRED_MAX (default 4). Approvals are consumed
    atomically by the flush that uses them.
  * Signed override token: Ed25519 signature by any operator key over the
    canonical string "OVERRIDE:<device_id>:<nonce>:<expires_at>" (pipe-joined,
    utf-8, base64 signature b64url-safe). Nonces are single-use and tracked
    server-side so tokens cannot be replayed.
"""

import base64
import json
import logging
import math
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("ApprovalGate")

DEFAULT_DB_PATH = os.environ.get("APPROVALGATE_DB", "approvalgate.db")

RISK_THRESHOLD = int(os.environ.get("APPROVALGATE_RISK_THRESHOLD", "75"))
W_REJECT_RATIO = 35
W_CHAIN_BREAKS = 25
W_STALE_DEVICES = 15
W_QUEUE_BACKLOG = 15
W_CLOCK_SKEW = 10

STALE_DEVICE_S = float(os.environ.get("APPROVALGATE_STALE_DEVICE_S", "900"))
CLOCK_SKEW_TOLERANCE_S = 60.0
QUEUE_BACKLOG_FULL = 20          # pending entries at which backlog score maxes
CHAIN_BREAKS_FULL = 5            # breaks at which chain score maxes
APPROVAL_REQUIRED_MAX = 4        # cap on distinct approvals needed


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS gate_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,              -- 'rejected' | 'acked' | 'heartbeat'
    device_id TEXT,
    reason TEXT,
    pending INTEGER,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    approver TEXT NOT NULL,
    note TEXT,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS used_nonces (
    nonce TEXT PRIMARY KEY,
    device_id TEXT,
    used_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_gate_events_created ON gate_events(created_at);
CREATE INDEX IF NOT EXISTS idx_approvals_device ON approvals(device_id, approver);
"""


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    return conn


class ApprovalGateStore:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.conn = _connect(db_path)
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass

    # -- event log ----------------------------------------------------------
    def record_event(
        self,
        kind: str,
        device_id: Optional[str] = None,
        reason: Optional[str] = None,
        pending: Optional[int] = None,
    ) -> None:
        self.conn.execute(
            "INSERT INTO gate_events (kind, device_id, reason, pending, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (kind, device_id, reason, pending, time.time()),
        )
        self.conn.commit()

    def event_counts(self, since: float) -> Tuple[int, int]:
        """Return (n_rejected, n_total_policy_evals) since timestamp."""
        cur = self.conn.execute(
            "SELECT SUM(kind = 'rejected'), COUNT(*) FROM gate_events"
            " WHERE kind IN ('rejected','acked') AND created_at >= ?",
            (since,),
        )
        rej, tot = cur.fetchone()
        return (rej or 0), (tot or 0)

    def latest_pending_by_device(self) -> Dict[str, int]:
        """Most recent heartbeat-reported PENDING queue depth per device."""
        cur = self.conn.execute(
            "SELECT device_id, pending FROM gate_events e"
            " WHERE kind = 'heartbeat' AND pending IS NOT NULL"
            "   AND created_at = (SELECT MAX(created_at) FROM gate_events"
            "                      WHERE kind='heartbeat' AND device_id = e.device_id)"
        )
        return {row[0]: row[1] for row in cur.fetchall()}

    # -- approvals ----------------------------------------------------------
    def add_approval(self, device_id: str, approver: str, note: str = "") -> None:
        self.conn.execute(
            "INSERT INTO approvals (device_id, approver, note, created_at)"
            " VALUES (?, ?, ?, ?)",
            (device_id, approver, note, time.time()),
        )
        self.conn.commit()

    def available_approvals(self, device_id: str) -> List[str]:
        cur = self.conn.execute(
            "SELECT DISTINCT approver FROM approvals WHERE device_id = ?",
            (device_id,),
        )
        return [r[0] for r in cur.fetchall()]

    def consume_approvals(self, device_id: str, n: int) -> int:
        """Atomically delete up to n approval rows for device; returns count."""
        cur = self.conn.execute(
            "DELETE FROM approvals WHERE id IN ("
            "  SELECT id FROM approvals WHERE device_id = ? ORDER BY id LIMIT ?)",
            (device_id, n),
        )
        self.conn.commit()
        return cur.rowcount

    # -- override nonces ----------------------------------------------------
    def nonce_used(self, nonce: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM used_nonces WHERE nonce = ?", (nonce,)
        ).fetchone() is not None

    def mark_nonce_used(self, nonce: str, device_id: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO used_nonces (nonce, device_id, used_at)"
            " VALUES (?, ?, ?)",
            (nonce, device_id, time.time()),
        )
        self.conn.commit()


_STORE: Optional[ApprovalGateStore] = None


def get_store() -> ApprovalGateStore:
    global _STORE
    if _STORE is None:
        _STORE = ApprovalGateStore()
    return _STORE


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def compute_risk_score(conn: sqlite3.Connection, store: ApprovalGateStore) -> dict:
    """Composite 0-100 risk score with per-signal breakdown."""
    components: Dict[str, float] = {}

    # 1. Rejection ratio over the last hour of policy evaluations.
    n_rej, n_tot = store.event_counts(time.time() - 3600)
    rej_ratio = (n_rej / n_tot) if n_tot else 0.0
    components["rejection_ratio"] = round(W_REJECT_RATIO * min(1.0, rej_ratio * 2), 1)

    # 2. Hash-chain breaks: within each device's contiguous run (by
    #    seq_start order), stored prev_head_hash must equal the previous
    #    anchor's head_hash. Genesis runs start with ''.
    breaks = 0
    cur = conn.execute(
        "SELECT device_id, seq_start, head_hash, prev_head_hash"
        " FROM anchors ORDER BY device_id, seq_start ASC"
    )
    prev_dev, prev_head = None, None
    for dev, _seq, head, prev_head_hash in cur.fetchall():
        if dev != prev_dev:
            prev_dev = dev
            if (prev_head_hash or "") != "":
                breaks += 1  # non-genesis anchor claims genesis lineage
        else:
            if (prev_head_hash or "") != (prev_head or ""):
                breaks += 1
        prev_head = head
    components["chain_breaks"] = round(
        W_CHAIN_BREAKS * min(1.0, breaks / CHAIN_BREAKS_FULL), 1
    )

    # 3. Stale devices: registered but no anchor within STALE_DEVICE_S.
    cur = conn.execute(
        "SELECT COUNT(*) FROM devices d WHERE NOT EXISTS ("
        "  SELECT 1 FROM anchors a WHERE a.device_id = d.device_id"
        "    AND a.server_received_at >= ?)",
        (time.time() - STALE_DEVICE_S,),
    )
    n_stale = cur.fetchone()[0]
    cur = conn.execute("SELECT COUNT(*) FROM devices")
    n_devices = cur.fetchone()[0] or 1
    components["stale_devices"] = round(
        W_STALE_DEVICES * min(1.0, n_stale / max(1, n_devices // 3)), 1
    )

    # 4. Queue backlog reported by edge heartbeats.
    pending_total = sum(store.latest_pending_by_device().values())
    components["queue_backlog"] = round(
        W_QUEUE_BACKLOG * min(1.0, pending_total / QUEUE_BACKLOG_FULL), 1
    )

    # 5. Clock skew between edge sts_timestamp and server receipt.
    cur = conn.execute(
        "SELECT COUNT(*), SUM(ABS(server_received_at - sts_timestamp) > ?)"
        " FROM anchors",
        (CLOCK_SKEW_TOLERANCE_S,),
    )
    n_anchors, n_skew = cur.fetchone()
    skew_ratio = (n_skew / n_anchors) if n_anchors else 0.0
    components["clock_skew"] = round(W_CLOCK_SKEW * min(1.0, skew_ratio * 2), 1)

    score = int(round(sum(components.values())))
    score = max(0, min(100, score))
    return {
        "score": score,
        "threshold": RISK_THRESHOLD,
        "components": components,
        "signals": {
            "evaluations_last_hour": n_tot,
            "rejections_last_hour": n_rej,
            "chain_breaks": breaks,
            "stale_devices": n_stale,
            "total_devices": n_devices,
            "pending_queue_entries": pending_total,
            "anchors_with_clock_skew": int(n_skew or 0),
            "total_anchors": n_anchors,
        },
        "computed_at": time.time(),
    }


def required_approvals(score: int) -> int:
    return min(APPROVAL_REQUIRED_MAX, max(1, math.ceil(score / 25)))


# ---------------------------------------------------------------------------
# Override verification
# ---------------------------------------------------------------------------

def load_operator_keys() -> List[Any]:
    """Ed25519 VerifyKeys from APPROVALGATE_OPERATOR_PUBKEYS_B64 (comma-sep)."""
    from nacl.signing import VerifyKey

    raw = os.environ.get("APPROVALGATE_OPERATOR_PUBKEYS_B64", "").strip()
    keys = []
    if not raw:
        return keys
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            keys.append(VerifyKey(base64.b64decode(item)))
        except Exception as exc:
            logger.warning("Ignoring malformed operator pubkey entry: %s", exc)
    return keys


def override_message(device_id: str, nonce: str, expires_at: float) -> bytes:
    return f"OVERRIDE:{device_id}:{nonce}:{int(expires_at)}".encode("utf-8")


def verify_override_token(
    device_id: str, token_b64: str, nonce: str, expires_at: float, store: ApprovalGateStore
) -> Tuple[bool, str]:
    """Validate a signed operator override token (single-use, time-boxed)."""
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError, CryptoError

    op_keys = load_operator_keys()
    if not op_keys:
        return False, "no operator keys configured (APPROVALGATE_OPERATOR_PUBKEYS_B64)"
    if expires_at < time.time():
        return False, "override token expired"
    if store.nonce_used(nonce):
        return False, "override token nonce already used (replay)"
    try:
        sig = base64.b64decode(token_b64)
    except Exception:
        return False, "override token is not valid base64"
    msg = override_message(device_id, nonce, expires_at)
    for key in op_keys:
        try:
            key.verify(msg, sig)
            store.mark_nonce_used(nonce, device_id)
            return True, "valid override token"
        except (BadSignatureError, CryptoError):
            continue
    return False, "override token signature matches no registered operator"


def make_override_token(
    signing_key_b64: str, device_id: str, nonce: str, ttl_s: float = 300.0
) -> dict:
    """Helper for operators/CLI: produce a valid override envelope."""
    from nacl.signing import SigningKey

    sk = SigningKey(base64.b64decode(signing_key_b64))
    expires_at = time.time() + ttl_s
    msg = override_message(device_id, nonce, expires_at)
    token = base64.b64encode(sk.sign(msg).signature).decode()
    return {"token": token, "nonce": nonce, "expires_at": expires_at}


# ---------------------------------------------------------------------------
# Gate decision
# ---------------------------------------------------------------------------

def evaluate_flush_request(
    core_conn: sqlite3.Connection,
    store: ApprovalGateStore,
    device_id: str,
    forced: bool,
    override: Optional[dict] = None,
) -> dict:
    """Decide whether a flush may proceed. Never blocks normal (non-forced)
    flushes — the gate only governs FORCED syncs, per policy."""
    risk = compute_risk_score(core_conn, store)
    decision = {
        "allowed": True,
        "forced": forced,
        "risk": risk,
        "requirement": None,
        "reason": "normal flush: gate does not apply",
    }
    if not forced:
        return decision

    if risk["score"] <= RISK_THRESHOLD:
        decision["reason"] = (
            f"forced flush allowed: risk {risk['score']} <= threshold {RISK_THRESHOLD}"
        )
        return decision

    need = required_approvals(risk["score"])
    decision["requirement"] = {
        "type": "manual_override_or_bundle_approvals",
        "approvals_required": need,
        "approvals_available": len(store.available_approvals(device_id)),
    }

    # Path A: bundle approvals.
    have = store.available_approvals(device_id)
    if len(have) >= need:
        consumed = store.consume_approvals(device_id, need)
        decision["allowed"] = True
        decision["reason"] = (
            f"forced flush approved: consumed {consumed}/{need} bundle approvals "
            f"({', '.join(have[:need])}) despite risk {risk['score']}"
        )
        logger.info(decision["reason"])
        return decision

    # Path B: signed operator override token.
    if override:
        ok, why = verify_override_token(
            device_id,
            override.get("token", ""),
            override.get("nonce", ""),
            float(override.get("expires_at", 0) or 0),
            store,
        )
        if ok:
            decision["allowed"] = True
            decision["reason"] = (
                f"forced flush permitted via operator override despite risk "
                f"{risk['score']}: {why}"
            )
            logger.info(decision["reason"])
            return decision
        decision["reason"] = f"override rejected: {why}"
        decision["allowed"] = False
        return decision

    decision["allowed"] = False
    decision["reason"] = (
        f"BLOCKED: risk score {risk['score']} > threshold {RISK_THRESHOLD}; "
        f"requires {need} bundle approvals (have {len(have)}) or a signed "
        f"operator override token"
    )
    logger.warning(decision["reason"])
    return decision


# ---------------------------------------------------------------------------
# FastAPI router (mounted into main:app)
# ---------------------------------------------------------------------------

def build_router(get_core_conn):
    """Return an APIRouter wired to a Core-WORM connection provider.

    ``get_core_conn`` is a zero-arg callable returning an open sqlite3
    connection to the anchors WORM database.
    """
    from fastapi import APIRouter, Body, HTTPException

    router = APIRouter(prefix="/approvalgate", tags=["approvalgate"])

    @router.get("/risk_score")
    async def risk_score():
        conn = get_core_conn()
        try:
            return compute_risk_score(conn, get_store())
        finally:
            conn.close()

    @router.post("/approve")
    async def approve(payload: dict = Body(...)):
        device_id = payload.get("device_id")
        approver = payload.get("approver")
        if not device_id or not approver:
            raise HTTPException(400, "device_id and approver are required")
        get_store().add_approval(device_id, approver, payload.get("note", ""))
        avail = get_store().available_approvals(device_id)
        return {"status": "recorded", "device_id": device_id,
                "approvals_available": len(avail)}

    @router.post("/check_flush")
    async def check_flush(payload: dict = Body(...)):
        device_id = payload.get("device_id")
        if not device_id:
            raise HTTPException(400, "device_id is required")
        conn = get_core_conn()
        try:
            decision = evaluate_flush_request(
                conn,
                get_store(),
                device_id=device_id,
                forced=bool(payload.get("forced", False)),
                override=payload.get("override"),
            )
            status = 200 if decision["allowed"] else 403
            return JSONResponse_compat(status, decision)
        finally:
            conn.close()

    @router.post("/heartbeat")
    async def heartbeat(payload: dict = Body(...)):
        device_id = payload.get("device_id")
        if not device_id:
            raise HTTPException(400, "device_id is required")
        get_store().record_event(
            "heartbeat", device_id=device_id,
            pending=int(payload.get("pending_queue", 0) or 0),
        )
        return {"status": "ok"}

    return router


def JSONResponse_compat(status_code: int, content: dict):
    """Return a JSONResponse carrying the full decision body."""
    from fastapi.responses import JSONResponse

    return JSONResponse(status_code=status_code, content=content)
