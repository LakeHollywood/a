"""Core Command validation layer: Ed25519 signatures, sequence continuity, hash chain.

Hardening notes vs. the original draft:
- Canonical JSON uses separators=(",", ":") AND is re-derived from a whitelisted
  subset of fields, so a client cannot smuggle extra keys into the signed payload.
- Key/signature lengths are validated up front (nacl raises TypeError for wrong
  sizes; we convert that to a clean reject).
- validate_sequence_continuity rejects overlaps and non-monotonic ranges.
- validate_hash_chain performs real checkpoint-level linkage verification:
  each new anchor must carry prev_head_hash matching the stored head_hash of
  the previous batch (genesis batches must carry an empty/None prev head).
"""

import base64
import json
import logging

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError, CryptoError

logger = logging.getLogger("CoreValidator")

# Fields covered by the edge node's signature (canonical, order-independent).
SIGNED_FIELDS = (
    "anchor_id",
    "ledger_id",
    "seq_start",
    "seq_end",
    "head_hash",
    "prev_head_hash",
    "merkle_root",
    "sts_timestamp",
)

ED25519_PUBKEY_LEN = 32
ED25519_SIG_LEN = 64


def canonical_anchor_payload(checkpoint_dict: dict) -> bytes:
    """Deterministic byte encoding used as the signed message.

    Must match core_db.canonical_anchor_payload exactly. Only whitelisted
    fields are included so injected/extra keys can never alter what was
    actually signed.
    """
    subset = {k: checkpoint_dict.get(k) for k in SIGNED_FIELDS}
    return json.dumps(subset, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_anchor_signature(device_public_key_b64: str, checkpoint_dict: dict, signature_b64: str) -> bool:
    """Verifies the Ed25519 signature of the checkpoint."""
    try:
        raw_key = base64.b64decode(device_public_key_b64, validate=True)
        if len(raw_key) != ED25519_PUBKEY_LEN:
            logger.warning(
                f"Rejecting signature: public key is {len(raw_key)} bytes, expected {ED25519_PUBKEY_LEN}."
            )
            return False

        raw_sig = base64.b64decode(signature_b64, validate=True)
        if len(raw_sig) != ED25519_SIG_LEN:
            logger.warning(
                f"Rejecting signature: signature is {len(raw_sig)} bytes, expected {ED25519_SIG_LEN}."
            )
            return False

        verify_key = VerifyKey(raw_key)
        payload_bytes = canonical_anchor_payload(checkpoint_dict)
        verify_key.verify(payload_bytes, raw_sig)
        return True
    except BadSignatureError:
        logger.warning("Signature verification failed for device.")
        return False
    except (CryptoError, ValueError, TypeError) as e:
        logger.error(f"Signature validation error: {e}")
        return False


def validate_sequence_continuity(last_anchor: dict, new_seq_start: int, new_seq_end: int) -> tuple[bool, str]:
    """
    Ensures no gaps or overlaps in the event sequence.
    Returns (is_valid, error_message).
    """
    # Basic range sanity applies regardless of history.
    if not isinstance(new_seq_start, int) or not isinstance(new_seq_end, int):
        return False, f"Non-integer sequence range: start={new_seq_start!r}, end={new_seq_end!r}"
    if new_seq_start < 1:
        return False, f"Sequence numbers must be >= 1, got start {new_seq_start}"
    if new_seq_end <= new_seq_start:
        return False, f"Invalid sequence range: start {new_seq_start} >= end {new_seq_end}"

    if last_anchor is None:
        # First anchor from this device must start at 1
        if new_seq_start != 1:
            return False, f"First anchor must start at seq 1, got {new_seq_start}"
        return True, ""

    expected_start = last_anchor["seq_end"] + 1
    if new_seq_start != expected_start:
        if new_seq_start < expected_start:
            kind = "overlap"
        else:
            kind = "gap"
        return False, (
            f"Sequence {kind} detected. Expected start {expected_start}, got {new_seq_start}"
        )
    return True, ""


def validate_hash_chain(last_anchor: dict, new_checkpoint: dict) -> tuple[bool, str]:
    """Checkpoint-level hash-chain linkage verification.

    Each batch must reference the head_hash of the immediately preceding
    batch as ``prev_head_hash``. This lets the server detect chain forks or
    replayed/stale batches even though it does not hold the full Merkle
    proof set. (Full leaf-inclusion proofs would require the edge node to
    ship a per-event audit path; noted as future work.)

    Accepts either (last_anchor, new_checkpoint_dict) or the legacy
    (last_anchor, new_head_hash_str) call form.
    """
    if isinstance(new_checkpoint, str):
        # Legacy call form: only the head hash was passed; nothing to link-check.
        new_prev_head = None
        new_head_hash = new_checkpoint
    else:
        new_prev_head = new_checkpoint.get("prev_head_hash")
        new_head_hash = new_checkpoint.get("head_hash")

    if not new_head_hash:
        return False, "New checkpoint missing head_hash"

    if last_anchor is None:
        # Genesis batch: must NOT claim a predecessor.
        if new_prev_head not in (None, ""):
            return False, (
                f"Genesis batch claims prev_head_hash {new_prev_head!r} but no prior anchor exists"
            )
        return True, ""

    expected_prev = last_anchor["head_hash"]
    if new_prev_head != expected_prev:
        return False, (
            f"Hash chain break: batch references prev head {new_prev_head!r}, "
            f"but last anchored head is {expected_prev!r}"
        )
    return True, ""
