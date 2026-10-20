"""End-to-end verification: validator + Core Command FastAPI server.

Covers:
- Unit tests for verify_anchor_signature / continuity / hash-chain linkage.
- Full pipeline integration via Starlette TestClient: edge AnchorEngine ->
  signed checkpoint -> /anchors/batch -> WORM store -> ACK -> watermark.
- Rejection paths: unknown device, bad signature, tampered payload (field
  smuggling), sequence gap/overlap, broken hash chain, duplicate redelivery
  (idempotent re-ACK), malformed key registration.
- WORM immutability triggers still enforced after server commits.
"""

import base64
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nacl.signing import SigningKey
from starlette.testclient import TestClient

import core_db
from validator import (
    verify_anchor_signature,
    validate_sequence_continuity,
    validate_hash_chain,
    canonical_anchor_payload,
)

TMP = tempfile.mkdtemp(prefix="sts_test_")
CORE_DB = os.path.join(TMP, "core.db")

# Route every get_db() through a temp DB (avoids stale schemas from earlier runs).
_orig_init = core_db.init_core_db
def _init_temp(db_path: str = CORE_DB):
    return _orig_init(CORE_DB)
core_db.init_core_db = _init_temp

import main  # noqa: E402  (imports core_db.init_core_db)
from anchor import AnchorEngine, Checkpoint, compute_merkle_root  # noqa: E402

results = []

def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS" if cond else "FAIL"), "-", name)


# --------------------------------------------------------------------------
# Unit-level validator tests
# --------------------------------------------------------------------------
sk = SigningKey.generate()
pk_b64 = base64.b64encode(bytes(sk.verify_key)).decode()

cp = {
    "anchor_id": "a-1", "ledger_id": "dev-1", "seq_start": 1, "seq_end": 5,
    "head_hash": "ab" * 32, "prev_head_hash": "",
    "merkle_root": "cd" * 32, "sts_timestamp": 123.5,
}
sig = base64.b64encode(sk.sign(canonical_anchor_payload(cp)).signature).decode()

check("valid signature accepted", verify_anchor_signature(pk_b64, cp, sig))

bad_sig = base64.b64encode(bytes(64)).decode()
check("bad signature rejected", not verify_anchor_signature(pk_b64, cp, bad_sig))

tampered = dict(cp); tampered["seq_end"] = 99
check("tampered payload rejected", not verify_anchor_signature(pk_b64, tampered, sig))

smuggled = dict(cp); smuggled["admin"] = True  # extra key must not alter message
check("extra-field smuggling keeps verification", verify_anchor_signature(pk_b64, smuggled, sig))

wrong_len_key = base64.b64encode(b"\x00" * 16).decode()
check("short pubkey rejected cleanly", not verify_anchor_signature(wrong_len_key, cp, sig))
check("short sig rejected cleanly", not verify_anchor_signature(pk_b64, cp, base64.b64encode(b"x" * 10).decode()))
check("non-base64 sig rejected cleanly", not verify_anchor_signature(pk_b64, cp, "!!!!not b64!!!!"))

ok, _ = validate_sequence_continuity(None, 1, 5)
check("genesis starts at 1", ok)
ok, msg = validate_sequence_continuity(None, 3, 5)
check("genesis not-at-1 rejected", not ok and "must start at seq 1" in msg)
ok, msg = validate_sequence_continuity({"seq_end": 10, "head_hash": "h"}, 11, 15)
check("contiguous accepted", ok)
ok, msg = validate_sequence_continuity({"seq_end": 10, "head_hash": "h"}, 12, 15)
check("gap detected", not ok and "gap" in msg)
ok, msg = validate_sequence_continuity({"seq_end": 10, "head_hash": "h"}, 8, 15)
check("overlap detected", not ok and "overlap" in msg)
ok, msg = validate_sequence_continuity({"seq_end": 10, "head_hash": "h"}, 11, 11)
check("start>=end rejected", not ok)

ok, _ = validate_hash_chain(None, cp)  # prev "" => genesis OK
check("genesis chain ok", ok)
ok, msg = validate_hash_chain(None, {**cp, "prev_head_hash": "deadbeef"})
check("genesis with false predecessor rejected", not ok and "Genesis" in msg)
last = {"seq_end": 5, "head_hash": "ab" * 32}
cp_linked = {**cp, "prev_head_hash": "ab" * 32}
ok, err = validate_hash_chain(last, cp_linked)
check("linked chain ok", ok)
ok, msg = validate_hash_chain(last, {**cp_linked, "prev_head_hash": "ff" * 32})
check("broken chain rejected", not ok and "Hash chain break" in msg)

# --------------------------------------------------------------------------
# Server integration via TestClient
# --------------------------------------------------------------------------
client = TestClient(main.app)

r = client.post("/devices/register", params={"device_id": "dev-1", "public_key_b64": pk_b64})
check("register device ok", r.status_code == 200 and r.json()["status"] == "registered")

r = client.post("/devices/register", params={"device_id": "dev-1", "public_key_b64": pk_b64})
check("duplicate register -> 400", r.status_code == 400)

r = client.post("/devices/register", params={"device_id": "dev-bad", "public_key_b64": "!!!notb64!!!"})
check("malformed b64 key -> 400", r.status_code == 400)

r = client.post("/devices/register", params={"device_id": "dev-short", "public_key_b64": base64.b64encode(b"x" * 16).decode()})
check("wrong-length key -> 400", r.status_code == 400)


def make_item(qid, ckpt_dict, signkey=sk):
    s = base64.b64encode(signkey.sign(canonical_anchor_payload(ckpt_dict)).signature).decode()
    return {"id": qid, "payload": ckpt_dict, "signature": s, "timestamp": ckpt_dict["sts_timestamp"]}


def batch(items):
    return client.post("/anchors/batch", json={"batch": items}).json()


# -- real edge node pipeline -------------------------------------------------
edge_db = os.path.join(TMP, "edge.db")
eng = AnchorEngine(edge_db, ledger_id="dev-1", batch_size=5)
for i in range(10):
    eng.append_event({"sensor": "t", "value": i})

c1 = eng.generate_checkpoint()
check("first batch generated", c1 is not None)
check("genesis prev empty", c1.prev_head_hash == "")

d1 = json.loads(eng.checkpoint_to_json(c1))
resp = batch([make_item(1, d1)])
check("first batch ACKed", resp["acknowledged"] == [{"id": 1}] and resp["rejected"] == [])

eng.confirm_checkpoint(c1.anchor_id)
check("watermark advanced after confirm", eng.last_anchored_seq == c1.seq_end)

# A second batch generated NOW links onto c1's head (correct lifecycle).
c2 = eng.generate_checkpoint()
d2 = json.loads(eng.checkpoint_to_json(c2))
check("second batch links to confirmed head", d2["prev_head_hash"] == c1.head_hash)

# Stale/forged linkage: same seq range but prev pointing elsewhere -> reject.
stale = {**d2, "anchor_id": d2["anchor_id"] + "-stale", "prev_head_hash": "ee" * 32}
resp = batch([make_item(20, stale)])
check("stale chain-linkage rejected", resp["acknowledged"] == [] and "Hash chain break" in resp["rejected"][0]["reason"])

# Overlap attempt: re-anchor c1's exact range -> continuity rejects overlap.
overlap = {**d1, "anchor_id": "x-overlap"}
resp = batch([make_item(21, overlap)])
check("overlap rejected", resp["acknowledged"] == [] and "overlap" in resp["rejected"][0]["reason"])

# Correct next batch (fresh c3 continuing from c2's head)
eng.mark_failed(c2.anchor_id)
c3 = eng.generate_checkpoint()
d3 = json.loads(eng.checkpoint_to_json(c3))
check("new batch links to confirmed head", d3["prev_head_hash"] == c1.head_hash)
resp = batch([make_item(3, d3)])
check("linked batch ACKed", resp["acknowledged"] == [{"id": 3}])
eng.confirm_checkpoint(c3.anchor_id)

# Duplicate redelivery -> idempotent re-ACK, no second row
conn = core_db.init_core_db()
n_before = conn.execute("SELECT COUNT(*) FROM anchors").fetchone()[0]
resp = batch([make_item(3, d3)])
n_after = conn.execute("SELECT COUNT(*) FROM anchors").fetchone()[0]
check("duplicate re-ACKed idempotently", resp["acknowledged"] == [{"id": 3}] and n_before == n_after)

# Unknown device
ghost = {**d3, "ledger_id": "ghost-device"}
resp = batch([make_item(9, ghost)])
check("unknown device rejected", "unknown device" in resp["rejected"][0]["reason"])

# Bad signature from registered device
forged = make_item(10, d3, signkey=SigningKey.generate())
resp = batch([forged])
check("forged signature rejected", "invalid signature" in resp["rejected"][0]["reason"])

# Sequence gap (skip ahead) — signed properly so it reaches continuity check
gap = {**d3, "anchor_id": "x-gap", "seq_start": 100, "seq_end": 105,
       "prev_head_hash": d3["head_hash"], "sts_timestamp": 999.0}
resp = batch([make_item(11, gap)])
check("sequence gap rejected", "gap" in resp["rejected"][0]["reason"])

# Mixed batch: one good (continuing chain) + one bad -> partial ACK semantics
good_next = {**d3, "anchor_id": "x-good", "seq_start": d3["seq_end"] + 1,
             "seq_end": d3["seq_end"] + 3, "prev_head_hash": d3["head_hash"],
             "sts_timestamp": 1000.0}
bad_missing = {"id": 13, "payload": {"ledger_id": "dev-1"}, "signature": sig, "timestamp": 1.0}
resp = batch([make_item(12, good_next), bad_missing])
check("mixed batch partial ACK", resp["acknowledged"] == [{"id": 12}] and len(resp["rejected"]) == 1)

# WORM immutability still enforced
try:
    conn.execute("UPDATE anchors SET merkle_root = 'zz' WHERE id = 1")
    check("WORM blocks UPDATE", False)
except Exception as e:
    check("WORM blocks UPDATE", "Immutability" in str(e))
try:
    conn.execute("DELETE FROM anchors WHERE id = 1")
    check("WORM blocks DELETE", False)
except Exception as e:
    check("WORM blocks DELETE", "Immutability" in str(e))

# Audit: signatures over stored rows verify; chain hashes recomputable
rows = conn.execute(
    "SELECT anchor_id, device_id, seq_start, seq_end, head_hash, prev_head_hash,"
    " merkle_root, sts_timestamp, signature_b64 FROM anchors ORDER BY seq_start"
).fetchall()
stored_ok = True
for r_ in rows:
    d = dict(zip(("anchor_id","device_id","seq_start","seq_end","head_hash","prev_head_hash","merkle_root","sts_timestamp","signature_b64"), r_))
    if not verify_anchor_signature(pk_b64, d, d["signature_b64"]):
        stored_ok = False
check("stored anchors re-verify", stored_ok and len(rows) >= 2)
conn.close()

print()
failed = [n for n, ok in results if not ok]
print(f"{len(results) - len(failed)}/{len(results)} checks passed")
if failed:
    print("FAILED:", failed)
    sys.exit(1)
print("ALL GOOD")
