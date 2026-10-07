import base64, copy, hashlib, io, json, os, sys, unittest, contextlib
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import jcs, merkle, verifier as V
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

FX = os.path.join(ROOT, "fixtures")
# Spec files (SPEC.md, witness-rotate-v1.json from 1f916-ai/protocol @ 728e33e) are vendored in ./spec/.
# VERIFIER_SPEC_DIR overrides that location; spec-dependent tests skip if the files are missing.
SPEC = os.environ.get("VERIFIER_SPEC_DIR", os.path.join(ROOT, "spec"))
HAVE_SPEC = os.path.exists(os.path.join(SPEC, "SPEC.md")) and os.path.exists(os.path.join(SPEC, "witness-rotate-v1.json"))
NEED_SPEC = unittest.skipUnless(HAVE_SPEC, "spec files not found; set VERIFIER_SPEC_DIR")
REG = "mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw"
W6 = "nPYx-7Q4Zq-bpWuut006X0DzsoBF0cPjgo9UEhHqm9M"

def fx(name):
    with open(os.path.join(FX, name)) as f: return json.load(f)
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def keypair(seed=None):
    sk = Ed25519PrivateKey.from_private_bytes(seed) if seed else Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk, b64u(pk)
def run_cli(*args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = V.main(list(args))
    return rc, out.getvalue()
def tmpjson(obj, name):
    p = os.path.join(HERE, "_tmp_" + name); json.dump(obj, open(p, "w")); return p

class TestJCS(unittest.TestCase):
    def test_numbers_rfc8785(self):
        cases = {0.0: "0", -0.0: "0", 1e21: "1e+21", 1e20: "100000000000000000000", 1e-7: "1e-7",
                 0.000001: "0.000001", 333333333.33333329: "333333333.3333333", 4.50: "4.5", 2e-3: "0.002",
                 1e30: "1e+30", 5e-324: "5e-324", 1.7976931348623157e308: "1.7976931348623157e+308",
                 -1.5: "-1.5", 123456789012345680000.0: "123456789012345680000", 9007199254740992: "9007199254740992",
                 1786500831085: "1786500831085", -5: "-5"}
        for x, want in cases.items():
            self.assertEqual(jcs.canonicalize(x), want, repr(x))
    def test_reject_nonfinite_and_unsafe(self):
        for bad in (float("nan"), float("inf")):
            self.assertRaises(jcs.JCSError, jcs.canonicalize, bad)
        self.assertRaises(jcs.JCSError, jcs.canonicalize, 2**53 + 1)
        self.assertRaises(jcs.JCSError, jcs.loads_strict, '{"a":NaN}')
    def test_key_order_utf16(self):
        # RFC 8785 sec 3.2.3 sorting example
        obj = {"\u20ac": "Euro Sign", "\r": "Carriage Return", "\ufb33": "Hebrew Letter Dalet With Dagesh",
               "1": "One", "\U0001F600": "Emoji: Grinning Face", "\u0080": "Control", "\u00f6": "Latin Small Letter O With Diaeresis"}
        keys = list(json.loads(jcs.canonicalize(obj)).keys())
        self.assertEqual(keys, ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\U0001F600", "\ufb33"])
    def test_strings(self):
        self.assertEqual(jcs.canonicalize("\u20ac$\u000f\nA'B\"\\\\\"/"), '"\u20ac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"')
        self.assertEqual(jcs.canonicalize("\x1f\b\t"), '"\\u001f\\b\\t"')
        self.assertRaises(jcs.JCSError, jcs.canonicalize, "\ud800")
    def test_structures(self):
        self.assertEqual(jcs.canonicalize({"b": [1, {"z": None, "a": True}], "a": False}), '{"a":false,"b":[1,{"a":true,"z":null}]}')
        self.assertRaises(jcs.JCSError, jcs.loads_strict, '{"a":1,"a":2}')
    def test_live_attestation_payload_is_jcs(self):
        p = fx("record-1f916-agent.json")["attestations_about"][0]["payload"]
        self.assertEqual(jcs.canonicalize(jcs.loads_strict(p)), p)

class TestMerkle(unittest.TestCase):
    def test_known_hashes(self):
        self.assertEqual(merkle.mth([]).hex(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(merkle.leaf_hash(b"").hex(), "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
        l, r = b"\x11" * 32, b"\x22" * 32
        self.assertEqual(merkle.node_hash(l, r), hashlib.sha256(b"\x01" + l + r).digest())
        h = "ab" * 32
        self.assertEqual(merkle.event_leaf(h), hashlib.sha256(b"\x00" + h.encode()).digest())  # hex TEXT, not bytes
    def test_all_proofs_small_trees(self):
        for n in range(1, 34):
            leaves = [("%064x" % (i * 7919)).encode() for i in range(n)]
            root = merkle.mth(leaves).hex()
            for m in range(n):
                p = [x.hex() for x in merkle.inclusion_path(m, leaves)]
                merkle.verify_inclusion(m, n, merkle.leaf_hash(leaves[m]), p, root)
                if p:
                    bad = list(p); bad[0] = "00" * 32
                    self.assertRaises(merkle.ProofError, merkle.verify_inclusion, m, n, merkle.leaf_hash(leaves[m]), bad, root)
                self.assertRaises(merkle.ProofError, merkle.verify_inclusion, m, n, merkle.leaf_hash(b"other"), p, root)
                self.assertRaises(merkle.ProofError, merkle.verify_inclusion, n, n, merkle.leaf_hash(leaves[m]), p, root)
            for m in range(1, n + 1):
                r1 = merkle.mth(leaves[:m]).hex()
                p = [x.hex() for x in merkle.consistency_path(m, leaves)]
                merkle.verify_consistency(m, n, r1, root, p)
                if m < n:
                    self.assertRaises(merkle.ProofError, merkle.verify_consistency, m, n, "00" * 32, root, p)
                    self.assertRaises(merkle.ProofError, merkle.verify_consistency, m, n, r1, "11" * 32, p)
    def test_hex_and_int_validation(self):
        for bad in ("AB" * 32, "ab" * 31, "ab" * 32 + "a", "gg" * 32, 5, None):
            self.assertRaises(merkle.ProofError, merkle.check_hex64, bad)
        for bad in (-1, True, 1.0, "3", 2**53):
            self.assertRaises(merkle.ProofError, merkle.check_uint, bad)
    def test_2pow32_plus1_forgery_rejected(self):
        # SPEC 5a: n = 2^32+1 must not let a short proof pass
        leaf = merkle.leaf_hash(b"x")
        self.assertRaises(merkle.ProofError, merkle.verify_inclusion, 2**32, 2**32 + 1, leaf, [], leaf.hex())
        self.assertRaises(merkle.ProofError, merkle.verify_consistency, 2**32, 2**32 + 1, "aa" * 32, "bb" * 32, ["aa" * 32])
    def test_consistency_edges(self):
        merkle.verify_consistency(5, 5, "aa" * 32, "aa" * 32, [])
        self.assertRaises(merkle.ProofError, merkle.verify_consistency, 5, 5, "aa" * 32, "bb" * 32, [])
        self.assertRaises(merkle.ProofError, merkle.verify_consistency, 6, 5, "aa" * 32, "aa" * 32, [])

class TestPayloads(unittest.TestCase):
    def test_strings(self):
        self.assertEqual(V.checkpoint_payload("identity_events", 89, "ab" * 32, 1786500831085),
                         ("1f916.checkpoint.v1:identity_events:89:" + "ab" * 32 + ":1786500831085").encode())
        self.assertEqual(V.witness_payload("https://1f916.ai", "ledger", 11, "cd" * 32),
                         ("1f916.witness.v1:https://1f916.ai:ledger:11:" + "cd" * 32).encode())
        self.assertEqual(V.seal_payload("h", None, "ef" * 32), ("1f916.seal.v1:h::" + "ef" * 32).encode())
        self.assertEqual(V.keybind_payload("h", "X"), b"1f916.key-bind.v1:h:X")
        self.assertEqual(V.attestation_payload("i", '{"a":1}'), b'1f916.attestation.v1:i:{"a":1}')
        self.assertEqual(V.record_payload({"b": 1, "a": 2}), ("1f916.record.v1:" + hashlib.sha256(b'{"a":2,"b":1}').hexdigest()).encode())
    def test_thumbprint_rfc8037_example(self):
        self.assertEqual(V.jwk_thumbprint("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k")
    def test_base64url_strict(self):
        self.assertRaises(V.Fail, V.b64u_decode, REG + "=", 32)
        self.assertRaises(V.Fail, V.b64u_decode, REG[:-1], 32)
        self.assertRaises(V.Fail, V.b64u_decode, REG[:-1] + "+", 32)
    @NEED_SPEC
    def test_registry_key_in_spec(self):
        self.assertIn(REG, open(os.path.join(SPEC, "SPEC.md")).read())
        self.assertEqual(fx("checkpoint.json")["registry_public_key"]["x"], REG)

@NEED_SPEC
class TestWitnessRotate(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(SPEC, "witness-rotate-v1.json")) as f: self.v = json.load(f)
    def test_keys_from_seeds(self):
        _, old = keypair(bytes.fromhex(self.v["seeds"]["old_key_seed_hex"]))
        _, new = keypair(bytes.fromhex(self.v["seeds"]["new_key_seed_hex"]))
        self.assertEqual((old, new), (self.v["old_public_key"], self.v["new_public_key"]))
    def test_payload_and_byte_for_byte_sigs(self):
        v = self.v
        p = V.rotate_payload(v["witness_id"], v["new_epoch"], v["old_public_key"], v["new_public_key"])
        self.assertEqual(p, v["payload"].encode())
        sk_old, _ = keypair(bytes.fromhex(v["seeds"]["old_key_seed_hex"]))
        self.assertEqual(b64u(sk_old.sign(p)), v["old_sig"])  # Ed25519 is deterministic (RFC 8032)
    def test_must_accept(self):
        v = self.v
        ok, why = V.verify_rotation(v["witness_id"], 0, v["new_epoch"], v["old_public_key"], v["new_public_key"], v["old_sig"], v["new_sig"])
        self.assertTrue(ok, why)
    def test_must_refuse(self):
        v = self.v; a = (v["witness_id"], 0, v["new_epoch"], v["old_public_key"], v["new_public_key"], v["old_sig"], v["new_sig"])
        refuse = [a[:5] + (None, a[6]), a[:6] + ("",),                       # missing sig
                  a[:4] + (a[3],) + (a[5], a[5]),                           # same key
                  (2,) + a[1:], a[:2] + (2,) + a[3:],                        # other id / epoch in payload
                  a[:3] + (a[4], a[3]) + a[5:],                              # swapped keys
                  (a[0], 1) + a[2:], (a[0], 0, 3) + a[3:]]                   # epoch not current+1
        for r in refuse:
            self.assertFalse(V.verify_rotation(*r)[0], r)

class TestLiveFixtures(unittest.TestCase):
    def test_inclusion_103(self):
        rc, out = run_cli("--inclusion", os.path.join(FX, "proof-identity_events-103.json"), "--registry-key", REG)
        self.assertIn("VERDICT: consistent-unwitnessed", out); self.assertEqual(rc, 3)
    def test_consistency(self):
        rc, out = run_cli("--consistency", os.path.join(FX, "consistency-identity_events-89-24221.json"), "--registry-key", REG)
        self.assertIn("VERDICT: consistent-unwitnessed", out)
    def test_checkpoint_no_key_is_unanchored(self):
        rc, out = run_cli("--checkpoint", os.path.join(FX, "checkpoint.json"))
        self.assertIn("VERDICT: unanchored", out); self.assertIn("FROM THE ARTIFACT", out); self.assertEqual(rc, 5)
    def test_witnessed_head(self):
        rc, out = run_cli("--checkpoint", os.path.join(FX, "checkpoint-24210-from-witness6-line.json"), "--registry-key", REG,
                          "--witness-key", W6, "--witness-file", os.path.join(FX, "witness-6-commonwealth.jsonl"))
        self.assertIn("VERDICT: witnessed", out); self.assertEqual(rc, 0)
    def test_witness_absent_for_head_is_unusable(self):
        rc, out = run_cli("--checkpoint", os.path.join(FX, "checkpoint.json"), "--log", "identity_events", "--registry-key", REG,
                          "--witness-key", W6, "--witness-file", os.path.join(FX, "witness-6-commonwealth.jsonl"))
        self.assertIn("VERDICT: witness-unusable", out); self.assertEqual(rc, 4)
    def test_dossier_inclusion_proofs(self):
        d = fx("record-1f916-agent.json"); cp = d["checkpoint"]; n = 0
        for e in d["events"]:
            if e["proof"] is not None:
                merkle.verify_inclusion(e["leaf_index"], cp["tree_size"], merkle.event_leaf(e["hash"]), e["proof"], cp["root"]); n += 1
        self.assertEqual(n, 191)
        for k in d["keys"]:
            self.assertEqual(V.jwk_thumbprint(k["public_key"]), k["thumbprint"])

class TestNegative(unittest.TestCase):
    def test_tampered_root(self):
        p = fx("proof-identity_events-103.json"); p["checkpoint"]["root"] = "0" * 64
        rc, out = run_cli("--inclusion", tmpjson(p, "t1.json"), "--registry-key", REG)
        self.assertIn("VERDICT: diverged", out); self.assertEqual(rc, 1)
    def test_tampered_proof_node_signature_still_ok(self):
        p = fx("proof-identity_events-103.json"); p["proof"][0] = "f" * 64
        rc, out = run_cli("--inclusion", tmpjson(p, "t2.json"), "--registry-key", REG)
        self.assertIn("VERDICT: diverged", out); self.assertIn("computed root", out)
    def test_uppercase_hex_rejected(self):
        p = fx("proof-identity_events-103.json"); p["proof"][0] = p["proof"][0].upper()
        rc, out = run_cli("--inclusion", tmpjson(p, "t3.json"), "--registry-key", REG)
        self.assertIn("VERDICT: diverged", out)
    def test_wrong_key(self):
        _, other = keypair()
        rc, out = run_cli("--inclusion", os.path.join(FX, "proof-identity_events-103.json"), "--registry-key=" + other)
        self.assertIn("VERDICT: diverged", out)
    def test_artifact_key_mismatch_pin(self):
        _, other = keypair()
        rc, out = run_cli("--checkpoint", os.path.join(FX, "checkpoint.json"), "--registry-key=" + other)
        self.assertIn("does not match pinned key", out); self.assertIn("VERDICT: diverged", out)
    def test_self_signed_forgery_is_unanchored(self):
        sk, pk = keypair(); root = "ab" * 32
        cp = {"log": "identity_events", "tree_size": 1, "root": root, "created_at": 1,
              "sig": b64u(sk.sign(V.checkpoint_payload("identity_events", 1, root, 1)))}
        doc = {"registry_public_key": {"kty": "OKP", "crv": "Ed25519", "x": pk}, "checkpoints": [cp]}
        rc, out = run_cli("--checkpoint", tmpjson(doc, "t4.json"))
        self.assertIn("VERDICT: unanchored", out)
        rc, out = run_cli("--checkpoint", tmpjson(doc, "t4.json"), "--registry-key", REG)
        self.assertIn("VERDICT: diverged", out)
    def _forged(self, lines, pin=True):
        reg_sk, reg = keypair(); w_sk, w = keypair(); root = "cd" * 32
        cp = {"log": "L", "tree_size": 7, "root": root, "created_at": 5, "sig": b64u(reg_sk.sign(V.checkpoint_payload("L", 7, root, 5)))}
        wl = []
        for kind in lines:
            line = {"type": "witness-countersignature", "registry": "https://1f916.ai", "log": "L", "tree_size": 7, "root": root,
                    "created_at": 5, "registry_sig": cp["sig"], "consistency": "verified from 3", "status": "countersigned", "witness_public_key": w}
            if kind == "first": line["consistency"] = "first observation"
            if kind == "refusal": line["status"] = "refused-consistency-failure"; line["type"] = "witness-refusal"
            if kind == "conflict": line["root"] = "ee" * 32
            if kind == "badsig": line["witness_sig"] = b64u(b"\0" * 64)
            else: line["witness_sig"] = b64u(w_sk.sign(V.witness_payload("https://1f916.ai", "L", 7, line["root"])))
            wl.append(line)
        wf = os.path.join(HERE, "_tmp_w.jsonl"); open(wf, "w").write("\n".join(json.dumps(x) for x in wl) + "\n")
        args = ["--checkpoint", tmpjson(cp, "c.json"), "--registry-key=" + reg, "--witness-file", wf]
        if pin: args += ["--witness-key=" + w]  # "=" form: random base64url keys can start with "-"
        return run_cli(*args)
    def test_witness_good(self): self.assertIn("VERDICT: witnessed", self._forged(["good"])[1])
    def test_witness_first_observation_not_top(self): self.assertIn("VERDICT: witness-unusable", self._forged(["first"])[1])
    def test_witness_refusal_fails_run(self): self.assertIn("VERDICT: diverged", self._forged(["good", "refusal"])[1])
    def test_witness_conflicting_root(self): self.assertIn("VERDICT: diverged", self._forged(["good", "conflict"])[1])
    def test_witness_bad_sig_claiming_pin(self): self.assertIn("VERDICT: diverged", self._forged(["badsig"])[1])
    def test_witness_unpinned_line_does_not_count(self):
        out = self._forged(["good"], pin=False)[1]
        self.assertIn("VERDICT: witness-unusable", out)
    def test_witness_only_anchor(self):
        # no registry key supplied; artifact carries it; a pinned witness covering (log,size,root) anchors the run
        rc, out = run_cli("--checkpoint", os.path.join(FX, "checkpoint.json"), "--log", "ledger",
                          "--witness-key", W6, "--witness-file", os.path.join(FX, "witness-6-commonwealth.jsonl"))
        self.assertIn("VERDICT: witnessed", out)
    def test_dossier_tamper_event(self):
        d = fx("record-1f916-agent.json"); e = next(x for x in d["events"] if x["proof"]); e["hash"] = "0" * 64
        run = V.Run(REG); V.mode_dossier(run, d)
        self.assertTrue(any("inclusion" in f for f in run.failures))

class TestDigest(unittest.TestCase):
    def test_deterministic_and_sensitive(self):
        docs = [fx("record-1f916-agent.json"), fx("proof-identity_events-103.json")]
        rows = V.decision_rows(REG, docs); d1 = V.decision_digest(rows)
        self.assertEqual(d1, V.decision_digest(V.decision_rows(REG, list(reversed(docs)))))
        self.assertEqual(len(rows), 201)
        self.assertEqual(sum(r["decision"] == "accept" for r in rows), 192)
        docs[1]["proof"][0] = "0" * 64
        self.assertNotEqual(d1, V.decision_digest(V.decision_rows(REG, docs)))
        _, other = keypair()
        self.assertTrue(all(r["decision"] == "reject" for r in V.decision_rows(other, docs)))

def tearDownModule():
    for f in os.listdir(HERE):
        if f.startswith("_tmp_"): os.remove(os.path.join(HERE, f))

if __name__ == "__main__":
    unittest.main()
