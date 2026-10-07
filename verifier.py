#!/usr/bin/env python3
"""Clean-room 1F916 verifier. Built ONLY from SPEC.md, draft-maintainer-1f916-agent-record-01
and witness-rotate-v1.json (protocol commit 728e33e) plus RFC 8785/6962/9162/8032/7638.
See README.md for provenance and SPEC-GAPS.md for every assumption (tagged [G-n] below)."""
import argparse, base64, hashlib, json, re, sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

import jcs
import merkle
from merkle import ProofError

DEFAULT_ORIGIN = "https://1f916.ai"
PUBLISHED_REGISTRY_KEY = "mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw"  # SPEC.md sec 8

WITNESSED, CONSISTENT_UNWITNESSED, WITNESS_UNUSABLE, UNANCHORED, DIVERGED = (
    "witnessed", "consistent-unwitnessed", "witness-unusable", "unanchored", "diverged")
EXIT = {WITNESSED: 0, DIVERGED: 1, CONSISTENT_UNWITNESSED: 3, WITNESS_UNUSABLE: 4, UNANCHORED: 5}

NOT_PROVEN = [
    "WHO holds any private key: custody labels are the registry's/agent's claims, not proofs (SPEC 2, draft 3.1).",
    "The TRUTH of any event, attestation claim or sealed content: signatures, checkpoints, seals and "
    "countersignatures fix authorship and time, never validity of content (SPEC 5, draft 3.4).",
    "That a matching seal means nobody touched the content in between: it compares endpoints, not the interval (SPEC 5).",
    "Anything about unbound names, or about legacy_unsealed rows (no inclusion proof exists for them) (SPEC 8).",
    "That an event's kind/detail/created_at fields are what its chain hash commits to: the spec does not define "
    "the event-hash preimage, so only the hash is proven present in the log [G-5].",
    "Completeness: a dossier page (events_has_more/caps) can omit rows; inclusion proves presence, never absence.",
    "Anything about split views beyond the witnesses actually checked; witness independence is not verified.",
    "consistent-unwitnessed means registry-trust only: timing is registry-asserted and it is NOT 'fully verified'.",
]

class Fail(Exception):
    """A proof/signature failure -> diverged, naming the exact check."""

def b64u_decode(s, nbytes=None, what="value"):
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", s) or len(s) % 4 == 1:
        raise Fail("%s is not unpadded base64url: %r" % (what, s))
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != s:
        raise Fail("%s is non-canonical base64url" % what)  # [G-11]
    if nbytes is not None and len(raw) != nbytes:
        raise Fail("%s decodes to %d bytes, expected %d" % (what, len(raw), nbytes))
    return raw

def ed25519_ok(pub_b64u, sig_b64u, msg: bytes):
    try:
        pk = Ed25519PublicKey.from_public_bytes(b64u_decode(pub_b64u, 32, "public key"))
        sig = b64u_decode(sig_b64u, 64, "signature")
    except Fail:
        return False
    try:
        pk.verify(sig, msg); return True
    except InvalidSignature:
        return False

def jwk_thumbprint(x):
    """RFC 7638 for an Ed25519 OKP key: members crv,kty,x in lexicographic order."""
    j = '{"crv":"Ed25519","kty":"OKP","x":"%s"}' % x
    return base64.urlsafe_b64encode(hashlib.sha256(j.encode()).digest()).rstrip(b"=").decode()

# ---- payload strings (normative per SPEC 2,3,4,5,6,8; draft 3.x) ----
def checkpoint_payload(log, size, root, created_at):
    return ("1f916.checkpoint.v1:%s:%d:%s:%d" % (log, size, root, created_at)).encode()
def witness_payload(origin, log, size, root):
    return ("1f916.witness.v1:%s:%s:%d:%s" % (origin, log, size, root)).encode()
def rotate_payload(wid, epoch, old, new):
    return ("1f916.witness-rotate.v1:%d:%d:%s:%s" % (wid, epoch, old, new)).encode()
def record_payload(core):
    return ("1f916.record.v1:" + hashlib.sha256(jcs.canonical_bytes(core)).hexdigest()).encode()
def attestation_payload(issuer, payload_jcs_text):
    return ("1f916.attestation.v1:%s:" % issuer).encode() + payload_jcs_text.encode()
def seal_payload(handle, label, h):
    return ("1f916.seal.v1:%s:%s:%s" % (handle, label or "", h)).encode()
def keybind_payload(handle, x):
    return ("1f916.key-bind.v1:%s:%s" % (handle, x)).encode()

def verify_rotation(witness_id, current_epoch, new_epoch, old_key, new_key, old_sig, new_sig):
    """witness-rotate-v1.json must_accept / must_refuse. Returns (ok, reason)."""
    if not old_sig or not new_sig:
        return False, "either signature missing"
    if old_key == new_key or old_sig == new_sig:
        return False, "both signatures made by the same key"
    if isinstance(new_epoch, bool) or not isinstance(new_epoch, int) or new_epoch != current_epoch + 1:
        return False, "epoch is not exactly one greater than the current epoch"
    msg = rotate_payload(witness_id, new_epoch, old_key, new_key)
    if not ed25519_ok(old_key, old_sig, msg):
        return False, "old_sig does not verify under old key over the exact payload"
    if not ed25519_ok(new_key, new_sig, msg):
        return False, "new_sig does not verify under new key over the exact payload"
    return True, "rotation cross-signed by both keys"

# ---- run context ----
class Run:
    def __init__(self, registry_key=None, witness_keys=(), witness_lines=None, origin=DEFAULT_ORIGIN):
        self.registry_key = registry_key          # caller-supplied (external) or None
        self.witness_keys = list(witness_keys)    # caller-pinned
        self.witness_lines = witness_lines        # None = no witness input given
        self.origin = origin
        self.lines = []        # human-readable report lines
        self.failures = []
        self.anchored = False
        self.witness_ok = False  # pinned countersig with continuity covering every checked head
        self.witness_heads = []  # per-head result

    def say(self, s): self.lines.append(s)
    def fail(self, s): self.failures.append(s); self.lines.append("FAIL  " + s)

    def registry_key_for(self, artifact_key, where):
        """Anchor rule: prefer caller key; never silently accept a differing artifact key."""
        if self.registry_key:
            if artifact_key and artifact_key != self.registry_key:
                raise Fail("%s: artifact registry key %s does not match pinned key %s" % (where, artifact_key, self.registry_key))
            return self.registry_key, "caller-supplied (external, anchored)"
        if artifact_key:
            return artifact_key, "FROM THE ARTIFACT UNDER TEST (self-supplied, unanchored)"
        raise Fail("%s: no registry key supplied and none in artifact" % where)

    def check_checkpoint(self, cp, log=None, artifact_key=None, where="checkpoint"):
        log = cp.get("log", log)
        if not isinstance(log, str) or ":" in log or not log:
            raise Fail("%s: log name missing or contains ':'" % where)  # [G-9]
        size = merkle.check_uint(cp.get("tree_size"), where + ".tree_size")
        merkle.check_hex64(cp.get("root"), where + ".root")
        created = merkle.check_uint(cp.get("created_at"), where + ".created_at")
        key, how = self.registry_key_for(artifact_key, where)
        ok = ed25519_ok(key, cp.get("sig"), checkpoint_payload(log, size, cp["root"], created))
        self.say("%s  %s signature (%s size=%d root=%s) under registry key %s [%s]" %
                 ("OK  " if ok else "FAIL", where, log, size, cp["root"][:16] + "...", key, how))
        if not ok:
            raise Fail("%s: registry signature does not verify" % where)
        if self.registry_key:
            self.anchored = True
        self.witness_heads.append(self.check_witness(log, size, cp["root"], key, where))
        return log, size, cp["root"]

    def check_witness(self, log, size, root, reg_key, where):
        """Evaluate witness lines covering (log,size,root). Returns 'cont'|'nocont'|'none'."""
        if self.witness_lines is None:
            return "none"
        best = "none"; nmatch = 0
        for i, w in enumerate(self.witness_lines):
            if not isinstance(w, dict):
                continue
            if w.get("registry", None) != self.origin:   # [G-7] lines must name the bound origin
                continue
            if w.get("log") != log or w.get("tree_size") != size:
                continue
            status = str(w.get("status", "")); typ = str(w.get("type", ""))
            if "refus" in status or "refus" in typ or status in ("registry_signature_invalid",):
                raise Fail("%s: witness REFUSAL line #%d (%s) covers this head" % (where, i, status or typ))
            if w.get("root") != root:
                # conflicting head: an alarm only if a pinned witness signed it [G-8]
                for pk in self.witness_keys:
                    if ed25519_ok(pk, w.get("witness_sig"), witness_payload(self.origin, log, size, w.get("root", ""))):
                        raise Fail("%s: pinned witness %s countersigned a DIFFERENT root %s at size %d" % (where, pk, w.get("root"), size))
                continue
            for pk in self.witness_keys:
                msg = witness_payload(self.origin, log, size, root)
                if ed25519_ok(pk, w.get("witness_sig"), msg):
                    self.anchored = True  # a pinned witness covering (log,size,root) anchors the run
                    # re-verify the registry signature the line cites (SPEC 6: line carries created_at)
                    if "created_at" in w and "registry_sig" in w:
                        if not ed25519_ok(reg_key, w["registry_sig"], checkpoint_payload(log, size, root, w["created_at"])):
                            raise Fail("%s: witness line #%d cites a registry_sig that does not verify" % (where, i))
                    cons = str(w.get("consistency", ""))
                    cont = cons.startswith("verified from")   # [G-4]
                    nmatch += 1
                    if nmatch == 1 or (cont and best != "cont"):
                        self.say("OK    %s countersigned by PINNED witness key %s (line #%d, consistency=%r)%s" %
                                 (where, pk, i, cons or None, "" if cont else " -- no continuity asserted: cannot grant 'witnessed'"))
                    if cont:
                        best = "cont"
                    elif best == "none":
                        best = "nocont"
                elif w.get("witness_public_key") == pk:
                    raise Fail("%s: line #%d claims pinned key %s but witness_sig does not verify" % (where, i, pk))
        if nmatch > 1:
            self.say("OK    %s: %d pinned countersignature lines in total cover this head" % (where, nmatch))
        if best == "none":
            self.say("NOTE  %s: no pinned witness line covers %s/%d" % (where, log, size))
        return best

    def verdict(self):
        if self.failures:
            return DIVERGED
        if not self.anchored:
            return UNANCHORED
        if self.witness_heads and all(h == "cont" for h in self.witness_heads) and self.witness_keys:
            return WITNESSED
        if self.witness_lines is not None or self.witness_keys:
            return WITNESS_UNUSABLE   # [G-1][G-3] asked, nothing applicable arrived
        return CONSISTENT_UNWITNESSED

# ---- modes ----
def mode_checkpoint(run, doc, log_filter=None):
    cps = doc["checkpoints"] if isinstance(doc, dict) and "checkpoints" in doc else [doc]
    art = (doc.get("registry_public_key") or {}).get("x") if isinstance(doc, dict) and isinstance(doc.get("registry_public_key"), dict) else None
    for cp in cps:
        if log_filter and cp.get("log") != log_filter:
            continue
        guard(run, lambda: run.check_checkpoint(cp, artifact_key=art, where="checkpoint[%s]" % cp.get("log")))

def guard(run, fn):
    try:
        return fn()
    except (Fail, ProofError, jcs.JCSError, KeyError, TypeError) as e:
        run.fail(str(e) if not isinstance(e, (KeyError, TypeError)) else "malformed input: %r" % e)

def mode_inclusion(run, doc):
    log = doc.get("log")
    def go():
        run.check_checkpoint(doc["checkpoint"], log=log, where="proof.checkpoint")
        ev = doc["event"]
        merkle.verify_inclusion(ev["leaf_index"], doc["checkpoint"]["tree_size"], merkle.event_leaf(ev["hash"]),
                                doc["proof"], doc["checkpoint"]["root"])
        run.say("OK    inclusion: event %s (leaf %d) in %s tree_size %d" % (ev.get("id"), ev["leaf_index"], log, doc["checkpoint"]["tree_size"]))
    guard(run, go)

def mode_consistency(run, doc):
    log = doc.get("log")
    def go():
        a = doc["from"]; b = doc["to"]
        run.check_checkpoint(a, log=log, where="consistency.from")
        run.check_checkpoint(b, log=log, where="consistency.to")
        merkle.verify_consistency(a["tree_size"], b["tree_size"], a["root"], b["root"], doc["proof"])
        run.say("OK    consistency: %s %d -> %d is append-only" % (log, a["tree_size"], b["tree_size"]))
    guard(run, go)

# [G-2] the spec never defines "dossier core". Documented reading: every top-level member except the
# registry_sig itself, the members the dossier itself labels as outside the signed core (seals view),
# and per-response clock members (now, now_utc).
CORE_EXCLUDE_DEFAULT = ("registry_sig", "seals", "seals_note", "seals_returned", "seals_total", "seals_has_more", "now", "now_utc")

def dossier_core(d, exclude=CORE_EXCLUDE_DEFAULT):
    return {k: v for k, v in d.items() if k not in exclude}

def mode_dossier(run, d, core_exclude=CORE_EXCLUDE_DEFAULT):
    rs = d.get("registry_sig") or {}
    art = rs.get("registry_public_key")
    cp = d.get("checkpoint")
    guard(run, lambda: run.check_checkpoint(cp, artifact_key=art, where="dossier.checkpoint"))
    def sig():
        key, how = run.registry_key_for(art, "dossier.registry_sig")
        ok = ed25519_ok(key, rs.get("sig"), record_payload(dossier_core(d, core_exclude)))
        run.say("%s  dossier registry_sig over 1f916.record.v1:sha256(JCS(core)) under %s [%s]; core = all members minus %s" %
                ("OK  " if ok else "FAIL", key, how, ",".join(core_exclude)))
        if not ok:
            raise Fail("dossier.registry_sig: does not verify over our reading of 'dossier core' [G-2]")
    guard(run, sig)
    handle = d.get("handle")
    keys = {}
    for k in d.get("keys") or []:
        def kk(k=k):
            x = k["public_key"]; b64u_decode(x, 32, "agent key")
            tp = jwk_thumbprint(x)
            if k.get("thumbprint") != tp:
                raise Fail("key %s: thumbprint %s != RFC 7638 %s" % (x, k.get("thumbprint"), tp))
            keys[tp] = x
            run.say("OK    agent key %s thumbprint RFC7638 ok; custody=%r status=%r (custody is a CLAIM, see not-proven)" % (x, k.get("custody"), k.get("status")))
        guard(run, kk)
    nok = nleg = 0
    for e in d.get("events") or []:
        if e.get("proof") is None:
            nleg += 1; continue
        def ev(e=e):
            merkle.verify_inclusion(e["leaf_index"], cp["tree_size"], merkle.event_leaf(e["hash"]), e["proof"], cp["root"])
        before = len(run.failures); guard(run, ev)
        if len(run.failures) > before:
            run.failures[-1] = "event %s inclusion: %s" % (e.get("id"), run.failures[-1])
        else:
            nok += 1
    run.say("OK    %d event inclusion proofs verify against dossier.checkpoint; %d rows carry no proof (legacy_unsealed / newer than checkpoint) and are NOT proven" % (nok, nleg))
    if d.get("events_has_more"):
        run.say("NOTE  events page is partial (%s of %s returned); omitted rows are not checked" % (d.get("events_returned"), d.get("events_total")))
    for a in d.get("attestations_about") or []:
        def at(a=a):
            p = a.get("payload")
            if not isinstance(p, str):
                raise Fail("attestation %s: no payload string" % a.get("id"))
            if a.get("payload_hash") and hashlib.sha256(p.encode()).hexdigest() != a["payload_hash"]:
                raise Fail("attestation %s: payload_hash != sha256(payload)" % a.get("id"))
            parsed = jcs.loads_strict(p)
            if jcs.canonicalize(parsed) != p:
                raise Fail("attestation %s: payload is not in JCS canonical form" % a.get("id"))
            if not a.get("signature"):
                run.say("NOTE  attestation %s unsigned (bearer-only, signed:false)" % a.get("id")); return
            k = keys.get(a.get("key_thumbprint"))
            if not k:
                run.say("NOTE  attestation %s: signing key %s not in this dossier; not checked" % (a.get("id"), a.get("key_thumbprint"))); return
            if not ed25519_ok(k, a["signature"], attestation_payload(a.get("issuer"), p)):
                raise Fail("attestation %s: signature does not verify" % a.get("id"))
            run.say("OK    attestation %s (%s) signature under agent key %s [key from the registry-signed dossier]; claim content NOT validated" % (a.get("id"), a.get("class"), k))
        guard(run, at)
    sv = 0
    for s in d.get("seals") or []:
        if s.get("signature") and s.get("key_thumbprint") in keys:
            if ed25519_ok(keys[s["key_thumbprint"]], s["signature"], seal_payload(handle, s.get("label"), s.get("hash"))):
                sv += 1
            else:
                run.say("WARN  seal %s signature does not verify (seals view is outside the signed core; anchor is its memory.seal event)" % s.get("id"))
    if d.get("seals"):
        ns = sum(1 for s in d["seals"] if s.get("signature"))
        run.say("OK    %d/%d signed seals verify under agent keys; %d unsigned (signed:false, bearer-only) (convenience view outside the signed core; proves unchanged-since-sealed only)" % (sv, ns, len(d["seals"]) - ns))

# ---- decision digest (SPEC 8a.1) [G-6] ----
def decision_rows(registry_key, docs):
    """Per-row accept/reject. Row = one log event (log, id). Accept iff its inclusion proof verifies
    against a checkpoint whose signature verifies under the caller-supplied registry key."""
    rows = {}
    for d in docs:
        cps = []
        if "events" in d:
            cp = d["checkpoint"]; evs = d["events"]
        elif "event" in d:
            cp = dict(d["checkpoint"]); cp.setdefault("log", d.get("log")); evs = [dict(d["event"], proof=d.get("proof"))]
        else:
            continue
        log = cp.get("log")
        try:
            cp_ok = ed25519_ok(registry_key, cp["sig"], checkpoint_payload(log, merkle.check_uint(cp["tree_size"]), cp["root"], merkle.check_uint(cp["created_at"])))
        except Exception:
            cp_ok = False
        for e in evs:
            ok = False
            if cp_ok and e.get("proof") is not None:
                try:
                    merkle.verify_inclusion(e["leaf_index"], cp["tree_size"], merkle.event_leaf(e["hash"]), e["proof"], cp["root"]); ok = True
                except Exception:
                    ok = False
            key = (log, e.get("id"))
            # same row seen twice: reject if any copy rejects
            rows[key] = (rows.get(key, True) and ok)
    out = [{"log": k[0], "id": k[1], "decision": "accept" if v else "reject"} for k, v in rows.items()]
    out.sort(key=lambda r: (r["log"] or "", r["id"] if isinstance(r["id"], int) else -1))
    return out

def decision_digest(rows):
    return hashlib.sha256(jcs.canonical_bytes(rows)).hexdigest()

def load_json(path):
    with open(path, "rb") as f:
        return jcs.loads_strict(f.read().decode("utf-8"))

def load_witness_lines(paths):
    lines = []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            txt = f.read()
        s = txt.strip()
        if s.startswith("["):
            lines.extend(json.loads(s)); continue
        for ln in txt.splitlines():
            ln = ln.strip()
            if not ln: continue
            try: lines.append(json.loads(ln))
            except ValueError: lines.append(None)
    return lines

def main(argv=None):
    ap = argparse.ArgumentParser(description="Clean-room 1F916 verifier")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--checkpoint"); g.add_argument("--inclusion"); g.add_argument("--consistency")
    g.add_argument("--dossier"); g.add_argument("--digest", nargs="+", metavar="CORPUS_FILE")
    ap.add_argument("--registry-key", help="externally obtained base64url Ed25519 x of the registry")
    ap.add_argument("--witness-key", action="append", default=[], help="pinned witness key (base64url x); repeatable")
    ap.add_argument("--witness-file", action="append", default=[], help="witness countersignature JSONL; repeatable")
    ap.add_argument("--origin", default=DEFAULT_ORIGIN, help="registry origin witnesses bind to (no trailing slash)")
    ap.add_argument("--log", help="only check this log (checkpoint mode)")
    ap.add_argument("--rows-out", help="digest mode: write per-row decisions JSONL here")
    ap.add_argument("--json", action="store_true", help="emit machine-readable result")
    a = ap.parse_args(argv)

    if a.digest:
        if not a.registry_key:
            print("digest mode requires --registry-key (an unanchored digest is meaningless)", file=sys.stderr); return 2
        rows = decision_rows(a.registry_key, [load_json(p) for p in a.digest])
        if a.rows_out:
            with open(a.rows_out, "w") as f:
                for r in rows: f.write(jcs.canonicalize(r) + "\n")
        dg = decision_digest(rows)
        acc = sum(r["decision"] == "accept" for r in rows)
        print(json.dumps({"rows": len(rows), "accept": acc, "reject": len(rows) - acc,
                          "decision_digest_sha256": dg, "definition": "sha256(JCS([{log,id,decision}...] sorted by log,id)) [G-6]"}, indent=1))
        return 0

    run = Run(a.registry_key, a.witness_key, load_witness_lines(a.witness_file) if a.witness_file else None, a.origin)
    if a.witness_key and not a.witness_file:
        run.say("NOTE  witness key pinned but no witness file given")
    try:
        if a.checkpoint: mode_checkpoint(run, load_json(a.checkpoint), a.log)
        elif a.inclusion: mode_inclusion(run, load_json(a.inclusion))
        elif a.consistency: mode_consistency(run, load_json(a.consistency))
        elif a.dossier: mode_dossier(run, load_json(a.dossier))
    except (jcs.JCSError, ValueError) as e:
        run.fail("input rejected: %s" % e)
    v = run.verdict()
    if a.json:
        print(json.dumps({"verdict": v, "anchored": run.anchored, "failures": run.failures, "lines": run.lines, "not_proven": NOT_PROVEN}, indent=1))
    else:
        for l in run.lines: print(l)
        if not run.registry_key:
            print("NOTE  no --registry-key supplied: every registry signature used a key from the artifact; at best 'unanchored'.")
        print("\nWHAT A PASS DOES NOT PROVE:")
        for n in NOT_PROVEN: print("  - " + n)
        print("\nVERDICT: %s" % v)
        if v == CONSISTENT_UNWITNESSED:
            print("  (registry-trust only: no pinned witness countersignature was presented; this is NOT 'verified')")
        if v == WITNESS_UNUSABLE:
            print("  (witness input was supplied but no applicable pinned countersignature with continuity covered the head; go look)")
        if v == DIVERGED:
            for f in run.failures: print("  failed: " + f)
    return EXIT[v]

if __name__ == "__main__":
    sys.exit(main())
