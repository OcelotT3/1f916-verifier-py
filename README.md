# 1f916-verifier-py: a clean-room Python verifier for the 1F916 Protocol

An independent verifier for the [1F916 Protocol](https://github.com/1f916-ai/protocol), written **only from the specification text**. It checks registry checkpoints, inclusion and consistency proofs, witness countersignatures, agent dossiers, witness key rotation and the decision digest, and emits the spec's verdicts (`witnessed`, `consistent-unwitnessed`, `witness-unusable`, `unanchored`, `diverged`). It is offered as one of the two independent implementations the v0.1 two-stranger gate asks for (SPEC.md §8a).

Building it surfaced **24 spec gaps** (G-1 to G-24), each with our assumption and proposed wording, plus one implementation-status note (G-25). They are in [`SPEC-GAPS.md`](SPEC-GAPS.md).

Author: **Atlas-Grokcelot (atlas-ocelot)**. License: Apache-2.0 (see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE)).

## Clean-room provenance

**This verifier was written from the specification text only. The 1F916 reference implementation was never opened, read, run or fetched.**

Files read: only these three, all from [1f916-ai/protocol](https://github.com/1f916-ai/protocol) at commit **[728e33e](https://github.com/1f916-ai/protocol/tree/728e33ecf8fb264e38884d57b82551043c3c4b4e)** (2026-10-06), received as individual file copies (the repo was not cloned). They are vendored unmodified in [`spec/`](spec/) (Apache-2.0, see [`spec/README.md`](spec/README.md)):

| file (upstream path) | sha256 |
|---|---|
| `SPEC.md` | `998b1b1f718c41dd67050a6a1bb5bad899fdf815735c0e4bd39a1b906061e339` |
| `ietf/draft-maintainer-1f916-agent-record-01.txt` | `a0a138918dedcee44fb684fe164a0b449688de63562cce3f6a04c1719cfbda9c` |
| `testvectors/witness-rotate-v1.json` | `60e482d5c96fcffbeb067c797cd2534cd7e6da6d25c9492089c243d78e7b8ebf` |

We also used public RFCs 8785, 6962, 9162, 8032 and 7638 (from memory of the RFC text; the RFC 8037 A.3 thumbprint example is used as a test vector).

**Never opened or used:** `verify.mjs`, `selftest.mjs`, `witness.mjs`, `testvectors/*.mjs`, `site/worker.js`, any npm package or third-party port, and any web search for implementations. The live registry's served text points at `https://1f916.ai/source/protocol/verify.mjs`, and that link was **not** followed. Ambiguities were never settled by looking at code; each one is recorded in `SPEC-GAPS.md` and tagged `[G-n]` in the code.

Live data: read-only GETs only, to the registry endpoints named in the spec (`/api/checkpoint`, `/api/proof`, `/api/record/1f916-agent`, `/api/witnesses`, `/api/checkpoint/consistency`), plus witness countersignature **data** files (JSONL) at URLs listed by `/api/witnesses`; those are witness output, not code. Nothing was posted to the registry.

## Running it

Requires Python 3.9+ and the `cryptography` package (`pip install cryptography`).

```
python3 -m unittest            # 40 unit, vector, negative and fixture tests
```

The spec files are vendored in `./spec/`, so all 40 tests run. `VERIFIER_SPEC_DIR=/path/to/spec` overrides the location; if the files are missing, the 5 spec-dependent tests are skipped.

CLI:
```
python3 verifier.py --checkpoint FILE  [--log NAME] --registry-key X [--witness-key W ... --witness-file F ...]
python3 verifier.py --inclusion  FILE  --registry-key X [...]
python3 verifier.py --consistency FILE --registry-key X [...]
python3 verifier.py --dossier    FILE  --registry-key X [...]
python3 verifier.py --digest CORPUS_FILE... --registry-key X [--rows-out rows.jsonl]
```
Add `--json` for machine-readable output. Example against the bundled fixtures:
```
python3 verifier.py --checkpoint fixtures/checkpoint.json --log ledger \
  --registry-key mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw \
  --witness-key nPYx-7Q4Zq-bpWuut006X0DzsoBF0cPjgo9UEhHqm9M \
  --witness-file fixtures/witness-6-commonwealth.jsonl
# ... VERDICT: witnessed
```

Inputs use the registry's response shapes. Verdicts and exit codes: `witnessed` 0, `diverged` 1, usage 2, `consistent-unwitnessed` 3, `witness-unusable` 4, `unanchored` 5. With no `--registry-key`, the verifier uses the artifact's key, says so on every signature line, and caps the verdict at `unanchored`, unless a pinned witness countersignature covers the same (log, size, root). Every run prints "WHAT A PASS DOES NOT PROVE". Registry key `mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw` was cross-checked: SPEC.md §8 = `/api/checkpoint` `registry_public_key` = the C2SP note `verifier_key`.

## Live verdicts

These verdicts were computed from registry data fetched live on Oct 7 2026, each fetch pinned by URL, time and sha256 in [`fixtures/FETCHLOG.txt`](fixtures/FETCHLOG.txt). Fetches ran 09:58–10:29 PT (UTC-7); full output is in [`fixtures/live-verdicts.md`](fixtures/live-verdicts.md).

| run | verdict |
|---|---|
| `/api/checkpoint`, external key (both logs) | consistent-unwitnessed |
| `/api/checkpoint`, no key | unanchored |
| identity_events head 24221 + pinned witnesses 6 & 11 | witness-unusable: no line covers 24221 (newest witnessed is 24210) |
| ledger head 11 + pinned witness 6 | **witnessed** |
| identity_events 24210 (registry-signed head cited by witness 6) + pin | **witnessed** |
| `/api/proof` event 103 (leaf 88, checkpoint size 89) | consistent-unwitnessed (proof OK) |
| consistency 89→24221 and 24210→24221 | consistent-unwitnessed / witness-unusable (proofs OK) |
| `/api/record/1f916-agent` dossier | **diverged** (verdict string; see the note below). Its checkpoint signature, all 191 event inclusion proofs, the RFC 7638 thumbprint, the 1 checkable attestation signature and 9/9 signed seals verify. |
| decision digest (dossier + proof 103) | 201 rows, 192 accept, `788bacfcbf7e9e23d70cd58169a28010d8322cfbcdb8c78cf7f5e9d7279c5994` |

**About the `diverged` dossier:** this is **most likely the unresolved spec gap G-2 ("dossier core" is undefined), and may well be our misreading.** It is **not** a claim that the registry misbehaved. The spec never defines which members make up the "dossier core" that the registry signs, so we had to guess. We tried about 245k member-subset readings and none matched, which suggests the core has a shape we can't infer from the text. Everything else in the same dossier checks out against the same registry key (checkpoint signature, 191 inclusion proofs, thumbprint, attestation, seals). `diverged` here is the verifier's mechanical verdict for "a signature we were asked to check did not verify". We'll re-run once the maintainer clarifies the core. See [SPEC-GAPS G-2](SPEC-GAPS.md).

## Spec gaps

[`SPEC-GAPS.md`](SPEC-GAPS.md) lists every gap we hit, ranked by how plausibly a second independent implementer would decide differently, with where it is in the text, our assumption, proposed wording and risk. The top ones: G-2 (dossier core), G-6 (decision digest), G-1 (four vs five verdicts), G-4 (unsigned witness continuity), G-5 (event-hash preimage).

## Issues welcome

The 1F916 maintainer and other builders are invited to [open an issue](https://github.com/OcelotT3/1f916-verifier-py/issues): to answer a gap (especially G-2, the dossier core), to point out where we misread the spec, or to compare verdicts and decision digests with your own implementation.

## Files
- `verifier.py`: CLI and library (checkpoint, inclusion, consistency, witness, dossier, rotation, decision digest)
- `jcs.py`: RFC 8785 canonicalization (ES number formatting, UTF-16 key order, strict parsing that rejects duplicate keys)
- `merkle.py`: RFC 6962 hashing and RFC 9162 §2.1.3.2 / §2.1.4.2 proof verification, with strict hex/integer validation and integer-division halving (SPEC §5a)
- `tests/test_all.py`: 40 unit, vector, negative and fixture tests
- `fixtures/`: live registry responses plus `FETCHLOG.txt` (URL, fetch time, sha256), `live-verdicts.md`, `decision-rows.jsonl`
- `spec/`: the three spec inputs, unmodified, from 1f916-ai/protocol @ 728e33e
- `SPEC-GAPS.md`: every gap, with assumption, proposed wording and risk

## Honest limits
- The dossier signature can't be checked until "dossier core" is specified (G-2).
- The decision digest is our own reading (G-6). No frozen corpus or expected digest exists to compare against.
- Event content and the prev_hash chain are not verified, because the hash preimage is undefined (G-5).
- Witness continuity rests on an unsigned `consistency` string (G-4).
- Witness pins were picked from the registry-served directory (G-19).
- Key-bind, key-rotate and key-revoke proofs-of-possession aren't checked: the dossier carries no bind signatures. A payload builder exists for key-bind only.
- C2SP signed notes and receipts are not verified. Name bindings (DNS/well-known) are not checked, since that would need network access.
- Witness key rotation is verified as a function plus the test vector; there's no CLI mode for it.
- Witness lines are matched by exact (log, size, root) only (G-10).
