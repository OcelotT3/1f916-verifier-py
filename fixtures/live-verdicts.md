# Live verdicts, run 2026-10-07T10:33:56-07:00 PT (UTC-7) over fixtures fetched per FETCHLOG.txt

## verifier.py --checkpoint checkpoint.json --registry-key $REGKEY
OK    checkpoint[identity_events] signature (identity_events size=24221 root=9e01cfe3459ed1ca...) under registry key mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw [caller-supplied (external, anchored)]
OK    checkpoint[ledger] signature (ledger size=11 root=ce96f39e1f5a5379...) under registry key mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw [caller-supplied (external, anchored)]
VERDICT: consistent-unwitnessed
exit=3

## verifier.py --checkpoint checkpoint.json
OK    checkpoint[identity_events] signature (identity_events size=24221 root=9e01cfe3459ed1ca...) under registry key mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw [FROM THE ARTIFACT UNDER TEST (self-supplied, unanchored)]
OK    checkpoint[ledger] signature (ledger size=11 root=ce96f39e1f5a5379...) under registry key mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw [FROM THE ARTIFACT UNDER TEST (self-supplied, unanchored)]
NOTE  no --registry-key supplied: every registry signature used a key from the artifact; at best 'unanchored'.
VERDICT: unanchored
exit=5

## verifier.py --checkpoint checkpoint.json --log identity_events --registry-key $REGKEY --witness-key nPYx-7Q4Zq-bpWuut006X0DzsoBF0cPjgo9UEhHqm9M --witness-key _OMJE5LUz7JoNRPyiLet1gVB1IDbIeA_R8mwvyecjjA --witness-file witness-6-commonwealth.jsonl --witness-file witness-11-glmflash.jsonl
OK    checkpoint[identity_events] signature (identity_events size=24221 root=9e01cfe3459ed1ca...) under registry key mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw [caller-supplied (external, anchored)]
NOTE  checkpoint[identity_events]: no pinned witness line covers identity_events/24221
VERDICT: witness-unusable
exit=4

## verifier.py --checkpoint checkpoint.json --log ledger --registry-key $REGKEY --witness-key nPYx-7Q4Zq-bpWuut006X0DzsoBF0cPjgo9UEhHqm9M --witness-key _OMJE5LUz7JoNRPyiLet1gVB1IDbIeA_R8mwvyecjjA --witness-file witness-6-commonwealth.jsonl --witness-file witness-11-glmflash.jsonl
OK    checkpoint[ledger] signature (ledger size=11 root=ce96f39e1f5a5379...) under registry key mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw [caller-supplied (external, anchored)]
OK    checkpoint[ledger] countersigned by PINNED witness key nPYx-7Q4Zq-bpWuut006X0DzsoBF0cPjgo9UEhHqm9M (line #531, consistency='verified from 8')
OK    checkpoint[ledger]: 859 pinned countersignature lines in total cover this head
VERDICT: witnessed
exit=0

## verifier.py --checkpoint checkpoint-24210-from-witness6-line.json --registry-key $REGKEY --witness-key nPYx-7Q4Zq-bpWuut006X0DzsoBF0cPjgo9UEhHqm9M --witness-key _OMJE5LUz7JoNRPyiLet1gVB1IDbIeA_R8mwvyecjjA --witness-file witness-6-commonwealth.jsonl --witness-file witness-11-glmflash.jsonl
OK    checkpoint[identity_events] signature (identity_events size=24210 root=b0ba814ff35d5801...) under registry key mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw [caller-supplied (external, anchored)]
OK    checkpoint[identity_events] countersigned by PINNED witness key nPYx-7Q4Zq-bpWuut006X0DzsoBF0cPjgo9UEhHqm9M (line #2230, consistency='verified from 24194')
VERDICT: witnessed
exit=0

## verifier.py --inclusion proof-identity_events-103.json --registry-key $REGKEY
OK    proof.checkpoint signature (identity_events size=89 root=3798c74b045e09c8...) under registry key mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw [caller-supplied (external, anchored)]
OK    inclusion: event 103 (leaf 88) in identity_events tree_size 89
VERDICT: consistent-unwitnessed
exit=3

## verifier.py --inclusion proof-identity_events-103.json --registry-key $REGKEY --witness-key nPYx-7Q4Zq-bpWuut006X0DzsoBF0cPjgo9UEhHqm9M --witness-key _OMJE5LUz7JoNRPyiLet1gVB1IDbIeA_R8mwvyecjjA --witness-file witness-6-commonwealth.jsonl --witness-file witness-11-glmflash.jsonl
OK    proof.checkpoint signature (identity_events size=89 root=3798c74b045e09c8...) under registry key mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw [caller-supplied (external, anchored)]
NOTE  proof.checkpoint: no pinned witness line covers identity_events/89
OK    inclusion: event 103 (leaf 88) in identity_events tree_size 89
VERDICT: witness-unusable
exit=4

## verifier.py --consistency consistency-identity_events-89-24221.json --registry-key $REGKEY
OK    consistency.from signature (identity_events size=89 root=3798c74b045e09c8...) under registry key mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw [caller-supplied (external, anchored)]
OK    consistency.to signature (identity_events size=24221 root=9e01cfe3459ed1ca...) under registry key mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw [caller-supplied (external, anchored)]
OK    consistency: identity_events 89 -> 24221 is append-only
VERDICT: consistent-unwitnessed
exit=3

## verifier.py --consistency consistency-identity_events-24210-24221.json --registry-key $REGKEY --witness-key nPYx-7Q4Zq-bpWuut006X0DzsoBF0cPjgo9UEhHqm9M --witness-key _OMJE5LUz7JoNRPyiLet1gVB1IDbIeA_R8mwvyecjjA --witness-file witness-6-commonwealth.jsonl --witness-file witness-11-glmflash.jsonl
OK    consistency.from signature (identity_events size=24210 root=b0ba814ff35d5801...) under registry key mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw [caller-supplied (external, anchored)]
OK    consistency.from countersigned by PINNED witness key nPYx-7Q4Zq-bpWuut006X0DzsoBF0cPjgo9UEhHqm9M (line #2230, consistency='verified from 24194')
OK    consistency.to signature (identity_events size=24221 root=9e01cfe3459ed1ca...) under registry key mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw [caller-supplied (external, anchored)]
NOTE  consistency.to: no pinned witness line covers identity_events/24221
OK    consistency: identity_events 24210 -> 24221 is append-only
VERDICT: witness-unusable
exit=4

## verifier.py --dossier record-1f916-agent.json --registry-key $REGKEY
OK    dossier.checkpoint signature (identity_events size=24221 root=9e01cfe3459ed1ca...) under registry key mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw [caller-supplied (external, anchored)]
FAIL  dossier registry_sig over 1f916.record.v1:sha256(JCS(core)) under mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw [caller-supplied (external, anchored)]; core = all members minus registry_sig,seals,seals_note,seals_returned,seals_total,seals_has_more,now,now_utc
FAIL  dossier.registry_sig: does not verify over our reading of 'dossier core' [G-2]
OK    agent key 74QOP5d3Y0VLRKzuyKE616uDVLgF-_dhjRPOxHecQcw thumbprint RFC7638 ok; custody='self' status='active' (custody is a CLAIM, see not-proven)
OK    191 event inclusion proofs verify against dossier.checkpoint; 9 rows carry no proof (legacy_unsealed / newer than checkpoint) and are NOT proven
NOTE  events page is partial (200 of 2879 returned); omitted rows are not checked
OK    attestation 3 (correction) signature under agent key 74QOP5d3Y0VLRKzuyKE616uDVLgF-_dhjRPOxHecQcw [key from the registry-signed dossier]; claim content NOT validated
OK    9/9 signed seals verify under agent keys; 13 unsigned (signed:false, bearer-only) (convenience view outside the signed core; proves unchanged-since-sealed only)
VERDICT: diverged
  failed: dossier.registry_sig: does not verify over our reading of 'dossier core' [G-2]
exit=1

## verifier.py --dossier record-1f916-agent.json
OK    dossier.checkpoint signature (identity_events size=24221 root=9e01cfe3459ed1ca...) under registry key mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw [FROM THE ARTIFACT UNDER TEST (self-supplied, unanchored)]
FAIL  dossier registry_sig over 1f916.record.v1:sha256(JCS(core)) under mpQPa0FjyynqoSg2Z9j91hRhb8WckxIpRGod43CQqLw [FROM THE ARTIFACT UNDER TEST (self-supplied, unanchored)]; core = all members minus registry_sig,seals,seals_note,seals_returned,seals_total,seals_has_more,now,now_utc
FAIL  dossier.registry_sig: does not verify over our reading of 'dossier core' [G-2]
OK    agent key 74QOP5d3Y0VLRKzuyKE616uDVLgF-_dhjRPOxHecQcw thumbprint RFC7638 ok; custody='self' status='active' (custody is a CLAIM, see not-proven)
OK    191 event inclusion proofs verify against dossier.checkpoint; 9 rows carry no proof (legacy_unsealed / newer than checkpoint) and are NOT proven
NOTE  events page is partial (200 of 2879 returned); omitted rows are not checked
OK    attestation 3 (correction) signature under agent key 74QOP5d3Y0VLRKzuyKE616uDVLgF-_dhjRPOxHecQcw [key from the registry-signed dossier]; claim content NOT validated
OK    9/9 signed seals verify under agent keys; 13 unsigned (signed:false, bearer-only) (convenience view outside the signed core; proves unchanged-since-sealed only)
NOTE  no --registry-key supplied: every registry signature used a key from the artifact; at best 'unanchored'.
VERDICT: diverged
  failed: dossier.registry_sig: does not verify over our reading of 'dossier core' [G-2]
exit=1

## decision digest over [record-1f916-agent.json, proof-identity_events-103.json]
{
 "rows": 201,
 "accept": 192,
 "reject": 9,
 "decision_digest_sha256": "788bacfcbf7e9e23d70cd58169a28010d8322cfbcdb8c78cf7f5e9d7279c5994",
 "definition": "sha256(JCS([{log,id,decision}...] sorted by log,id)) [G-6]"
}
