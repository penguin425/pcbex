# Factory-release transparency external gossip quorum

v1.491 acquires external-log observations through a bounded remote adapter and
requires distinct, policy-pinned organizations to agree on one exact signed
head. It closes the single-observer threshold gap left by v1.490.

The verifier stays strict. Every observation is replayed against the exact
latest v1.489 local head before it can count.

> [!IMPORTANT]
> A successful report proves agreement only among the selected configured
> observers and views. It does not prove global non-equivocation, real
> organizational independence, trusted time, legal identity, ledger rollback
> resistance, capacity, ordering, payment, or exactly-once execution.

## What it adds

- **Acquires safely:** Sends one bounded JSON request over HTTPS, rejects
  redirects, and limits total time to 1–600 seconds.

- **Bounds responses:** Requires HTTP 200, `application/json`, and at most
  1 MiB before parsing.

- **Keeps secrets out:** Reads an optional bearer token only from a named
  environment variable. No output retains the variable name or token.

- **Binds transport:** Records exact request and response SHA-256 values,
  response bytes, selected local head, policy digest, and observer tuple.

- **Replays verification:** Reauthenticates both external-log heads, the
  observer signature, freshness window, role separation, and consistency proof
  under the v1.490 rules.

- **Requires exact agreement:** Counts organizations only when every selected
  observer signs the same exact external tree head.

- **Commits once:** Retains a met quorum through descriptor-pinned no-replace
  publication keyed by local v1.489 generation and observer policy digest.

## Why exact-head agreement matters

Checking every observer only against the local head is insufficient. Two
observers can each present a valid extension of the same local prefix while
showing different later branches.

v1.491 rejects that shape. Different signed-head digests never form one selected
quorum, even when both branches carry valid local-prefix consistency proofs.

```text
                    observer A: head X
                   /
local v1.489 head ─┤
                   \
                    observer B: head Y

X != Y  =>  no quorum
```

Equal-size different roots produce an explicit split-view failure. Different
sizes or otherwise different signed heads fail exact-head agreement.

## Observer-quorum policy

The deployment pins the canonical semantic SHA-256 of one static policy.
Endpoints remain deployment configuration; they do not define trust identity.

```json
{
  "schema_version": 1,
  "policy_scope": "factory-release-state-transparency-external-gossip-quorum-policy-v1",
  "policy_id": "production-external-observers",
  "minimum_organizations": 2,
  "maximum_receipt_age_seconds": 3600,
  "trusted_observers": [
    {
      "organization_id": "independent-lab-a",
      "observer_id": "external-observer-a",
      "algorithm": "ed25519",
      "public_key": "<64 lowercase hex characters>"
    },
    {
      "organization_id": "independent-lab-b",
      "observer_id": "external-observer-b",
      "algorithm": "ed25519",
      "public_key": "<64 lowercase hex characters>"
    }
  ]
}
```

The policy enforces these invariants:

- `minimum_organizations` is between 2 and 100.
- `maximum_receipt_age_seconds` is between 1 second and 24 hours.
- Trusted entries are sorted by `(organization_id, observer_id)`.
- Organization IDs, observer IDs, and Ed25519 keys are each unique.
- Every public key is a valid, non-weak Ed25519 key.
- Observer organizations, IDs, and keys do not reuse selected log, witness, or
  factory roles.

Discover the closed schema:

```sh
pcbex factory-release-state-transparency-external-gossip-quorum-policy-schema \
  --output observer-quorum-policy.schema.json
```

## Stage 1: acquire one observation

The remote endpoint receives a canonical compact request containing the pinned
log context, exact local signed head, observer policy digest, organization, and
observer ID. It returns one canonical observation envelope.

```sh
export PCBEX_EXTERNAL_GOSSIP_TOKEN='deployment-secret'

pcbex request-factory-release-state-transparency-external-gossip-observation \
  --local-external-consistency-report external-consistency-latest.json \
  --external-anchor-policy external-anchor-policy.json \
  --expected-external-anchor-policy-sha256 "$EXTERNAL_ANCHOR_POLICY_SHA256" \
  --external-log-id production-external-log \
  --observer-quorum-policy observer-quorum-policy.json \
  --expected-observer-quorum-policy-sha256 "$OBSERVER_QUORUM_POLICY_SHA256" \
  --organization-id independent-lab-a \
  --observer-id external-observer-a \
  --endpoint https://observer-a.example/v1/external-gossip \
  --bearer-token-env PCBEX_EXTERNAL_GOSSIP_TOKEN \
  --timeout-seconds 30 \
  --output observation-a.json \
  --receipt-output transport-a.json
```

> [!TIP]
> Use a separate output and transport-receipt path for every observer. Both
> files use create-new publication and reject aliases with inputs or each
> other.

The observation envelope contains only the signed v1.490 receipt and its
optional consistency proof:

```json
{
  "schema_version": 1,
  "observation_scope": "factory-release-state-transparency-external-gossip-observation-v1",
  "gossip_receipt": {},
  "consistency_proof": null
}
```

An identical observed tree requires `null`. Different local and observed sizes
require the exact bounded v1.489 proof in the correct smaller-to-larger order.

## Stage 2: verify the quorum

The durable command reloads the complete v1.484–v1.489 chain from the pinned
ledger. Supplied observations and transport receipts must be positionally
paired.

```sh
pcbex verify-factory-release-state-transparency-external-gossip-quorum \
  --reservation-ledger /srv/pcbex/release-ledger \
  --expected-ledger-id "$LEDGER_ID" \
  --idempotency-key "$IDEMPOTENCY_KEY" \
  --log-id factory-release-log \
  --policy-pack organization-policy.json \
  --expected-policy-sha256 "$ORGANIZATION_POLICY_SHA256" \
  --transparency-policy transparency-policy.json \
  --expected-transparency-policy-sha256 "$TRANSPARENCY_POLICY_SHA256" \
  --witness-policy witness-policy.json \
  --expected-witness-policy-sha256 "$WITNESS_POLICY_SHA256" \
  --external-anchor-policy external-anchor-policy.json \
  --expected-external-anchor-policy-sha256 "$EXTERNAL_ANCHOR_POLICY_SHA256" \
  --external-log-id production-external-log \
  --observer-quorum-policy observer-quorum-policy.json \
  --expected-observer-quorum-policy-sha256 "$OBSERVER_QUORUM_POLICY_SHA256" \
  --observation observation-a.json \
  --observation observation-b.json \
  --transport-receipt transport-a.json \
  --transport-receipt transport-b.json \
  --output external-gossip-quorum.json \
  --require-quorum \
  --require-accepted
```

Durable verification is Unix-only because it depends on the pinned-directory,
permission, synchronization, and no-replace filesystem contract. Acquisition
and every schema command remain cross-platform.

## Evaluation order

The verifier fails closed in this order:

1. Pin the ledger and validate its independently configured manifest identity.
2. Reload the monotonic v1.484 head and complete v1.485–v1.489 chains.
3. Recompute the external-anchor and observer-quorum policy digests.
4. Reject role reuse across every trusted observer policy member.
5. Bind each transport receipt to the exact request, response, local head, and
   observer tuple.
6. Replay the complete v1.490 verification for every observation.
7. Enforce the configured receipt-age window at the quorum evaluation time.
8. Reject duplicate organizations, observer IDs, keys, observations, transport
   receipts, or signed gossip receipts.
9. Require every selected observer to agree on one exact signed head.
10. Count distinct organizations and evaluate the policy threshold.
11. Publish the requested report; retain it in the ledger only when quorum is
    met.

Authentication happens before size, time, or Merkle claims are interpreted.
The unsigned transport receipt never replaces observer or external-log
signature verification.

## Below-threshold evidence

One valid observation under a two-organization policy produces a closed report
with `status: "insufficient_organizations"` and `quorum_met: false`. The command
writes that report before `--require-quorum` returns failure.

`--require-accepted` also requires a met observer quorum. It cannot promote an
accepted inner factory state when the external observation threshold is still
incomplete.

Below-threshold evidence is not committed to the selected ledger. A later run
can therefore add observations and meet the same policy without conflicting
with an incomplete attempt.

## Durable retry and conflicts

A met quorum uses one deterministic ledger name derived from:

- release idempotency key;
- source and external log identities;
- witness and external-anchor policy digests;
- latest local external-consistency generation; and
- observer-quorum policy digest.

Concurrent identical writers converge on the same bytes. An exact retry can
reorder the paired inputs and still returns the retained report after observer
receipt expiry.

Different observation/transport pairs conflict once a quorum occupies that
name. New external-consistency generations or new observer-policy digests select
new durable contexts.

## Schemas and limits

| Artifact | Maximum | Discovery command |
| --- | ---: | --- |
| Observer-quorum policy | 64 KiB | `factory-release-state-transparency-external-gossip-quorum-policy-schema` |
| Observation envelope | 256 KiB | `factory-release-state-transparency-external-gossip-observation-schema` |
| Remote response | 1 MiB | Transport boundary, before parsing |
| Transport receipt | 64 KiB | `remote-factory-release-state-transparency-external-gossip-receipt-schema` |
| Quorum report | 32 MiB | `factory-release-state-transparency-external-gossip-quorum-verification-report-schema` |
| Selected observations | 100 | Policy and report schemas |

All persisted JSON uses closed objects, bounded arrays, duplicate-key
rejection, canonical pretty rendering, and a trailing newline.

## What remains

v1.492 adds policy-bound, generation- and digest-chained observer key rotation
without changing this wire contract. See [External-gossip Observer Key
Rotation](FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_ROTATION.md).

A governed organization registry remains separate. Trusted timestamping,
selected-ledger rollback protection, legal identity, capacity, order authority,
payment, and exactly-once execution also remain outside this contract.
