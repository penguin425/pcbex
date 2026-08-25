# External-gossip observer key rotation

Rotate v1.491 observer keys without replacing identity, weakening exact-head verification, or trusting an unlinked successor.

v1.492 keeps the v1.491 policy, observation, transport-receipt, and quorum wire
formats unchanged. It adds a policy-bound trust history that deterministically
derives the v1.491 policy carrying each observer's current key.

## Key features

- **Pins genesis:** Binds organization, observer, initial key, policy ID, and
  the immutable semantic SHA-256 of the base v1.491 policy.

- **Requires dual control:** Verifies old-key authorization and new-key
  possession over one domain-separated transition payload.

- **Advances exactly once:** Accepts only the next generation with the exact
  preceding transition digest and a nondecreasing explicit timestamp.

- **Rejects key reuse:** Prevents a retained observer from returning to any
  historical key and recreating an older effective-policy digest.

- **Retains safely:** Commits canonical transitions through descriptor-pinned,
  no-replace selected-ledger publication. Concurrent identical writers
  converge; competing forks conflict.

- **Reuses v1.491:** Produces a canonical effective policy for the existing
  acquisition and exact-head quorum commands.

- **Binds the result:** Embeds the base policy, effective policy, complete
  transition histories, current trust states, and exact v1.491 quorum report in
  one replayable report.

> [!IMPORTANT]
> Keep the base policy and its independently configured semantic digest. The
> base policy is genesis; the effective policy is a derived operational view.

## Quick start

Set the selected ledger and immutable base-policy pin:

```sh
LEDGER=/absolute/path/to/release-ledger
LEDGER_ID=<64-lowercase-hex>
BASE_POLICY=external-observers.base.json
BASE_SHA256=<semantic-sha256-of-base-policy>
```

Export the latest selected trust state for one observer:

```sh
pcbex export-factory-release-state-transparency-external-gossip-observer-trust-state \
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --organization-id independent-lab \
  --observer-id observer-a \
  --output observer-a.trust.json
```

Dual-sign the exact next transition. This step does not mutate the ledger:

```sh
pcbex sign-factory-release-state-transparency-external-gossip-observer-key-rotation \
  --trust-state observer-a.trust.json \
  --old-private-key observer-a.current.private.hex \
  --new-private-key observer-a.successor.private.hex \
  --rotated-at-unix 1787600000 \
  --output observer-a.rotation.json
```

Apply it through durable no-replace publication:

```sh
pcbex apply-factory-release-state-transparency-external-gossip-observer-key-rotation \
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --rotation observer-a.rotation.json \
  --output observer-a.current-trust.json
```

Derive the current v1.491 policy and its semantic digest:

```sh
pcbex derive-factory-release-state-transparency-external-gossip-effective-quorum-policy \
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --output external-observers.effective.json \
  --digest-output external-observers.effective.sha256

EFFECTIVE_SHA256=$(tr -d '\r\n' < external-observers.effective.sha256)
```

Use that effective policy with the unchanged v1.491 acquisition and quorum
commands. Each remote transport receipt binds its exact effective-policy
digest and current observer key.

After v1.491 retains a met quorum, bind it to the latest selected histories:

```sh
pcbex verify-factory-release-state-transparency-external-gossip-quorum-with-observer-trust \
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --effective-observer-quorum-policy external-observers.effective.json \
  --expected-effective-observer-quorum-policy-sha256 "$EFFECTIVE_SHA256" \
  --quorum-report external-gossip-quorum.report.json \
  --output external-gossip-observer-trust.report.json \
  --require-quorum \
  --require-accepted
```

> [!TIP]
> Export immediately before signing. If another valid transition wins first,
> applying the stale transition fails instead of silently rebasing it.

## Trust chain

| Stage | Bound input | Result |
| --- | --- | --- |
| Genesis | Exact base-policy semantic digest and member tuple | Generation-zero trust state |
| Sign | Current trust state plus retained and successor secrets | Canonical old/new dual-signed transition |
| Apply | Latest selected-ledger history | One durable next-generation transition |
| Derive | Every complete member history | Canonical effective v1.491 policy and semantic digest |
| Acquire | Effective policy and remote endpoint | Unchanged v1.491 observation plus hash-bound transport receipt |
| Verify | Durable v1.491 quorum plus latest histories | Self-contained v1.492 trust report |

The transition payload covers the base-policy digest, policy ID, organization,
observer, both generations, previous transition digest, both public keys,
explicit time, and algorithm. Mutating any field invalidates both signatures.

## Retry and conflict behavior

An exact retry of the latest transition returns the same current trust state.
Once a later generation exists, replaying an older transition fails as stale.

Two concurrent writers may submit the same canonical transition. Both succeed
only when the retained bytes match exactly; different successor keys compete
for one filename and one writer loses with a conflict.

The effective-policy command reloads every observer history before publication.
It rejects gaps, digest forks, invalid signatures, timestamp reversal, unknown
members, historical-key reuse, and current-key collisions.

The trust-bound verifier reloads those histories again around publication. An
older policy or history prefix fails after a newer selected transition exists.

## Schemas and limits

| Artifact | Maximum | Discovery command |
| --- | ---: | --- |
| Observer trust state | 16 KiB | `factory-release-state-transparency-external-gossip-observer-trust-state-schema` |
| Signed key rotation | 16 KiB | `signed-factory-release-state-transparency-external-gossip-observer-key-rotation-schema` |
| Per-observer generation | 4,096 | Trust-state and rotation schemas |
| Aggregate selected rotations | 4,096 | Trust-report schema |
| Base/effective policy | 64 KiB, 100 observers | Existing v1.491 policy schema |
| Trust-bound report | 64 MiB | `factory-release-state-transparency-external-gossip-observer-trust-verification-report-schema` |

Every persisted document uses canonical pretty JSON, one trailing LF,
duplicate-key rejection, closed objects, bounded arrays, and create-new output
semantics. Semantic policy and trust digests hash normalized compact objects;
artifact identities separately bind exact canonical bytes.

## Explicit nonclaims

This layer proves the latest history visible in one selected trusted ledger at
verification time. It does not prove that the host cannot restore an older
ledger snapshot.

It also does not establish global non-equivocation, trusted time, real
organizational independence, key custody, legal identity, endpoint identity,
capacity, order authority, payment, or exactly-once execution. A governed
organization registry remains a separate trust boundary.
