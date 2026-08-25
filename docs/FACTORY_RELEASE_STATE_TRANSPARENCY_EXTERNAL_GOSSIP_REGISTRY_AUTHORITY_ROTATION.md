# External-gossip registry authority rotation

Replace a factory-release organization-registry authority without breaking its signed history.

v1.494 adds one dual-signed rotation event to the v1.493 registry chain. The
current authority authorizes the handoff, the successor proves possession, and
the selected ledger admits exactly one event for each generation.

## Key features

- **Dual-signs handoff:** Requires valid Ed25519 signatures from both the
  retained authority and its successor over one domain-separated payload.

- **Preserves membership:** Changes only the authority key, generation, prior
  event digest, and update time. Organizations and observer admissions remain
  byte-for-byte equivalent as structured state.

- **Replays mixed history:** Verifies v1.493 organization transitions and
  v1.494 authority rotations in one generation- and digest-chained sequence.

- **Rejects key reuse:** Forbids any successor key that appeared earlier in
  the registry authority history.

- **Separates every role:** Compares all historical registry authority keys
  with every initial, rotated, and current observer key.

- **Converges exactly:** Serializes registry mutations on the pinned ledger
  manifest, then publishes without replacement. Identical retries converge;
  a transition and rotation cannot both claim one generation.

- **Fails closed for legacy verification:** The v1.493 verifier rejects a
  history containing rotations. Use the authority-rotation-aware verifier.

> [!IMPORTANT]
> Keep the registry genesis and its semantic SHA-256 in independent trusted
> configuration. Rotating the operational authority does not replace that
> trust root.

## Quick start

Start from the same pinned ledger, base policy, and registry genesis used by
the v1.493 workflow:

```sh
LEDGER=/absolute/path/to/release-ledger
LEDGER_ID=<64-lowercase-hex>
BASE_POLICY=external-observers.base.json
BASE_SHA256=<semantic-sha256-of-base-policy>
REGISTRY_GENESIS=observer-organizations.genesis.json
REGISTRY_SHA256=<semantic-sha256-of-registry-genesis>
OLD_AUTHORITY_PRIVATE=registry-authority.current.private.hex
NEW_AUTHORITY_PRIVATE=registry-authority.next.private.hex
```

Export the exact current registry before signing:

```sh
pcbex export-factory-release-state-transparency-external-gossip-organization-registry \
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --registry-genesis "$REGISTRY_GENESIS" \
  --expected-registry-genesis-sha256 "$REGISTRY_SHA256" \
  --output observer-organizations.current.json
```

Create the dual-signed handoff:

```sh
pcbex sign-factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation \
  --registry-state observer-organizations.current.json \
  --old-authority-private-key "$OLD_AUTHORITY_PRIVATE" \
  --new-authority-private-key "$NEW_AUTHORITY_PRIVATE" \
  --rotated-at-unix 1787600000 \
  --output registry-authority.rotation.json
```

Apply the exact next generation:

```sh
pcbex apply-factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation \
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --registry-genesis "$REGISTRY_GENESIS" \
  --expected-registry-genesis-sha256 "$REGISTRY_SHA256" \
  --rotation registry-authority.rotation.json \
  --output observer-organizations.rotated.json
```

Verify a retained v1.492 observer-trust quorum against the mixed registry
history:

```sh
pcbex verify-factory-release-state-transparency-external-gossip-quorum-with-organization-registry-authority-rotation \
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --registry-genesis "$REGISTRY_GENESIS" \
  --expected-registry-genesis-sha256 "$REGISTRY_SHA256" \
  --observer-trust-report external-gossip-observer-trust.report.json \
  --output external-gossip-registry-authority-rotation.report.json \
  --require-quorum \
  --require-accepted
```

> [!TIP]
> Export again immediately before signing. Any winning organization transition
> or authority rotation makes a stale handoff fail instead of rebasing it.

## Rotation contract

| Field group | Bound value |
| --- | --- |
| Context | Base-policy digest, policy ID, and registry ID |
| Chain | Exact `from_generation`, `to_generation = from + 1`, and prior history-event digest |
| Keys | Current non-weak Ed25519 public key and distinct non-weak successor key |
| Time | Explicit timestamp no earlier than the retained registry update time |
| Proof | Old-key signature plus new-key signature over the same payload |

The signed artifact contains public keys and signatures only. Private key
bytes never enter registry state, reports, or selected-ledger records.

The apply command rejects a valid dual-signed event when its successor appears
anywhere in the retained authority history. This prevents `A → B → A` rollback
even though both current signers could otherwise authorize it.

## Mixed-history verification

| Stage | Fresh check |
| --- | --- |
| Genesis | Match the independently configured semantic digest and immutable base policy |
| Event selection | Require exactly one transition or authority rotation at every generation |
| Transition replay | Verify the current authority signature, action, admission, time, and prior digest |
| Rotation replay | Verify both signatures, successor possession, unique key history, time, and prior digest |
| Observer replay | Rebuild the latest v1.492 trust report from selected-ledger observer rotations |
| Role separation | Reject any historical registry authority key reused by observer trust history |
| Eligibility | Require every selected quorum member to remain active and exactly admitted |
| Retention | Commit a met-quorum report without replacement; keep below-threshold evidence output-only |

The report embeds the registry genesis, every typed history event, the complete
current registry, and the exact observer-trust report. Artifact identities bind
the canonical bytes separately from semantic state digests.

`registry_authority_rotation_dual_signatures_verified` and
`registry_authority_successor_possession_verified` are true only after complete
replay. `authority_threshold_governance_verified` remains false.

## Retry and conflict behavior

An exact retry of the latest rotation returns the same current registry. Once
a later event exists, the older rotation is stale.

Registry transition and rotation apply commands acquire one advisory exclusive
lock on the already pinned ledger manifest. Within that critical section they
reload all history, verify exact inputs, and use descriptor-relative no-replace
publication. A competing event therefore wins one generation; the loser leaves
no alternate history record.

Verification reloads registry and observer histories around report publication.
A concurrent event, observer rotation, input mutation, or durable report
conflict prevents output publication.

## Schemas and limits

| Artifact | Maximum | Discovery command |
| --- | ---: | --- |
| Registry state | 256 KiB | `factory-release-state-transparency-external-gossip-organization-registry-schema` |
| Signed organization transition | 16 KiB | `signed-factory-release-state-transparency-external-gossip-organization-registry-transition-schema` |
| Dual-signed authority rotation | 16 KiB | `signed-factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation-schema` |
| Mixed history events | 4,096 | Authority-rotation report schema |
| Authority-rotation-aware report | 128 MiB | `factory-release-state-transparency-external-gossip-organization-registry-authority-rotation-verification-report-schema` |

Every artifact uses canonical pretty JSON with one trailing LF, duplicate-key
rejection, closed objects, bounded arrays, and create-new outputs. Semantic
digests hash normalized compact objects; artifact identities bind exact bytes
and lengths.

## Explicit nonclaims

This boundary proves one selected ledger's visible registry history and
successor-key possession. It does not prove threshold governance, multisignature
policy, or independent authorization by multiple registry administrators.

The ledger manifest lock coordinates cooperating pcbex writers; it does not
make the host rollback-resistant. Trusted time, global non-equivocation, real
organizational independence, key custody, legal identity, capacity, ordering,
payment, and exactly-once execution remain unproved.
