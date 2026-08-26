# Governed external-gossip registry-root rotation

Rotate the registry root without reopening root-only control.

v1.497 couples a prospective-root-signed governance document with one
old-and-new quorum rotation event. The registry root and active governance
digest move together—or neither moves.

## Key features

- **Proves successor possession:** The prospective root signs governance bound
  to the exact current generation and semantic registry digest.

- **Requires both quorums:** Retained and successor governance each satisfy
  their own threshold over one domain-separated next-generation payload.

- **Rotates atomically:** One event replaces `authority_public_key` and
  `active_governance_sha256` while preserving organizations and admissions.

- **Rejects historical roots:** A successor key may not equal the current root
  or any root already retained in the selected history.

- **Replays five event types:** The verifier accepts legacy transitions, root
  rotations, threshold transitions, governance rotations, and governed root
  rotations from one pinned genesis.

- **Fails closed:** The v1.496 verifier rejects the fifth event instead of
  verifying only a historical prefix.

- **Converges exactly:** Every mutation shares one manifest lock, generation
  namespace, gap check, and no-replace publication contract.

> [!IMPORTANT]
> Keep the genesis digest and expected ledger identity outside the ledger being
> evaluated. A copied ledger plus copied trust anchors is not an independent
> rollback boundary.

## Quick start

Export the exact current registry state:

```sh
LEDGER=/absolute/path/to/release-ledger
LEDGER_ID=<64-lowercase-hex>
BASE_POLICY=external-observers.base.json
BASE_SHA256=<semantic-sha256-of-base-policy>
REGISTRY_GENESIS=observer-organizations.genesis.json
REGISTRY_SHA256=<semantic-sha256-of-registry-genesis>

pcbex export-factory-release-state-transparency-external-gossip-organization-registry \
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --registry-genesis "$REGISTRY_GENESIS" \
  --expected-registry-genesis-sha256 "$REGISTRY_SHA256" \
  --output observer-organizations.current.json
```

Have the prospective root sign successor governance against that exact state:

```sh
pcbex sign-factory-release-state-transparency-external-gossip-organization-registry-successor-root-governance \
  --registry-state observer-organizations.current.json \
  --successor-registry-authority-private-key registry-root.next.private.hex \
  --minimum-approvals 2 \
  --authority-id release-admin-d \
  --authority-public-key release-admin-d.public.hex \
  --authority-id release-admin-e \
  --authority-public-key release-admin-e.public.hex \
  --authority-id release-admin-f \
  --authority-public-key release-admin-f.public.hex \
  --issued-at-unix 1787700200 \
  --output registry-governance.next-root.json
```

Approve one atomic rotation under both governance policies:

```sh
pcbex sign-factory-release-state-transparency-external-gossip-organization-registry-governed-authority-key-rotation \
  --registry-state observer-organizations.current.json \
  --old-governance registry-governance.current.json \
  --new-governance registry-governance.next-root.json \
  --old-authority-id release-admin-a \
  --old-authority-private-key release-admin-a.private.hex \
  --old-authority-id release-admin-b \
  --old-authority-private-key release-admin-b.private.hex \
  --new-authority-id release-admin-d \
  --new-authority-private-key release-admin-d.private.hex \
  --new-authority-id release-admin-e \
  --new-authority-private-key release-admin-e.private.hex \
  --rotated-at-unix 1787700300 \
  --output registry-root.rotation.json
```

Apply and durably retain the next generation:

```sh
pcbex apply-factory-release-state-transparency-external-gossip-organization-registry-governed-authority-key-rotation \
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --registry-genesis "$REGISTRY_GENESIS" \
  --expected-registry-genesis-sha256 "$REGISTRY_SHA256" \
  --rotation registry-root.rotation.json \
  --output observer-organizations.root-rotated.json
```

Use `registry-governance.next-root.json` for every later threshold transition.
The previous governance now fails the retained-root check.

Verify the complete selected-ledger history:

```sh
pcbex verify-factory-release-state-transparency-external-gossip-quorum-with-organization-registry-governed-authority-rotation \
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --registry-genesis "$REGISTRY_GENESIS" \
  --expected-registry-genesis-sha256 "$REGISTRY_SHA256" \
  --observer-trust-report external-gossip-observer-trust.report.json \
  --output external-gossip-registry-governed-root.report.json \
  --require-quorum \
  --require-accepted
```

> [!TIP]
> Export immediately before signing successor governance. Any winning registry
> event changes the bound generation and state digest, so stale handoffs fail.

## Authorization contract

| Layer | Required binding |
| --- | --- |
| Retained governance | Exact active digest, current root signature, configured threshold, authorities, and issue time |
| Successor governance | Same base policy, policy ID, and registry ID; exact current generation and state digest; distinct prospective-root signature |
| Rotation | Exact next generation, prior event digest, old/new root keys, old/new governance digests, time, and algorithm |
| Old approvals | Ordered unique identities, distinct policy-matched keys, retained threshold, and valid signatures over the rotation payload |
| New approvals | Ordered unique identities, distinct policy-matched keys, successor threshold, and valid signatures over the same payload |
| Result | Replace root and active governance together; preserve organizations and admissions; advance generation, digest, and time once |

The prospective root proves possession before activation. It cannot activate
itself without both governance quorums.

## Selected-ledger architecture

| Stage | Fresh check |
| --- | --- |
| Genesis | Match the independently configured semantic digest and immutable base policy |
| Event selection | Require exactly one of five event types at every generation |
| Root history | Verify every signature and reject current or historical root-key reuse |
| Governance history | Verify every embedded root signature, threshold, authority set, state binding, and handoff |
| Governed rotation | Verify both approval sets, exact state, roots, governance digests, time, generation, and prior digest |
| Observer replay | Rebuild the latest v1.492 trust report from selected-ledger observer rotations |
| Role separation | Reject every historical root or governance key reused by observer trust, and every root/governance collision |
| Eligibility | Require every selected quorum organization to remain active and exactly admitted |
| Retention | Commit a met-quorum report without replacement; keep below-threshold evidence output-only |

The v1.496 governance-rotation verifier rejects a governed root event. Switch
to the v1.497 verifier as soon as the fifth event enters the ledger.

## Retry and conflict behavior

An exact retry of the latest rotation returns the same registry bytes. Once a
later event exists, the older rotation is stale.

All five mutation types occupy one serialized generation namespace. Competing
filenames, gaps, forks, stale state, root or policy substitution, signature
mutation, historical root reuse, and time rollback fail closed.

Verification reloads registry and observer history around report publication.
Concurrent mutation, input replacement, or report conflict prevents output.

## Schemas and limits

| Artifact | Maximum | Discovery command |
| --- | ---: | --- |
| Registry state | 256 KiB | `factory-release-state-transparency-external-gossip-organization-registry-schema` |
| Root-signed governance | 32 KiB | `signed-factory-release-state-transparency-external-gossip-organization-registry-governance-schema` |
| Governed root rotation | 256 KiB | `signed-factory-release-state-transparency-external-gossip-organization-registry-governed-authority-key-rotation-schema` |
| Governance authorities | 100 per policy | Governance schema |
| Mixed history events | 4,096 | Governed-authority-rotation report schema |
| Self-contained report | 128 MiB | `factory-release-state-transparency-external-gossip-organization-registry-governed-authority-rotation-verification-report-schema` |

Every artifact uses canonical pretty JSON with one trailing LF, duplicate-key
rejection, closed objects, bounded arrays, and create-new outputs. Semantic
digests hash normalized compact objects; artifact identities bind exact bytes.

## Explicit nonclaims

Two valid quorum sets do not prove independent people, organizations, or key
custody. The policies may overlap, and one operator may control several keys.
`independent_governance_control_verified` therefore remains false.

The selected ledger remains locally mutable storage. Host rollback resistance,
trusted time, global non-equivocation, legal identity, capacity, order
placement, payment, and exactly-once execution remain unproved.
