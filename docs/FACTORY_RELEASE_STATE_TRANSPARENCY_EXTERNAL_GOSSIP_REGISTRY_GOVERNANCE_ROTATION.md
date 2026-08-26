# External-gossip registry governance rotation

Change governance membership, keys, or threshold without reopening a root-only bypass.

v1.496 adds one state-bound successor governance document and one
old-and-new quorum rotation event. Both configured quorums must approve the
same exact next-generation payload before the active governance digest changes.

## Key features

- **Requires both quorums:** The retained governance and its successor each
  satisfy their own threshold over one domain-separated rotation payload.

- **Pins the successor state:** The registry root signs the exact current
  generation and semantic registry digest, plus the successor authorities,
  threshold, and issue time.

- **Rejects no-op rotation:** The successor must change the threshold,
  authority identities, or authority keys.

- **Preserves the registry:** Rotation advances one generation and one digest
  link without changing organizations, observer admissions, or the root key.

- **Expires stale governance:** After rotation, the old governance cannot sign
  another threshold transition. Only the retained successor digest is active.

- **Replays four event types:** The verifier handles legacy transitions,
  dual-signed root rotations, threshold transitions, and governance rotations
  from the independently pinned genesis.

- **Converges exactly:** Every registry mutation shares one pinned-ledger lock,
  generation namespace, gap check, and no-replace publication contract.

> [!IMPORTANT]
> Keep the registry genesis digest and current governance outside the ledger
> being evaluated. A copied ledger and copied trust anchors do not provide an
> independent rollback boundary.

## Quick start

Export the exact active-governance registry state:

```sh
LEDGER=/absolute/path/to/release-ledger
LEDGER_ID=<64-lowercase-hex>
BASE_POLICY=external-observers.base.json
BASE_SHA256=<semantic-sha256-of-base-policy>
REGISTRY_GENESIS=observer-organizations.genesis.json
REGISTRY_SHA256=<semantic-sha256-of-registry-genesis>
ROOT_PRIVATE=registry-root.current.private.hex

pcbex export-factory-release-state-transparency-external-gossip-organization-registry \
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --registry-genesis "$REGISTRY_GENESIS" \
  --expected-registry-genesis-sha256 "$REGISTRY_SHA256" \
  --output observer-organizations.current.json
```

Root-sign successor governance against those exact current bytes. This example
changes a 2-of-3 policy to 3-of-4:

```sh
pcbex sign-factory-release-state-transparency-external-gossip-organization-registry-successor-governance \
  --registry-state observer-organizations.current.json \
  --registry-authority-private-key "$ROOT_PRIVATE" \
  --minimum-approvals 3 \
  --authority-id release-admin-b \
  --authority-public-key release-admin-b.next.public.hex \
  --authority-id release-admin-c \
  --authority-public-key release-admin-c.public.hex \
  --authority-id release-admin-d \
  --authority-public-key release-admin-d.public.hex \
  --authority-id release-admin-e \
  --authority-public-key release-admin-e.public.hex \
  --issued-at-unix 1787700000 \
  --output registry-governance.successor.json
```

Approve one rotation with enough keys from both policies:

```sh
pcbex sign-factory-release-state-transparency-external-gossip-organization-registry-governance-rotation \
  --registry-state observer-organizations.current.json \
  --old-governance registry-governance.current.json \
  --new-governance registry-governance.successor.json \
  --old-authority-id release-admin-a \
  --old-authority-private-key release-admin-a.private.hex \
  --old-authority-id release-admin-c \
  --old-authority-private-key release-admin-c.private.hex \
  --new-authority-id release-admin-b \
  --new-authority-private-key release-admin-b.next.private.hex \
  --new-authority-id release-admin-d \
  --new-authority-private-key release-admin-d.private.hex \
  --new-authority-id release-admin-e \
  --new-authority-private-key release-admin-e.private.hex \
  --rotated-at-unix 1787700100 \
  --output registry-governance.rotation.json
```

Apply and durably retain the exact next generation:

```sh
pcbex apply-factory-release-state-transparency-external-gossip-organization-registry-governance-rotation \
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --registry-genesis "$REGISTRY_GENESIS" \
  --expected-registry-genesis-sha256 "$REGISTRY_SHA256" \
  --rotation registry-governance.rotation.json \
  --output observer-organizations.rotated.json
```

Use `registry-governance.successor.json` for every later threshold transition.
The old document now fails the retained active-governance check.

Verify the complete selected-ledger history:

```sh
pcbex verify-factory-release-state-transparency-external-gossip-quorum-with-organization-registry-governance-rotation \
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --registry-genesis "$REGISTRY_GENESIS" \
  --expected-registry-genesis-sha256 "$REGISTRY_SHA256" \
  --observer-trust-report external-gossip-observer-trust.report.json \
  --output external-gossip-registry-governance-rotation.report.json \
  --require-quorum \
  --require-accepted
```

> [!TIP]
> Export immediately before creating successor governance. Any winning registry
> event changes the signed generation and state digest, so stale successor
> governance fails instead of silently rebasing.

## Authorization contract

| Layer | Required binding |
| --- | --- |
| Active governance | Exact retained `active_governance_sha256`, valid root signature, authorities, threshold, and issue time |
| Successor governance | Same base policy, policy ID, registry ID, and root; exact current generation and semantic registry digest; changed authorities or threshold |
| Rotation | Exact next generation, prior event digest, old and new governance digests, rotation time, and algorithm |
| Old approvals | Ordered unique identities, distinct policy-matched keys, old threshold, and valid Ed25519 signatures over the rotation payload |
| New approvals | Ordered unique identities, distinct policy-matched keys, new threshold, and valid Ed25519 signatures over the same payload |
| Result | Preserve root, organizations, and admissions; retain the successor digest; advance generation, history digest, and time once |

The root authenticates the successor policy. It cannot activate that policy
without both governance quorums.

## Selected-ledger architecture

| Stage | Fresh check |
| --- | --- |
| Genesis | Match the independently configured semantic digest and immutable base policy |
| Event selection | Require exactly one legacy transition, root rotation, threshold transition, or governance rotation at each generation |
| Root history | Verify legacy signatures, successor possession, dual signatures, and historical root-key uniqueness |
| Governance history | Verify every embedded root signature, digest, threshold, ordered authority set, and active-governance handoff |
| Rotation | Verify current-state successor binding, semantic change, timestamps, both approval sets, generation, and prior digest |
| Observer replay | Rebuild the exact latest v1.492 trust report from selected-ledger observer rotations |
| Role separation | Reject every historical or active governance/root key reused in observer trust history |
| Eligibility | Require every selected quorum member to remain active and exactly admitted |
| Retention | Commit a met-quorum report without replacement; keep below-threshold evidence output-only |

The v1.495 threshold-governance verifier rejects a governance-rotation event.
Use the governance-rotation-aware verifier after the first rotation.

## Retry and conflict behavior

An exact retry of the latest rotation returns the same current registry bytes.
Once a later event exists, the older rotation is stale.

All four mutation types lock the descriptor-pinned manifest and probe one shared
generation namespace. A competing filename at the same generation fails, a gap
fails, and a different artifact cannot replace the winning bytes.

Verification reloads registry and observer history around report publication.
Concurrent mutation, observer rotation, input replacement, or report conflict
prevents output publication.

## Schemas and limits

| Artifact | Maximum | Discovery command |
| --- | ---: | --- |
| Registry state | 256 KiB | `factory-release-state-transparency-external-gossip-organization-registry-schema` |
| Root-signed governance | 32 KiB | `signed-factory-release-state-transparency-external-gossip-organization-registry-governance-schema` |
| Threshold transition | 128 KiB | `signed-factory-release-state-transparency-external-gossip-organization-registry-threshold-transition-schema` |
| Governance rotation | 256 KiB | `signed-factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-schema` |
| Governance authorities | 100 per policy | Governance schema |
| Mixed history events | 4,096 | Governance-rotation report schema |
| Governance-rotation report | 128 MiB | `factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-verification-report-schema` |

Every artifact uses canonical pretty JSON with one trailing LF, duplicate-key
rejection, closed objects, bounded arrays, and create-new outputs. Semantic
digests hash normalized compact objects; artifact identities bind exact bytes
and lengths.

## Explicit nonclaims

Two valid quorum sets do not prove two independent groups. The old and new
policies may share identities or keys, and one operator may control several
keys. The report therefore leaves `independent_governance_control_verified`
false.

This contract does not replace the registry root. A governed root rotation must
atomically change the root and active governance under a separate future
contract; root-only rotation remains locked out.

The selected ledger remains locally mutable storage. Host rollback resistance,
trusted time, global non-equivocation, legal identity, capacity, order
placement, payment, and exactly-once execution remain unproved.
