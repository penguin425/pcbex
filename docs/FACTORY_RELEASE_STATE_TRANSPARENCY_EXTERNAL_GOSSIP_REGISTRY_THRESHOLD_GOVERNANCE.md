# External-gossip registry threshold governance

Replace one privileged registry signer with a root-authorized quorum for every organization decision.

v1.495 activates a fixed governance policy on the first threshold-approved
transition. From that point forward, root-only transitions and root-key
rotations fail closed.

## Key features

- **Requires a real threshold:** Select 2–100 distinct Ed25519 authorities and
  require at least two approvals for every admission, suspension, or revocation.

- **Pins the activation state:** The registry root signs the exact base policy,
  registry identity, generation, semantic state digest, authority set,
  threshold, and issue time.

- **Embeds complete authorization:** Every threshold transition carries the
  root-signed governance document plus ordered, distinct approvals over one
  domain-separated payload.

- **Locks out bypasses:** The first accepted threshold transition stores the
  governance digest in registry state. Legacy root-only mutation and root
  rotation stop immediately.

- **Replays mixed history:** One verifier handles legacy organization
  transitions, dual-signed root rotations, and threshold-approved transitions
  from the independently pinned genesis.

- **Separates key roles:** Governance keys cannot reuse any registry root or
  initial, historical, or current observer key visible in the selected ledger.

- **Converges exactly:** All registry mutations share one pinned-ledger lock and
  no-replace generation namespace. Exact retries converge; competing event
  types cannot both win.

> [!IMPORTANT]
> Treat the registry genesis digest as the trust anchor and the governance
> document as an authorization handoff. Store both outside the ledger you are
> evaluating.

## Quick start

Start from the exact current registry exported from the selected ledger:

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

Root-sign a 2-of-3 policy. Public-key files contain one lowercase hex-encoded
32-byte Ed25519 public key:

```sh
pcbex sign-factory-release-state-transparency-external-gossip-organization-registry-governance \
  --registry-state observer-organizations.current.json \
  --registry-authority-private-key "$ROOT_PRIVATE" \
  --minimum-approvals 2 \
  --authority-id release-admin-a \
  --authority-public-key release-admin-a.public.hex \
  --authority-id release-admin-b \
  --authority-public-key release-admin-b.public.hex \
  --authority-id release-admin-c \
  --authority-public-key release-admin-c.public.hex \
  --issued-at-unix 1787600000 \
  --output registry-governance.json
```

Create one self-contained transition with two approvals:

```sh
pcbex sign-factory-release-state-transparency-external-gossip-organization-registry-threshold-transition \
  --registry-state observer-organizations.current.json \
  --governance registry-governance.json \
  --authority-id release-admin-a \
  --authority-private-key release-admin-a.private.hex \
  --authority-id release-admin-c \
  --authority-private-key release-admin-c.private.hex \
  --action admit-observer \
  --organization-id external-lab-a \
  --observer-trust-state external-lab-a.current-trust.json \
  --reason-sha256 <64-lowercase-hex> \
  --effective-at-unix 1787600100 \
  --output registry-transition.threshold.json
```

Apply the exact next generation:

```sh
pcbex apply-factory-release-state-transparency-external-gossip-organization-registry-threshold-transition \
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --registry-genesis "$REGISTRY_GENESIS" \
  --expected-registry-genesis-sha256 "$REGISTRY_SHA256" \
  --transition registry-transition.threshold.json \
  --output observer-organizations.governed.json
```

Verify the latest retained observer quorum against the complete mixed history:

```sh
pcbex verify-factory-release-state-transparency-external-gossip-quorum-with-organization-registry-threshold-governance \
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --registry-genesis "$REGISTRY_GENESIS" \
  --expected-registry-genesis-sha256 "$REGISTRY_SHA256" \
  --observer-trust-report external-gossip-observer-trust.report.json \
  --output external-gossip-registry-threshold-governance.report.json \
  --require-quorum \
  --require-accepted
```

> [!TIP]
> Export immediately before signing the governance document. Any winning
> registry event changes the activation generation and state digest, making a
> stale policy fail instead of silently rebasing.

## Authorization contract

| Layer | Required binding |
| --- | --- |
| Root authorization | Base-policy digest, policy ID, registry ID, exact activation generation and state digest, retained root key, ordered authorities, threshold, and issue time |
| Transition | Exact next generation, prior event digest, governance digest, action, organization, optional current observer trust digest, reason digest, and effective time |
| Approvals | Ordered unique authority IDs, distinct governance-matched keys, and valid Ed25519 signatures over the same transition payload |
| Activation | First accepted threshold transition stores `active_governance_sha256` in current registry state |
| Continued operation | Every later transition embeds the same governance document and meets the retained threshold |

The root signature authorizes the policy. It does not approve later actions by
itself.

## Selected-ledger architecture

| Stage | Fresh check |
| --- | --- |
| Genesis | Match the independently configured semantic digest and immutable base policy |
| Event selection | Require exactly one legacy transition, root rotation, or threshold transition at each generation |
| Root history | Verify legacy signatures, dual-signed rotations, successor possession, and historical key uniqueness |
| Governance | Verify the retained root signature, activation generation and state digest, unique authority IDs and keys, and threshold bounds |
| Threshold transition | Verify every distinct approval, exact governance digest, action semantics, time, generation, and prior digest |
| Observer replay | Rebuild the exact latest v1.492 trust report from selected-ledger observer rotations |
| Role separation | Reject governance or root keys reused anywhere in observer trust history |
| Eligibility | Require every selected quorum member to remain active and exactly admitted |
| Retention | Commit a met-quorum report without replacement; keep below-threshold evidence output-only |

The v1.493 and v1.494 verifiers reject threshold-governed history. Use the
threshold-aware verifier after activation.

## Retry and conflict behavior

An exact retry of the latest threshold transition returns the same current
registry. Once a later event exists, the older artifact is stale.

Legacy transition, root-rotation, and threshold-transition apply commands lock
the same descriptor-pinned ledger manifest. Each reloads all registry and
observer history before no-replace publication, so one event wins a generation
and every loser leaves no alternate record.

Verification reloads those histories around report publication. Concurrent
registry mutation, observer rotation, input replacement, or report conflict
prevents output publication.

## Schemas and limits

| Artifact | Maximum | Discovery command |
| --- | ---: | --- |
| Registry state | 256 KiB | `factory-release-state-transparency-external-gossip-organization-registry-schema` |
| Root-signed governance | 32 KiB | `signed-factory-release-state-transparency-external-gossip-organization-registry-governance-schema` |
| Threshold-approved transition | 128 KiB | `signed-factory-release-state-transparency-external-gossip-organization-registry-threshold-transition-schema` |
| Governance authorities | 100 | Governance schema |
| Mixed history events | 4,096 | Threshold-governance report schema |
| Threshold-aware report | 128 MiB | `factory-release-state-transparency-external-gossip-organization-registry-threshold-governance-verification-report-schema` |

Every artifact uses canonical pretty JSON with one trailing LF, duplicate-key
rejection, closed objects, bounded arrays, and create-new outputs. Semantic
digests hash normalized compact objects; artifact identities bind exact bytes
and lengths.

## Explicit nonclaims

This boundary proves that the configured keys produced enough valid approvals.
It does not prove that those keys belong to independent people or organizations,
that their custody is sound, or that an operator did not control several keys.

The governance set is fixed after activation. Changing its members, keys, or
threshold requires a future dual-quorum governance-rotation contract; the root
cannot bypass the active policy.

The selected ledger remains locally mutable storage. Host rollback resistance,
trusted time, global non-equivocation, legal identity, capacity, order placement,
payment, and exactly-once execution remain unproved.
