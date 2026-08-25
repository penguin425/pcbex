# External-gossip organization registry

Govern which organizations may contribute to a factory-release external-gossip quorum without changing the v1.491 or v1.492 wire contracts.

v1.493 adds an independently pinned, authority-governed registry. It admits an
observer's exact current v1.492 trust state, suspends an organization, or
revokes it permanently through one signed, generation-chained history.

## Key features

- **Pins genesis:** Binds one registry ID, authority key, base-policy digest,
  and policy ID in an empty generation-zero artifact.

- **Admits current trust:** Records the semantic digest of one exact latest
  observer trust state. A later observer rotation requires a new admission.

- **Governs organizations:** Applies explicit `admit-observer`,
  `suspend-organization`, and `revoke-organization` transitions.

- **Separates roles:** Rejects an authority key reused anywhere in the complete
  observer key history.

- **Retains safely:** Publishes each canonical transition without replacement
  in the selected ledger. Identical concurrent writers converge; forks fail.

- **Replays completely:** Embeds genesis, every authority-signed transition,
  the current registry, and the exact v1.492 trust report in one closed report.

- **Invalidates immediately:** Rejects a selected quorum member whose
  organization is suspended, revoked, unadmitted, or bound to stale trust.

> [!IMPORTANT]
> Keep the registry genesis and its semantic SHA-256 outside the selected
> ledger. The ledger stores transition history; it does not choose its own
> trust root.

## Quick start

Select the existing release ledger, immutable v1.491 base policy, and
independently controlled registry authority:

```sh
LEDGER=/absolute/path/to/release-ledger
LEDGER_ID=<64-lowercase-hex>
BASE_POLICY=external-observers.base.json
BASE_SHA256=<semantic-sha256-of-base-policy>
AUTHORITY_PUBLIC=registry-authority.public.hex
AUTHORITY_PRIVATE=registry-authority.private.hex
```

Create and pin the empty registry:

```sh
pcbex init-factory-release-state-transparency-external-gossip-organization-registry \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --registry-id production-observers \
  --authority-public-key "$AUTHORITY_PUBLIC" \
  --output observer-organizations.genesis.json \
  --digest-output observer-organizations.genesis.sha256

REGISTRY_SHA256=$(tr -d '\r\n' < observer-organizations.genesis.sha256)
```

Export the current registry before signing:

```sh
pcbex export-factory-release-state-transparency-external-gossip-organization-registry \
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --registry-genesis observer-organizations.genesis.json \
  --expected-registry-genesis-sha256 "$REGISTRY_SHA256" \
  --output observer-organizations.current.json
```

Export the observer trust state from the same selected ledger:

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

Sign one admission. `--reason-sha256` identifies operator-controlled evidence;
the reason document itself stays outside the public transition.

```sh
pcbex sign-factory-release-state-transparency-external-gossip-organization-registry-transition \
  --registry-state observer-organizations.current.json \
  --authority-private-key "$AUTHORITY_PRIVATE" \
  --action admit-observer \
  --organization-id independent-lab \
  --observer-trust-state observer-a.trust.json \
  --reason-sha256 <64-lowercase-hex> \
  --effective-at-unix 1787600000 \
  --output independent-lab.admission.json
```

Apply it through durable no-replace publication:

```sh
pcbex apply-factory-release-state-transparency-external-gossip-organization-registry-transition \
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --registry-genesis observer-organizations.genesis.json \
  --expected-registry-genesis-sha256 "$REGISTRY_SHA256" \
  --transition independent-lab.admission.json \
  --output observer-organizations.next.json
```

After v1.492 retains a trust-bound quorum, require the latest registry:

```sh
pcbex verify-factory-release-state-transparency-external-gossip-quorum-with-organization-registry \
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy "$BASE_POLICY" \
  --expected-base-observer-quorum-policy-sha256 "$BASE_SHA256" \
  --registry-genesis observer-organizations.genesis.json \
  --expected-registry-genesis-sha256 "$REGISTRY_SHA256" \
  --observer-trust-report external-gossip-observer-trust.report.json \
  --output external-gossip-registry.report.json \
  --require-quorum \
  --require-accepted
```

> [!TIP]
> Export both the registry and observer trust state immediately before signing.
> A winning registry transition or observer rotation makes stale admission
> evidence fail instead of silently rebasing it.

## Transition model

| Action | Required observer state | Result |
| --- | --- | --- |
| `admit-observer` | Exact current state for the named base-policy member | Creates an active organization or refreshes one observer admission |
| `suspend-organization` | None | Makes every selected member from that organization ineligible |
| `revoke-organization` | None | Permanently marks the organization ineligible |

An admission cannot reactivate a suspended or revoked organization. A
suspended organization may advance only to revoked; v1.493 intentionally has
no reinstatement action.

Each transition covers the registry and policy identities, both generations,
previous transition digest, action, organization, optional observer and trust
digest, reason digest, explicit time, authority key, and algorithm. The
authority signs that domain-separated payload with Ed25519.

## Verification flow

| Stage | Fresh check |
| --- | --- |
| Genesis | Match the independently configured semantic digest and immutable base policy |
| Registry replay | Verify every signature, generation, previous digest, timestamp, and action |
| Observer replay | Rebuild the complete latest v1.492 trust report from selected-ledger rotations |
| Role separation | Reject authority reuse by any initial, retained, or current observer key |
| Eligibility | Require each selected quorum member's organization to be active and its trust digest admitted |
| Retention | Commit a met-quorum report without replacement; keep below-threshold evidence output-only |

Only organizations represented in the selected quorum must be active. A
suspended organization that contributes no selected member does not invalidate
another organization's quorum.

The report field `selected_ledger_registry_bound_report_committed` remains
`false` because the self-contained evidence is rendered before the optional
ledger commit. Durable presence is a property checked by the CLI, not a claim
that the report can prove about itself.

## Retry and conflict behavior

An exact retry of the latest transition returns the same current registry.
Once a later generation exists, an older transition is stale.

Two writers may apply the same canonical next transition concurrently. Both
succeed only when the retained bytes match exactly. Different transitions for
one generation compete for one deterministic filename and one fails closed.

Verification reloads registry and observer histories around publication. A
concurrent registry transition, observer rotation, input mutation, or durable
evidence conflict prevents output publication.

## Schemas and limits

| Artifact | Maximum | Discovery command |
| --- | ---: | --- |
| Registry state | 256 KiB | `factory-release-state-transparency-external-gossip-organization-registry-schema` |
| Signed transition | 16 KiB | `signed-factory-release-state-transparency-external-gossip-organization-registry-transition-schema` |
| Registry generations | 4,096 | Registry and transition schemas |
| Organizations and admissions | Existing v1.491 maximum of 100 | Registry schema |
| Registry-bound report | 128 MiB | `factory-release-state-transparency-external-gossip-organization-registry-verification-report-schema` |

Every artifact uses canonical pretty JSON with one trailing LF, duplicate-key
rejection, closed objects, bounded arrays, and create-new outputs. Semantic
digests hash normalized compact objects; exact artifact identities separately
bind bytes and byte counts.

## Explicit nonclaims

This boundary proves the latest registry and observer histories visible in one
selected trusted ledger. It does not prove that the host cannot restore an
older ledger snapshot or withhold another valid authority-signed branch.

The explicit timestamp is ordered but not trusted. The registry also does not
establish global non-equivocation, real organizational independence, key
custody, legal identity, endpoint identity, factory capacity, order authority,
payment, or exactly-once execution.

Authority key rotation and threshold governance are separate future trust
boundaries. v1.493 pins one authority key for the lifetime of this registry.
