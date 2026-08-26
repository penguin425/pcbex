# Portable Factory-release Registry History Audit

Replay the complete external-gossip organization registry anywhere—without
trusting a copied final snapshot.

The v1.498 contract packages an exact generation-zero registry and every
selected ledger event into one bounded, typed history. An independent auditor
replays the same production transition and rotation verifiers, then computes
the final registry from that evidence alone.

> [!IMPORTANT]
> A valid history proves that the supplied events form one authentic chain. It
> does not prove that the chain is the latest head selected by another host.

## Key features

- **Preserves exact evidence:** Records the byte length and SHA-256 of the
  canonical genesis and every event artifact.
- **Replays five event kinds:** Applies organization transitions, root-key
  rotations, threshold transitions, governance rotations, and governed root
  rotations through the production verifiers.
- **Starts from genesis:** Rejects non-empty, non-zero, or otherwise altered
  initial registry state.
- **Audits every generation:** Emits the event index, kind, generations, exact
  artifact identity, semantic event digest, resulting registry digest, current
  root, and active governance digest.
- **Computes the result:** Produces the final registry from replay instead of
  accepting a caller-supplied snapshot.
- **Fails atomically:** Refuses aliases and existing destinations, revalidates
  the input before publication, and never leaves only one audit output behind.

## Quick start

Export the selected Unix ledger into a portable history. Pin the ledger,
immutable base policy, and exact generation-zero registry independently.

```bash
pcbex export-factory-release-state-transparency-external-gossip-organization-registry-history \
  --reservation-ledger /srv/pcbex/release-ledger \
  --expected-ledger-id "$LEDGER_ID" \
  --base-observer-quorum-policy base-observer-policy.json \
  --expected-base-observer-quorum-policy-sha256 "$BASE_POLICY_SHA256" \
  --registry-genesis registry.genesis.json \
  --expected-registry-genesis-sha256 "$REGISTRY_GENESIS_SHA256" \
  --output registry.history.json
```

Move only the history to the audit environment. Replay it on any supported
platform and retain both outputs.

```bash
pcbex audit-factory-release-state-transparency-external-gossip-organization-registry-history \
  --history registry.history.json \
  --output registry.history-audit.json \
  --final-registry-output registry.history-final.json
```

The audit command creates both files as one no-clobber file set. If validation,
replay, source revalidation, or publication fails, neither output remains.

## Validate artifacts

Normalize and validate a history before transfer:

```bash
pcbex validate-factory-release-state-transparency-external-gossip-organization-registry-history \
  registry.history.json \
  --output registry.history.normalized.json
```

Validate a retained audit report independently:

```bash
pcbex validate-factory-release-state-transparency-external-gossip-organization-registry-history-audit \
  registry.history-audit.json \
  --output registry.history-audit.normalized.json
```

Both validators require canonical pretty JSON with one trailing LF. Unknown
fields, duplicate JSON keys, non-canonical formatting, and inconsistent report
state fail closed.

## Event model

| Event kind | Evidence | Replay rule |
| --- | --- | --- |
| `organization_transition` | Root-signed admission, suspension, or revocation | Applies only before threshold governance activates |
| `authority_key_rotation` | Old/new root dual-signed rotation | Preserves membership and rejects historical root reuse |
| `threshold_transition` | Governance document plus ordered threshold approvals | Pins or uses active governance and locks out root-only mutation |
| `governance_rotation` | Retained/successor governance and both approval sets | Replaces governance while preserving the registry root |
| `governed_authority_key_rotation` | Retained/successor governance, both quorums, and prospective-root possession | Replaces the root and active governance atomically |

Each event carries an `artifact` object for its standalone canonical bytes. The
audit also records `event_sha256`, the semantic digest used by the registry
generation chain.

```text
exact empty genesis
        │
        ▼
typed event 0 ──verify/apply──▶ generation 1
        │
        ▼
typed event n ──verify/apply──▶ generation n + 1
        │
        ├──▶ per-event audit entry
        └──▶ computed final registry
```

## Output contracts

| Artifact | Contents | Maximum |
| --- | --- | ---: |
| Portable history | Exact genesis identity, genesis registry, and typed events | 128 MiB |
| History audit | Genesis identity, one entry per event, computed final registry, and `chain_valid` | 128 MiB |
| Event stream | Contiguous generations starting at zero | 4,096 events |
| Registry artifact | Canonical organization registry state | 256 KiB |

Print the recursively closed JSON Schemas with:

```bash
pcbex factory-release-state-transparency-external-gossip-organization-registry-history-schema
pcbex factory-release-state-transparency-external-gossip-organization-registry-history-audit-schema
```

All arrays are bounded. Every schema object rejects additional properties.

## What the audit proves

A passing audit proves that:

- the supplied initial artifact is the exact canonical empty generation-zero
  registry;
- every supplied event has the declared exact byte identity;
- generations, previous-event digests, and timestamps form one contiguous
  chain;
- required root signatures, dual signatures, governance signatures, and
  threshold approvals verify;
- historical root keys remain unique and root/governance roles stay separate;
- the reported final registry is the deterministic replay result.

## What it does not prove

The portable history does not establish:

- that the supplied final generation is the selected ledger's latest head;
- rollback resistance for the host ledger or exported file;
- global non-equivocation across independently supplied histories;
- trusted time, real organizational independence, or independent key custody;
- factory or legal identity, capacity, order placement, payment, or exactly-once
  execution.

> [!TIP]
> Pin the exported history digest in deployment-owned configuration. Use the
> next checkpoint and witness layers when you need rollback or equivocation
> detection across hosts.
