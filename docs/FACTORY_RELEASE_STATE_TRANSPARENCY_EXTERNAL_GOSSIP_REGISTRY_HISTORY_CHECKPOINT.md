# Witnessed Factory-release Registry History Checkpoints

Pin one audited registry head. Detect rollback and equivocation across retained
consumers.

The v1.499 contract signs the exact output of the portable v1.498 history
audit with the registry root retained at that final generation. Consumers keep
an immutable trust state, while independent witnesses endorse the same exact
checkpoint under distinct Ed25519 keys.

> [!IMPORTANT]
> A checkpoint protects only consumers that retain and supply their previous
> trust state. It does not make the host filesystem append-only or prove global
> non-equivocation when independent consumers never compare observations.

## Key features

- **Replays before signing:** Audits the complete typed history from exact empty
  genesis before the retained root can sign its head.
- **Binds the full result:** Covers the audit SHA-256, final registry SHA-256,
  generation, final transition, active governance, current root, and issue
  time.
- **Pins monotonic trust:** Rejects generation rollback, same-generation
  equivocation, time reversal, and a later history that omits or changes the
  previously accepted prefix.
- **Requires fresh witnesses:** Verifies a configurable threshold of 2–100
  distinct identities and keys over one exact checkpoint.
- **Separates key roles:** Rejects checkpoint-witness keys reused by any current
  or historical registry root or embedded governance authority.
- **Retains negative evidence:** Writes a valid below-threshold quorum report
  before `--require-quorum` returns nonzero.

## Quick start

Start with the canonical portable history produced by the
[v1.498 history exporter](FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_HISTORY_AUDIT.md).

### 1. Sign the audited head

Use the private key for the root retained at the history's final generation.
An old root fails after either a legacy or governed root rotation.

```bash
pcbex sign-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint \
  --history registry.history.json \
  --authority-private-key current-root.secret.hex \
  --issued-at-unix 1787702400 \
  --output registry.history.checkpoint.json
```

The command revalidates the history immediately before no-clobber publication.
Private-key bytes never enter the checkpoint.

### 2. Accept and retain monotonic trust

Accept the first checkpoint without a baseline:

```bash
pcbex accept-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint \
  --history registry.history.json \
  --checkpoint registry.history.checkpoint.json \
  --accepted-at-unix 1787702460 \
  --output registry.history.checkpoint-trust.json
```

For every later generation, supply the previously retained trust state:

```bash
pcbex accept-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint \
  --history registry.history.next.json \
  --checkpoint registry.history.next.checkpoint.json \
  --baseline registry.history.checkpoint-trust.json \
  --accepted-at-unix 1787706060 \
  --output registry.history.next.checkpoint-trust.json
```

Exact same-checkpoint retry returns the retained trust-state bytes. A different
checkpoint at the same generation fails as equivocation.

> [!TIP]
> Store accepted trust states in deployment-owned, rollback-resistant storage.
> Copying the newest file over an unprotected path does not preserve the
> monotonic guarantee.

### 3. Create independent witnesses

Each witness independently receives both the complete history and checkpoint.
It replays the history before signing.

```bash
pcbex sign-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness \
  --history registry.history.json \
  --checkpoint registry.history.checkpoint.json \
  --witness-id witness-a \
  --witness-private-key witness-a.secret.hex \
  --witnessed-at-unix 1787702500 \
  --output registry.history.witness-a.json
```

Repeat with a different identity and key for `witness-b`.

### 4. Verify the witness quorum

Trusted identities and public-key files pair by position. Witness artifact
order does not affect the canonical member order.

```bash
pcbex verify-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witnesses \
  --history registry.history.json \
  --checkpoint registry.history.checkpoint.json \
  --witness registry.history.witness-b.json \
  --witness registry.history.witness-a.json \
  --trusted-witness-id witness-b \
  --trusted-witness-id witness-a \
  --trusted-witness-public-key witness-b.public.hex \
  --trusted-witness-public-key witness-a.public.hex \
  --minimum-witnesses 2 \
  --evaluated-at-unix 1787702600 \
  --require-quorum \
  --output registry.history.witness-quorum.json
```

## Verification flow

```text
portable v1.498 history
          │
          ├── replay all five event kinds ──▶ computed final registry
          │                                      │
          │                                      ▼
          └──────────────────────────────▶ retained-root checkpoint
                                                 │
                           ┌─────────────────────┼─────────────────────┐
                           ▼                     ▼                     ▼
                     local trust state      witness A             witness B
                           │                     │                     │
                           └──────────── exact checkpoint quorum ──────┘
```

Every signing and verification path calls the production history auditor. No
operation trusts a copied final registry or a caller-supplied audit result.

## Contracts and limits

| Artifact | Bound | Critical fields |
| --- | ---: | --- |
| Signed checkpoint | 32 KiB | Registry, generation, audit/final-state digests, final transition, governance, root, issue time, signature |
| Accepted trust state | 64 KiB | Exact checkpoint plus accepted generation and acceptance time |
| Signed witness | 32 KiB | Exact checkpoint SHA-256, witness identity/key, witness time, signature |
| Witness-quorum report | 128 KiB | Checkpoint and audit digests, evaluation time, threshold, sorted members, decision |
| Witness/trust sets | 100 entries | Distinct identities and distinct non-weak Ed25519 keys |
| Acceptance delay | 24 hours | `accepted_at_unix - issued_at_unix` |
| Witness freshness | 24 hours | `evaluated_at_unix - witnessed_at_unix` |

All four documents use canonical pretty JSON with one trailing LF. Parsers
reject duplicate keys, unknown fields, non-canonical formatting, weak keys,
invalid self-signatures, oversized inputs, and generation values above 4,096.

## Schemas and validators

Print the recursively closed schemas:

```bash
pcbex signed-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-schema
pcbex factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-trust-state-schema
pcbex signed-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-schema
pcbex factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-quorum-schema
```

Each schema has a matching `validate-...` command. Validators authenticate the
self-contained checkpoint or witness signature and preserve canonical bytes.
The quorum-report validator checks structure and invariants; use the full
`verify-...-witnesses` command to replay its underlying evidence.

## What a passing result proves

A passing accepted checkpoint proves that:

- the supplied history replays from exact empty genesis through the production
  verifier;
- the checkpoint binds that exact audit and computed final registry;
- the signer controls the root retained at the final generation;
- when a baseline is supplied, the new history contains its exact previously
  accepted generation and state;
- a passing quorum report contains fresh signatures from enough distinct,
  configured, role-disjoint witness keys over one exact checkpoint.

## What it does not prove

The contract does not prove:

- rollback resistance when the consumer loses or replaces its baseline;
- global non-equivocation among consumers that never exchange checkpoints;
- trusted wall-clock time or secure private-key custody;
- that configured keys belong to independent people or legal organizations;
- factory identity, capacity, order placement, payment, or exactly-once
  execution.

Version 1.500 adds generation-chained checkpoint-witness key rotation. Until
then, changing a trusted witness key requires an out-of-band trust update.
