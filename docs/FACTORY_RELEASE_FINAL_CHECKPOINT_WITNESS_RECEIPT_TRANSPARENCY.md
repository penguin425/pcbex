# Final Checkpoint-witness Receipt Transparency

Publish one verified final-witness exchange through the existing signed,
append-only approval transparency chain.

The v1.519 contract adds one artifact kind for the unchanged canonical v1.517
receipt. Every v1.512–v1.518 report, log, checkpoint, witness, quorum, trust,
request, receipt, manifest, and acquisition-report format remains unchanged.

> [!IMPORTANT]
> Append performs strict structural admission. It does not replay the v1.512
> quorum report, admission log, v1.514 checkpoint, exact response, witness
> signature, freshness, or current v1.516 trust state. Admit receipts only from
> a trusted v1.517 or v1.518 acquisition boundary, or use the v1.520
> verifier-bound append when the complete retained evidence is available.

## Key Features

- **Rejects Malformed Receipts:** Requires canonical pretty JSON, the closed
  64 KiB v1.517 contract, exact adapter identity, complete trust bindings,
  bounded internally consistent timestamps, a non-weak witness key, and
  `verified: true`.

- **Binds Exact Transport Evidence:** Records the normalized receipt digest
  together with its final checkpoint, request, response, and witness identities.

- **Chains Every Append:** Reuses monotonic sequence and event time,
  predecessor digests, and entry self-digests.

- **Signs One Exact Head:** Reuses the approval-log Ed25519 checkpoint over the
  log ID, entry count, head, complete normalized digest, and signer identity.

- **Composes with Existing Controls:** Anchoring, consistency proofs, gossip,
  witness rotation, and witness quorum work without a new wire format.

- **Publishes Safely:** Writes one new no-clobber snapshot. Invalid input leaves
  the source log and destination untouched.

## Quick Start

Create a dedicated log:

```sh
pcbex init-approval-log \
  --log-id final-checkpoint-witness-receipts \
  --output final-receipts.log.0.json
```

Append a canonical receipt emitted by the v1.517 remote request command:

```sh
pcbex append-approval-log final-receipts.log.0.json \
  --artifact final-witness-a.receipt.json \
  --kind remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-receipt \
  --recorded-at-unix 1788220800 \
  --output final-receipts.log.1.json
```

Sign and verify the exact new head:

```sh
pcbex sign-approval-log final-receipts.log.1.json \
  --private-key final-receipt-log.secret.hex \
  --signer-id final-checkpoint-witness-receipt-log \
  --output final-receipts.checkpoint.json

pcbex verify-approval-log final-receipts.log.1.json \
  --checkpoint final-receipts.checkpoint.json \
  --public-key final-receipt-log.public.hex \
  --output final-receipts.verification.json
```

> [!TIP]
> Keep prior log snapshots and signed checkpoints in deployment-owned,
> rollback-resistant storage. One valid newest snapshot cannot prove that an
> older accepted head was never replaced.

## Event Mapping

One admitted v1.517 receipt produces one normalized event:

| Event field | Receipt binding |
| --- | --- |
| `artifact_kind` | `remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt` |
| `artifact_sha256` | SHA-256 of canonical compact receipt JSON |
| `subject_id` | `checkpoint_sha256` |
| `request_sha256` | Exact compact remote-request digest |
| `session_sha256` | Exact raw response digest |
| `signer_id` | `null`; the receipt represents local transport evidence |
| `outcome` | `verified-witness:<witness_id>` |

The approval-log checkpoint signer acts as the admission authority. Signing
the log protects the history; it does not turn the local transport receipt into
a remotely signed statement.

## Verification Flow

```text
canonical v1.517 receipt
          │
          ├── closed structural validation
          ▼
normalized final-receipt event
          │
          ├── sequence + predecessor + self digest
          ▼
new approval-log snapshot
          │
          ├── Ed25519 checkpoint
          ├── external anchor / consistency proof
          └── gossip / independent witness quorum
```

Each layer keeps its own authority. Receipt admission does not bypass any
checkpoint signer, anchor, observer, or witness policy.

## Contracts and Limits

| Input or state | Limit | Enforcement |
| --- | ---: | --- |
| Final-witness receipt | 64 KiB | Canonical, duplicate-key-free, closed v1.517 parser |
| Remote response represented by the receipt | 1 MiB | Recorded and enforced during acquisition |
| Approval transparency entries | 100,000 | Existing log contract |
| Generic CLI file read | 128 MiB | Regular, non-symlink, identity-checked input |
| Event text | 256 bytes | Existing approval-event validator |

Append rejects false verification, malformed endpoints or digests, weak keys,
invalid response size, witness times later than evaluation or outside the
receipt age bound, and incomplete generation-bound trust evidence. Compact
JSON, duplicate keys, unknown fields, aliases, and existing destinations also
fail closed.

## Trust Boundary

A passing signed-log verification proves that the supplied log is internally
hash-chain consistent, one event binds a structurally valid canonical v1.517
receipt, and the checkpoint signer signed the exact log state.

It does not prove that append replayed the report, log, checkpoint, response,
signature, freshness, or trust evidence. It does not protect files, states, or
keys; establish trusted time, endpoint or legal identity, independent
operation, global publication, or cross-consumer non-equivocation; place an
order; approve payment; or guarantee exactly-once execution.

The [remote final-witness guide](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_REMOTE_WITNESSES.md)
defines the unchanged receipt. The [parallel acquisition guide](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_QUORUM_ACQUISITION.md)
defines how v1.518 retains multiple successful receipts beside coarse failures.
The [verifier-bound admission guide](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_ADMISSION.md)
replays the complete retained boundary before emitting this same event.
