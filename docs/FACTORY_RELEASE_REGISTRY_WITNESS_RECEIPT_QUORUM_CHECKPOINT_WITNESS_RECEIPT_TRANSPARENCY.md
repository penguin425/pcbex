# Factory Receipt-quorum Checkpoint Witness Receipt Transparency

Publish verified remote checkpoint-witness receipts through a signed,
append-only evidence chain that independent consumers can compare.

The v1.510 contract adds one artifact kind to the existing approval
transparency log. Every v1.504–v1.509 report, log, checkpoint, witness, quorum,
trust-state, rotation, request, and receipt format remains unchanged.

> [!IMPORTANT]
> Append performs strict structural admission. It does not replay the report,
> approval log, dedicated checkpoint, response bytes, witness signature, or
> retained trust state. Admit only receipts produced inside a trusted v1.509
> acquisition boundary.

## Key Features

- **Rejects malformed receipts:** Requires canonical pretty JSON, a closed
  field set, the exact adapter, complete direct-key or trust-state bindings,
  valid bounds and freshness, and `verified: true`.

- **Binds exact transport evidence:** Records the normalized receipt digest
  together with its checkpoint, request, response, and witness identities.

- **Chains every append:** Uses monotonic sequence and event time, predecessor
  digests, and self-digests to expose mutation, deletion, reorder, and replay.

- **Signs one exact head:** Reuses the approval-log Ed25519 checkpoint over the
  log ID, entry count, head digest, complete log digest, and signer identity.

- **Composes with existing controls:** Approval-log anchoring, consistency,
  gossip, witness rotation, and witness quorum work without a new wire format.

- **Publishes safely:** Writes a new no-clobber snapshot. A rejected receipt
  leaves both the source log and destination path untouched.

## Quick Start

Create a dedicated receipt log:

```sh
pcbex init-approval-log \
  --log-id factory-receipt-quorum-checkpoint-witness-receipts \
  --output checkpoint-witness-receipts.log.0.json
```

Append one canonical receipt emitted by the v1.509 remote request command:

```sh
pcbex append-approval-log checkpoint-witness-receipts.log.0.json \
  --artifact factory-receipt-quorum.witness-a.receipt.json \
  --kind remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt \
  --recorded-at-unix 1788134400 \
  --output checkpoint-witness-receipts.log.1.json
```

Sign and verify the exact resulting head:

```sh
pcbex sign-approval-log checkpoint-witness-receipts.log.1.json \
  --private-key receipt-log.secret.hex \
  --signer-id factory-checkpoint-witness-receipt-log \
  --output checkpoint-witness-receipts.checkpoint.json

pcbex verify-approval-log checkpoint-witness-receipts.log.1.json \
  --checkpoint checkpoint-witness-receipts.checkpoint.json \
  --public-key receipt-log.public.hex \
  --output checkpoint-witness-receipts.verification.json
```

> [!TIP]
> Give the transparency-log signer its own deployment-controlled key. Keep
> prior log snapshots and checkpoints in rollback-resistant storage; one valid
> newest file cannot prove that an older accepted head was never replaced.

## Event Mapping

One admitted v1.509 receipt produces one normalized event:

| Event field | Receipt binding |
| --- | --- |
| `artifact_kind` | `remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt` |
| `artifact_sha256` | SHA-256 of canonical compact receipt JSON |
| `subject_id` | `checkpoint_sha256` |
| `request_sha256` | Exact remote request digest |
| `session_sha256` | Exact raw response digest |
| `signer_id` | `null`; this event represents local transport evidence |
| `outcome` | `verified-witness:<witness_id>` |

The checkpoint signer acts as the receipt admission authority. Its signature
protects the resulting history; it does not turn the transport receipt into a
remote witness signature.

## Verification Flow

```text
canonical v1.509 receipt
          │
          ├── closed structural validation
          ▼
normalized receipt event
          │
          ├── sequence + predecessor + self digest
          ▼
new approval-log snapshot
          │
          ├── Ed25519 checkpoint
          ├── external anchor / consistency proof
          └── gossip / independent witness quorum
```

Each layer keeps its own trust boundary. Receipt admission does not bypass
checkpoint-signing, anchor, observer, or witness policy.

## Contracts and Limits

| Input or state | Limit | Enforcement |
| --- | ---: | --- |
| Remote checkpoint-witness receipt | 64 KiB | Canonical, duplicate-key-free, closed v1.509 parser |
| Remote response represented by the receipt | 1 MiB | Bound recorded and enforced during v1.509 acquisition |
| Approval transparency entries | 100,000 | Existing log contract |
| Generic CLI file read | 128 MiB | Regular, non-symlink, identity-checked input |
| Event text | 256 bytes | Existing approval-event validator |

Append rejects a false verification result, malformed endpoint or digest,
weak key, invalid response size, future or stale witness time, and incomplete
direct-key or generation-bound trust evidence. It also rejects compact JSON,
duplicate keys, unknown fields, and non-canonical field formatting.

## What Passing Verification Proves

A passing signed-log verification proves that:

- the supplied log is internally complete and hash-chain consistent;
- one event binds a structurally valid canonical v1.509 receipt;
- the event preserves the receipt's checkpoint, request, response, and witness
  identities;
- the log signer signed the exact log ID, entry count, head, and normalized
  complete-log digest.

## What It Does Not Prove

This contract does not prove that:

- append replayed the v1.504 receipt quorum, complete approval log, dedicated
  checkpoint, exact response, current witness trust, freshness, or signature;
- retained logs, trust states, or keys resist rollback or replacement;
- either recorded timestamp comes from a trusted clock;
- an endpoint or operator has a claimed legal identity or operates
  independently;
- the receipt was remotely signed, globally published, or observed by every
  consumer;
- the system provides global non-equivocation, ordering, payment, or
  exactly-once execution.

Version 1.511 adds a separate
[verifier-bound admission path](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_ADMISSION.md).
Use it when append must replay the retained public evidence and current witness
trust instead of relying on the original v1.509 acquisition boundary. This
structural command remains available when an already trusted operator only
needs to publish the canonical receipt.
