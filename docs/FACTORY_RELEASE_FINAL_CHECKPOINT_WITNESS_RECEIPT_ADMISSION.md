# Verifier-bound Final Checkpoint-witness Receipt Admission

Re-verify every retained public byte before a final-witness receipt enters the
signed approval history.

The v1.520 contract adds one dedicated append command and one task-forbidden
MCP tool. Every v1.512–v1.519 report, log, checkpoint, witness, receipt, event,
and signature format remains unchanged.

> [!IMPORTANT]
> Admission is offline verification, not another network exchange. Retain the
> exact canonical v1.517 response, v1.512 report, complete admission log,
> v1.514 checkpoint, checkpoint key, and selected final-witness trust evidence.

## Key Features

- **Replays the final checkpoint:** Runs the production v1.514 verifier over
  the canonical receipt-quorum report, complete admission log and suffix,
  signed checkpoint, and independently pinned checkpoint key.

- **Reconstructs the request:** Serializes the exact compact v1.517 request
  and requires its SHA-256 to match the receipt.

- **Matches every byte:** Checks raw and semantic report, log, checkpoint,
  request, response, and normalized witness identities.

- **Re-verifies the witness:** Enforces direct-key or current v1.516 trust,
  identity, freshness, signer-role separation, and strict Ed25519 verification.

- **Preserves the event:** Appends the same normalized v1.519 artifact kind,
  checkpoint, request, response, and witness bindings.

- **Publishes safely:** Rejects aliases and existing destinations, then re-reads
  all eight inputs by identity, byte count, and SHA-256 before publication.

## Quick Start

Use a directly pinned final-witness key:

```sh
pcbex append-verified-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-receipt \
  final-receipts.log.0.json \
  --receipt final-witness-a.receipt.json \
  --quorum-report checkpoint-witness-receipts.quorum.json \
  --approval-log checkpoint-witness-receipts.log.json \
  --checkpoint checkpoint-witness-receipts.checkpoint.json \
  --checkpoint-public-key final-checkpoint.public.hex \
  --response final-witness-a.json \
  --witness-public-key final-witness-a.public.hex \
  --evaluated-at-unix 1788220800 \
  --recorded-at-unix 1788220800 \
  --output final-receipts.log.1.json
```

Or bind admission to the current rotated trust state:

```sh
pcbex append-verified-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-receipt \
  final-receipts.log.0.json \
  --receipt final-witness-a.receipt.json \
  --quorum-report checkpoint-witness-receipts.quorum.json \
  --approval-log checkpoint-witness-receipts.log.json \
  --checkpoint checkpoint-witness-receipts.checkpoint.json \
  --checkpoint-public-key final-checkpoint.public.hex \
  --response final-witness-a.json \
  --witness-trust-state final-witness-a.trust.current.json \
  --output final-receipts.log.1.json
```

Exactly one final-witness trust mode is required. If omitted, evaluation and
event times use the local clock.

> [!TIP]
> Pin the v1.514 checkpoint key independently from final-witness trust.
> Admission rejects a witness key that reuses the checkpoint signer's key.

## Verification Flow

```text
v1.512 report + complete admission log + v1.514 checkpoint + checkpoint key
                                      │
                                      ├── production checkpoint verification
                                      ▼
                         reconstructed compact request
                                      │
v1.517 receipt + exact response + direct key/current v1.516 trust state
                                      │
                                      ├── raw and semantic binding checks
                                      ├── freshness + role separation
                                      └── strict Ed25519 verification
                                      ▼
                           unchanged v1.519 event
                                      │
                                      ├── final reread of every input
                                      ▼
                             new no-clobber log snapshot
```

The command does not trust `verified: true`. Every retained input must
independently reproduce the receipt and signed witness.

## Input Contracts

| Input | Limit | Required verification |
| --- | ---: | --- |
| Destination approval log | 128 MiB | Complete existing hash chain |
| v1.517 receipt | 64 KiB | Canonical, closed, duplicate-key-free |
| v1.512 quorum report | 128 KiB | Canonical, met quorum, exact log binding |
| Complete checkpoint-witness receipt admission log | 128 MiB | Exact ID, count, head, digest, and suffix |
| v1.514 dedicated checkpoint | 64 KiB | Final-checkpoint domain signature and exact report/log binding |
| Checkpoint public-key file | 65 bytes | Non-weak Ed25519 key matching the checkpoint |
| Exact v1.515 witness response | 64 KiB | Canonical signed final witness bytes |
| Direct final-witness key | 65 bytes | Non-weak, receipt-matching, role-separated |
| Final-witness trust state | 32 KiB | Canonical current identity, key, digest, and generation |

The endpoint is validated from the receipt. Admission does not contact it,
read a Bearer credential, or treat TLS as final-witness proof.

## Event Mapping

Successful admission emits the unchanged v1.519 event:

| Event field | Verified receipt binding |
| --- | --- |
| `artifact_kind` | `remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt` |
| `artifact_sha256` | SHA-256 of canonical compact receipt JSON |
| `subject_id` | Final `checkpoint_sha256` |
| `request_sha256` | Reconstructed compact request digest |
| `session_sha256` | Exact raw response digest |
| `signer_id` | `null` |
| `outcome` | `verified-witness:<witness_id>` |

Structural v1.519 append and verifier-bound v1.520 append produce byte-identical
logs when given the same source log, receipt, and event time.

## Filesystem Boundary

The destination is reserved before evidence reads. Each input is a regular,
non-symlink artifact and is checked again immediately before publication.

This detects sequential replacement or mutation. It does not create an atomic
snapshot across several files controlled by the same principal.

## MCP

The MCP tool is named
`append_verified_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt`.
It mirrors every CLI input, rejects unknown properties, requires exactly one
trust mode, creates a new log snapshot, and is forbidden inside MCP Tasks.

## What Passing Admission Proves

A successful append proves that:

- the exact v1.512 report, admission log, suffix, and v1.514 checkpoint pass
  the production verifier;
- the exact report, log, checkpoint, and reconstructed request reproduce the
  receipt;
- the exact response reproduces the signed v1.515 witness and receipt;
- direct or current generation-bound trust matches the witness;
- signature, identity, freshness, and checkpoint-signer role separation pass
  at the independent admission time; and
- the unchanged normalized event entered a new valid log snapshot.

## What It Does Not Prove

This contract does not prove an atomic same-principal filesystem snapshot,
rollback resistance for retained files or logs, trusted local time, endpoint
availability, operator independence, legal identity, remote signature of the
transport receipt, global publication or non-equivocation, ordering, payment,
or exactly-once execution.

The [receipt transparency guide](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_TRANSPARENCY.md)
defines the unchanged event. The
[remote final-witness guide](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_REMOTE_WITNESSES.md)
defines the retained receipt and response contracts.
