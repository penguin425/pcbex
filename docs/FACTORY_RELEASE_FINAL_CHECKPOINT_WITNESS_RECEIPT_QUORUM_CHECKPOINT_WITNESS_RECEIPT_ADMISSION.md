# Verifier-bound Final Receipt-quorum Checkpoint-witness Receipt Admission

Re-verify every retained public byte before a v1.526 receipt enters the signed
approval history.

The v1.529 contract adds one dedicated CLI command and one task-forbidden MCP
tool. Every v1.521–v1.528 report, log, checkpoint, witness, receipt, event, and
signature format remains byte-compatible.

> [!IMPORTANT]
> Admission is offline verification. It never contacts the witness endpoint or
> reads a Bearer credential. Retain the exact v1.521 report and complete log,
> v1.523 checkpoint and pinned key, v1.524 response, v1.526 receipt, and the
> selected witness trust evidence.

## Key Features

- **Replays the checkpoint:** Runs the production v1.523 verifier over the
  canonical v1.521 quorum report, complete final admission log and suffix,
  signed checkpoint, and independently pinned checkpoint key.

- **Reconstructs the request:** Serializes the exact compact v1.526 request,
  including the expected witness identity and direct or generation-bound key
  trust, then matches its SHA-256.

- **Matches every byte:** Checks the raw and semantic report, log, checkpoint,
  request, response, normalized witness, key, and receipt bindings.

- **Re-verifies freshness:** Applies the production v1.524 signature, identity,
  24-hour age, and checkpoint-signer role-separation checks at an independent
  admission time.

- **Preserves the event:** Emits the same normalized artifact kind and field
  mapping as the v1.528 structural append.

- **Publishes safely:** Reserves one new destination, rejects aliases, and
  re-reads all eight inputs by identity, byte count, and SHA-256 before atomic
  publication.

## Quick Start

Use a directly pinned final-checkpoint witness key:

```sh
pcbex append-verified-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-receipt \
  final-checkpoint-receipts.log.0.json \
  --receipt final-checkpoint.witness-a.receipt.json \
  --quorum-report final-receipts.quorum.json \
  --approval-log final-receipts.log.json \
  --checkpoint final-receipts.quorum.checkpoint.json \
  --checkpoint-public-key final-receipts.quorum.checkpoint.public.hex \
  --response final-checkpoint.witness-a.json \
  --witness-id witness-a \
  --witness-public-key witness-a.public.hex \
  --evaluated-at-unix 1788393600 \
  --recorded-at-unix 1788393600 \
  --output final-checkpoint-receipts.log.1.json
```

Or bind admission to the current rotated trust state:

```sh
pcbex append-verified-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-receipt \
  final-checkpoint-receipts.log.0.json \
  --receipt final-checkpoint.witness-a.receipt.json \
  --quorum-report final-receipts.quorum.json \
  --approval-log final-receipts.log.json \
  --checkpoint final-receipts.quorum.checkpoint.json \
  --checkpoint-public-key final-receipts.quorum.checkpoint.public.hex \
  --response final-checkpoint.witness-a.json \
  --witness-id witness-a \
  --witness-trust-state witness-a.trust.current.json \
  --output final-checkpoint-receipts.log.1.json
```

Exactly one witness trust mode is required. Evaluation and event times default
to the local clock when omitted.

> [!TIP]
> Pin the v1.523 checkpoint key independently from witness trust. Admission
> rejects any witness key that reuses the checkpoint signer's key.

## Verification Flow

```text
v1.521 report + complete final log + v1.523 checkpoint + checkpoint key
                                   │
                                   ├── production checkpoint verification
                                   ▼
                 reconstructed identity-bound compact request
                                   │
v1.526 receipt + exact v1.524 response + direct key/current v1.525 trust
                                   │
                                   ├── raw and semantic binding checks
                                   ├── admission-time freshness
                                   └── strict Ed25519 verification
                                   ▼
                         unchanged v1.528 event
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
| v1.526 receipt | 64 KiB | Canonical, closed, duplicate-key-free |
| v1.521 quorum report | 128 KiB | Canonical, met threshold, exact final-log binding |
| Complete final admission log | 128 MiB | Exact ID, count, head, digest, and sorted suffix |
| v1.523 dedicated checkpoint | 64 KiB | Final receipt-quorum domain signature and exact report/log binding |
| Checkpoint public-key file | 65 bytes | Non-weak Ed25519 key matching the checkpoint |
| Exact v1.524 witness response | 64 KiB | Canonical signed witness bytes |
| Direct witness key | 65 bytes | Non-weak, receipt-matching, role-separated |
| Current witness trust state | 32 KiB | Canonical identity, key, digest, and generation |

The expected `--witness-id` is an independent CLI value. It must match the
request, receipt, response, and any supplied trust state.

## Event Mapping

Successful admission emits the unchanged v1.528 event:

| Event field | Verified receipt binding |
| --- | --- |
| `artifact_kind` | `remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt` |
| `artifact_sha256` | SHA-256 of canonical compact receipt JSON |
| `subject_id` | `checkpoint_sha256` |
| `request_sha256` | Reconstructed compact request digest |
| `session_sha256` | Exact raw response digest |
| `signer_id` | `null` |
| `outcome` | `verified-witness:<witness_id>` |

Structural v1.528 append and verifier-bound v1.529 append produce byte-identical
logs when given the same source log, receipt, and event time.

## Filesystem Boundary

The command reserves the destination before reading evidence. It accepts only
regular, non-symlink inputs and checks each one again immediately before
publication.

This detects sequential replacement or mutation. It does not create an atomic
snapshot across several files controlled by the same principal.

## MCP

The MCP tool is named
`append_verified_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt`.
It mirrors every CLI input, rejects unknown properties, requires exactly one
trust mode, creates a new log snapshot, and is forbidden inside MCP Tasks.

## What Passing Admission Proves

A successful append proves that:

- the exact v1.521 report, final admission log and suffix, and v1.523
  checkpoint pass the production verifier;
- the exact report, log, checkpoint, expected identity, selected trust, and
  reconstructed request reproduce the receipt;
- the exact response reproduces the signed v1.524 witness and receipt;
- direct or current generation-bound v1.525 trust matches the witness;
- signature, identity, 24-hour freshness, and checkpoint-signer role
  separation pass at the independent admission time; and
- the unchanged normalized event entered one new valid log snapshot.

## What It Does Not Prove

This contract does not prove an atomic same-principal filesystem snapshot,
rollback-resistant retained files or logs, trusted local time, endpoint
availability or legal identity, operator independence, remote signing of the
transport receipt, global publication or non-equivocation, ordering, payment,
or exactly-once execution.

The [structural transparency guide](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_TRANSPARENCY.md)
defines the unchanged event. The
[remote witness guide](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_REMOTE_WITNESSES.md)
defines the retained v1.524 response and v1.526 receipt contracts.

Use the [parallel acquisition guide](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_QUORUM_ACQUISITION.md)
to acquire multiple witnesses. It does not replace verifier-bound admission of
an individual receipt into a signed transparency history.
