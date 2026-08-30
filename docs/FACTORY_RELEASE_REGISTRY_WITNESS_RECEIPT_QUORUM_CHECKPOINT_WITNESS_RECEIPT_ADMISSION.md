# Verifier-bound Factory Checkpoint-witness Receipt Admission

Re-verify every retained public byte before a remote checkpoint-witness
receipt enters the signed approval history.

The v1.511 contract adds one dedicated append command and one task-forbidden
MCP tool. Every v1.504–v1.510 report, log, checkpoint, witness, receipt, event,
and signature format remains unchanged.

> [!IMPORTANT]
> Admission is local verification, not a second network exchange. Retain the
> exact canonical v1.509 response bytes, quorum report, complete approval log,
> dedicated checkpoint, checkpoint key, and selected witness trust evidence.

## Key Features

- **Replays public evidence:** Runs the production dedicated-checkpoint
  verifier over the canonical quorum report, complete approval log, signed
  checkpoint, and independently pinned checkpoint key.

- **Reconstructs the request:** Serializes the exact compact v1.509 request and
  requires its SHA-256 to match the receipt.

- **Matches raw bytes:** Checks the report, log, checkpoint, request, response,
  and normalized witness digests plus the exact response length.

- **Re-verifies the witness:** Requires the receipt's direct-key or current
  generation-bound trust mode, identity, freshness, role separation, and strict
  Ed25519 signature.

- **Preserves the event:** Appends the same normalized v1.510 artifact kind,
  checkpoint, request, response, and witness bindings.

- **Publishes safely:** Rejects output aliases and existing destinations, then
  re-reads every input by identity, byte count, and SHA-256 before publication.

## Quick Start

Use a directly pinned witness key:

```sh
pcbex append-verified-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt \
  checkpoint-witness-receipts.log.0.json \
  --receipt factory-receipt-quorum.witness-a.receipt.json \
  --quorum-report factory-receipts.quorum.json \
  --approval-log factory-receipts.log.json \
  --checkpoint factory-receipts.checkpoint.json \
  --checkpoint-public-key checkpoint.public.hex \
  --response factory-receipt-quorum.witness-a.json \
  --witness-public-key witness-a.public.hex \
  --evaluated-at-unix 1788134400 \
  --recorded-at-unix 1788134400 \
  --output checkpoint-witness-receipts.log.1.json
```

Or bind admission to the current rotatable witness trust state:

```sh
pcbex append-verified-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt \
  checkpoint-witness-receipts.log.0.json \
  --receipt factory-receipt-quorum.witness-a.receipt.json \
  --quorum-report factory-receipts.quorum.json \
  --approval-log factory-receipts.log.json \
  --checkpoint factory-receipts.checkpoint.json \
  --checkpoint-public-key checkpoint.public.hex \
  --response factory-receipt-quorum.witness-a.json \
  --witness-trust-state witness-a.trust.current.json \
  --output checkpoint-witness-receipts.log.1.json
```

Exactly one witness trust mode is required. When omitted,
`--evaluated-at-unix` and `--recorded-at-unix` use the local clock.

> [!TIP]
> Pin the checkpoint key independently from witness trust. Admission rejects a
> witness key that reuses the dedicated checkpoint signer's key.

## Verification Flow

```text
quorum report + complete approval log + dedicated checkpoint + checkpoint key
                                  │
                                  ├── production v1.506 verification
                                  ▼
                     reconstructed compact request
                                  │
v1.509 receipt + exact response + direct key/current trust state
                                  │
                                  ├── raw and semantic binding checks
                                  ├── freshness + role separation
                                  └── strict Ed25519 verification
                                  ▼
                       unchanged v1.510 event
                                  │
                                  ├── final reread of every input
                                  ▼
                         new no-clobber log snapshot
```

The command does not trust `verified: true` alone. That field must be valid,
and every retained input must independently reproduce the receipt.

## Input Contracts

| Input | Limit | Required verification |
| --- | ---: | --- |
| Destination approval log | 128 MiB | Complete existing hash chain |
| v1.509 receipt | 64 KiB | Canonical, closed, duplicate-key-free |
| v1.504 quorum report | 128 KiB | Canonical, met quorum, exact log binding |
| Complete factory receipt approval log | 128 MiB | Exact ID, count, head, digest, and suffix |
| v1.506 dedicated checkpoint | 64 KiB | Factory-domain signature and exact report/log binding |
| Checkpoint public-key file | 65 bytes | Non-weak Ed25519 key matching the checkpoint |
| Exact v1.507 witness response | 64 KiB | Canonical signed witness bytes |
| Direct witness key | 65 bytes | Non-weak, receipt-matching, role-separated |
| Witness trust state | 32 KiB | Canonical current identity, key, digest, and generation |

The retained endpoint is structurally validated from the receipt. Admission
does not contact it, read a Bearer credential, or treat TLS as witness proof.

## Event Mapping

Successful admission emits the unchanged v1.510 event:

| Event field | Verified receipt binding |
| --- | --- |
| `artifact_kind` | `remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt` |
| `artifact_sha256` | SHA-256 of canonical compact receipt JSON |
| `subject_id` | Dedicated `checkpoint_sha256` |
| `request_sha256` | Reconstructed compact request digest |
| `session_sha256` | Exact raw response digest |
| `signer_id` | `null` |
| `outcome` | `verified-witness:<witness_id>` |

The structural v1.510 append and verifier-bound v1.511 append therefore produce
the same bytes when they receive the same log, receipt, and event time.

## Filesystem Boundary

The destination is prepared before evidence reads. Every input is then read as
a regular, non-symlink artifact and checked again immediately before the new
snapshot is published.

This detects sequential replacement or mutation. It does not provide one
atomic filesystem snapshot across multiple files controlled by the same
principal; place retained evidence in protected immutable storage when that
threat matters.

## MCP

The MCP tool is named
`append_verified_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt`.
It mirrors every CLI input, rejects unknown properties, requires exactly one
witness trust mode, is destructive because it creates a log snapshot, and is
forbidden inside MCP Tasks.

## What Passing Admission Proves

A successful append proves that:

- the exact v1.504 report and complete approval log pass the production
  dedicated-checkpoint verification path;
- the exact report, log, checkpoint, and request bytes reproduce the receipt;
- the exact retained response reproduces the signed witness and receipt;
- the selected direct key or current trust state matches the receipt;
- the witness signature, identity, freshness, and checkpoint-signer role
  separation pass at the independent admission time;
- the unchanged normalized event entered one new internally valid log snapshot.

## What It Does Not Prove

This contract does not prove:

- an atomic snapshot across same-principal input files;
- rollback resistance for retained files, trust state, or the destination log;
- that local evaluation or event time comes from a trusted clock;
- endpoint availability, operator independence, or legal identity;
- that the local transport receipt was remotely signed or globally published;
- global non-equivocation, ordering, payment, or exactly-once execution.

Version 1.512 is the planned next boundary: atomic verifier-bound admission of
a distinct checkpoint-witness receipt quorum.
