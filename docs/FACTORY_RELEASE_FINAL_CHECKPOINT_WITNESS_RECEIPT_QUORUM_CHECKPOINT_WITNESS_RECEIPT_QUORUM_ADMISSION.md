# Final Receipt-quorum Checkpoint-witness Receipt Quorum Admission

Re-verify a distinct v1.526 receipt set. Publish one exact v1.528 event suffix.

The v1.530 contract extends verifier-bound v1.529 admission from one receipt to
a bounded quorum. Every v1.521–v1.529 wire artifact and command remains
unchanged.

> [!IMPORTANT]
> This boundary performs offline admission, not remote acquisition. Retain the
> exact v1.521 report and complete log, v1.523 checkpoint and pinned key, every
> v1.524 response, every v1.526 receipt, and the selected trust evidence.

## Key Features

- **Verifies shared evidence once:** Runs the production v1.523 verifier over
  one canonical v1.521 report, its complete final admission log and suffix, the
  signed checkpoint, and an independently pinned checkpoint key.

- **Reconstructs every request:** Recreates each identity- and key-specific
  compact v1.526 request. Request digests must be valid and distinct.

- **Checks every member:** Matches each receipt to its exact v1.524 response,
  witness, key, trust generation, source evidence, and independent admission
  time.

- **Reuses production quorum rules:** Invokes the v1.524 witness-quorum verifier
  once for strict Ed25519 signatures, 24-hour freshness, signer-role
  separation, and distinct witness identities and keys.

- **Rejects evidence reuse:** Refuses duplicate receipt, request, response, and
  witness digests, even when the requested threshold would otherwise pass.

- **Produces canonical order:** Sorts successful members by witness ID before
  appending the unchanged v1.528 event for each receipt.

- **Binds both outputs:** Emits one closed 128 KiB report that commits to the
  complete resulting log and its exact sorted suffix.

- **Publishes without overwrite:** Rejects aliases and existing destinations,
  re-reads every input, and attempts to remove an earlier output if later
  publication fails.

## Quick Start

Use directly pinned witness keys:

```sh
pcbex append-verified-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-receipt-quorum \
  final-checkpoint-witness-receipts.log.0.json \
  --receipt witness-a.receipt.json \
  --receipt witness-b.receipt.json \
  --quorum-report final-receipts.quorum.json \
  --approval-log final-receipts.log.json \
  --checkpoint final-receipts.quorum.checkpoint.json \
  --checkpoint-public-key final-receipts.quorum.checkpoint.public.hex \
  --response witness-a.response.json \
  --response witness-b.response.json \
  --trusted-witness-id witness-a \
  --trusted-witness-public-key witness-a.public.hex \
  --trusted-witness-id witness-b \
  --trusted-witness-public-key witness-b.public.hex \
  --minimum-witnesses 2 \
  --evaluated-at-unix 1788480000 \
  --recorded-at-unix 1788480000 \
  --output final-checkpoint-witness-receipts.log.1.json \
  --report-output final-checkpoint-witness-receipts.quorum.json
```

Or use current v1.525 trust states:

```sh
pcbex append-verified-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-receipt-quorum \
  final-checkpoint-witness-receipts.log.0.json \
  --receipt witness-a.receipt.json \
  --receipt witness-b.receipt.json \
  --quorum-report final-receipts.quorum.json \
  --approval-log final-receipts.log.json \
  --checkpoint final-receipts.quorum.checkpoint.json \
  --checkpoint-public-key final-receipts.quorum.checkpoint.public.hex \
  --response witness-a.response.json \
  --response witness-b.response.json \
  --witness-trust-state witness-a.trust.current.json \
  --witness-trust-state witness-b.trust.current.json \
  --minimum-witnesses 2 \
  --output final-checkpoint-witness-receipts.log.1.json \
  --report-output final-checkpoint-witness-receipts.quorum.json
```

Receipt and response arguments pair by position. Direct IDs and keys pair with
each other; both trust modes resolve receipts by witness ID.

> [!TIP]
> Pass members in any order. pcbex sorts verified receipts by witness ID, so
> equivalent evidence and event times produce byte-identical outputs.

## Verification Flow

```text
v1.521 report + complete final log + v1.523 checkpoint + pinned key
                                  │
                                  └── production checkpoint verification × 1
                                                        │
       identity/key/trust-specific compact request[i] ──┤
                                                        ▼
              v1.526 receipt[i] + exact v1.524 response[i]
                                  │
                                  ├── raw + semantic binding for every member
                                  └── canonical signed witnesses
                                                        │
                                                        ▼
                         production witness quorum × 1
                                  │
                                  ├── distinct IDs, keys, and digests
                                  ├── sort by witness ID
                                  └── unchanged v1.528 event suffix
                                                        │
                                                        ▼
                    no-clobber log + closed bound report
```

The command never trusts `verified: true` by itself. Every retained byte must
reproduce the receipt and signed witness decision.

## Input Contract

| Input | Count | Limit | Verification |
| --- | ---: | ---: | --- |
| Destination approval log | 1 | 128 MiB | Complete existing hash chain |
| Canonical v1.526 receipts | 1–100 | 64 KiB each | Closed, canonical, complete trust binding |
| Canonical v1.521 quorum report | 1 | 128 KiB | Met threshold and exact final-log binding |
| Complete final admission log | 1 | 128 MiB | Exact ID, count, head, digest, and sorted suffix |
| Signed v1.523 checkpoint | 1 | 64 KiB | Dedicated-domain signature and exact evidence binding |
| Checkpoint public key | 1 | 65 bytes | Independently pinned, non-weak Ed25519 key |
| Exact v1.524 responses | 1–100 | 64 KiB each | Positionally paired with receipts |
| Direct witness ID/key pairs | 1–100 | 65-byte keys | All-direct mode only |
| Current v1.525 trust states | 1–100 | 32 KiB each | All-trust-state mode only |
| Minimum witnesses | 1 | 2–100 | Must be met before publication |

Exactly one trust mode applies to the entire set. Mixing direct keys and trust
states fails before output publication.

## Output Report

Inspect or normalize the closed report:

```sh
pcbex remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-receipt-quorum-report-schema

pcbex validate-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-receipt-quorum-report \
  final-checkpoint-witness-receipts.quorum.json
```

The report binds the shared report/log/checkpoint source digests, checkpoint
key, evaluation time, threshold, sorted members, and quorum result. A published
report also binds these destination fields:

| Field | Meaning |
| --- | --- |
| `final_checkpoint_witness_receipt_admission_log_id` | Complete destination log identity |
| `final_checkpoint_witness_receipt_admission_log_entry_count` | Complete destination entry count |
| `final_checkpoint_witness_receipt_admission_log_head_sha256` | Final hash-chain head |
| `final_checkpoint_witness_receipt_admission_log_sha256` | Canonical complete-log digest |

Each member records the verified identity and key, optional trust-state digest
and generation, normalized receipt digest, distinct request digest, exact
response digest, signed witness digest, and witnessed time.

## Exact Event Suffix

Every member emits the unchanged v1.528 mapping:

| Event field | Value |
| --- | --- |
| `artifact_kind` | `remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt` |
| `artifact_sha256` | Member `receipt_sha256` |
| `subject_id` | Shared `checkpoint_sha256` |
| `request_sha256` | Member request digest |
| `session_sha256` | Member response digest |
| `signer_id` | `null` |
| `outcome` | `verified-witness:<witness_id>` |

The validator requires these events to form the exact final suffix in sorted
member order. Extension, substitution, reordering, or kind confusion fails.

## Filesystem Boundary

Both output paths must be new, distinct, and non-aliased with every input. The
command prepares both destinations, verifies the complete evidence, re-reads
every input by identity, size, and SHA-256, then publishes both files.

This detects sequential replacement. Cleanup after a later publication failure
is best effort; the command does not create one atomic snapshot across
same-principal files or a globally atomic two-file commit.

## MCP

The task-forbidden destructive tool is named
`append_verified_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum`.
It mirrors the CLI, rejects unknown properties, enforces one trust mode, and
returns both retained JSON documents after successful execution.

## What Passing Proves

A successful quorum admission proves that:

- the exact v1.521 report/log and v1.523 checkpoint pass production
  verification;
- every identity-specific request, receipt, exact response, and trust binding
  agrees;
- every witness signature, identity, key role, and 24-hour freshness check
  passes at the independent admission time;
- witness IDs, keys, receipt, request, response, and witness digests are
  distinct; and
- the sorted unchanged event suffix matches the bound complete log exactly.

## What It Does Not Prove

This boundary does not prove protected state or keys, trusted time, atomic
same-principal snapshots, endpoint availability or legal identity, receipt
authenticity independent of replayed evidence, operator independence, global
publication or non-equivocation, ordering, payment, or exactly-once execution.

Use [single-receipt admission](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_ADMISSION.md)
when policy requires one witness. Use [parallel acquisition](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_QUORUM_ACQUISITION.md)
to collect v1.526 receipts before admission.
