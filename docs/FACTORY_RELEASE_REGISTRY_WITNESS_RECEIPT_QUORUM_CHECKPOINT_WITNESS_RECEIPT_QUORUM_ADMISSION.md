# Factory Checkpoint-witness Receipt Quorum Admission

Re-verify a distinct witness set. Publish one exact admission suffix.

The v1.512 contract extends verifier-bound v1.511 admission from one receipt to
a bounded quorum. Every v1.504–v1.511 wire format and single-receipt command
remains unchanged.

> [!IMPORTANT]
> This command performs offline admission, not witness acquisition. Retain each
> canonical v1.509 receipt beside its exact v1.507 response and trust evidence.

## Key Features

- **Verifies shared evidence once:** Replays the production v1.506 verifier over
  one exact v1.504 report, complete approval log, dedicated checkpoint, and
  independently pinned checkpoint key.

- **Checks every member:** Reconstructs the shared compact request, binds every
  canonical receipt to its exact raw response, and verifies either all direct
  keys or all current v1.508 trust states.

- **Reuses production quorum rules:** Invokes the v1.507 witness-quorum verifier
  once for strict Ed25519 signatures, 24-hour freshness, signer-role separation,
  and distinct witness identities and keys.

- **Rejects evidence reuse:** Refuses duplicate receipt, response, and witness
  digests, even when the requested threshold would otherwise pass.

- **Produces canonical order:** Sorts verified receipts by witness ID before
  appending the unchanged v1.510 event for each member.

- **Binds both outputs:** Emits a closed canonical report that commits to the
  complete resulting admission log and its exact quorum suffix.

- **Publishes without overwrite:** Rejects aliases and existing destinations,
  then re-reads every input by identity, byte count, and SHA-256 before
  publishing the log and report.

## Quick Start

Use directly pinned witness keys:

```sh
pcbex append-verified-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum \
  checkpoint-witness-receipts.log.0.json \
  --receipt witness-a.receipt.json \
  --receipt witness-b.receipt.json \
  --quorum-report factory-receipts.quorum.json \
  --approval-log factory-receipts.log.json \
  --checkpoint factory-receipts.checkpoint.json \
  --checkpoint-public-key checkpoint.public.hex \
  --response witness-a.response.json \
  --response witness-b.response.json \
  --trusted-witness-id checkpoint-witness-a \
  --trusted-witness-public-key witness-a.public.hex \
  --trusted-witness-id checkpoint-witness-b \
  --trusted-witness-public-key witness-b.public.hex \
  --minimum-witnesses 2 \
  --evaluated-at-unix 1788134400 \
  --recorded-at-unix 1788134400 \
  --output checkpoint-witness-receipts.log.1.json \
  --report-output checkpoint-witness-receipts.quorum.json
```

Or use current generation-bound trust states:

```sh
pcbex append-verified-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum \
  checkpoint-witness-receipts.log.0.json \
  --receipt witness-a.receipt.json \
  --receipt witness-b.receipt.json \
  --quorum-report factory-receipts.quorum.json \
  --approval-log factory-receipts.log.json \
  --checkpoint factory-receipts.checkpoint.json \
  --checkpoint-public-key checkpoint.public.hex \
  --response witness-a.response.json \
  --response witness-b.response.json \
  --witness-trust-state witness-a.trust.current.json \
  --witness-trust-state witness-b.trust.current.json \
  --minimum-witnesses 2 \
  --output checkpoint-witness-receipts.log.1.json \
  --report-output checkpoint-witness-receipts.quorum.json
```

Receipt and response arguments pair by position. Direct ID/key arguments pair
with each other; trust evidence then resolves receipts by witness ID.

> [!TIP]
> Pass receipts in any order. pcbex sorts successful members by witness ID so
> equivalent evidence produces the same event suffix and report member order.

## Verification Flow

```text
v1.504 report + complete log + v1.506 checkpoint + pinned checkpoint key
                                  │
                                  └── production checkpoint verification × 1
                                                        │
                reconstructed shared compact request ───┤
                                                        ▼
          receipt[i] + exact response[i] + witness trust[i]
                                  │
                                  ├── raw + semantic binding for every member
                                  └── canonical v1.507 witnesses
                                                        │
                                                        ▼
                    production witness-quorum verification × 1
                                  │
                                  ├── distinct IDs, keys, and digests
                                  ├── sort by witness ID
                                  └── unchanged v1.510 event suffix
                                                        │
                                                        ▼
                  no-clobber admission log + bound report
```

The command does not count `verified: true` fields. It independently reproduces
the evidence and signatures that make each receipt admissible.

## Input Contract

| Input | Count | Limit | Verification |
| --- | ---: | ---: | --- |
| Destination approval log | 1 | 128 MiB | Complete existing hash chain |
| Canonical v1.509 receipts | 1–100 | 64 KiB each | Closed, canonical, duplicate-key-free |
| Canonical v1.504 quorum report | 1 | 128 KiB | Met quorum and exact retained-log binding |
| Complete retained approval log | 1 | 128 MiB | Exact ID, count, head, digest, and suffix |
| Signed v1.506 checkpoint | 1 | 64 KiB | Factory-domain signature and exact evidence binding |
| Checkpoint public key | 1 | 65 bytes | Independently pinned, non-weak Ed25519 key |
| Exact v1.507 responses | 1–100 | 64 KiB each | Positionally paired with receipts |
| Direct witness ID/key pairs | 1–100 | 65-byte keys | All-direct mode only |
| Current v1.508 trust states | 1–100 | 32 KiB each | All-trust-state mode only |
| Minimum witnesses | 1 | 2–100 | Must be met before publication |

Exactly one witness trust mode is allowed for the entire quorum. Mixing direct
keys and trust states fails before publication.

## Output Report

Inspect or validate the closed 128 KiB report contract:

```sh
pcbex remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-report-schema

pcbex validate-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-report \
  checkpoint-witness-receipts.quorum.json
```

The report binds the shared report/log/checkpoint source digests, checkpoint
key, evaluation time, threshold, sorted members, and quorum result. A successful
published report also binds the destination log ID, entry count, head, and
complete canonical digest.

Each member records:

| Field | Meaning |
| --- | --- |
| `witness_id` / `witness_public_key` | Verified v1.507 identity and key |
| `witness_key_trust_state_sha256` / `witness_key_generation` | Exact v1.508 trust binding, or both `null` in direct mode |
| `receipt_sha256` | Normalized compact-JSON digest of the canonical v1.509 receipt, used by the event |
| `request_sha256` | Shared reconstructed request digest |
| `response_sha256` | Exact retained response digest |
| `witness_sha256` | Canonical signed v1.507 witness digest |
| `witnessed_at_unix` | Signed witness time checked at admission |

## Exact Event Suffix

Every successful member emits the unchanged v1.510 mapping:

| Event field | Value |
| --- | --- |
| `artifact_kind` | `remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt` |
| `artifact_sha256` | Member `receipt_sha256` |
| `subject_id` | Shared dedicated `checkpoint_sha256` |
| `request_sha256` | Member request digest |
| `session_sha256` | Member response digest |
| `signer_id` | `null` |
| `outcome` | `verified-witness:<witness_id>` |

The report validator requires these events to form the exact final suffix in
the same sorted order. Extension, substitution, reordering, or kind confusion
fails closed.

## Filesystem Boundary

Both output paths must be new, distinct, and non-aliased with every input. The
command prepares both destinations, re-reads all inputs, and removes an earlier
published output if later publication fails.

This detects sequential mutation. It does not create one atomic snapshot across
multiple same-principal files or an atomic multi-file commit visible to every
reader.

## MCP

The task-forbidden destructive tool is named
`append_verified_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum`.
It mirrors the CLI, rejects unknown properties, and returns both retained JSON
documents when execution succeeds.

## What Passing Proves

A successful quorum admission proves that:

- the exact shared v1.504–v1.506 evidence passes production verification;
- every receipt reproduces the same request and its own exact response;
- every witness passes current direct or generation-bound trust;
- witness signatures, freshness, identity, and role separation pass together;
- witness IDs, keys, receipt digests, response digests, and witness digests are
  distinct;
- the sorted unchanged event suffix matches the bound resulting log exactly.

## What It Does Not Prove

This boundary does not prove protected local state or keys, trusted time,
atomic same-principal snapshots, endpoint availability or legal identity,
operator independence, global publication or non-equivocation, ordering,
payment, or exactly-once execution.
