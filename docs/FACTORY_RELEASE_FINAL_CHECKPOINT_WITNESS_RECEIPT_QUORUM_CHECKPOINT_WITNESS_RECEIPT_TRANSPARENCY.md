# Final Receipt-quorum Checkpoint-witness Receipt Transparency

Publish one verified v1.526 transport receipt through the existing signed,
append-only approval transparency chain.

The v1.528 contract adds one artifact kind. Every v1.521–v1.527 report, log,
checkpoint, witness, quorum, trust, receipt, manifest, and acquisition format
remains byte-compatible.

> [!IMPORTANT]
> Generic append performs strict structural admission. It does not replay the
> v1.521 report, final admission log, v1.523 checkpoint, exact v1.524 response,
> witness signature, freshness, or current v1.525 trust state. Use the v1.529
> verifier-bound append when the complete retained evidence is available.

## Key Features

- **Rejects Invalid Receipts:** Accepts only the closed canonical 64 KiB v1.526
  contract with `verified: true`, internally consistent timestamps, complete
  trust bindings, and non-weak role-separated keys.

- **Binds Exact Evidence:** Records the compact receipt digest together with
  its final checkpoint, request, raw response, and witness identities.

- **Preserves the Log:** Reuses the existing sequence, predecessor digest,
  entry digest, and complete-log digest contracts.

- **Reuses Every Control:** Existing signing, anchoring, consistency, gossip,
  witness rotation, and witness quorum operate without a new wire format.

- **Publishes Safely:** Creates one no-clobber successor snapshot. Invalid
  input leaves both the source log and destination unchanged.

- **Keeps MCP Bounded:** Extends the existing append tool with one enum value;
  it adds no tool and grants no new network authority.

## Quick Start

Create a dedicated receipt log:

```sh
pcbex init-approval-log \
  --log-id final-receipt-quorum-checkpoint-witness-receipts \
  --output final-checkpoint-receipts.log.0.json
```

Append one canonical v1.526 receipt:

```sh
pcbex append-approval-log final-checkpoint-receipts.log.0.json \
  --artifact final-checkpoint.witness-a.remote-receipt.json \
  --kind remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-receipt \
  --recorded-at-unix 1788307200 \
  --output final-checkpoint-receipts.log.1.json
```

Sign and verify the exact new head:

```sh
pcbex sign-approval-log final-checkpoint-receipts.log.1.json \
  --private-key final-checkpoint-receipt-log.private.hex \
  --signer-id final-checkpoint-receipt-log \
  --output final-checkpoint-receipts.checkpoint.json

pcbex verify-approval-log final-checkpoint-receipts.log.1.json \
  --checkpoint final-checkpoint-receipts.checkpoint.json \
  --public-key final-checkpoint-receipt-log.public.hex \
  --output final-checkpoint-receipts.verification.json
```

> [!TIP]
> Prefer the v1.529 verifier-bound append when the complete retained evidence
> is available. It repeats replay at an independent admission time and emits
> this same event.

## Replay Before Admission

Reconstruct the original request and repeat the declared-time local decision:

```sh
pcbex validate-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-receipt \
  final-checkpoint.witness-a.remote-receipt.json \
  --log final-receipts.log.json \
  --quorum-report final-receipts.quorum.json \
  --checkpoint final-receipts.quorum.checkpoint.json \
  --checkpoint-public-key final-receipts.quorum.checkpoint.public.hex \
  --response final-checkpoint.witness-a.json \
  --witness-id witness-a \
  --witness-trust-state witness-a.trust.3.json \
  --output final-checkpoint.witness-a.remote-receipt.verified.json
```

Use `--witness-public-key` for direct trust. A successful normalized output is
byte-identical to the supplied receipt.

## Event Mapping

One admitted v1.526 receipt produces one normalized event:

| Event field | Receipt binding |
| --- | --- |
| `artifact_kind` | `remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt` |
| `artifact_sha256` | SHA-256 of canonical compact receipt JSON |
| `subject_id` | `checkpoint_sha256` |
| `request_sha256` | Exact compact remote-request digest |
| `session_sha256` | Exact raw response digest |
| `signer_id` | `null`; this is local transport evidence |
| `outcome` | `verified-witness:<witness_id>` |

The approval-log checkpoint signer remains the admission authority. Signing
the log authenticates its exact history; it does not turn the local receipt
into an endpoint-signed transport statement.

## Verification Flow

```text
canonical v1.526 receipt
          │
          ├── closed structural validation
          ▼
normalized final-checkpoint receipt event
          │
          ├── sequence + predecessor + self digest
          ▼
new approval-log snapshot
          │
          ├── Ed25519 checkpoint
          ├── external anchor / consistency proof
          └── gossip / independent witness quorum
```

Each layer retains its own authority. Receipt admission does not bypass any
checkpoint signer, external log, observer, or witness policy.

## Contracts and Limits

| Input or state | Limit | Enforcement |
| --- | ---: | --- |
| v1.526 receipt | 64 KiB | Canonical, duplicate-key-free, closed parser |
| Represented v1.524 response | 64 KiB | Bound by receipt and acquisition contract |
| Approval transparency entries | 100,000 | Existing log contract |
| Generic CLI file read | 128 MiB | Regular, non-symlink, identity-checked input |
| Event text | 256 bytes | Existing approval-event validator |

Append rejects false verification, malformed endpoints or digests, weak or
role-reused keys, invalid response size, inconsistent trust fields, and witness
times outside the receipt age bound. Compact JSON, duplicate keys, unknown
fields, aliases, and existing destinations also fail closed.

## MCP

The existing `append_approval_transparency_log` tool accepts the new artifact
kind. The inventory remains 186 tools, and v1.528 adds no MCP transport command.

## Trust Boundary

A passing signed-log verification proves that the log is internally
hash-chain consistent, one event binds a structurally valid canonical v1.526
receipt, and the checkpoint signer signed the exact log state.

It does not prove that append replayed the v1.521 report, final admission log,
v1.523 checkpoint, response, witness signature, freshness, or trust state. It
does not protect files or keys; establish trusted time, endpoint or legal
identity, independent operation, global publication, or non-equivocation;
place an order; approve payment; or guarantee exactly-once execution.

The [single-witness transport guide](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_REMOTE_WITNESSES.md)
defines the unchanged v1.526 receipt. The [parallel acquisition guide](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_QUORUM_ACQUISITION.md)
defines how v1.527 retains successful receipts beside coarse failures.
The [verifier-bound admission guide](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_ADMISSION.md)
replays the complete retained boundary before emitting this same event.
