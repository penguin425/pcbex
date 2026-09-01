# Independent Final Receipt-quorum Checkpoint Witnesses

Require multiple trusted keys to endorse one exact dedicated final checkpoint.

The v1.524 contract preserves every v1.512–v1.523 wire artifact. It adds one
closed signed witness and one closed quorum report for the dedicated v1.523
checkpoint.

> [!IMPORTANT]
> Every witness re-verifies the exact v1.521 report, complete final admission
> log, v1.523 checkpoint, and pinned checkpoint key before its private key is
> opened.

## Key Features

- **Replays Public Evidence:** Runs the production v1.523 verification path
  before signing or accepting any witness.

- **Separates the Domain:** Prefixes the witness payload with
  `pcbex-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-v1`
  and a NUL byte.

- **Binds the Full Chain:** Commits to the v1.523 checkpoint digest, registry
  identity and generation, both prior factory checkpoints, and complete final
  admission-log state.

- **Enforces Freshness:** Accepts witnesses created at or after the v1.521
  evaluation and no more than 24 hours before quorum verification.

- **Separates Key Roles:** Rejects a witness key that reuses the v1.523
  checkpoint signing key.

- **Requires Independence:** Rejects repeated witness identities and public
  keys, then canonicalizes both sets in lexical order.

- **Retains Threshold Evidence:** Writes a valid `insufficient_witnesses`
  report before the quorum command returns nonzero.

## Quick Start

Create two independent witnesses. Both commands replay the same exact public
evidence before accessing their witness keys.

```sh
pcbex witness-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint \
  final-witness-receipts.log.json \
  --quorum-report final-witness-receipts.quorum.json \
  --checkpoint final-witness-receipts.dedicated-checkpoint.json \
  --checkpoint-public-key final-receipt-quorum.public.hex \
  --private-key final-witness-a.private.hex \
  --witness-id final-witness-a \
  --output final-receipt-quorum.witness-a.json

pcbex witness-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint \
  final-witness-receipts.log.json \
  --quorum-report final-witness-receipts.quorum.json \
  --checkpoint final-witness-receipts.dedicated-checkpoint.json \
  --checkpoint-public-key final-receipt-quorum.public.hex \
  --private-key final-witness-b.private.hex \
  --witness-id final-witness-b \
  --output final-receipt-quorum.witness-b.json
```

Verify a 2-of-2 quorum:

```sh
pcbex verify-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witnesses \
  final-witness-receipts.log.json \
  --quorum-report final-witness-receipts.quorum.json \
  --checkpoint final-witness-receipts.dedicated-checkpoint.json \
  --checkpoint-public-key final-receipt-quorum.public.hex \
  --witnesses final-receipt-quorum.witness-a.json \
  --witnesses final-receipt-quorum.witness-b.json \
  --witness-public-keys final-witness-a.public.hex \
  --witness-public-keys final-witness-b.public.hex \
  --minimum-witnesses 2 \
  --output final-receipt-quorum.witness-quorum.json
```

Witness and public-key arguments form positional pairs. Reordering complete
pairs does not affect the report because identities and keys are sorted
independently.

> [!TIP]
> Use explicit `--witnessed-at-unix` and `--evaluated-at-unix` values in
> reproducible fixtures. Omit them during live operation to use the current
> Unix time.

## Wire Contracts

| Contract | Exact binding | Limit |
| --- | --- | ---: |
| Signed witness | v1.523 checkpoint SHA-256, registry ID/generation, both prior checkpoint SHA-256 values, final log ID/count/head/digest, witness ID/time/key/signature | 64 KiB |
| Witness quorum report | Same checkpoint chain and final-log identity, evaluation time, threshold/result, sorted distinct IDs and keys | 128 KiB |
| Private or public key | One Ed25519 key encoded as 64 lowercase hex digits | 1 KiB |
| Final admission log | Complete validated approval log | 128 MiB |
| v1.521 quorum report | Closed canonical report with at most 100 members | 128 KiB |
| v1.523 checkpoint | Closed canonical dedicated checkpoint | 64 KiB |

Discover and normalize both schemas:

```sh
pcbex signed-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-schema
pcbex remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-quorum-report-schema

pcbex validate-signed-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness \
  final-receipt-quorum.witness-a.json

pcbex validate-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-quorum-report \
  final-receipt-quorum.witness-quorum.json
```

## Verification Flow

1. Parse the canonical v1.521 report, complete final log, and v1.523
   checkpoint.
2. Re-run the exact report/log/suffix gate and strict v1.523 signature
   verification against its pinned public key.
3. Match every witness to its paired directly pinned public key.
4. Require exact checkpoint-chain and log bindings, strict Ed25519 signatures,
   and the 24-hour freshness window.
5. Reject checkpoint-key reuse and repeated witness identities or keys.
6. Re-read every input by identity, byte count, and SHA-256.
7. Publish one alias-free, no-clobber canonical quorum report.

## Failure Semantics

Malformed, noncanonical, substituted, stale, incorrectly signed, untrusted, or
role-colliding evidence returns nonzero and creates no output. Changed inputs,
aliases, and existing destinations fail the same way.

A below-threshold set behaves differently. When every supplied witness is
valid, verification writes `quorum_met: false` with
`status: "insufficient_witnesses"`, then returns nonzero.

## MCP

Two task-forbidden destructive tools mirror the signing and quorum paths:

- `witness_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint`
- `verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses`

## Trust Boundary

Passing proves that the configured distinct Ed25519 keys signed one exact,
freshly reverified v1.523 checkpoint. The dedicated domain prevents earlier or
generic checkpoint-witness signatures from substituting.

This boundary uses direct key pins. It does not prove that keys belong to
separate people or organizations, protect files or keys, establish trusted
time or legal identity, publish evidence globally, prevent equivocation, or
prove ordering, payment, or exactly-once execution.

The v1.525
[key-rotation boundary](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_ROTATION.md)
adds generation-chained witness trust without changing either v1.524 wire
contract.
