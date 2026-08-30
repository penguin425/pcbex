# Independent Factory Checkpoint-witness Receipt-quorum Checkpoint Witnesses

Require multiple trusted keys to endorse the exact v1.514 dedicated checkpoint
before release evidence advances.

The v1.515 contract preserves every v1.504–v1.514 wire artifact. It adds one
canonical witness and one canonical quorum report without changing the
admission log, receipt quorum, or dedicated checkpoint formats.

> [!IMPORTANT]
> A witness must receive the exact admission log, v1.512 quorum report, v1.514
> checkpoint, and independently pinned checkpoint public key. It re-verifies
> that complete public boundary before it reads its own private key.

## Key Guarantees

- **Re-verifies Evidence:** Checks the successful v1.512 report, complete
  admission log and sorted suffix, v1.514 checkpoint signature, and trusted
  checkpoint key before signing.

- **Separates the Domain:** Signs beneath
  `pcbex-factory-release-registry-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-v1`
  followed by a NUL byte.

- **Binds the Exact Checkpoint:** Commits to the canonical v1.514 checkpoint
  SHA-256, registry identity and generation, prior v1.506 checkpoint, and
  complete admission-log state.

- **Requires Freshness:** Accepts witnesses created at or after the underlying
  v1.512 evaluation and no more than 24 hours before quorum verification.

- **Separates Key Roles:** Rejects any witness key that reuses the v1.514
  checkpoint signing key.

- **Enforces a Quorum:** Requires a threshold from 2 to 100 and rejects weak or
  repeated witness identities and public keys.

- **Retains Negative Evidence:** Writes a valid `insufficient_witnesses` report
  before the verification command returns nonzero.

## Quick Start

Create two independently keyed witnesses. Each command replays the same exact
public evidence before accessing its witness key.

```bash
pcbex witness-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint \
  checkpoint-witness-receipts.log.json \
  --quorum-report checkpoint-witness-receipts.quorum.json \
  --checkpoint checkpoint-witness-receipts.dedicated-checkpoint.json \
  --checkpoint-public-key checkpoint-witness-receipt-quorum.public.hex \
  --private-key checkpoint-witness-a.private.hex \
  --witness-id checkpoint-witness-a \
  --output checkpoint-witness-receipts.witness-a.json

pcbex witness-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint \
  checkpoint-witness-receipts.log.json \
  --quorum-report checkpoint-witness-receipts.quorum.json \
  --checkpoint checkpoint-witness-receipts.dedicated-checkpoint.json \
  --checkpoint-public-key checkpoint-witness-receipt-quorum.public.hex \
  --private-key checkpoint-witness-b.private.hex \
  --witness-id checkpoint-witness-b \
  --output checkpoint-witness-receipts.witness-b.json
```

Verify a 2-of-2 quorum:

```bash
pcbex verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witnesses \
  checkpoint-witness-receipts.log.json \
  --quorum-report checkpoint-witness-receipts.quorum.json \
  --checkpoint checkpoint-witness-receipts.dedicated-checkpoint.json \
  --checkpoint-public-key checkpoint-witness-receipt-quorum.public.hex \
  --witnesses checkpoint-witness-receipts.witness-a.json \
  --witnesses checkpoint-witness-receipts.witness-b.json \
  --witness-public-keys checkpoint-witness-a.public.hex \
  --witness-public-keys checkpoint-witness-b.public.hex \
  --minimum-witnesses 2 \
  --output checkpoint-witness-receipts.witness-quorum.json
```

The witness and public-key arguments form positional pairs. Input order does
not change the canonical report; identities and keys are sorted independently.

> [!TIP]
> Pass explicit `--witnessed-at-unix` and `--evaluated-at-unix` values in
> reproducible fixtures. Omit them in live operation to use current Unix time.

## Wire Contracts

| Contract | Exact binding | Limit |
| --- | --- | ---: |
| Signed witness | v1.514 checkpoint SHA-256, registry ID/generation, prior checkpoint, admission-log ID/count/head/digest, witness ID/time/key/signature | 64 KiB |
| Witness quorum report | Same checkpoint and log identity, evaluation time, threshold/result, sorted distinct IDs and keys | 128 KiB |
| Private or public key file | One Ed25519 key encoded as 64 lowercase hex digits | 1 KiB |
| Admission transparency log | Complete validated log | 128 MiB |
| v1.512 quorum report | Canonical report with at most 100 members | 128 KiB |
| v1.514 dedicated checkpoint | Canonical checkpoint | 64 KiB |

Discover and normalize both closed schemas:

```bash
pcbex signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-schema
pcbex remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-quorum-report-schema

pcbex validate-signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness \
  checkpoint-witness-receipts.witness-a.json

pcbex validate-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-quorum-report \
  checkpoint-witness-receipts.witness-quorum.json
```

## Verification Flow

1. Parse the canonical v1.512 report, complete admission log, and v1.514
   checkpoint.
2. Re-run the strict report/log/suffix binding and dedicated checkpoint
   signature verification.
3. Match every witness to its paired directly pinned public key.
4. Require exact checkpoint and log bindings, a strict Ed25519 signature, and
   the 24-hour freshness window.
5. Reject weak keys, checkpoint-key reuse, and repeated witness identities or
   keys.
6. Re-read every input by identity, byte count, and SHA-256.
7. Publish one alias-free, no-clobber canonical quorum report.

## Failure Semantics

The commands return nonzero and create no output when public evidence is
malformed, noncanonical, substituted, stale, incorrectly signed, untrusted, or
role-colliding. They also fail when an input changes, an output aliases an
input, or the output already exists.

A below-threshold set behaves differently. If every supplied witness is valid,
the verifier writes a canonical report with `quorum_met: false` and
`status: "insufficient_witnesses"`, then returns nonzero.

## MCP

Two task-forbidden destructive tools mirror the CLI:

- `witness_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint`
- `verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses`

## Trust Boundary

Passing proves that the configured distinct keys signed one exact, freshly
reverified v1.514 checkpoint. It prevents signature-domain substitution and
checkpoint-signer key reuse.

It does not prove that the keys belong to separate people, organizations, or
systems. It also does not protect local files or keys, establish trusted time
or legal identity, publish evidence globally, prevent equivocation, establish
ordering, place an order, authorize payment, or prove exactly-once execution.

This version accepts direct public-key pins only. A later rotation boundary can
add generation-chained witness trust without changing either v1.515 wire
contract.

The v1.514
[dedicated checkpoint boundary](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT.md)
defines the exact checkpoint reverified by every witness.
