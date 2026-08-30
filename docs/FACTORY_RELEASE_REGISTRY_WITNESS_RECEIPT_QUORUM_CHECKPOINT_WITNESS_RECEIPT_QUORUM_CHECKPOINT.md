# Domain-separated Factory Checkpoint-witness Receipt-quorum Checkpoints

Sign one exact verifier-bound checkpoint-witness receipt quorum under its own
cryptographic domain.

The v1.514 contract preserves every v1.504–v1.513 wire artifact. It adds a
closed dedicated checkpoint and verification result for the exact log/report
pair published by v1.512.

> [!IMPORTANT]
> Supply the admission log and canonical report produced by the same v1.512
> invocation. Verification also requires a public key trusted specifically for
> this checkpoint domain.

## Key Features

- **Separates the Domain:** Prefixes the signed payload with
  `pcbex-factory-release-registry-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-v1`
  and a NUL byte.

- **Binds the Complete Report:** Signs the SHA-256 of the normalized v1.512
  report, including every retained source digest and sorted member.

- **Links the Prior Checkpoint:** Commits to the exact v1.506 factory
  receipt-quorum checkpoint digest recorded by the admission report.

- **Locks the Admission Log:** Signs its ID, entry count, head, and complete
  canonical SHA-256.

- **Defers Key Access:** Rejects an invalid report, log, or suffix before
  opening private signing material.

- **Revalidates Inputs:** Re-reads the report, log, and key before one
  alias-free, no-clobber publication.

## Quick Start

Create the dedicated checkpoint:

```bash
pcbex sign-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint \
  checkpoint-witness-receipts.log.json \
  --quorum-report checkpoint-witness-receipts.quorum.json \
  --private-key checkpoint-witness-receipt-quorum.private.hex \
  --signer-id factory-checkpoint-witness-receipt-quorum \
  --output checkpoint-witness-receipts.dedicated-checkpoint.json
```

Verify the signature and every evidence binding:

```bash
pcbex verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint \
  checkpoint-witness-receipts.log.json \
  --quorum-report checkpoint-witness-receipts.quorum.json \
  --checkpoint checkpoint-witness-receipts.dedicated-checkpoint.json \
  --public-key checkpoint-witness-receipt-quorum.public.hex \
  --output checkpoint-witness-receipts.dedicated-verification.json
```

Discover and normalize the closed wire contract:

```bash
pcbex signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-schema

pcbex validate-signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint \
  checkpoint-witness-receipts.dedicated-checkpoint.json \
  --output checkpoint-witness-receipts.dedicated-checkpoint.normalized.json
```

## Signed Contract

| Field group | Exact binding |
| --- | --- |
| Admission quorum | Normalized v1.512 report SHA-256, threshold, and valid witness count |
| Registry | Registry ID, generation, and registry-history checkpoint SHA-256 |
| Prior checkpoint | Exact v1.506 factory receipt-quorum checkpoint SHA-256 |
| Admission log | Log ID, entry count, head SHA-256, and complete canonical SHA-256 |
| Issuer | Signer ID, Ed25519 algorithm, and embedded public key |
| Signature | Ed25519 over the dedicated domain plus compact canonical payload |

The normalized report digest covers the original v1.504 report and source, the
complete v1.504 approval log and source, the v1.506 checkpoint and source,
checkpoint key, evaluation time, ordered distinct receipt members, quorum
decision, and exact v1.512 admission-log binding.

## Validation Order

1. Parse the closed canonical v1.512 report and complete admission log.
2. Require a met 2–100 threshold and the exact report-bound log snapshot.
3. Match every sorted suffix event to its checkpoint-witness receipt member.
4. Read and validate the private checkpoint key.
5. Sign the normalized report and log state under the new domain.
6. Re-read the log, report, and key by identity, byte count, and SHA-256.
7. Publish one canonical checkpoint without replacing an existing path.

Verification repeats the report/log checks, requires the exact trusted public
key, and performs strict Ed25519 verification. A generic approval checkpoint or
v1.506 factory receipt-quorum checkpoint signature cannot substitute.

## Failure Semantics

The commands return nonzero and create no output when:

- the report is malformed, noncanonical, unbound, or below threshold;
- the log chain, snapshot identity, digest, or sorted suffix differs;
- the checkpoint changes any report, registry, prior-checkpoint, log,
  threshold, signer, key, or signature field;
- the trusted key differs from the embedded checkpoint key;
- an input changes before publication;
- an output aliases an input or already exists.

> [!TIP]
> Pair mismatched public evidence with a deliberately absent private key when
> testing access order. The command reports the evidence mismatch first.

## Limits

| Artifact | Bound |
| --- | ---: |
| Approval transparency log | 128 MiB / 100,000 entries |
| Canonical v1.512 quorum report | 128 KiB / 100 members |
| Private or public key file | 1 KiB; trims to 64 lowercase hex digits |
| Canonical dedicated checkpoint | 64 KiB |
| Canonical verification result | 64 KiB |

## MCP

Two task-forbidden destructive tools mirror the CLI:

- `sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint`
- `verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint`

## Trust Boundary

Passing proves that one trusted key signed the exact semantic v1.512 report,
the prior factory-domain checkpoint identity, and the exact admission-log state
under a checkpoint-witness receipt-quorum-specific domain. It prevents
cross-protocol signature reuse.

It does not replay raw receipts, responses, witness signatures, or trust states
during checkpoint signing; v1.512 owns those checks. It also does not protect
files or keys, establish trusted time, prove independent operation, publish
evidence globally, prevent equivocation, establish legal identity, or prove
ordering, payment, or exactly-once execution.
