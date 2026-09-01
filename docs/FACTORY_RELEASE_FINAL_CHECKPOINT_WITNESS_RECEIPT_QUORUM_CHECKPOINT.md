# Domain-separated Final Checkpoint-witness Receipt-quorum Checkpoints

Sign the exact final receipt quorum under one purpose-built domain.

The v1.523 contract preserves every v1.512–v1.522 artifact. It adds a closed
dedicated checkpoint and verification result for the exact final log/report
pair published by v1.521.

> [!IMPORTANT]
> Supply the final admission log and canonical report produced by the same
> v1.521 invocation. Verification also requires a public key trusted
> specifically for this final checkpoint domain.

## Key Features

- **Separates the Domain:** Prefixes the signed payload with
  `pcbex-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-v1`
  and a NUL byte.

- **Binds the Final Report:** Signs the SHA-256 of the normalized v1.521 report,
  including every retained source digest and sorted final-witness member.

- **Links Both Checkpoints:** Commits to the exact v1.506 factory receipt-quorum
  checkpoint and v1.514 checkpoint-witness receipt-quorum checkpoint.

- **Locks the Final Log:** Signs its ID, entry count, head, and complete
  canonical SHA-256.

- **Defers Key Access:** Rejects an invalid report, log, or suffix before
  opening private signing material.

- **Revalidates Inputs:** Re-reads the report, log, and key before one
  alias-free, no-clobber publication.

## Quick Start

Create the dedicated checkpoint:

```sh
pcbex sign-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint \
  final-witness-receipts.log.json \
  --quorum-report final-witness-receipts.quorum.json \
  --private-key final-receipt-quorum.private.hex \
  --signer-id factory-final-checkpoint-witness-receipt-quorum \
  --output final-witness-receipts.dedicated-checkpoint.json
```

Verify the signature and every retained binding:

```sh
pcbex verify-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint \
  final-witness-receipts.log.json \
  --quorum-report final-witness-receipts.quorum.json \
  --checkpoint final-witness-receipts.dedicated-checkpoint.json \
  --public-key final-receipt-quorum.public.hex \
  --output final-witness-receipts.dedicated-verification.json
```

Discover and normalize the closed wire contract:

```sh
pcbex signed-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-schema

pcbex validate-signed-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint \
  final-witness-receipts.dedicated-checkpoint.json \
  --output final-witness-receipts.dedicated-checkpoint.normalized.json
```

## Signed Contract

| Field group | Exact binding |
| --- | --- |
| Final quorum | Normalized v1.521 report SHA-256, threshold, and valid witness count |
| Registry | Registry ID, generation, and registry-history checkpoint SHA-256 |
| Prior checkpoints | Exact v1.506 and v1.514 dedicated checkpoint SHA-256 values |
| Final admission log | Log ID, entry count, head SHA-256, and complete canonical SHA-256 |
| Issuer | Signer ID, Ed25519 algorithm, and embedded public key |
| Signature | Ed25519 over the dedicated domain plus compact canonical payload |

The normalized report digest covers the original v1.512 report and source,
the complete v1.512 admission log and source, both prior checkpoint identities,
the v1.514 key, evaluation time, ordered distinct final receipts, quorum
decision, and exact v1.521 final-log binding.

## Validation Order

1. Parse the closed canonical v1.521 report and complete final admission log.
2. Require a met 2–100 threshold and the exact report-bound log snapshot.
3. Match every sorted v1.519 suffix event to its final receipt member.
4. Read and validate the private checkpoint key.
5. Sign the report, both prior checkpoints, and final log under the new domain.
6. Re-read the log, report, and key by identity, byte count, and SHA-256.
7. Publish one canonical checkpoint without replacing an existing path.

Verification repeats the report/log checks, requires the exact trusted public
key, and performs strict Ed25519 verification. A generic approval checkpoint or
an earlier factory checkpoint signature cannot substitute.

## Failure Semantics

The commands return nonzero and create no output when:

- the report is malformed, noncanonical, unbound, or below threshold;
- the log chain, snapshot identity, digest, or sorted suffix differs;
- either prior checkpoint identity differs;
- the checkpoint changes any report, registry, threshold, log, signer, key, or
  signature field;
- the trusted key differs from the embedded checkpoint key;
- an input changes before publication; or
- an output aliases an input or already exists.

> [!TIP]
> Pair mismatched public evidence with a deliberately absent private key when
> testing access order. The command reports the evidence mismatch first.

## Limits

| Artifact | Bound |
| --- | ---: |
| Approval transparency log | 128 MiB / 100,000 entries |
| Canonical v1.521 quorum report | 128 KiB / 100 members |
| Private or public key file | 1 KiB; trims to 64 lowercase hex digits |
| Canonical dedicated checkpoint | 64 KiB |
| Canonical verification result | 64 KiB |

## MCP

Two task-forbidden destructive tools mirror the CLI:

- `sign_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint`
- `verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint`

## Trust Boundary

Passing proves that one trusted key signed the exact semantic v1.521 report,
both prior factory checkpoint identities, and the exact final admission-log
state under a final receipt-quorum-specific domain. It prevents cross-protocol
signature reuse.

It does not replay raw receipts, responses, final-witness signatures, or trust
states during checkpoint signing; v1.521 owns those checks. It also does not
protect files or keys, establish trusted time, prove independent operation,
publish evidence globally, prevent equivocation, establish legal identity, or
prove ordering, payment, or exactly-once execution.

Use the existing approval-log anchor, consistency, gossip, and witness controls
when the dedicated checkpoint must be published across trust domains.
