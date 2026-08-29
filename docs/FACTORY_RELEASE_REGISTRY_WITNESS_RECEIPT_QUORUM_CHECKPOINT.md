# Domain-separated Factory Receipt-quorum Checkpoints

Sign one exact verifier-bound factory receipt quorum under a purpose-built
cryptographic domain.

The v1.506 contract preserves every v1.501–v1.505 artifact. It adds a dedicated
checkpoint and verification result without changing the generic approval-log
checkpoint path.

> [!IMPORTANT]
> Supply the log and canonical report produced by the same v1.504 quorum
> admission. Verification also requires the public key trusted specifically for
> factory receipt-quorum checkpoints.

## Key Guarantees

- **Separates the Domain:** Prefixes the signed payload with
  `pcbex-factory-release-registry-receipt-quorum-log-checkpoint-v1` and a NUL
  byte.
- **Binds the Report:** Signs the SHA-256 of the normalized complete quorum
  report.
- **Binds the Log:** Signs the exact log ID, entry count, head, and complete log
  SHA-256.
- **Binds the Decision:** Signs the registry checkpoint, enforced threshold,
  valid witness count, and signer identity.
- **Defers Key Access:** Rejects an invalid report, log, or suffix before reading
  private signing material.
- **Fails Closed:** Re-reads every input before publishing one canonical,
  alias-free, no-clobber artifact.

## Quick Start

Create a dedicated checkpoint from the exact v1.504 log/report pair:

```bash
pcbex sign-remote-factory-release-registry-history-receipt-quorum-log-checkpoint \
  approval-log.with-receipt-quorum.json \
  --quorum-report receipt-quorum.report.json \
  --private-key factory-receipt-quorum.private.hex \
  --signer-id factory-release-registry-receipt-quorum \
  --output factory-receipt-quorum.checkpoint.json
```

Verify the signature and every evidence binding:

```bash
pcbex verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint \
  approval-log.with-receipt-quorum.json \
  --quorum-report receipt-quorum.report.json \
  --checkpoint factory-receipt-quorum.checkpoint.json \
  --public-key factory-receipt-quorum.public.hex \
  --output factory-receipt-quorum.verification.json
```

Discover and normalize the closed wire contract:

```bash
pcbex signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-schema

pcbex validate-signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint \
  factory-receipt-quorum.checkpoint.json \
  --output factory-receipt-quorum.checkpoint.normalized.json
```

## Signed Contract

| Field group | Exact binding |
|---|---|
| Quorum | Normalized report SHA-256, minimum witnesses, valid witnesses |
| Registry | Registry ID, generation, signed registry-checkpoint SHA-256 |
| Approval log | Log ID, entry count, head SHA-256, complete log SHA-256 |
| Issuer | Signer ID, Ed25519 algorithm, embedded public key |
| Signature | Ed25519 over the dedicated domain plus compact canonical payload |

The report digest covers its complete canonical meaning, including history and
checkpoint trust-state identities, ordered distinct members, receipt/request/
response/witness digests, evaluation time, quorum decision, and exact log
binding. It is the SHA-256 of the normalized typed report, not its incidental
file whitespace.

## Validation Order

1. Parse the canonical closed quorum report and complete approval log.
2. Require a met 2–100 threshold and the exact report-bound log snapshot.
3. Match every ordered suffix event to its factory receipt-quorum member.
4. Read and validate the private checkpoint key.
5. Sign under the factory-specific domain.
6. Re-read the log, report, and key by byte count and SHA-256.
7. Publish one canonical checkpoint without replacing an existing path.

Verification repeats the report/log checks, requires the exact trusted public
key, and uses strict Ed25519 verification. A signature created for the generic
approval checkpoint or the approval-registry receipt-quorum domain cannot be
substituted.

## Failure Semantics

The commands return nonzero and create no output when:

- the report is noncanonical, malformed, unbound, or below threshold;
- the log chain, snapshot identity, or ordered factory-receipt suffix differs;
- the checkpoint changes any report, registry, threshold, log, signer, key, or
  signature field;
- the trusted key differs from the embedded checkpoint key;
- an input changes before publication;
- an output aliases an input or already exists.

> [!TIP]
> A mismatched public log combined with a missing private key reports the log
> mismatch first. This keeps the secret-access ordering observable in tests.

## Limits

| Artifact | Bound |
|---|---:|
| Approval transparency log | 128 MiB / 100,000 entries |
| Canonical receipt-quorum report | 128 KiB / 100 members |
| Private or public key file | 1 KiB; trims to 64 lowercase hex digits |
| Canonical dedicated checkpoint | 64 KiB |
| Canonical verification result | 64 KiB |

## Trust Boundary

This contract proves that one trusted checkpoint key signed the exact semantic
v1.504 quorum report and exact approval-log state under the factory
receipt-quorum domain. It prevents cross-protocol signature reuse.

It does not replay raw history, receipts, responses, trust states, or witness
signatures during checkpoint signing; the v1.504 admission boundary owns those
checks. It also does not protect local files or keys, establish trusted time,
prove independent operation, publish evidence globally, establish
non-equivocation, or place an order or payment.

Independent witnesses over this dedicated checkpoint are the next boundary.
