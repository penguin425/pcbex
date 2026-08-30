# Independent Factory Receipt-quorum Checkpoint Witnesses

Require multiple trusted keys to endorse the exact dedicated factory
receipt-quorum checkpoint before the release evidence advances.

The v1.507 contract preserves every v1.501–v1.506 artifact. It adds one
canonical witness and one canonical quorum report without changing the
checkpoint, receipt, approval-log, or registry-history formats.

> [!IMPORTANT]
> A witness must receive the exact log, quorum report, checkpoint, and trusted
> checkpoint public key. It re-verifies that complete v1.506 boundary before it
> reads its own private key.

## Key Guarantees

- **Re-verifies Evidence:** Checks the successful receipt-quorum report, exact
  approval log and suffix, dedicated checkpoint signature, and trusted
  checkpoint key before signing.

- **Separates the Domain:** Signs beneath
  `pcbex-factory-release-registry-receipt-quorum-log-checkpoint-witness-v1`
  followed by a NUL byte.

- **Binds the Exact Checkpoint:** Commits to the canonical checkpoint SHA-256,
  registry identity and generation, and complete approval-log state.

- **Requires Freshness:** Accepts only witnesses created at or after the
  underlying quorum evaluation and no more than 24 hours before verification.

- **Separates Key Roles:** Rejects any witness key that reuses the dedicated
  checkpoint signing key.

- **Enforces a Quorum:** Requires a threshold from 2 to 100 and rejects
  repeated witness identities or public keys.

- **Retains Negative Evidence:** Writes a valid `insufficient_witnesses` report
  before the verification command returns nonzero.

## Quick Start

Create two independent witnesses. Each command replays the same exact public
evidence before it accesses the witness key.

```bash
pcbex witness-remote-factory-release-registry-history-receipt-quorum-log-checkpoint \
  approval-log.with-receipt-quorum.json \
  --quorum-report receipt-quorum.report.json \
  --checkpoint factory-receipt-quorum.checkpoint.json \
  --checkpoint-public-key factory-receipt-quorum.public.hex \
  --private-key witness-a.private.hex \
  --witness-id witness-a \
  --output factory-receipt-quorum.witness-a.json

pcbex witness-remote-factory-release-registry-history-receipt-quorum-log-checkpoint \
  approval-log.with-receipt-quorum.json \
  --quorum-report receipt-quorum.report.json \
  --checkpoint factory-receipt-quorum.checkpoint.json \
  --checkpoint-public-key factory-receipt-quorum.public.hex \
  --private-key witness-b.private.hex \
  --witness-id witness-b \
  --output factory-receipt-quorum.witness-b.json
```

Verify a 2-of-2 quorum:

```bash
pcbex verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witnesses \
  approval-log.with-receipt-quorum.json \
  --quorum-report receipt-quorum.report.json \
  --checkpoint factory-receipt-quorum.checkpoint.json \
  --checkpoint-public-key factory-receipt-quorum.public.hex \
  --witnesses factory-receipt-quorum.witness-a.json \
  --witnesses factory-receipt-quorum.witness-b.json \
  --witness-public-keys witness-a.public.hex \
  --witness-public-keys witness-b.public.hex \
  --minimum-witnesses 2 \
  --output factory-receipt-quorum.witness-quorum.json
```

The witness and public-key arguments are positional pairs. Input order does not
change the canonical report; identities and keys are sorted independently.

> [!TIP]
> Pass explicit `--witnessed-at-unix` and `--evaluated-at-unix` values in
> reproducible fixtures. Omit them in live operation to use the current Unix
> time.

## Wire Contracts

| Contract | Exact binding | Limit |
|---|---|---:|
| Signed witness | Checkpoint SHA-256, registry ID/generation, log ID/count/head/digest, witness ID/time/key/signature | 64 KiB |
| Witness quorum report | Same checkpoint and log identity, evaluation time, threshold/result, sorted distinct IDs and keys | 128 KiB |
| Private or public key file | One Ed25519 key encoded as 64 lowercase hex digits | 1 KiB |
| Approval transparency log | Complete validated log | 128 MiB |
| Receipt-quorum report | Canonical v1.504 report | 128 KiB |
| Dedicated checkpoint | Canonical v1.506 checkpoint | 64 KiB |

Discover and normalize both closed schemas:

```bash
pcbex signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-schema
pcbex remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-quorum-report-schema

pcbex validate-signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness \
  factory-receipt-quorum.witness-a.json

pcbex validate-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-quorum-report \
  factory-receipt-quorum.witness-quorum.json
```

## Verification Flow

1. Parse the canonical v1.504 report, complete approval log, and v1.506
   checkpoint.
2. Re-run the strict report/log/suffix binding and dedicated checkpoint
   signature verification.
3. Match every witness to its paired trusted public key.
4. Require exact checkpoint and log bindings, a strict Ed25519 signature, and
   the 24-hour freshness window.
5. Reject checkpoint-key reuse and repeated witness identities or keys.
6. Re-read every input by byte count and SHA-256.
7. Publish one alias-free, no-clobber canonical quorum report.

## Failure Semantics

The commands return nonzero and create no output when public evidence is
malformed, noncanonical, substituted, stale, incorrectly signed, untrusted, or
role-colliding. They also fail when an input changes, an output aliases an
input, or the output already exists.

A below-threshold set behaves differently. If every supplied witness is valid,
the verifier writes a canonical report with `quorum_met: false` and
`status: "insufficient_witnesses"`, then returns nonzero.

## Trust Boundary

This boundary proves that the configured distinct keys signed one exact,
freshly reverified v1.506 checkpoint. It prevents signature-domain substitution
and checkpoint-signer key reuse.

It does not prove that the keys belong to separate people or organizations. It
also does not protect local files or keys, establish trusted time or legal
identity, publish evidence globally, guarantee non-equivocation, or place an
order or payment.

The v1.508
[key-rotation boundary](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_ROTATION.md)
adds generation-chained trust without changing either v1.507 wire contract.
Use direct public-key pins for static deployments or pair each witness with its
current retained trust state when keys rotate.

The v1.509
[remote acquisition boundary](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_REMOTE_WITNESSES.md)
fetches this unchanged witness over bounded HTTPS, verifies it locally, and
retains a hash-bound transport receipt.
