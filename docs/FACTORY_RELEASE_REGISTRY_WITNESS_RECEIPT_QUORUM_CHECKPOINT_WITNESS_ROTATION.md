# Factory Checkpoint-witness Key Rotation

Rotate dedicated factory receipt-quorum checkpoint-witness keys without
changing witness identities or trusting an unapproved replacement key.

The v1.508 contract preserves the v1.507 witness and quorum-report formats. It
adds a retained trust state plus one dual-signed, generation-chained rotation
artifact.

> [!IMPORTANT]
> Keep the latest trust state in deployment-owned protected storage. The
> artifact detects stale or skipped transitions; it does not stop an attacker
> from replacing every local file with an older, internally consistent set.

## Key Features

- **Pins Identity:** Binds one witness ID to its current Ed25519 public key and
  generation.

- **Requires Both Keys:** The retained key authorizes the change. The successor
  key proves possession before activation.

- **Advances Once:** Accepts only `generation + 1`, from generation 0 through
  4096.

- **Chains Rotations:** Commits every transition to the previous canonical
  rotation SHA-256.

- **Rejects Rollback:** Refuses stale state, replayed rotations, skipped
  generations, decreasing timestamps, weak keys, and unchanged keys.

- **Preserves Quorum:** Verifies the unchanged v1.507 witness artifacts through
  either direct public-key pins or current trust states.

## Quick Start

Initialize trust from the currently approved witness key:

```bash
pcbex init-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-trust \
  --witness-id witness-a \
  --public-key witness-a.public.hex \
  --output witness-a.trust.0.json
```

Create one transition. Both private keys sign the same domain-separated
payload.

```bash
pcbex sign-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation \
  witness-a.trust.0.json \
  --old-private-key witness-a.private.hex \
  --new-private-key witness-a-next.private.hex \
  --output witness-a.rotation.0-1.json
```

Verify the transition and publish the next immutable trust snapshot:

```bash
pcbex apply-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation \
  witness-a.trust.0.json \
  --rotation witness-a.rotation.0-1.json \
  --output witness-a.trust.1.json

pcbex export-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-public-key \
  witness-a.trust.1.json \
  --output witness-a.current.public.hex
```

> [!TIP]
> Pass `--rotated-at-unix` in reproducible fixtures. Omit it in live operation
> to record the current Unix time.

## Verify with Retained Trust

Pair each witness with its corresponding trust state. Do not mix trust states
and `--witness-public-keys` in one invocation.

```bash
pcbex verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witnesses \
  approval-log.with-receipt-quorum.json \
  --quorum-report receipt-quorum.report.json \
  --checkpoint factory-receipt-quorum.checkpoint.json \
  --checkpoint-public-key factory-receipt-quorum.public.hex \
  --witnesses factory-receipt-quorum.witness-a.json \
  --witnesses factory-receipt-quorum.witness-b.json \
  --witness-trust-states witness-a.trust.1.json \
  --witness-trust-states witness-b.trust.0.json \
  --minimum-witnesses 2 \
  --output factory-receipt-quorum.witness-quorum.json
```

The verifier still enforces the v1.507 freshness, distinct-ID, distinct-key,
and checkpoint-signer role-separation rules. A pre-rotation witness cannot
satisfy post-rotation trust, and a new-key witness cannot satisfy stale trust.

## Contracts

| Artifact | Exact binding | Limit |
| --- | --- | ---: |
| Trust state | Witness ID, generation, current key, latest rotation digest/time | 32 KiB |
| Signed rotation | Witness ID, adjacent generations, predecessor digest, old/new keys, time, two signatures | 32 KiB |
| Key file | One Ed25519 key as 64 lowercase hexadecimal digits, with optional LF | 65 bytes |

Rotation signatures use
`pcbex-factory-release-registry-receipt-quorum-log-checkpoint-witness-key-rotation-v1`
followed by a NUL byte. Approval-registry and other checkpoint-witness rotation
signatures cannot substitute.

Discover or normalize the closed contracts:

```bash
pcbex remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-trust-state-schema
pcbex signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation-schema

pcbex validate-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-trust-state \
  witness-a.trust.1.json

pcbex validate-signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation \
  witness-a.rotation.0-1.json
```

## Verification Flow

1. Parse one canonical retained trust state.
2. Require the rotation to name the same witness, retained generation, key,
   and predecessor digest.
3. Require exactly one generation of progress and a nondecreasing rotation
   time.
4. Verify old-key authorization and new-key possession over the exact same
   domain-separated payload.
5. Re-read every input by byte count and SHA-256.
6. Publish one alias-free, no-clobber trust snapshot.

## Trust Boundary

This contract proves that both the retained and successor keys approved one
exact adjacent transition for one witness identity. It makes stale keys and
missing rotation links fail closed when the verifier receives the current
trust state.

It does not protect private keys or retained files, establish trusted time or
legal identity, prove that witness operators are independent, prevent global
equivocation, publish evidence, place an order, approve payment, or guarantee
exactly-once execution.
