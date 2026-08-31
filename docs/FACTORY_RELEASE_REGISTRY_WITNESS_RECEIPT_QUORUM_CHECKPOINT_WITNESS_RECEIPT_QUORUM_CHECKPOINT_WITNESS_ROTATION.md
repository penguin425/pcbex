# Factory Checkpoint-witness Receipt-quorum Witness Key Rotation

Rotate the final factory checkpoint witness keys without changing witness
identities or trusting an unapproved successor.

The v1.516 contract preserves the v1.515 signed witness and quorum-report wire
formats. It adds a retained trust state and one dual-signed,
generation-chained rotation artifact.

> [!IMPORTANT]
> Protect the latest trust state in deployment-owned storage. The digest chain
> detects stale or skipped transitions, but cannot stop an attacker from
> replacing every local file with an older, internally consistent set.

## Key Features

- **Pins Identity:** Binds one final witness ID to its current Ed25519 key and
  generation.

- **Requires Both Keys:** The retained key authorizes the change. The successor
  key proves possession before activation.

- **Advances Once:** Accepts only `generation + 1`, from generation 0 through
  4096.

- **Chains Rotations:** Commits each transition to the previous canonical
  rotation SHA-256.

- **Rejects Rollback:** Refuses stale state, replayed rotations, skipped
  generations, decreasing timestamps, weak keys, and unchanged keys.

- **Preserves Quorum:** Verifies unchanged v1.515 witnesses through either
  direct public-key pins or current trust states.

## Quick Start

Initialize trust from the currently approved final witness key:

```bash
pcbex init-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-trust \
  --witness-id witness-a \
  --public-key witness-a.public.hex \
  --output witness-a.trust.0.json
```

Create one transition. Both private keys sign the same domain-separated
payload.

```bash
pcbex sign-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-key-rotation \
  witness-a.trust.0.json \
  --old-private-key witness-a.private.hex \
  --new-private-key witness-a-next.private.hex \
  --output witness-a.rotation.0-1.json
```

Verify the transition and publish the next immutable trust snapshot:

```bash
pcbex apply-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-key-rotation \
  witness-a.trust.0.json \
  --rotation witness-a.rotation.0-1.json \
  --output witness-a.trust.1.json

pcbex export-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-public-key \
  witness-a.trust.1.json \
  --output witness-a.current.public.hex
```

> [!TIP]
> Pass `--rotated-at-unix` in reproducible fixtures. Omit it in live operation
> to record the current Unix time.

## Verify with Retained Trust

Pair every signed witness with its corresponding trust state. Never mix trust
states and `--witness-public-keys` in one invocation.

```bash
pcbex verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witnesses \
  checkpoint-witness-receipts.log.json \
  --quorum-report checkpoint-witness-receipts.quorum.json \
  --checkpoint checkpoint-witness-receipts.quorum.checkpoint.json \
  --checkpoint-public-key checkpoint-witness-receipts.quorum.public.hex \
  --witnesses final-checkpoint.witness-a.json \
  --witnesses final-checkpoint.witness-b.json \
  --witness-trust-states witness-a.trust.1.json \
  --witness-trust-states witness-b.trust.0.json \
  --minimum-witnesses 2 \
  --output final-checkpoint.witness-quorum.json
```

The verifier still enforces v1.515 freshness, distinct identities, distinct
keys, and checkpoint-signer role separation. A pre-rotation witness fails
current trust; a successor-key witness fails stale trust.

## Contracts

| Artifact | Exact binding | Limit |
| --- | --- | ---: |
| Trust state | Witness ID, generation, current key, latest rotation digest/time | 32 KiB |
| Signed rotation | Witness ID, adjacent generations, predecessor digest, old/new keys, time, two signatures | 32 KiB |
| Key file | One Ed25519 key as 64 lowercase hexadecimal digits, with optional LF | 65 bytes |

Rotation signatures use
`pcbex-factory-release-registry-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-key-rotation-v1`
followed by a NUL byte. Earlier factory witness-rotation signatures cannot
substitute.

Discover or normalize the closed contracts:

```bash
pcbex remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-trust-state-schema
pcbex signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-key-rotation-schema

pcbex validate-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-trust-state \
  witness-a.trust.1.json

pcbex validate-signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-key-rotation \
  witness-a.rotation.0-1.json
```

## Verification Flow

1. Parse one canonical retained trust state.
2. Match the witness identity, retained generation, current key, and
   predecessor digest.
3. Require exactly one generation of progress and a nondecreasing rotation
   time.
4. Verify old-key authorization and new-key possession over one exact payload.
5. Re-read every input by byte count and SHA-256.
6. Publish one alias-free, no-clobber trust snapshot.

## Trust Boundary

This contract proves that both the retained and successor keys approved one
exact adjacent transition for one final witness identity. Current trust makes
stale keys and missing rotation links fail closed.

It does not protect private keys or retained files, establish trusted time or
legal identity, prove independent witness operation, prevent global
equivocation, publish evidence, place an order, approve payment, or guarantee
exactly-once execution.

The unchanged v1.515
[witness boundary](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESSES.md)
accepts direct pins for static deployments and current trust states when final
witness keys rotate.

The v1.517
[remote acquisition boundary](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_REMOTE_WITNESSES.md)
can resolve this current trust state before verifying and retaining an
unchanged v1.515 response.
