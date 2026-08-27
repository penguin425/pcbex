# Verifier-bound Factory-release Registry Receipt Admission

Re-verify retained registry evidence at the moment a remote-witness receipt
enters the signed transparency log.

The v1.503 contract preserves the v1.501 receipt and v1.502 event formats. It
adds one stricter admission command with no new receipt schema.

> [!IMPORTANT]
> Supply the exact response file retained by the v1.501 request command. A
> parsed, rewritten, or substituted witness is different evidence.

## Key features

- **Replays complete history:** Audits the canonical registry history from
  empty genesis through every retained governance event.
- **Reconstructs checkpoint trust:** Requires the supplied trust state to equal
  the production acceptance result for that exact history and checkpoint.
- **Rebuilds the request:** Recreates the protocol request and matches its
  SHA-256 against the receipt.
- **Matches raw evidence:** Checks exact history, trust-state, response, and
  normalized witness digests plus the recorded response length.
- **Re-verifies the witness:** Enforces identity, key, trust generation,
  freshness, role disjointness, and the Ed25519 signature at admission time.
- **Publishes atomically:** Writes one alias-free no-clobber log snapshot only
  after every verifier and final input re-read succeeds.

## Quick start

Create an empty receipt log:

```sh
pcbex init-approval-log \
  --log-id factory-release-registry-witness-receipts \
  --output receipt-log.0.json
```

Admit a receipt against a rotatable witness trust state:

```sh
pcbex append-verified-remote-factory-release-registry-history-checkpoint-witness-receipt \
  receipt-log.0.json \
  --receipt witness-a.remote-receipt.json \
  --history registry-history.json \
  --checkpoint-trust-state registry-checkpoint.trust.json \
  --response witness-a.remote.json \
  --witness-key-trust-state witness-a.trust.json \
  --output receipt-log.1.json
```

Then sign and verify the admitted log head:

```sh
pcbex sign-approval-log receipt-log.1.json \
  --private-key receipt-log.secret.hex \
  --signer-id factory-release-registry-receipt-log \
  --output receipt-log.checkpoint.json

pcbex verify-approval-log receipt-log.1.json \
  --checkpoint receipt-log.checkpoint.json \
  --public-key receipt-log.public.hex \
  --output receipt-log.verification.json
```

> [!TIP]
> Set `--evaluated-at-unix` only for deterministic replay or tests. Production
> admission should use the current clock and a deployment-owned trust source.

## Direct-key mode

Use a directly pinned key when rotation is managed outside pcbex:

```sh
pcbex append-verified-remote-factory-release-registry-history-checkpoint-witness-receipt \
  receipt-log.0.json \
  --receipt witness-b.remote-receipt.json \
  --history registry-history.json \
  --checkpoint-trust-state registry-checkpoint.trust.json \
  --response witness-b.remote.json \
  --public-key witness-b.public.hex \
  --output receipt-log.1.json
```

`--public-key` and `--witness-key-trust-state` are mutually exclusive. The
receipt must record the same trust mode supplied during admission.

## Verification pipeline

| Stage | Required binding | Failure result |
| --- | --- | --- |
| Capture | Log, receipt, complete history, checkpoint trust, response, key evidence | No destination file |
| History replay | Empty genesis, every event, final registry, retained root and governance | No append |
| Checkpoint reconstruction | Exact signed checkpoint and accepted trust state | No append |
| Request reconstruction | Protocol, schema version, exact checkpoint trust state | No append |
| Response binding | Exact bytes, byte count, SHA-256, canonical signed witness | No append |
| Trust verification | Direct key or exact trust-state digest and generation | No append |
| Witness verification | Identity, key, freshness, role separation, Ed25519 signature | No append |
| Publication | Same normalized v1.502 event plus final input re-read | New immutable snapshot |

The event mapping remains unchanged. Existing signed checkpoints, anchors,
consistency proofs, gossip receipts, witness rotation, and witness quorum can
consume the resulting log.

## Inputs and limits

| Input | Limit | Enforcement |
| --- | ---: | --- |
| Complete registry history | 128 MiB | Canonical, duplicate-key-free, closed history parser |
| Checkpoint trust state | 64 KiB | Canonical retained-root trust parser and reconstruction |
| Remote receipt | 64 KiB | Canonical closed v1.501 receipt parser |
| Exact response witness | 32 KiB | Canonical signed-witness parser |
| Direct public key | 65 bytes | Lowercase 32-byte Ed25519 key plus optional LF |
| Witness trust state | 32 KiB | Canonical generation-chained trust parser |
| Approval log | 128 MiB and 100,000 entries | Existing log validator and append bound |

Every captured input is read again before publication. The second read must
match the original byte count and SHA-256.

> [!NOTE]
> Final revalidation detects sequential changes. It does not create an atomic
> snapshot across files controlled by the same local principal.

## Failure behavior

Admission fails without the requested output when any retained artifact is
missing, non-canonical, aliased with the output, changed during verification,
or bound to different evidence.

It also rejects false receipt decisions, truncated history, checkpoint
substitution, response substitution, stale or future-dated witnesses, old trust
generations, identity/key substitution, weak keys, and invalid signatures.

## What success proves

A successful admission proves that:

- one exact canonical v1.501 receipt was re-verified at the supplied admission
  time;
- its complete history and retained checkpoint trust replayed through the
  production verifier;
- its request and response bindings match the exact retained bytes;
- its witness matched the selected current trust and supplied a valid fresh
  Ed25519 signature;
- the same normalized v1.502 event entered one internally valid successor log
  snapshot.

## What it does not prove

The contract does not protect the retained history, trust state, response, or
log from rollback before capture. It does not establish a trusted clock,
endpoint authenticity, legal identity, independent operation, or global
publication and non-equivocation.

One admitted receipt is still selected-witness evidence. It does not prove a
multi-witness admission quorum, factory capacity, ordering, payment, or
exactly-once execution.

Version 1.504 should require a configurable threshold of distinct independently
reverified receipts before appending their canonically ordered events as one
transaction.
