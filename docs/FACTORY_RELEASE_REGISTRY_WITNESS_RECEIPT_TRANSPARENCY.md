# Factory-release Registry Witness Receipt Transparency

Turn verified remote-witness transport receipts into signed, append-only
evidence that independent consumers can compare.

The v1.502 contract adds one factory-release receipt kind to the existing
approval transparency log. It preserves every v1.501 receipt, witness,
checkpoint, trust-state, and quorum wire format.

> [!IMPORTANT]
> Append performs strict structural admission. It does not re-fetch the remote
> response or re-verify the witness signature against retained trust evidence.
> Admit only receipts produced inside a trusted v1.501 acquisition boundary.

## Key features

- **Rejects malformed receipts:** Requires canonical JSON, a closed field set,
  the exact adapter identity, valid bounds, a true verification decision, and
  a non-weak Ed25519 witness key.
- **Binds exact evidence:** Records the canonical compact receipt digest plus
  its checkpoint, request, response, and witness identities.
- **Chains every append:** Uses monotonic sequence and time, predecessor
  digests, and self-digests to expose mutation, deletion, reorder, and replay.
- **Signs one exact head:** Reuses the existing Ed25519 approval-log checkpoint
  over the full log digest, head, entry count, log ID, and signer.
- **Composes without a new trust format:** Existing anchors, consistency proofs,
  gossip observations, witness rotation, and witness quorum apply unchanged.
- **Publishes safely:** Writes a new no-clobber snapshot. The input log remains
  intact when receipt validation or append fails.

## Quick start

Start an empty receipt log:

```sh
pcbex init-approval-log \
  --log-id factory-release-registry-witness-receipts \
  --output receipt-log.0.json
```

Append one canonical receipt created by the v1.501 remote request command:

```sh
pcbex append-approval-log receipt-log.0.json \
  --artifact witness-a.remote-receipt.json \
  --kind remote-factory-release-registry-history-checkpoint-witness-receipt \
  --recorded-at-unix 1787811000 \
  --output receipt-log.1.json
```

Sign and verify the resulting head:

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
> Keep each prior log snapshot and signed checkpoint in deployment-owned,
> rollback-resistant storage. A valid newest file alone cannot prove that an
> older accepted head was never replaced.

## Event mapping

One admitted receipt produces one normalized event:

| Event field | Receipt binding |
| --- | --- |
| `artifact_kind` | `remote_factory_release_registry_history_checkpoint_witness_receipt` |
| `artifact_sha256` | SHA-256 of the canonical compact receipt JSON |
| `subject_id` | `checkpoint_sha256` |
| `request_sha256` | Exact remote request digest |
| `session_sha256` | Exact remote response digest |
| `signer_id` | `null`; the receipt is local transport evidence |
| `outcome` | `verified-witness:<witness_id>` |

The log checkpoint signer is the admission authority. Its signature protects
the resulting history; it does not transform the original receipt into an
externally signed witness statement.

## Verification flow

```text
v1.501 canonical receipt
          │
          ├── closed structural validation
          ▼
normalized receipt event
          │
          ├── sequence + predecessor + self digest
          ▼
new approval-log snapshot
          │
          ├── Ed25519 checkpoint
          ├── public anchor / consistency proof
          └── gossip / independent witness quorum
```

Each layer retains its own trust boundary. Receipt admission does not bypass
checkpoint-signing, anchor, observer, or witness policies.

## Contracts and limits

| Input or state | Limit | Enforcement |
| --- | ---: | --- |
| Remote receipt | 64 KiB | Canonical, duplicate-key-free, closed v1.501 parser |
| Remote response represented by the receipt | 1 MiB | Bound recorded and enforced during v1.501 acquisition |
| Transparency entries | 100,000 | Existing approval-log contract |
| Generic CLI file | 128 MiB | Regular, non-symlink, identity-checked read |
| Event text | 256 bytes | Existing approval-event validator |

Append rejects a false `verified` value, invalid HTTPS or test-loopback
endpoint, malformed lowercase SHA-256, weak witness key, out-of-range response
size or generation, future witness time, and incomplete trust-state binding.

## What a passing verification proves

A passing signed-log verification proves that:

- the supplied log is internally complete and hash-chain consistent;
- the admitted event binds one structurally valid canonical v1.501 receipt;
- the event preserves that receipt's checkpoint, request, response, and witness
  identities;
- the checkpoint signer signed the exact log ID, entry count, head, and full
  normalized log digest.

## What it does not prove

The contract does not prove that:

- append independently replayed the complete registry history, checkpoint
  trust state, exact response bytes, or witness signature;
- the local log or its retained baseline is rollback-resistant;
- recorded time comes from a trusted clock;
- an endpoint or operator has a claimed legal identity or operates
  independently;
- the receipt was externally signed, globally published, or observed by every
  consumer;
- the system has global non-equivocation, factory capacity, ordering, payment,
  or exactly-once execution.

Version 1.503 should add verifier-bound admission. That command should require
the retained complete history, checkpoint trust state, exact response bytes,
and direct or generation-chained witness trust, then replay v1.501 verification
before append.
