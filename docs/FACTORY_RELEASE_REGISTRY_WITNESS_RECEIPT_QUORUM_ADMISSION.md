# Factory-release Registry Receipt Quorum Admission

Require multiple separately verified registry witnesses before their remote
receipts enter one approval transparency log.

The v1.504 contract preserves every v1.501 receipt and v1.502 event. It extends
the v1.503 admission boundary from one witness to a configurable 2–100 witness
quorum and emits a report bound to the exact resulting log.

> [!IMPORTANT]
> A receipt is not enough. Supply its exact retained response and the exact key
> evidence used when that receipt was created.

## What It Guarantees

- **Replays Once:** Audits the complete canonical registry history and
  reconstructs the retained checkpoint trust state once for the whole quorum.
- **Re-verifies Every Member:** Matches each receipt to its request, raw response
  bytes, normalized witness digest, identity, key, trust generation, and time.
- **Requires Distinct Members:** Rejects repeated witness identities, public
  keys, receipt digests, response digests, or witness digests.
- **Enforces Quorum:** Requires a configurable threshold from 2 through 100
  valid witnesses before any event is appended.
- **Canonicalizes Order:** Sorts admitted members by witness ID, so CLI argument
  order cannot change the resulting log or report.
- **Publishes Together:** Writes the new immutable log snapshot and its bound
  quorum report as a no-clobber output set.
- **Detects Late Changes:** Re-reads every input by byte count and SHA-256
  immediately before publication.

## Quick Start

Use either directly pinned witness keys or witness key trust states for the
entire quorum. Do not mix the two modes in one invocation.

```bash
pcbex append-verified-remote-factory-release-registry-history-checkpoint-witness-receipt-quorum \
  approval-log.json \
  --receipt witness-a.receipt.json \
  --receipt witness-b.receipt.json \
  --history registry-history.json \
  --checkpoint-trust-state registry-history.checkpoint.trust.json \
  --response witness-a.response.json \
  --response witness-b.response.json \
  --trusted-witness-id witness-a \
  --trusted-witness-public-key witness-a.public.hex \
  --trusted-witness-id witness-b \
  --trusted-witness-public-key witness-b.public.hex \
  --minimum-witnesses 2 \
  --output approval-log.with-receipt-quorum.json \
  --report-output receipt-quorum.report.json
```

For rotatable witness keys, replace the direct identity/key pairs:

```bash
pcbex append-verified-remote-factory-release-registry-history-checkpoint-witness-receipt-quorum \
  approval-log.json \
  --receipt witness-a.receipt.json \
  --receipt witness-b.receipt.json \
  --history registry-history.json \
  --checkpoint-trust-state registry-history.checkpoint.trust.json \
  --response witness-a.response.json \
  --response witness-b.response.json \
  --witness-key-trust-state witness-a.trust.json \
  --witness-key-trust-state witness-b.trust.json \
  --minimum-witnesses 2 \
  --output approval-log.with-receipt-quorum.json \
  --report-output receipt-quorum.report.json
```

> [!TIP]
> `--receipt` and `--response` pair by position. Key evidence resolves by
> witness ID, so its argument order does not matter.

## Verification Flow

| Stage | Check |
|---|---|
| History | Parse the complete canonical genesis-to-head history and replay every production transition verifier |
| Checkpoint | Reconstruct the retained checkpoint trust state from that exact history |
| Request | Recreate the exact v1.501 request and match its SHA-256 |
| Receipt | Require canonical, verified, bounded receipts for one registry, generation, history, and checkpoint |
| Response | Match the exact retained bytes, byte length, SHA-256, and normalized witness digest |
| Trust | Require either direct keys for every member or exact generation-bound trust states for every member |
| Witness | Re-verify freshness, identity, key, role separation, and Ed25519 signature |
| Quorum | Reject duplicate identities, keys, receipts, responses, or witnesses; then enforce the threshold |
| Admission | Append normalized receipt events in witness-ID order and bind the report to the resulting log |
| Publication | Re-read every input, then publish the log/report pair without overwrite |

## Quorum Report

The canonical report records:

- the exact history, checkpoint, and checkpoint trust-state digests;
- the evaluation time and configured threshold;
- one sorted member per admitted witness;
- each member's key mode, trust generation, receipt, request, response, witness,
  and witness time;
- the final log ID, entry count, head digest, and complete log digest.

Validate or normalize a retained report without admitting anything:

```bash
pcbex validate-remote-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-receipt-quorum-report \
  receipt-quorum.report.json \
  --output receipt-quorum.report.normalized.json
```

## Failure Semantics

Admission fails closed. Neither output is created when:

- any receipt, response, trust state, key, history, or checkpoint is invalid;
- members target different retained evidence;
- a witness is stale, future-dated, untrusted, role-colliding, or incorrectly
  signed;
- identities, keys, receipt digests, response digests, or witness digests repeat;
- the configured threshold is not met;
- an input changes during final revalidation;
- an output aliases an input, aliases the other output, or already exists.

## Limits

| Input | Limit |
|---|---:|
| Receipts / responses / key-evidence members | 100 each |
| Minimum witnesses | 2–100 |
| Complete registry history | 128 MiB |
| Approval transparency log | 128 MiB |
| Receipt | 64 KiB each |
| Signed witness response | 32 KiB each |
| Witness key trust state | 32 KiB each |
| Direct public-key file | 65 bytes each |
| Quorum report | 128 KiB |

## Trust Boundary

This command proves that the supplied local evidence met one verifier-bound
quorum at one evaluation time. It does not protect the local files or clock,
prove that witnesses belong to independent organizations, authenticate an
endpoint or legal identity, or establish global publication and
non-equivocation.

It also does not prove factory capacity, order placement, payment, fulfillment,
or exactly-once execution. The final input check is sequential; it is not an
atomic same-principal filesystem snapshot.

The next boundary should bind receipt-quorum-aware signing to this exact report
and log suffix, refusing partial, extended, or unrelated logs.
