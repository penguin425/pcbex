# Quorum-bound Final Checkpoint-witness Receipt-log Signing

Sign the exact final-receipt quorum snapshot. Nothing else.

The v1.522 gate preserves every v1.521 artifact and the generic approval
checkpoint format. It validates the complete public snapshot before reading
private signing material.

> [!IMPORTANT]
> Use the log and report published by the same v1.521 quorum-admission command.
> A partial, extended, substituted, unbound, or unrelated log fails closed.

## Key Features

- **Requires a met quorum:** Accepts only a canonical v1.521 report whose
  configured final-witness threshold succeeded.

- **Matches the full log:** Recomputes the chain and requires the exact log ID,
  entry count, head, and canonical digest recorded by the report.

- **Checks the sorted suffix:** Matches every final v1.519 receipt event to its
  report member in canonical witness-ID order.

- **Defers key access:** Rejects invalid public evidence before opening the
  private-key file.

- **Re-reads every input:** Detects sequential mutation of the log, report, or
  key before publication.

- **Keeps compatibility:** Emits the existing generic approval checkpoint, so
  `verify-approval-log` remains unchanged.

## Quick Start

First create the exact log/report pair with the
[v1.521 quorum-admission boundary](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_ADMISSION.md).
Then sign that pair:

```sh
pcbex sign-approval-log-with-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-receipt-quorum \
  final-witness-receipts.log.json \
  --quorum-report final-witness-receipts.quorum.json \
  --private-key approval-log.private.hex \
  --signer-id factory-final-checkpoint-witness-receipt-log \
  --output final-witness-receipts.checkpoint.json
```

Verify the unchanged checkpoint contract:

```sh
pcbex verify-approval-log \
  final-witness-receipts.log.json \
  --checkpoint final-witness-receipts.checkpoint.json \
  --public-key approval-log.public.hex \
  --output final-witness-receipts.verification.json
```

## Signing Gate

| Stage | Required check |
| --- | --- |
| Report | Closed canonical v1 document, 2–100 threshold, sorted distinct members, successful decision, complete final-log binding |
| Log | Valid bounded approval log, monotonic event times, intact hash chain, exact final head |
| Snapshot | Report and log agree on ID, entry count, head SHA-256, and complete canonical SHA-256 |
| Suffix | One unchanged v1.519 final checkpoint-witness receipt event per report member, in witness-ID order |
| Event | Exact receipt/checkpoint/request/response binding, no signer ID, exact `verified-witness:<id>` outcome |
| Key | Read only after every public-evidence check succeeds |
| Publication | Re-read all inputs, reject aliases and existing destinations, write one generic checkpoint |

The complete log digest covers every entry before the admitted suffix. The gate
therefore rejects both a truncated prefix and any later append.

## Failure Semantics

The command returns nonzero and creates no output when:

- the report is malformed, noncanonical, unbound, or below threshold;
- the log ID, count, head, complete digest, or hash chain differs;
- the final suffix is incomplete, reordered, extended, or uses another kind;
- any receipt, checkpoint, request, response, signer, or outcome field differs;
- the output aliases an input, traverses a symlink alias, or already exists; or
- an input changes before publication, or the signer ID/private key is invalid.

> [!TIP]
> Pair a deliberately missing private key with mismatched public evidence when
> testing key-access order. The command reports the evidence mismatch first.

## Limits

| Artifact | Bound |
| --- | ---: |
| Approval transparency log | 128 MiB / 100,000 entries |
| Canonical v1.521 quorum report | 128 KiB / 100 members |
| Private-key file | 1 KiB; trims to 64 lowercase hex digits |
| Checkpoint output | Existing bounded generic approval checkpoint |

## MCP

The task-forbidden destructive tool is
`sign_quorum_bound_factory_final_checkpoint_witness_receipt_transparency_log`.
It mirrors the CLI and returns the generic checkpoint on success.

## Trust Boundary

Passing proves that one generic checkpoint was issued for the exact final
admission log bound by one successful v1.521 report. It does not replay the raw
receipts, responses, report inputs, dedicated checkpoint, signatures, or trust
states during signing; v1.521 owns those checks.

The gate does not protect files, state, or keys; add a dedicated signature
domain; establish trusted time or operator independence; publish evidence
globally; prevent equivocation; or prove ordering, payment, or exactly-once
execution.
