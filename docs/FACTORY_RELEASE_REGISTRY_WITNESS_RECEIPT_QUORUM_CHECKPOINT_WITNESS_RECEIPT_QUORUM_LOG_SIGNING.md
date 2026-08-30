# Factory Checkpoint-witness Receipt-quorum Log Signing

Sign one admitted checkpoint-witness receipt quorum. Nothing else.

The v1.513 gate preserves the v1.512 report and generic approval-checkpoint
formats. It validates the exact admission snapshot before reading private
signing material.

> [!IMPORTANT]
> Use the log and report published by the same v1.512 admission invocation. A
> partial, extended, substituted, unbound, or unrelated log fails closed.

## Key Features

- **Requires a successful quorum:** Accepts only a canonical v1.512 report whose
  configured threshold was met.

- **Matches the complete snapshot:** Recomputes the log chain and requires the
  exact ID, entry count, head, and canonical digest recorded by the report.

- **Checks every suffix event:** Matches the final sorted v1.510 events to the
  report's receipt, checkpoint, request, response, witness, and outcome fields.

- **Defers key access:** Rejects invalid public evidence before opening the
  private key file.

- **Re-reads every input:** Detects sequential mutation of the report, log, or
  key before publication.

- **Preserves compatibility:** Emits the existing generic approval-log
  checkpoint, so `verify-approval-log` stays unchanged.

## Quick Start

First publish the exact log/report pair with the
[v1.512 admission quorum](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_QUORUM_ADMISSION.md).
Then sign that pair:

```sh
pcbex sign-approval-log-with-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum \
  checkpoint-witness-receipts.log.1.json \
  --quorum-report checkpoint-witness-receipts.quorum.json \
  --private-key approval-log.private.hex \
  --signer-id factory-checkpoint-witness-receipt-log \
  --output checkpoint-witness-receipts.checkpoint.json
```

Verify the unchanged checkpoint format:

```sh
pcbex verify-approval-log \
  checkpoint-witness-receipts.log.1.json \
  --checkpoint checkpoint-witness-receipts.checkpoint.json \
  --public-key approval-log.public.hex \
  --output checkpoint-witness-receipts.verification.json
```

## Signing Gate

| Stage | Required check |
| --- | --- |
| Report | Closed canonical v1 document, 2–100 threshold, sorted distinct members, successful decision, complete admission-log binding |
| Log | Valid bounded approval log, monotonic event times, intact hash chain, exact final head |
| Snapshot | Report and log agree on ID, entry count, head SHA-256, and complete canonical SHA-256 |
| Suffix | One unchanged v1.510 checkpoint-witness receipt event per report member, in witness-ID order |
| Event | Exact receipt/checkpoint/request/response binding, no signer ID, exact `verified-witness:<id>` outcome |
| Key | Read only after every public evidence check succeeds |
| Publication | Re-read all inputs, reject aliases and existing destinations, write one generic checkpoint |

The complete log digest binds every entry before the admitted suffix. The gate
therefore rejects both a truncated prefix and any later append.

## Failure Semantics

The command returns nonzero and creates no output when:

- the report is malformed, noncanonical, unbound, or below threshold;
- the log ID, count, head, complete digest, or hash chain differs;
- the final suffix is incomplete, reordered, extended, or uses another artifact
  kind;
- any receipt, checkpoint, request, response, witness, signer, or outcome field
  differs;
- the output aliases an input, traverses a symlink alias, or already exists;
- an input changes before publication, or the signer ID/private key is invalid.

> [!TIP]
> Pair a deliberately missing private key with mismatched public evidence when
> testing key-access order. The command reports the evidence mismatch first.

## Limits

| Artifact | Bound |
| --- | ---: |
| Approval transparency log | 128 MiB / 100,000 entries |
| Canonical v1.512 quorum report | 128 KiB / 100 members |
| Private key file | 1 KiB; trims to 64 lowercase hex digits |
| Checkpoint output | Existing bounded generic approval checkpoint |

## MCP

The task-forbidden destructive tool is
`sign_quorum_bound_factory_checkpoint_witness_receipt_transparency_log`. It
mirrors the CLI and returns the generic checkpoint when execution succeeds.

## Trust Boundary

Passing proves that one generic checkpoint was issued for the exact admission
log bound by one successful v1.512 report. It does not replay the raw receipts,
responses, report inputs, dedicated checkpoint, witness signatures, or trust
states during signing; v1.512 owns those checks.

The gate also does not protect files, state, or keys; add a dedicated signature
domain; establish trusted time or operator independence; publish evidence
globally; prevent equivocation; or prove ordering, payment, or exactly-once
execution.
