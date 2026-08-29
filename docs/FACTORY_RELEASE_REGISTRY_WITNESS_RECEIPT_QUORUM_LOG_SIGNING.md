# Factory-release Receipt-quorum Log Signing

Sign only the approval-log snapshot produced by one successful verifier-bound
factory receipt quorum.

The v1.505 gate preserves the v1.504 report and generic approval checkpoint
formats. It adds a strict evidence check before private signing material is read.

> [!IMPORTANT]
> Use the log and report written by the same quorum-admission invocation. A
> partial, extended, substituted, unbound, or unrelated log fails closed.

## Key Guarantees

- **Validates the Chain:** Recomputes every approval-log entry and the final log
  digest before signing.
- **Matches the Snapshot:** Requires the exact log ID, entry count, head, and
  complete SHA-256 recorded by the quorum report.
- **Checks the Suffix:** Matches every ordered factory receipt event to its
  receipt, checkpoint, request, response, signer, and witness outcome.
- **Defers Key Access:** Rejects mismatched evidence before reading the private
  key file.
- **Fails Closed:** Creates no checkpoint when validation or signing fails.
- **Preserves Compatibility:** Emits the existing generic approval-log
  checkpoint format, so `verify-approval-log` remains unchanged.

## Quick Start

First create the bound log/report pair with the
[receipt quorum admission](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_ADMISSION.md)
command. Then sign that exact pair:

```bash
pcbex sign-approval-log-with-remote-factory-release-registry-history-checkpoint-witness-receipt-quorum \
  approval-log.with-receipt-quorum.json \
  --quorum-report receipt-quorum.report.json \
  --private-key approval-log.private.hex \
  --signer-id factory-release-registry-receipt-log \
  --output approval-log.checkpoint.json
```

Verify the resulting checkpoint with the existing command:

```bash
pcbex verify-approval-log \
  approval-log.with-receipt-quorum.json \
  --checkpoint approval-log.checkpoint.json \
  --public-key approval-log.public.hex \
  --output approval-log.verification.json
```

## Signing Gate

| Stage | Required check |
|---|---|
| Report | Canonical v1 document, met 2–100 threshold, sorted distinct members, complete log binding |
| Log | Valid schema, bounded entry count, monotonic time, intact hash chain, exact final head |
| Snapshot | Report and log agree on ID, entry count, head SHA-256, and complete log SHA-256 |
| Suffix | One factory registry-history witness-receipt event per report member, in witness-ID order |
| Event | Exact receipt/checkpoint/request/response binding, no signer ID, exact `verified-witness:<id>` outcome |
| Key | Read only after every evidence check succeeds |
| Output | One alias-free, no-clobber generic approval-log checkpoint |

The full log digest also binds all entries before the admitted suffix. The gate
therefore rejects both a truncated prefix and any later append.

## Failure Semantics

The command returns nonzero and creates no output when:

- the report is noncanonical, malformed, unbound, or below threshold;
- the log chain, ID, count, head, or complete digest differs;
- the log contains fewer receipt events than the report;
- any suffix event uses another artifact kind or mismatched evidence;
- the output aliases an input, is a symlink alias, or already exists;
- the signer ID or private key is invalid.

> [!TIP]
> A missing private key combined with mismatched public evidence reports the
> evidence error first. This makes key-access ordering testable.

## Limits

| Artifact | Bound |
|---|---:|
| Approval transparency log | 128 MiB / 100,000 entries |
| Receipt quorum report | 128 KiB / 100 members |
| Private key file | 1 KiB; trims to 64 lowercase hex digits |
| Checkpoint output | Existing bounded generic approval checkpoint |

## Trust Boundary

This gate proves that one generic checkpoint was issued for the exact local log
bound by the supplied successful quorum report. It does not replay the raw
history, receipts, responses, trust states, or witness signatures during
signing; v1.504 admission owns those checks.

It also does not protect local files or keys, add a receipt-quorum-specific
signature domain, establish trusted time, prove independent operators, or
provide global publication and non-equivocation. Use the v1.506
[domain-separated checkpoint](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT.md)
when the signature itself must carry the factory receipt-quorum purpose.
