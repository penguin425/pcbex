# Factory-state transparency witness quorum

Require independent, policy-pinned organizations to endorse one exact signed
factory-release checkpoint.

The v1.487 boundary layers distinct-organization Ed25519 receipts over the
latest fully reverified v1.486 consistency report. Every accepted witness must
sign the same report identity and the same embedded log tree head.

> [!IMPORTANT]
> This contract proves agreement only inside the supplied, policy-selected
> witness quorum. It does not prove global non-equivocation, real-world
> organizational independence, ledger rollback resistance, trusted time,
> endpoint or legal identity, capacity, order placement, payment, or
> exactly-once execution.

## When to use it

Use this boundary after
`verify-factory-release-state-transparency-consistency` has retained at least
one strict extension. Give the latest canonical v1.486 report to each witness.

Each witness signs offline. The release verifier later reloads the complete
v1.484–v1.486 chain and accepts only receipts for its exact latest checkpoint.

## 1. Define witness trust

Discover the closed policy schema:

```sh
pcbex factory-release-state-transparency-witness-policy-schema
```

A policy pins the threshold, maximum local receipt age, and one unique key per
configured organization:

```json
{
  "schema_version": 1,
  "policy_scope": "factory-release-state-transparency-witness-policy-v1",
  "policy_id": "production-release-witnesses",
  "minimum_organizations": 2,
  "maximum_receipt_age_seconds": 300,
  "trusted_witnesses": [
    {
      "organization_id": "audit-org-a",
      "witness_id": "release-witness-a",
      "algorithm": "ed25519",
      "public_key": "<64 lowercase hex>"
    },
    {
      "organization_id": "audit-org-b",
      "witness_id": "release-witness-b",
      "algorithm": "ed25519",
      "public_key": "<64 lowercase hex>"
    }
  ]
}
```

- **Pins externally:** Supply the expected policy SHA-256 from protected
  deployment configuration. The artifact cannot trust its own digest.

- **Counts organizations:** Requires 2–100 trusted entries and a threshold of
  2–100. Organization IDs, witness IDs, and public keys must each be unique.

- **Orders canonically:** Sort entries by organization ID, then witness ID.
  Reordered or duplicate entries fail before signing or verification.

- **Separates keys:** Rejects every witness policy that reuses the selected
  transparency-log signing key.

The expected digest is SHA-256 over compact semantic JSON in the documented
field order. The source itself must be canonical pretty JSON with one final
newline.

> [!NOTE]
> Distinct configured organization IDs and keys are enforceable facts.
> Ownership, custody, legal identity, and operational independence remain
> deployment assertions, so `independent_organization_operation_verified`
> stays false.

## 2. Sign the checkpoint

Each witness keeps its 32-byte Ed25519 seed in a separate file encoded as 64
lowercase hexadecimal characters. Sign the exact canonical v1.486 report
received by that witness:

```sh
pcbex sign-factory-release-state-transparency-witness-receipt \
  --consistency-report checkpoint.consistency-report.json \
  --witness-policy witness-policy.json \
  --expected-witness-policy-sha256 "$WITNESS_POLICY_SHA256" \
  --organization-id audit-org-a \
  --witness-id release-witness-a \
  --private-key witness-a.private.hex \
  --expires-at-unix 1700000300 \
  --output witness-a.receipt.json
```

`--witnessed-at-unix` defaults to the current local clock. Supplying it is
useful only for deterministic tests; it is not a trusted timestamp.

The command first validates the complete self-contained consistency report,
matches the derived public key to policy, and checks log-key separation. It
then signs a domain-separated payload that binds:

- the witness policy digest, organization ID, witness ID, and public key;
- the release idempotency key and v1.486 checkpoint generation;
- the exact canonical consistency-report SHA-256;
- the complete signed log tree head and its compact semantic SHA-256; and
- the witness and expiry instants.

Discover the receipt contract with:

```sh
pcbex factory-release-state-transparency-witness-receipt-schema
```

Receipt lifetime must be 1–604,800 seconds. A witness instant cannot predate
the signed log-head observation instant.

## 3. Verify and retain the quorum

Supply one receipt per selected organization:

```sh
pcbex verify-factory-release-state-transparency-witness-quorum \
  --reservation-ledger /srv/pcbex/release-ledger \
  --expected-ledger-id "$LEDGER_SHA256" \
  --idempotency-key "$IDEMPOTENCY_KEY" \
  --log-id factory-release-log \
  --policy-pack organization-policy.json \
  --expected-policy-sha256 "$POLICY_SHA256" \
  --transparency-policy transparency-policy.json \
  --expected-transparency-policy-sha256 "$TRANSPARENCY_POLICY_SHA256" \
  --witness-policy witness-policy.json \
  --expected-witness-policy-sha256 "$WITNESS_POLICY_SHA256" \
  --witness-receipt witness-a.receipt.json \
  --witness-receipt witness-b.receipt.json \
  --output checkpoint.witness-quorum-report.json \
  --require-accepted
```

The durable verifier is Unix-only because it reuses the pinned `0700` release
ledger. It consumes supplied evidence and performs no network request.

The verifier fails closed unless all conditions hold:

- **Replays every chain:** Reloads the complete monotonic factory-state chain,
  both inclusion reports for every retained transition, and the complete
  v1.486 predecessor chain back to its v1.485 anchor.

- **Selects the latest head:** Uses the exact latest retained v1.486 report for
  the independently supplied log ID. An older generation cannot be selected.

- **Pins every signer:** Matches each receipt to one exact organization, ID,
  and non-weak Ed25519 key from the externally pinned witness policy.

- **Requires exact agreement:** Every receipt must embed the exact current
  signed tree head and bind the exact canonical v1.486 report SHA-256. A
  different root at the same size reports a detected split view and fails.

- **Enforces freshness:** Requires the local evaluation instant inside every
  receipt window and no more than the policy age after each witness instant.

- **Counts once:** Rejects duplicate organizations, identities, keys, or
  receipt artifacts before applying the threshold.

## Durable retry

Accepted evidence commits without replacement under:

```text
factory-release-state-transparency-witness-quorum-v1-<idempotency-key>-<log-id>-<generation>-<witness-policy-sha256>.json
```

The pre-commit report keeps
`selected_ledger_witness_quorum_report_committed` false. Exact retry with the
same receipt set returns the retained bytes even after the original receipt
window closes.

A different receipt set, checkpoint, or policy cannot replace that record.
Input files, the ledger manifest, monotonic head, and v1.486 head are rechecked
around no-replace publication.

## Report and limits

Print the recursively closed report schema:

```sh
pcbex factory-release-state-transparency-witness-quorum-verification-report-schema
```

The report embeds the complete v1.486 report, witness policy, and every signed
receipt. It also binds exact artifact identities, sorted members, threshold,
freshness extrema, evaluation instant, positive claims, and explicit nonclaims.

| Boundary | Limit |
| --- | ---: |
| Witness policy | 64 KiB |
| Witness receipt | 64 KiB each |
| Witness entries and supplied receipts | 100 |
| Receipt lifetime and policy age | 604,800 seconds |
| Quorum report | 2 MiB |

Unknown or duplicate JSON fields, alternate formatting, oversized input,
unsafe file types, aliases, weak keys, mutation, and input/output overlap fail
before public output appears.

## What remains

This release closes bounded split-view comparison for the selected witness
set. A log can still withhold a view from every supplied witness or target
observers outside the quorum.

External ledger anchoring is the next independent trust step. Trusted
timestamping, transport and legal identity, real capacity, order authority,
payment, and exactly-once execution remain separate boundaries.
