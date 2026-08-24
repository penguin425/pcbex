# Factory-state transparency consistency

Prove that a newer signed factory-state transparency checkpoint strictly
extends a retained checkpoint from the same log.

The v1.486 boundary layers a bounded RFC 6962-shaped consistency proof over two
fully verified v1.485 inclusion reports. It retains each accepted transition in
one deterministic, no-replace chain inside the selected Unix ledger.

> [!IMPORTANT]
> This contract proves append-only consistency between the selected retained
> views. It does not prove that every observer received the same view, protect
> the ledger itself from rollback, establish trusted time, authenticate a
> network endpoint or legal factory, reserve capacity, place an order, or pay.

## When to use it

Use this boundary after `verify-factory-release-state-transparency-receipt` has
retained the first checkpoint for a state sequence and log. Obtain a strictly
newer inclusion receipt plus a consistency path from that log.

Generation 1 anchors to the retained v1.485 report. Later generations anchor to
the exact preceding v1.486 report automatically.

## Verify the first extension

```sh
pcbex verify-factory-release-state-transparency-consistency \
  --reservation-ledger /srv/pcbex/release-ledger \
  --expected-ledger-id "$LEDGER_SHA256" \
  --idempotency-key "$IDEMPOTENCY_KEY" \
  --policy-pack organization-policy.json \
  --expected-policy-sha256 "$POLICY_SHA256" \
  --transparency-policy factory-transparency-policy.json \
  --expected-transparency-policy-sha256 "$TRANSPARENCY_POLICY_SHA256" \
  --receipt checkpoint-42.receipt.json \
  --consistency-proof checkpoint-17-to-42.proof.json \
  --anchor-state-sequence 1 \
  --output checkpoint-42.consistency-report.json \
  --require-accepted
```

`--anchor-state-sequence` is required only while bootstrapping generation 1.
It selects this retained record:

```text
factory-release-state-transparency-v1-<idempotency-key>-<sequence>-<log-id>.json
```

For the next strict extension, omit the anchor:

```sh
pcbex verify-factory-release-state-transparency-consistency \
  --reservation-ledger /srv/pcbex/release-ledger \
  --expected-ledger-id "$LEDGER_SHA256" \
  --idempotency-key "$IDEMPOTENCY_KEY" \
  --policy-pack organization-policy.json \
  --expected-policy-sha256 "$POLICY_SHA256" \
  --transparency-policy factory-transparency-policy.json \
  --expected-transparency-policy-sha256 "$TRANSPARENCY_POLICY_SHA256" \
  --receipt checkpoint-58.receipt.json \
  --consistency-proof checkpoint-42-to-58.proof.json \
  --output checkpoint-58.consistency-report.json
```

> [!NOTE]
> The command consumes supplied evidence. It never contacts the transparency
> log and never reads a credential.

## Proof contract

Discover the closed schema at runtime:

```sh
pcbex factory-release-state-transparency-consistency-proof-schema
```

A proof binds the exact compact-JSON SHA-256 identities of both signed tree
heads and carries the ordered consistency nodes:

```json
{
  "schema_version": 1,
  "proof_scope": "factory-release-state-transparency-consistency-proof-v1",
  "previous_tree_head_sha256": "<64 lowercase hex>",
  "current_tree_head_sha256": "<64 lowercase hex>",
  "consistency_path": ["<64 lowercase hex>"]
}
```

The log or an independently operated client constructs this path from the
ordered leaf snapshot. `pcbex` only verifies it.

## Verification contract

The verifier fails closed unless all conditions hold:

- **Replays state:** Fully verifies the complete retained v1.484 monotonic state
  chain before selecting any report source.

- **Rechecks inclusion:** Revalidates both embedded v1.485 reports against their
  exact state entries, observations, organization-policy pin, transparency-policy
  pin, receipt bytes, log key, signature, inclusion path, and original local
  freshness evaluation.

- **Keeps one identity:** Requires the same release subject, idempotency key,
  factory, provider, manufacturing package, log ID, log key, and both policy
  digests.

- **Requires growth:** Rejects a smaller tree as rollback. Rejects a different
  root at the same size as equivocation, and rejects an identical same-size view
  because a v1.486 transition must be a strict extension.

- **Prevents time reversal:** Requires the newer signed observation instant to
  be greater than or equal to the retained one. This is ordering, not trusted
  time.

- **Reconstructs both roots:** Applies the bounded RFC 6962-shaped path to the
  trusted previous root and requires exact reconstruction of both signed roots.

- **Reloads the chain:** Validates every retained generation back to the exact
  v1.485 anchor before publication and again around the durable commit.

## Durable records and retry

Each accepted transition is committed under:

```text
factory-release-state-transparency-consistency-v1-<idempotency-key>-<log-id>-<generation>.json
```

The selected ledger must remain an absolute pinned `0700` Unix directory. Each
generation uses no-replace publication; a competing transition cannot overwrite
the winner.

Retry the latest receipt and proof byte for byte. An exact retry returns the
retained report, even when a later test-only evaluation time would make the
checkpoint stale. Reusing only one side of the evidence pair fails as a
conflict, and replaying an older generation after the chain advances fails as a
rollback.

## Report and limits

Print the closed report schema with:

```sh
pcbex factory-release-state-transparency-consistency-verification-report-schema
```

The report embeds both fully verified inclusion reports, the exact proof, its
artifact identity, predecessor identity, tree sizes, roots, observation order,
policy pins, generation, and explicit positive and negative claims.

| Boundary | Limit |
| --- | ---: |
| Consistency proof | 32 KiB |
| Consistency path | 64 nodes |
| Signed tree | 100,000 leaves |
| Consistency report | 256 KiB |
| Durable generations per log and release key | 10,000 |

Canonical pretty JSON is mandatory. Duplicate keys, unknown fields, oversized
inputs, unsafe file types, aliases, and input/output overlap fail before public
output appears.

## What remains

Version 1.487 adds an independent witness quorum over the exact latest report
and signed tree head. It can reject conflicting views inside the supplied,
policy-selected organization set; this local consistency chain alone cannot.

Global non-equivocation, ledger rollback resistance, and trusted timestamps
remain separate milestones. Keep those claims false until external trust
anchors prove them.
