# Factory-state transparency external-log gossip

Compare one retained external-log head with a separately observed signed view.

The v1.490 boundary reloads the complete v1.484–v1.489 release chain, verifies
the log and observer signatures, and proves that the two selected views describe
one append-only tree. A same-size root mismatch fails closed as a split view.

> [!IMPORTANT]
> This contract compares one local view with one pinned observer view. It does
> not prove global non-equivocation, an observer quorum, real organizational
> independence, key custody, trusted time, ledger rollback resistance,
> transport or legal identity, capacity, ordering, payment, or exactly-once
> execution.

## When to use it

Use this boundary after
`verify-factory-release-state-transparency-external-consistency` has retained at
least one v1.489 generation. Give an independently operated observer the
external-log identity and ask it to return a signed receipt for the head it saw.

The verifier performs no network request. Deployment configuration supplies
the observer ID and public key independently of both the receipt and the
external-anchor policy.

## Trust inputs

Keep the trust roots separate.

| Input | Owner | What it selects |
| --- | --- | --- |
| Organization policy digest | Release deployment | Factory and source release context |
| Transparency policy digest | Release deployment | Source-log key and freshness |
| Witness policy digest | Release deployment | Witness organizations, IDs, keys, and threshold |
| External-anchor policy digest | Release deployment | External log ID, key, and maximum checkpoint age |
| Observer ID and public key | Gossip deployment | The one observer allowed to sign this comparison |

The observer ID cannot reuse a source-log, external-log, witness, witness
organization, or factory ID. Its non-weak Ed25519 key cannot reuse a source-log,
external-log, or witness key.

> [!NOTE]
> Role separation is a configuration invariant, not proof that two services
> have different owners, operators, hosts, or key custodians.

## 1. Discover the contracts

Print both closed schemas:

```sh
pcbex factory-release-state-transparency-external-gossip-receipt-schema \
  --output external-gossip-receipt.schema.json

pcbex factory-release-state-transparency-external-gossip-verification-report-schema \
  --output external-gossip-report.schema.json
```

The receipt embeds the external log's complete signed tree head, then binds it
to a separately signed observer envelope:

```json
{
  "schema_version": 1,
  "receipt_scope": "factory-release-state-transparency-external-log-gossip-receipt-v1",
  "external_anchor_policy_sha256": "<64 lowercase hex>",
  "external_log_id": "release-public-log",
  "observer_id": "independent-observer-a",
  "observed_tree_head_sha256": "<64 lowercase hex>",
  "observed_tree_head": {
    "schema_version": 1,
    "tree_head_scope": "signed-factory-release-state-transparency-external-anchor-tree-head-v1",
    "log_id": "release-public-log",
    "tree_size": 73,
    "root_sha256": "<64 lowercase hex>",
    "observed_at_unix": 1700000030,
    "algorithm": "ed25519",
    "public_key": "<external-log public key>",
    "signature": "<external-log signature>"
  },
  "received_at_unix": 1700000031,
  "expires_at_unix": 1700000331,
  "algorithm": "ed25519",
  "observer_public_key": "<observer public key>",
  "signature": "<observer signature>"
}
```

JSON must use the canonical pretty form emitted by the schema-compatible
producer. Unknown fields, duplicate keys, uppercase hexadecimal, and alternate
whitespace fail parsing.

## 2. Sign the observer receipt

First compute `observed_tree_head_sha256` over the compact JSON bytes of the
complete external signed tree head. Then sign the compact JSON serialization of
this ordered payload with the observer key:

```json
{
  "domain": "pcbex-factory-release-state-transparency-external-log-gossip-receipt-v1",
  "schema_version": 1,
  "receipt_scope": "factory-release-state-transparency-external-log-gossip-receipt-v1",
  "external_anchor_policy_sha256": "<policy digest>",
  "external_log_id": "release-public-log",
  "observer_id": "independent-observer-a",
  "observed_tree_head_sha256": "<head digest>",
  "observed_tree_size": 73,
  "observed_root_sha256": "<root digest>",
  "observed_tree_head_observed_at_unix": 1700000030,
  "external_log_public_key": "<external-log public key>",
  "received_at_unix": 1700000031,
  "expires_at_unix": 1700000331,
  "algorithm": "ed25519",
  "observer_public_key": "<observer public key>"
}
```

The receipt lifetime must be positive and no longer than seven days. The
receipt cannot predate its embedded head, and the selected head must remain
within the external-anchor policy's age bound at evaluation.

## 3. Supply a consistency proof when needed

Compare the observer head with the current head embedded in the exact latest
v1.489 report.

| Relationship | Proof | Result |
| --- | --- | --- |
| Same size and same root | Omit | `same_tree` |
| Local size is smaller | Required, local → observed | `local_precedes_observed` |
| Observer size is smaller | Required, observed → local | `observed_precedes_local` |
| Same size and different root | Rejected | Split view |

The optional proof uses the unchanged v1.489 consistency-proof schema. Its
previous and current heads must equal the compared heads exactly, ordered from
the smaller tree to the larger tree.

> [!TIP]
> Do not attach a proof for an identical tree. Redundant proof bytes fail
> closed instead of becoming an alternate representation of the same result.

## 4. Verify and retain the comparison

Run the Unix-only verifier with the exact release-chain sources and independent
observer pins:

```sh
pcbex verify-factory-release-state-transparency-external-gossip \
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
  --external-anchor-policy external-anchor-policy.json \
  --expected-external-anchor-policy-sha256 "$ANCHOR_POLICY_SHA256" \
  --external-log-id release-public-log \
  --observer-id independent-observer-a \
  --expected-observer-public-key "$OBSERVER_PUBLIC_KEY" \
  --gossip-receipt external-gossip-receipt.json \
  --consistency-proof external-tree-58-to-73.proof.json \
  --output external-gossip-report.json \
  --require-accepted
```

Omit `--consistency-proof` only when both selected heads have the same size and
root. `--require-accepted` gates after durable retention, so valid negative
factory state cannot erase the gossip evidence.

## Verification order

The verifier fails closed unless it can:

- **Replay the local chain:** Reverify the current v1.484 state, v1.485
  inclusion, complete v1.486 source consistency, exact v1.487 witness quorum,
  v1.488 external anchor, and complete v1.489 external consistency chain.

- **Select the latest head:** Compare only the current head of the latest
  complete retained v1.489 generation.

- **Authenticate before interpretation:** Verify both external-log signatures,
  their policy/key binding, and the observer signature before using sizes,
  roots, timestamps, or proof nodes.

- **Match independent pins:** Require the exact observer ID and non-weak public
  key supplied by deployment configuration.

- **Separate roles:** Reject observer identity or key reuse across the selected
  log, witness, and factory roles.

- **Prove one relationship:** Accept an identical tree directly, or consume one
  bounded consistency path that reconstructs both unequal signed roots.

- **Bound freshness:** Require a non-future observed head, a receipt active at
  evaluation, a bounded receipt lifetime, and no evaluation before the selected
  local report.

- **Reload around commit:** Recheck the ledger manifest, current state, anchor,
  latest v1.489 head, direct input identities, and destination before and after
  descriptor-relative no-replace publication.

## Durable retry and observer fan-out

Accepted reports use this shape:

```text
factory-release-state-transparency-external-gossip-v1-<idempotency-key>-<local-generation>-<context-digest>.json
```

The context digest binds the source log, witness policy, external log, external
policy, local v1.489 generation, observer ID, and observer key. Different pinned
observers therefore receive different durable names.

Exact retry returns the retained bytes even after the receipt expires. A
different receipt or proof for the same local generation and observer pin
conflicts instead of replacing the winner.

The report keeps `selected_ledger_external_gossip_report_committed` false. The
canonical report is constructed before publication and cannot attest its own
later installation.

## Report and limits

The self-contained report embeds the exact latest v1.489 report, observer
receipt, optional proof, artifact identities, compared heads, relationship,
evaluation instant, positive claims, and explicit nonclaims.

| Boundary | Limit |
| --- | ---: |
| Observer receipt | 64 KiB |
| Optional consistency proof | 64 KiB |
| Consistency path | 64 nodes |
| External tree size | 100,000 |
| Verification report | 16 MiB |
| Observer receipt lifetime | 604,800 seconds |
| Observer ID | 128 ASCII slug bytes |
| Local v1.489 generation | 1–10,000 |

Inputs must be bounded stable regular files outside the trusted ledger and must
not alias the output. Durable execution fails closed off Unix; schema,
capability, and help discovery remain cross-platform.

## What remains

One observer comparison detects a selected split view but cannot establish what
other observers received. Version 1.491 adds bounded remote acquisition and an
exact-head threshold across multiple independently pinned observer receipts.

Observer key rotation and a governed observer-organization trust registry
remain separate boundaries. Trusted timestamping, ledger rollback protection,
legal identity, capacity, order authority, payment, and exactly-once execution
also remain outside this contract.
