# Factory-state transparency external-log consistency

Prove that later external signed views strictly extend one retained v1.488
factory-release anchor.

The v1.489 boundary replays the complete v1.484–v1.488 chain, authenticates
both external tree heads, verifies a bounded RFC 6962-shaped consistency path,
and retains each accepted extension in one deterministic no-replace chain.

> [!IMPORTANT]
> This contract proves append-only consistency between selected retained views
> of one policy-pinned external log. It does not prove global non-equivocation,
> protect the selected local ledger from rollback, establish trusted time or
> real organizational independence, authenticate transport or legal identity,
> reserve capacity, place an order, pay, or prove exactly-once execution.

## When to use it

Use this boundary after
`verify-factory-release-state-transparency-external-anchor` has durably retained
the exact v1.488 report. Ask the same external log for a strictly newer signed
tree head and a consistency path from the retained tree size.

The verifier performs no network request. The external service returns the
proof out of band; deployment configuration continues to supply the v1.488
external-anchor policy digest and external log ID independently.

## 1. Discover the proof contract

Print the closed schema:

```sh
pcbex factory-release-state-transparency-external-consistency-proof-schema
```

A proof carries both complete signed views, their compact-JSON identities, the
unchanged policy and log identities, and the ordered consistency nodes:

```json
{
  "schema_version": 1,
  "proof_scope": "factory-release-state-transparency-external-log-consistency-proof-v1",
  "external_anchor_policy_sha256": "<64 lowercase hex>",
  "external_log_id": "release-public-log",
  "previous_tree_head_sha256": "<64 lowercase hex>",
  "current_tree_head_sha256": "<64 lowercase hex>",
  "previous_tree_head": {
    "schema_version": 1,
    "tree_head_scope": "signed-factory-release-state-transparency-external-anchor-tree-head-v1",
    "log_id": "release-public-log",
    "tree_size": 42,
    "root_sha256": "<64 lowercase hex>",
    "observed_at_unix": 1700000001,
    "algorithm": "ed25519",
    "public_key": "<64 lowercase hex>",
    "signature": "<128 lowercase hex>"
  },
  "current_tree_head": {
    "schema_version": 1,
    "tree_head_scope": "signed-factory-release-state-transparency-external-anchor-tree-head-v1",
    "log_id": "release-public-log",
    "tree_size": 58,
    "root_sha256": "<64 lowercase hex>",
    "observed_at_unix": 1700000030,
    "algorithm": "ed25519",
    "public_key": "<64 lowercase hex>",
    "signature": "<128 lowercase hex>"
  },
  "consistency_path": ["<64 lowercase hex>"]
}
```

Both heads reuse the dedicated v1.488 signature domain. The proof cannot switch
the external log ID, algorithm, or key selected by the exact pinned policy.

## 2. Build the consistency path

The external log constructs the path from the ordered Merkle leaves represented
by the newer signed root. Internal nodes remain:

```text
SHA256(0x01 || left || right)
```

The verifier starts with the trusted previous root. It recursively consumes
the supplied nodes and must reconstruct both the previous and current signed
roots exactly, with no missing or extra node.

> [!NOTE]
> The proof does not retransmit the log. It proves only that the selected
> previous tree is a prefix of the selected current tree.

## 3. Bootstrap generation 1

Select the retained v1.488 checkpoint generation explicitly:

```sh
pcbex verify-factory-release-state-transparency-external-consistency \
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
  --anchor-checkpoint-generation 2 \
  --consistency-proof external-tree-42-to-58.proof.json \
  --output external-tree-58.consistency-report.json \
  --require-accepted
```

Generation 1 must start at the complete signed tree head embedded in that exact
durable v1.488 report. A different valid earlier view cannot bootstrap the
chain.

## 4. Extend the retained chain

For each later view, omit `--anchor-checkpoint-generation`. The proof must start
at the exact current head of the latest retained v1.489 report:

```sh
pcbex verify-factory-release-state-transparency-external-consistency \
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
  --consistency-proof external-tree-58-to-73.proof.json \
  --output external-tree-73.consistency-report.json
```

Each transition must use a strictly larger tree. A smaller size is rollback; a
different root at one size is equivocation; an identical same-size view is not
an extension.

## Verification contract

The Unix verifier fails closed unless it can:

- **Replay every predecessor:** Reverify the selected v1.484 state chain,
  v1.485 inclusion, complete v1.486 consistency chain, exact v1.487 witness
  quorum, and exact retained v1.488 external anchor.

- **Match every policy:** Recompute the organization, source-log, witness, and
  external-anchor policy identities from independently pinned sources.

- **Authenticate first:** Verify both Ed25519 external tree-head signatures
  under the selected external key before interpreting size, time, or the
  consistency path.

- **Keep one identity:** Require one external log ID, algorithm, public key,
  anchor report, release key, source log, witness policy, and external policy
  across every retained generation.

- **Require strict growth:** Reject rollback, same-size equivocation, same-size
  replay as a new generation, key substitution, and observation-time reversal.

- **Reconstruct both roots:** Consume the complete bounded path and reproduce
  both signed roots from the trusted previous root.

- **Check local freshness:** Require the current head not to be future-dated
  and no older than the v1.488 policy permits at local evaluation.

- **Reload around commit:** Recheck the exact input files, fixed ledger
  manifest, current state head, v1.488 anchor, and complete v1.489 chain before
  and after no-replace publication.

## Durable retry

Accepted reports use a context-bound filename:

```text
factory-release-state-transparency-external-consistency-v1-<idempotency-key>-<generation>-<context-digest>.json
```

The context digest binds the source log, witness-policy digest, external log,
and external-anchor-policy digest. One chain cannot silently switch any of
those identities.

Exact retry of the latest proof returns the retained bytes even after its
original freshness window closes. A competing extension from an earlier head
cannot overwrite the winner. A later valid generation must start from the
winner's exact signed head.

The report keeps
`selected_ledger_external_consistency_report_committed` false because a report
cannot truthfully attest its own later durable installation.

## Report and limits

Print the recursively closed report schema:

```sh
pcbex factory-release-state-transparency-external-consistency-verification-report-schema
```

The report embeds the exact v1.488 anchor, both signed heads, consistency proof,
artifact identities, predecessor link, policy pins, tree sizes, roots,
observation order, evaluation instant, positive claims, and explicit nonclaims.

| Boundary | Limit |
| --- | ---: |
| Consistency proof | 64 KiB |
| Consistency path | 64 nodes |
| External tree size | 100,000 |
| Consistency report | 8 MiB |
| Durable generations per selected context | 10,000 |
| Current checkpoint local age | v1.488 policy, at most 604,800 seconds |

Unknown or duplicate fields, noncanonical JSON, uppercase hexadecimal, unsafe
input files, aliases, oversized sources, mutation, input/output overlap, and
input/ledger overlap fail before public output appears. Durable execution fails
closed off Unix; schema and capability discovery remain cross-platform.

## What remains

A retained prefix proof still cannot show that independent consumers received
the same view. Version 1.490 compares the latest retained head with one
separately pinned observer receipt, and v1.491 adds bounded acquisition plus an
exact-head observer-organization threshold. Version 1.492 binds its current
keys to complete selected-ledger rotation histories, and v1.493 requires every
selected member to remain active in an authority-governed organization
registry. Version 1.494 adds dual-signed registry-authority rotation and mixed
history replay.

Trusted timestamping, real organizational independence, transport and legal
identity, capacity, order authority, payment, and exactly-once execution remain
separate milestones.
