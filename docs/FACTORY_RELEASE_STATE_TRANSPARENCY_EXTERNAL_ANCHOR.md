# Factory-state transparency external anchoring

Anchor one exact witness-backed factory-release checkpoint in a separately
trusted signed Merkle view.

The v1.488 boundary reloads the complete v1.484–v1.487 chain, selects the exact
latest retained witness-quorum report, and verifies its inclusion under an
independently digest-pinned external-log policy.

> [!IMPORTANT]
> This contract proves inclusion in one selected external signed view. It does
> not prove append-only consistency for that external log, global
> non-equivocation, rollback resistance for the selected local ledger, trusted
> time, real organizational independence, endpoint or legal identity,
> capacity, order placement, payment, or exactly-once execution.

## When to use it

Use this boundary after
`verify-factory-release-state-transparency-witness-quorum` has durably retained
the latest v1.487 report. Submit that exact canonical report to an external log
and obtain a signed tree head plus its Merkle inclusion path.

The verifier performs no network request. The external service returns the
proof out of band; deployment configuration supplies the policy digest and
selected external log ID independently.

## 1. Pin external-log trust

Print the closed policy schema:

```sh
pcbex factory-release-state-transparency-external-anchor-policy-schema
```

Define one or more canonically ordered external logs:

```json
{
  "schema_version": 1,
  "policy_scope": "factory-release-state-transparency-external-anchor-policy-v1",
  "policy_id": "production-release-anchor",
  "maximum_checkpoint_age_seconds": 300,
  "trusted_logs": [
    {
      "log_id": "release-public-log",
      "algorithm": "ed25519",
      "public_key": "<64 lowercase hex>"
    }
  ]
}
```

- **Pins externally:** Compute the expected policy SHA-256 over compact
  semantic JSON and store it in protected deployment configuration. Never read
  the expected digest from the policy artifact itself.

- **Orders canonically:** Sort `trusted_logs` by `log_id`. Duplicate IDs, keys,
  weak Ed25519 keys, and alternate ordering fail closed.

- **Separates roles:** Every configured external log ID and key must differ
  from the source transparency log, witness organizations, witness IDs, and
  witness keys embedded in the selected v1.487 report.

- **Bounds freshness:** Set `maximum_checkpoint_age_seconds` from 1 through
  604,800. Freshness compares the signed observation instant with the local
  evaluation clock; it is not trusted time.

The policy source must be canonical pretty JSON with a final newline. Its
semantic digest uses the documented field order and compact separators.

## 2. Construct the external leaf

The external operator hashes the exact canonical v1.487 report bytes. It then
serializes this field order as compact JSON:

```text
schema_version
witness_quorum_report_sha256
witness_quorum_binding_sha256
idempotency_key
source_log_id
checkpoint_generation
current_state_sequence
current_tree_head_sha256
witness_policy_sha256
external_anchor_policy_sha256
external_log_id
```

Compute the leaf binding:

```text
leaf_sha256 = SHA256(
  "pcbex:factory-release-state-transparency-external-anchor-leaf:v1\0" ||
  compact_json(binding)
)
```

Turn that semantic leaf into a Merkle leaf node:

```text
leaf_node = SHA256(
  0x00 ||
  "pcbex:factory-release-state-transparency-external-anchor-merkle-leaf:v1\0" ||
  hex_decode(leaf_sha256)
)
```

Internal nodes use `SHA256(0x01 || left || right)`. Proof ordering follows the
same RFC 6962-shaped recursive split used by the existing transparency
verifiers.

> [!NOTE]
> The report SHA-256 binds its exact canonical bytes. The report binding,
> release context, witness-policy digest, anchor-policy digest, and both log IDs
> remain explicit so cross-context reuse fails with a precise error.

## 3. Sign the external tree head

The external tree head contains:

```json
{
  "schema_version": 1,
  "tree_head_scope": "signed-factory-release-state-transparency-external-anchor-tree-head-v1",
  "log_id": "release-public-log",
  "tree_size": 3,
  "root_sha256": "<64 lowercase hex>",
  "observed_at_unix": 1700000001,
  "algorithm": "ed25519",
  "public_key": "<64 lowercase hex>",
  "signature": "<128 lowercase hex>"
}
```

Sign compact JSON containing these fields in order:

```text
domain = pcbex-factory-release-state-transparency-external-anchor-tree-head-v1
schema_version
tree_head_scope
log_id
tree_size
root_sha256
observed_at_unix
algorithm
public_key
```

The observation instant must not predate the selected witness report. The
verifier authenticates this tree head before interpreting any claimed
inclusion relationship.

## 4. Supply the proof

Print the closed proof schema:

```sh
pcbex factory-release-state-transparency-external-anchor-proof-schema
```

The proof binds the expected policy, exact report, semantic leaf, position,
bounded audit path, and complete signed tree head:

```json
{
  "schema_version": 1,
  "proof_scope": "factory-release-state-transparency-witness-quorum-external-anchor-proof-v1",
  "external_anchor_policy_sha256": "<64 lowercase hex>",
  "witness_quorum_report_sha256": "<64 lowercase hex>",
  "leaf_sha256": "<64 lowercase hex>",
  "leaf_index": 1,
  "audit_path": ["<64 lowercase hex>"],
  "tree_head": { "...": "complete signed tree head" }
}
```

Tree size is limited to 100,000 and the audit path to 64 nodes.

## 5. Verify and retain

Run the durable verifier on Unix:

```sh
pcbex verify-factory-release-state-transparency-external-anchor \
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
  --anchor-proof checkpoint.external-anchor-proof.json \
  --output checkpoint.external-anchor-report.json \
  --require-accepted
```

The verifier fails closed unless it can:

- **Replay every predecessor:** Reverify the complete v1.484 state chain,
  v1.485 inclusion reports, v1.486 consistency chain, and exact latest retained
  v1.487 witness report.

- **Match every trust root:** Recompute the organization, source-log, witness,
  and external-anchor policy identities from independently pinned sources.

- **Authenticate first:** Match the selected external log ID and key, verify
  the Ed25519 tree-head signature, then interpret the proof.

- **Reconstruct the root:** Recompute the domain-separated report leaf and
  consume the complete bounded path with no missing or extra node.

- **Check local freshness:** Require the external observation at or after the
  v1.487 evaluation and within the anchor policy age at evaluation.

## Durable retry

The accepted report commits without replacement under a bounded filename that
contains the idempotency key, v1.487 generation, and a domain-separated digest
of the source log, witness policy, external log, and anchor policy.

Exact retry with the same proof and policies returns the retained bytes even
after the original freshness window closes. A different otherwise valid proof
cannot replace that record.

The output report keeps
`selected_ledger_external_anchor_report_committed` false because a report
cannot truthfully attest its own later durable installation. The verifier
rechecks all direct inputs, the ledger manifest, current monotonic head, latest
consistency chain, and retained witness report around no-replace publication.

## Report and limits

Print the recursively closed report schema:

```sh
pcbex factory-release-state-transparency-external-anchor-verification-report-schema
```

| Boundary | Limit |
| --- | ---: |
| External-anchor policy | 64 KiB |
| External-anchor proof | 64 KiB |
| Trusted external logs | 100 |
| External tree size | 100,000 |
| Audit path | 64 nodes |
| Maximum local checkpoint age | 604,800 seconds |
| External-anchor report | 4 MiB |

Unknown or duplicate fields, noncanonical JSON, uppercase hexadecimal, weak or
reused keys, unsafe input files, aliases, oversized sources, mutation, and
input/output or input/ledger overlap fail before public output appears.

## What remains

One inclusion proof does not show that a later external tree extends an earlier
one. Version 1.489 adds that strict external-log consistency chain, and v1.490
compares its latest head with one separately pinned observer view. Version
1.491 adds bounded remote acquisition and exact-head threshold agreement; key
rotation remains separate.

Trusted timestamping, real organizational independence, transport and legal
identity, capacity, order authority, payment, and exactly-once execution remain
separate milestones.
