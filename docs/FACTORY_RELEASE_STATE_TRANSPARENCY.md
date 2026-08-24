# Factory-release state transparency

**Prove that the exact current factory state appears in one policy-pinned, signed Merkle view.**

The v1.485 boundary verifies an externally supplied inclusion receipt for the
fully reverified v1.484 ledger head. It keeps the existing organization policy,
state entries, observations, signatures, and policy digest byte-compatible.

> [!IMPORTANT]
> This contract proves inclusion in one signed log view. It does not prove
> global non-equivocation, append-only consistency between views, rollback
> resistance for the selected local ledger, trusted time, transport or legal
> identity, capacity, order placement, payment, or exactly-once execution.

## What it adds

- **Pins trust separately:** Uses a standalone canonical policy with its own
  deployment-supplied SHA-256, leaving every v1.484 policy pack unchanged.

- **Targets the verified head:** Replays the complete bounded monotonic chain,
  then binds the exact current state-entry and observation bytes.

- **Verifies inclusion:** Reconstructs an RFC 6962-shaped Merkle root from a
  bounded leaf index and audit path.

- **Authenticates the view:** Verifies an Ed25519 signature from the exact log
  ID and key selected by the transparency policy.

- **Checks local freshness:** Rejects future or stale tree heads relative to the
  evaluation clock while keeping `trusted_time_verified` false.

- **Retains one winner:** Stores one no-replace report for each state sequence
  and log ID, then replays the exact retained bytes locally.

## Quick start

Start with an existing v1.484 ledger and its original organization-policy pin.
Obtain a canonical receipt from the transparency log for the current state
entry, then verify it:

```sh
pcbex verify-factory-release-state-transparency-receipt \
  --reservation-ledger /srv/pcbex/release-ledger \
  --expected-ledger-id "$PCBEX_RELEASE_LEDGER_ID" \
  --idempotency-key "$IDEMPOTENCY_KEY" \
  --policy-pack config/organization-policy.json \
  --expected-policy-sha256 "$ORGANIZATION_POLICY_SHA256" \
  --transparency-policy config/factory-state-transparency-policy.json \
  --expected-transparency-policy-sha256 "$TRANSPARENCY_POLICY_SHA256" \
  --receipt build/factory-state-transparency-receipt.json \
  --output build/factory-state-transparency-report.json \
  --require-accepted
```

`--require-accepted` runs after the verified report is retained. Omit it when a
transparent pending or rejected state is still useful evidence.

> [!TIP]
> Store both expected digests in deployment-owned configuration. Supplying a
> policy and a digest chosen from that same untrusted handoff does not establish
> an independent trust root.

## Transparency policy

The standalone policy is canonical pretty JSON with one trailing newline:

```json
{
  "schema_version": 1,
  "policy_scope": "factory-release-state-transparency-trust-policy-v1",
  "maximum_checkpoint_age_seconds": 300,
  "trusted_logs": [
    {
      "log_id": "factory-release-log",
      "public_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ]
}
```

The policy accepts 1–100 unique log IDs and unique non-weak Ed25519 public
keys. The freshness bound is 1–604,800 seconds. Log IDs and keys must not reuse
an approval, fabrication, procurement, receipt-attestation, or adapter-response
trust role from the selected organization policy.

The expected transparency-policy digest is SHA-256 over the compact semantic
JSON serialization in the field order above. The verifier first requires the
canonical pretty source, recomputes that digest, and compares it with the
independently supplied lowercase value.

## Receipt contract

A receipt names one exact state entry, its domain-separated leaf digest, its
position, a bounded audit path, and one signed tree head:

```json
{
  "schema_version": 1,
  "receipt_scope": "policy-pinned-factory-release-state-transparency-receipt-v1",
  "state_entry_sha256": "<64 lowercase hex>",
  "leaf_sha256": "<64 lowercase hex>",
  "leaf_index": 0,
  "audit_path": [],
  "tree_head": {
    "schema_version": 1,
    "tree_head_scope": "signed-factory-release-state-transparency-tree-head-v1",
    "log_id": "factory-release-log",
    "tree_size": 1,
    "root_sha256": "<64 lowercase hex>",
    "observed_at_unix": 1700000000,
    "algorithm": "ed25519",
    "public_key": "<64 lowercase hex>",
    "signature": "<128 lowercase hex>"
  }
}
```

Receipts are capped at 32 KiB. Tree size is capped at 100,000 leaves and the
audit path at 64 nodes. Unknown or duplicate JSON fields, alternate formatting,
invalid lowercase encodings, out-of-range positions, weak keys, and malformed
paths fail closed.

### Leaf binding

The first SHA-256 binds this exact compact JSON projection after the domain
`pcbex:factory-release-state-transparency-leaf:v1\0`:

```text
state_entry_sha256
observation_sha256
state_sequence
state_sha256
state_status
idempotency_key
factory_id
provider
release_subject_sha256
manufacturing_package_sha256
```

The Merkle leaf is:

```text
SHA256(0x00 || "pcbex:factory-release-state-transparency-merkle-leaf:v1\0"
       || bytes.fromhex(leaf_sha256))
```

Each internal node is `SHA256(0x01 || left || right)`. Tree splitting follows
the largest power of two smaller than the subtree size, matching the shape of
RFC 6962 inclusion trees while preserving pcbex-specific domain separation.

### Signed tree head

The Ed25519 signature covers compact JSON containing these fields in order:

```text
domain = "pcbex-factory-release-state-transparency-tree-head-v1"
tree_head_scope
log_id
tree_size
root_sha256
observed_at_unix
```

The receipt's public key must exactly match the pinned log entry. The tree-head
time must not be later than evaluation or older than the policy bound. This is
a freshness comparison against the local clock, not trusted timestamping.

## Durable behavior

The command fully reloads and verifies every v1.484 state entry before choosing
the current head. It reads the matching observation, organization policy,
standalone transparency policy, and receipt as bounded exact artifacts.

A successful verification is committed under:

```text
factory-release-state-transparency-v1-<idempotency-key>-<sequence>-<log-id>.json
```

The sequence uses four zero-padded digits. The immutable report commits before
publication to the caller path, and a retry returns the exact retained bytes.
A different receipt or policy for the occupied state/log slot fails instead of
replacing the winner.

`selected_ledger_transparency_report_committed` remains false inside the
pre-commit report. The later no-replace record establishes which report won;
the report cannot truthfully attest its own future durable commit.

## Report semantics

A verified report sets these claims together:

- `monotonic_state_chain_verified`
- `state_entry_identity_verified`
- `observation_identity_verified`
- `policy_pack_pin_matched`
- `transparency_policy_pin_matched`
- `transparency_log_policy_matched`
- `tree_head_signature_verified`
- `inclusion_proof_verified`
- `transparency_inclusion_verified`
- `checkpoint_fresh_at_evaluation`

It embeds the canonical receipt and binds both policy digests, exact source
identities, state projection, tree-head digest, evaluation instant, and all
claim flags into one domain-separated report digest.

These claims always remain false:

- `selected_ledger_transparency_report_committed`
- `global_non_equivocation_verified`
- `selected_ledger_rollback_resistance_verified`
- `trusted_time_verified`
- `endpoint_transport_authenticity_verified`
- `factory_legal_identity_verified`
- `server_side_idempotency_enforced`
- `capacity_reserved`
- `order_placed`
- `payment_performed`
- `exactly_once_execution_verified`

## Compatibility and migration

Existing v1.484 ledgers need no migration. Keep using the exact organization
policy file and expected digest that authenticated the state chain, then add the
standalone transparency policy and its independent pin at verification time.

The command consumes a supplied receipt and performs no network request. Log
submission and receipt acquisition remain external. Use
[Factory-state Transparency Consistency](FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY.md)
to prove append-only extension between retained views; gossip, trusted
timestamping, and transport identity remain separate boundaries.

## Schema discovery

```sh
pcbex factory-release-state-transparency-policy-schema
pcbex factory-release-state-transparency-receipt-schema
pcbex factory-release-state-transparency-verification-report-schema
```

All three commands emit closed Draft 2020-12 JSON Schemas. Runtime validation
also enforces canonical bytes, bounded resources, role separation, full v1.484
chain replay, signature verification, inclusion reconstruction, and exact
report rebinding.
