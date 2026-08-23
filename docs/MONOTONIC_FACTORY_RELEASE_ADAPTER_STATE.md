# Monotonic factory-release adapter state

**Authenticate every state change—and reject any history that moves backward or forks.**

The v1.484 boundary extends signed factory responses with a bounded hash chain.
It preserves every v1.482 intent, acknowledgement, and receipt byte while adding a separate v2 signature profile, observation report, and durable state entry.

> [!IMPORTANT]
> This contract proves continuity relative to one retained local ledger. It does
> not prove global non-equivocation, legal factory identity, trusted time,
> capacity, order placement, payment, or exactly-once execution.

## What it adds

- **Binds the head:** Signs the client's last accepted sequence and state digest.

- **Chains transitions:** Requires generation `0` first, then permits only an exact replay or one linked successor.

- **Rejects rollback:** Detects older generations before they can replace accepted state.

- **Exposes equivocation:** Rejects a different state at the same generation.

- **Stops forks and gaps:** Requires `sequence + 1` and the exact retained predecessor digest.

- **Locks terminal states:** Allows no successor after `adapter_accepted` or `adapter_rejected`.

- **Repairs locally:** Commits the authenticated observation first, then reconstructs a missing state entry or compatible v1.482 receipt without another request.

## Quick start

Keep the Bearer credential in an environment variable. Keep the expected policy digest in deployment-owned configuration.

```sh
export PCBEX_FACTORY_RELEASE_TOKEN='replace-with-a-secret'

pcbex submit-monotonic-authenticated-signed-factory-receipt-release \
  build/manufacturing.zip \
  --reservation-ledger /srv/pcbex/release-ledger \
  --expected-ledger-id "$PCBEX_RELEASE_LEDGER_ID" \
  --challenge "$SIGNED_RECEIPT_CHALLENGE" \
  --policy-pack config/organization-policy.json \
  --expected-policy-sha256 "$POLICY_DIGEST" \
  --endpoint https://adapter.example/releases \
  --request-nonce "$REQUEST_NONCE" \
  --bearer-token-env PCBEX_FACTORY_RELEASE_TOKEN \
  --output build/factory-release-state-0.json
```

The first authenticated response must declare sequence `0` with no predecessor.
A pending state remains successful unless `--require-accepted` is set.

Reconcile without sending the ZIP again:

```sh
pcbex reconcile-monotonic-authenticated-signed-factory-receipt-release \
  --reservation-ledger /srv/pcbex/release-ledger \
  --expected-ledger-id "$PCBEX_RELEASE_LEDGER_ID" \
  --idempotency-key "$IDEMPOTENCY_KEY" \
  --policy-pack config/organization-policy.json \
  --expected-policy-sha256 "$POLICY_DIGEST" \
  --endpoint https://adapter.example/releases/status \
  --reconciliation-id "$RECONCILIATION_ID" \
  --bearer-token-env PCBEX_FACTORY_RELEASE_TOKEN \
  --output build/factory-release-next-state.json \
  --require-accepted
```

Reusing a reconciliation ID returns its exact retained observation without network access.
Once the chain reaches a terminal state, every later reconciliation also returns locally.

## State machine

| Retained head | Authenticated response | Result |
| --- | --- | --- |
| None | Sequence `0`, no predecessor | Accept genesis |
| None | Any other shape | `state_chain_genesis_required` |
| Pending | Same sequence and exact state digest | Accept replay |
| Pending | Next sequence, predecessor equals head | Accept successor |
| Any | Lower sequence | `state_rollback_detected` |
| Any | Same sequence, different state | `state_equivocation_detected` |
| Any | More than one sequence ahead | `state_sequence_gap_detected` |
| Any | Next sequence, wrong predecessor | `state_fork_detected` |
| Terminal | Any higher sequence | `terminal_state_mutation_detected` |
| Pending | Successor changes submission ID | `submission_identity_changed` |

`adapter_accepted` and `adapter_rejected` are terminal. `adapter_pending` may advance to pending, accepted, or rejected.

> [!NOTE]
> The adapter must return the earliest state after the request head—not merely
> its newest snapshot. A client with no head must receive generation `0`; a
> client at generation `n` may receive only an exact replay of `n` or generation
> `n + 1`.

## Wire profile

Every v1.484 request selects this profile:

```text
X-PCBEX-Response-Signature-Profile: rfc9421-ed25519-content-digest-monotonic-state-v1
```

It also sends the retained head:

```text
X-PCBEX-Accepted-State-Sequence: none
X-PCBEX-Accepted-State-SHA256: none
```

After accepting a state, `none` becomes the canonical unsigned decimal sequence and lowercase state SHA-256.
The response returns exactly one of each state header:

| Header | Value |
| --- | --- |
| `X-PCBEX-State-Sequence` | Canonical decimal `0`–`9999` |
| `X-PCBEX-State-Previous-SHA256` | `none` for genesis; otherwise the predecessor digest |
| `X-PCBEX-State-SHA256` | Lowercase SHA-256 recomputed by pcbex |

The response also returns the exact `Content-Type`, `Content-Digest`, `Signature-Input`, and `Signature` headers required by the v1.483 profile.

### Signature parameters

```text
label = pcbex-state
alg   = ed25519
tag   = pcbex-signed-factory-release-monotonic-state-response-v1
```

The [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) signature covers response status, body digest, media type, all three state headers, the request head, and the complete v1.483 request binding.
GET also covers the reconciliation ID.

### State digest

pcbex hashes a domain separator followed by canonical JSON containing:

```text
schema_version
state_scope
sequence
previous_state_sha256
idempotency_key
submission_id
factory_id
provider
release_subject_sha256
manufacturing_package_sha256
status
```

The signature bytes, signing time, reconciliation ID, endpoint, and response body digest are intentionally excluded.
That keeps one semantic state stable when a trusted key re-signs it for a fresh GET, while the HTTP signature still authenticates the exact request and body.

## Durable commit order

pcbex writes immutable records in this order:

1. The unchanged v1.482 submission intent, before POST.
2. The v1.484 authenticated observation report.
3. The sequence-keyed monotonic state entry, only after continuity succeeds.
4. The compatible unchanged v1.482 receipt.

Each write uses descriptor-pinned, synchronous, no-replace publication in the selected Unix ledger.
A crash after step 2 can repair steps 3 and 4 from the exact report without contacting the adapter again.

```text
monotonic-factory-release-submission-v1-<idempotency-key>.json
monotonic-factory-release-reconciliation-v1-<idempotency-key>-<reconciliation-id>.json
monotonic-factory-release-state-v1-<idempotency-key>-<sequence>.json
```

State filenames use four zero-padded digits. The chain is capped at 10,000 states (`0000`–`9999`) so complete verification stays bounded.

## Report semantics

Authentication and continuity remain separate.
A correctly signed rollback therefore sets `response_authenticated: true` while keeping `state_continuity_verified: false` and recording a closed continuity failure.

Positive continuity requires all of these fields together:

- `response_authenticated`
- `acknowledgement_authenticated`
- `state_headers_authenticated`
- `state_digest_verified`
- `request_head_bound`
- `transition_verified`
- `state_continuity_verified`
- `requested_head_continuity_verified`

`accepted` becomes true only when continuity succeeds and the observed state is `adapter_accepted`.
The compatible v1.482 receipt retains its original, narrower claims.

`selected_ledger_state_committed` always remains false in the immutable
observation because the report commits before the no-replace state entry. The
presence and full re-verification of that later entry—not a pre-commit report
flag—proves which concurrent state won the selected ledger slot.

These fields always remain false:

- `global_non_equivocation_verified`
- `selected_ledger_state_committed`
- `endpoint_transport_authenticity_verified`
- `factory_legal_identity_verified`
- `trusted_time_verified`
- `server_side_idempotency_enforced`
- `capacity_reserved`
- `order_placed`
- `payment_performed`
- `exactly_once_execution_verified`

## Compatibility and migration

The v1.483 commands and signature profile remain unchanged.
Existing v1.482 or v1.483 submissions must migrate through the new reconciliation command with a fresh reconciliation ID; pcbex never retransmits their package.

Use the v1.483 command when one independently authenticated snapshot is enough.
Use the v1.484 command when a later response must prove continuity with locally retained history.

## Schema discovery

```sh
pcbex factory-release-adapter-monotonic-state-schema
pcbex factory-release-adapter-monotonic-http-message-signature-schema
pcbex factory-release-adapter-monotonic-state-entry-schema
pcbex factory-release-adapter-monotonic-observation-report-schema
```

All four commands emit closed Draft 2020-12 JSON Schemas.
Runtime parsing additionally requires canonical pretty JSON, exact intent and policy binding, complete signature re-verification, and a valid domain-separated report binding.
