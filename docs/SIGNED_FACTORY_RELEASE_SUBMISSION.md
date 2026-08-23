# Durable signed factory-release submission

Submit once. Reconcile safely.

This boundary consumes one v1.481 signed-release reservation marker and its
exact manufacturing ZIP. It commits an immutable local intent before the first
adapter POST, then stores the adapter result beside that intent in the same
pinned Unix ledger.

> [!IMPORTANT]
> This is an adapter boundary, not proof of a factory order. An accepted
> acknowledgement records what the selected endpoint returned. It does not
> prove legal identity, capacity, server-side idempotency, order placement,
> payment, or exactly-once execution.

## What it solves

Side-effecting HTTP requests can fail after a server receives them but before
the client sees the response. Blindly repeating the ZIP can create a duplicate
submission.

`pcbex` handles that ambiguity with two explicit operations:

- **Submit once:** Commit a deterministic intent, issue one POST, and retain
  the result without automatic application-level retry.

- **Reconcile separately:** Query the adapter with GET and the same idempotency
  key. Reconciliation never sends the manufacturing ZIP.

- **Replay locally:** Reusing a completed submit or reconciliation key returns
  the exact durable receipt without contacting the endpoint.

- **Fail closed:** If only the intent survives, submit refuses to retransmit.
  The operator must reconcile the existing key.

## Prerequisites

You need:

1. A canonical v1.481 reservation marker in its original ledger.
2. The exact manufacturing ZIP bound by that marker.
3. The independently configured ledger ID.
4. An HTTPS adapter endpoint and a Bearer token stored in an environment
   variable.
5. A fresh 32-byte request nonce encoded as 64 lowercase hexadecimal digits.

The ledger must remain an absolute, effective-user-owned, mode-`0700` Unix
directory with the v1.481 fixed manifest. Windows exposes the command and
schemas for compatibility, but execution fails closed.

## Submit

```sh
export PCBEX_FACTORY_RELEASE_TOKEN='replace-with-a-secret'

pcbex submit-signed-factory-receipt-release \
  build/manufacturing.zip \
  --reservation-ledger /srv/pcbex/release-ledger \
  --expected-ledger-id "$PCBEX_RELEASE_LEDGER_ID" \
  --challenge "$SIGNED_RECEIPT_CHALLENGE" \
  --endpoint https://adapter.example/releases \
  --request-nonce "$REQUEST_NONCE" \
  --bearer-token-env PCBEX_FACTORY_RELEASE_TOKEN \
  --output build/factory-release-submission.json \
  --require-accepted
```

The command validates the ledger, marker, active windows, and complete ZIP
before committing the intent. It then performs one POST and durably records the
result before publishing the requested output.

> [!NOTE]
> `--require-accepted` is a final gate. A rejected or pending receipt is written
> first, then the command exits unsuccessfully. An unknown outcome is always
> written first and always exits unsuccessfully.

## Reconcile

Use the retained idempotency key after a pending result or a crash that left an
intent without a result:

```sh
pcbex reconcile-signed-factory-receipt-release \
  --reservation-ledger /srv/pcbex/release-ledger \
  --expected-ledger-id "$PCBEX_RELEASE_LEDGER_ID" \
  --idempotency-key "$IDEMPOTENCY_KEY" \
  --endpoint https://adapter.example/releases/status \
  --reconciliation-id "$RECONCILIATION_ID" \
  --bearer-token-env PCBEX_FACTORY_RELEASE_TOKEN \
  --output build/factory-release-reconciliation.json \
  --require-accepted
```

The reconciliation ID is another caller-generated 32-byte lowercase-hex
value. Reusing it replays the exact stored observation without network access.

## Durable state machine

| Local state | Submit behavior | Reconcile behavior |
| --- | --- | --- |
| Reservation marker only | Commit intent, then issue one POST | Refuse: no intent exists |
| Exact intent, no result | Refuse to retransmit | Issue one GET for a new reconciliation ID |
| Pending/unknown result | Replay result | Issue one GET for a new reconciliation ID |
| Accepted/rejected result | Replay result | Replay terminal result without GET |
| Existing reconciliation ID | Unchanged | Replay its exact observation without GET |
| Conflicting or malformed record | Fail with no new network operation | Fail with no new network operation |

Every ledger filename is deterministic:

```text
signed-factory-release-submission-intent-v1-<idempotency-key>.json
signed-factory-release-submission-result-v1-<idempotency-key>.json
signed-factory-release-reconciliation-v1-<idempotency-key>-<reconciliation-id>.json
```

Records use descriptor-pinned, no-replace publication with file and directory
synchronization. A durable ledger result survives failure to publish the
caller-selected output path.

## Adapter request contract

Submission uses POST with `Content-Type: application/zip`. Reconciliation uses
GET with no request body.

Both operations send these headers:

| Header | Value |
| --- | --- |
| `Idempotency-Key` | Deterministic hash of the ledger, signed release, marker, factory, and ZIP identity |
| `X-PCBEX-Request-Nonce` | Caller-supplied request nonce |
| `X-PCBEX-Release-Subject-SHA256` | Stable v1.480 release subject |
| `X-PCBEX-Package-SHA256` | Exact manufacturing ZIP digest |
| `X-PCBEX-Factory-ID` | Factory ID authenticated by the upstream signed receipt |
| `Authorization` | `Bearer <token>` loaded from the named environment variable |

Reconciliation also sends `X-PCBEX-Reconciliation-ID`. Redirects are disabled,
responses are capped at 64 KiB, and production endpoints must use HTTPS without
userinfo, query strings, or fragments.

The request nonce and endpoint remain bound by the committed intent, but they
do not mint a second key. Changing either value after the first intent commit
collides with that intent and fails before another POST.

The adapter must return `application/json` with this closed acknowledgement:

```json
{
  "schema_version": 1,
  "acknowledgement_scope": "pcbex-signed-factory-release-adapter-acknowledgement-v1",
  "operation": "submit",
  "idempotency_key": "<64 lowercase hex>",
  "request_nonce": "<64 lowercase hex>",
  "reconciliation_id": null,
  "release_subject_sha256": "<64 lowercase hex>",
  "manufacturing_package_sha256": "<64 lowercase hex>",
  "factory_id": "factory-a",
  "provider": "generic",
  "status": "adapter_accepted",
  "submission_id": "provider-visible-id"
}
```

`status` accepts `adapter_accepted`, `adapter_rejected`, or `adapter_pending`.
Unknown fields, duplicate JSON keys, malformed bindings, credential reflection,
unexpected status codes, and oversized bodies become a bounded
`outcome_unknown` receipt.

## Receipt semantics

The receipt binds the complete intent identity, operation, endpoint, raw
response byte identity, adapter status, submission ID, local attempt-start
time, and stable nonclaims under a domain-separated SHA-256 digest.

`attempted_at_unix` is sampled immediately before the adapter call. It is not
an authenticated response timestamp and does not establish when the remote
system processed the request.

Only these operational facts may become true:

- `adapter_network_performed`
- `manufacturing_package_transmission_attempted` for submit only
- `external_submission_attempted` for submit only
- `acknowledgement_validated` for an exact closed acknowledgement
- `accepted` when the acknowledgement status is `adapter_accepted`

These fields always remain false:

- `server_side_idempotency_enforced`
- `factory_legal_identity_verified`
- `endpoint_transport_authenticity_verified`
- `raw_response_authenticity_verified`
- `trusted_time_verified`
- `capacity_reserved`
- `order_placed`
- `payment_performed`
- `exactly_once_execution_verified`

> [!WARNING]
> The `Idempotency-Key` header is part of this adapter contract. pcbex cannot
> prove that the remote server enforces it. Keep the false server-side and
> exactly-once fields intact unless a separate authenticated server contract
> proves stronger semantics.

## Schema discovery

```sh
pcbex signed-factory-release-submission-intent-schema
pcbex signed-factory-release-adapter-acknowledgement-schema
pcbex signed-factory-release-adapter-receipt-schema
```

All three schemas are closed Draft 2020-12 documents. Runtime validation also
requires canonical pretty JSON for retained intent and receipt records.

## Trust boundary

The Bearer token stays out of the intent, receipt, durable filenames, output,
and normal errors. A response that reflects the credential is rejected and
reduced to a response digest plus a stable failure code.

The local ledger still assumes cooperative custody by the effective Unix user.
It does not sandbox same-user processes, prevent all concurrent filesystem
races, establish trusted time, authenticate the HTTPS endpoint beyond the host
TLS stack, or make the remote action globally exactly once.
