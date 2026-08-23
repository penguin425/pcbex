# Authenticated factory-release adapter responses

Authenticate the response. Keep the retry barrier.

This v1.483 boundary verifies each factory-release POST or reconciliation GET
response against an exact organization-policy key. It preserves the v1.482
intent, acknowledgement, and receipt formats byte for byte.

> [!TIP]
> Need rollback and fork detection across multiple observations? Use the
> [v1.484 monotonic state profile](MONOTONIC_FACTORY_RELEASE_ADAPTER_STATE.md).
> This v1.483 profile intentionally authenticates one response in isolation.

> [!IMPORTANT]
> A valid HTTP message signature authenticates the covered application message
> under the configured key. It does not prove legal factory identity, TLS
> authenticity, trusted time, capacity, order placement, payment, or exactly-once
> execution.

## What it adds

- **Pins policy:** Requires both the exact policy source and its independently
  configured canonical SHA-256.

- **Separates roles:** Rejects response keys reused for approval, escalation,
  receipt-attestation, or other configured trust roles.

- **Authenticates context:** Covers the response status and body plus the exact
  request method, URI, nonce, idempotency key, release, package, and factory.

- **Retains failures:** Writes a closed negative report before exiting when the
  response cannot be authenticated.

- **Avoids retransmission:** Replays durable reports locally. An existing intent
  remains a hard barrier against a second package POST.

The profile follows [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)
and [RFC 9530 Content-Digest](https://www.rfc-editor.org/rfc/rfc9530.html).
It intentionally supports one narrow, deterministic application profile.

## Configure trusted response keys

Add the optional policy block to an organization policy pack:

```json
{
  "factory_adapter_response_authentication_policy": {
    "maximum_validity_seconds": 300,
    "trusted_keys": [
      {
        "key_id": "factory-response-key-2026-08",
        "factory_id": "factory-a",
        "provider": "generic",
        "public_key": "<64 lowercase hex Ed25519 public key>"
      }
    ]
  }
}
```

`maximum_validity_seconds` accepts 1–604,800 seconds. The policy accepts 1–100
unique keys, and each key binds one key ID, factory ID, provider, and Ed25519
public key.

Use the canonical policy digest from a verified signed-policy envelope as
`--expected-policy-sha256`. Keep that value in deployment-owned configuration;
do not derive the expected value from the untrusted input at invocation time.

## Submit once

```sh
export PCBEX_FACTORY_RELEASE_TOKEN='replace-with-a-secret'

pcbex submit-authenticated-signed-factory-receipt-release \
  build/manufacturing.zip \
  --reservation-ledger /srv/pcbex/release-ledger \
  --expected-ledger-id "$PCBEX_RELEASE_LEDGER_ID" \
  --challenge "$SIGNED_RECEIPT_CHALLENGE" \
  --policy-pack config/organization-policy.json \
  --expected-policy-sha256 "$POLICY_DIGEST" \
  --endpoint https://adapter.example/releases \
  --request-nonce "$REQUEST_NONCE" \
  --bearer-token-env PCBEX_FACTORY_RELEASE_TOKEN \
  --output build/factory-release-authentication.json \
  --require-accepted
```

The command validates and pins the policy, ledger, marker, and package before
committing the unchanged v1.482 intent. It then performs exactly one POST and
records the authentication report before its compatible v1.482 receipt.

> [!NOTE]
> `--require-accepted` runs after durable retention. An authenticated pending or
> rejected response remains inspectable even when the final gate fails.

## Reconcile without the ZIP

```sh
pcbex reconcile-authenticated-signed-factory-receipt-release \
  --reservation-ledger /srv/pcbex/release-ledger \
  --expected-ledger-id "$PCBEX_RELEASE_LEDGER_ID" \
  --idempotency-key "$IDEMPOTENCY_KEY" \
  --policy-pack config/organization-policy.json \
  --expected-policy-sha256 "$POLICY_DIGEST" \
  --endpoint https://adapter.example/releases/status \
  --reconciliation-id "$RECONCILIATION_ID" \
  --bearer-token-env PCBEX_FACTORY_RELEASE_TOKEN \
  --output build/factory-release-reconciliation-authentication.json \
  --require-accepted
```

Reconciliation sends a GET with no package bytes. Reusing one reconciliation
ID returns its exact durable authentication report without network access.

If the same ID already names a legacy v1.482 observation without an
authentication report, pcbex refuses to query it again. Supply a fresh
reconciliation ID so the new signed observation cannot be confused with the
old unsigned one.

## Adapter response profile

Every authenticated request includes:

```text
X-PCBEX-Response-Signature-Profile: rfc9421-ed25519-content-digest-v1
```

The adapter returns exactly one of each header:

| Header | Required value |
| --- | --- |
| `Content-Type` | `application/json` |
| `Content-Digest` | Canonical RFC 9530 `sha-256=:<base64>:` over the exact body |
| `Signature-Input` | The exact `pcbex` profile below |
| `Signature` | `pcbex=:<base64 Ed25519 signature>:` |

The fixed signature parameters are:

```text
label = pcbex
alg   = ed25519
tag   = pcbex-signed-factory-release-response-v1
```

`created` and `expires` are unsigned decimal Unix seconds with no leading
zeroes. `expires` must follow `created`, the interval must not exceed the policy
maximum, and the local evaluation instant must fall inside the interval.

### Covered components

Both operations cover these components in this exact order:

```text
"@status"
"content-digest"
"content-type"
"x-pcbex-adapter";req
"x-pcbex-schema-version";req
"x-pcbex-response-signature-profile";req
"idempotency-key";req
"x-pcbex-request-nonce";req
"x-pcbex-release-subject-sha256";req
"x-pcbex-package-sha256";req
"x-pcbex-factory-id";req
"@method";req
"@target-uri";req
```

GET reconciliation inserts `"x-pcbex-reconciliation-id";req` immediately
after the request nonce. Request-derived components use RFC 9421's `;req`
parameter, so a signature for another method, URI, release, package, nonce,
factory, idempotency key, or reconciliation ID cannot validate here.

The body remains the closed v1.482 acknowledgement. A signature over malformed
or mismatched acknowledgement JSON authenticates bytes, but it cannot make
`acknowledgement_authenticated` or `accepted` true.

## Durable records

The v1.482 files remain unchanged:

```text
signed-factory-release-submission-intent-v1-<idempotency-key>.json
signed-factory-release-submission-result-v1-<idempotency-key>.json
signed-factory-release-reconciliation-v1-<idempotency-key>-<reconciliation-id>.json
```

v1.483 adds two outer records:

```text
authenticated-factory-release-submission-v1-<idempotency-key>.json
authenticated-factory-release-reconciliation-v1-<idempotency-key>-<reconciliation-id>.json
```

The outer record commits first. If the process stops before writing the
compatible receipt, the next invocation reconstructs that exact receipt from
the authenticated report and does not repeat network I/O.

All records use descriptor-pinned, synchronous, no-replace publication in the
same trusted Unix ledger. The policy and package must stay outside that ledger,
and their exact observed bytes are rechecked around critical commits.

## Report semantics

A positive report sets `response_authenticated`,
`response_signature_verified`, `response_content_digest_verified`,
`signer_policy_matched`, and `signature_time_active` together. It retains the
trusted key identity and exact signature headers.

A negative report sets all positive authentication flags false, omits signer
and signature evidence, and records one closed failure code. Missing or
duplicated headers, digest mismatch, invalid context or signature, untrusted
keys, expired windows, transport errors, and credential reflection all follow
this path.

The nested v1.482 receipt still keeps `raw_response_authenticity_verified`
false. The outer report alone may set it true after complete v1.483
verification, preserving old consumers and old wire bytes.

These claims always remain false:

- `endpoint_transport_authenticity_verified`
- `factory_legal_identity_verified`
- `trusted_time_verified`
- `server_side_idempotency_enforced`
- `capacity_reserved`
- `order_placed`
- `payment_performed`
- `exactly_once_execution_verified`

> [!WARNING]
> The local clock evaluates a signer-declared validity window; it is not trusted
> timestamp evidence. Use a separate trusted-timestamp or transparency service
> when the time of signing must be independently established.

## Schema discovery

```sh
pcbex factory-release-adapter-http-message-signature-schema
pcbex factory-release-adapter-response-authentication-report-schema
```

Both commands emit closed Draft 2020-12 JSON Schemas. Runtime parsing also
requires canonical pretty JSON, exact policy-source identity, the matching
intent, a valid report binding, and full cryptographic re-verification.
