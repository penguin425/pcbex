# Remote Factory Receipt-quorum Checkpoint Witnesses

Acquire a dedicated checkpoint witness over bounded HTTPS, verify it locally,
and retain transport evidence without changing the signed witness format.

The v1.509 boundary preserves the v1.507 witness/quorum contracts and the
v1.508 trust chain. It adds one remote request path and one canonical receipt.

> [!IMPORTANT]
> pcbex validates the endpoint and re-verifies the exact public report, log,
> checkpoint, and checkpoint key before reading a Bearer token or sending a
> request. Invalid public evidence never reaches the remote witness.

## Key Features

- **Verifies First:** Runs the production v1.506 verifier over the complete
  receipt-quorum report, approval log, and dedicated checkpoint before network
  I/O.

- **Bounds Transport:** Requires HTTPS, disables redirects, rejects URL
  credentials and queries, limits the deadline to 1–600 seconds, and accepts
  only `application/json`.

- **Pins the Responder:** Verifies the returned canonical v1.507 witness with
  either one direct public key or one current v1.508 trust state.

- **Separates Key Roles:** Rejects a witness key that matches the dedicated
  checkpoint signing key.

- **Preserves Compatibility:** Writes the unchanged signed witness, ready for
  the existing 2–100 witness-quorum command.

- **Retains a Receipt:** Binds raw and semantic source digests, endpoint,
  request, response, selected keys, trust generation, and evaluation time.

- **Drops Credentials:** Never writes the Bearer token to either output.

## Quick Start

Use a directly pinned witness key:

```bash
export FACTORY_WITNESS_TOKEN='replace-me'

pcbex request-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness \
  approval-log.with-receipt-quorum.json \
  --quorum-report receipt-quorum.report.json \
  --checkpoint factory-receipt-quorum.checkpoint.json \
  --checkpoint-public-key factory-receipt-quorum.public.hex \
  --endpoint https://witness.example/v1/factory-receipt-quorum-checkpoint \
  --witness-public-key witness-a.public.hex \
  --bearer-token-env FACTORY_WITNESS_TOKEN \
  --output factory-receipt-quorum.witness-a.json \
  --receipt-output factory-receipt-quorum.witness-a.receipt.json
```

Use retained rotatable trust instead:

```bash
pcbex request-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness \
  approval-log.with-receipt-quorum.json \
  --quorum-report receipt-quorum.report.json \
  --checkpoint factory-receipt-quorum.checkpoint.json \
  --checkpoint-public-key factory-receipt-quorum.public.hex \
  --endpoint https://witness.example/v1/factory-receipt-quorum-checkpoint \
  --witness-trust-state witness-a.trust.3.json \
  --output factory-receipt-quorum.witness-a.json \
  --receipt-output factory-receipt-quorum.witness-a.receipt.json
```

> [!TIP]
> Keep tokens in deployment-owned environment injection. Omit
> `--bearer-token-env` when the endpoint uses mutual TLS or needs no Bearer
> authentication.

## Build the Quorum

Acquire each witness independently, then feed the unchanged outputs into the
existing verifier. Choose direct keys or trust states for the whole command.

```bash
pcbex verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witnesses \
  approval-log.with-receipt-quorum.json \
  --quorum-report receipt-quorum.report.json \
  --checkpoint factory-receipt-quorum.checkpoint.json \
  --checkpoint-public-key factory-receipt-quorum.public.hex \
  --witnesses factory-receipt-quorum.witness-a.json \
  --witnesses factory-receipt-quorum.witness-b.json \
  --witness-trust-states witness-a.trust.3.json \
  --witness-trust-states witness-b.trust.0.json \
  --minimum-witnesses 2 \
  --output factory-receipt-quorum.witness-quorum.json
```

## HTTP Contract

pcbex sends one compact JSON object:

```json
{
  "schema_version": 1,
  "protocol": "pcbex-remote-factory-release-registry-receipt-quorum-log-checkpoint-witness-v1",
  "quorum_report": {},
  "approval_log": {},
  "checkpoint": {}
}
```

The three nested values are the locally verified public artifacts. A successful
endpoint returns one canonical pretty-JSON v1.507 witness with a trailing LF.

| Boundary | Limit |
| --- | ---: |
| Approval log source | 128 MiB |
| Receipt-quorum report | 128 KiB |
| Dedicated checkpoint | 64 KiB |
| Checkpoint or direct witness key file | 65 bytes |
| Witness trust state | 32 KiB |
| Serialized request | 129 MiB |
| Transport response | 1 MiB |
| Accepted canonical witness | 64 KiB |
| Canonical transport receipt | 64 KiB |
| End-to-end timeout | 1–600 seconds; default 30 |

Redirects fail. URL user information and query strings fail. Plain HTTP is not
available in production commands.

## Receipt Bindings

The receipt records what pcbex verified, not what the endpoint claims.

| Field group | Binding |
| --- | --- |
| Public evidence | Semantic and raw-source report digests, complete log identity/digests, registry checkpoint, and dedicated checkpoint digests |
| Transport | Endpoint, exact compact request digest, raw response digest, and response byte count |
| Trust | Checkpoint key, witness key, optional trust-state source digest, and trust generation |
| Decision | Evaluation time, witness time and identity, semantic witness digest, and `verified: true` |

Discover or normalize the closed receipt contract:

```bash
pcbex remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-schema

pcbex validate-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt \
  factory-receipt-quorum.witness-a.receipt.json
```

## Verification Flow

1. Validate endpoint syntax, timeout, evaluation time, and key-role separation.
2. Parse the canonical report and checkpoint plus the complete duplicate-free
   approval log.
3. Re-run the exact v1.506 report/log/checkpoint verification.
4. Serialize the bounded request, then read the optional Bearer token.
5. POST once with redirects disabled and bound the JSON response.
6. Parse one canonical v1.507 witness and verify its signature, evidence
   binding, key pin or current trust state, and 24-hour freshness window.
7. Re-read every local input by byte count and SHA-256.
8. Publish the witness and receipt as one alias-free, no-clobber output set.

## Failure Semantics

The command returns nonzero and creates neither output when public evidence,
transport metadata, response bytes, signature, freshness, trust, or output
paths fail validation. Existing outputs are never overwritten.

The remote endpoint can observe the public report, approval log, checkpoint,
source IP, and request timing. Do not place secrets in those public artifacts.

## Trust Boundary

This boundary proves that one configured witness key signed the exact locally
verified dedicated checkpoint and that pcbex received those signature bytes
through one bounded transport exchange. The receipt makes that exchange
reproducible and auditable.

It does not protect local files, trust states, or private keys; establish
trusted time, legal identity, or independent operation; guarantee endpoint
availability or idempotency; publish evidence globally; prevent equivocation
between consumers; or place an order, approve payment, or guarantee
exactly-once execution.
