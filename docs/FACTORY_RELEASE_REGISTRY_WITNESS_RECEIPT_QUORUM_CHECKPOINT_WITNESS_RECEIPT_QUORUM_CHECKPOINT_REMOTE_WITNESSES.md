# Remote Final Factory Checkpoint Witnesses

Acquire one final checkpoint witness over bounded HTTPS, verify it locally, and
retain a replayable receipt without changing the signed witness format.

The v1.517 boundary preserves every v1.512–v1.516 report, log, checkpoint,
witness, quorum, trust-state, and rotation contract. It adds one remote request
path, one closed receipt, and one full offline receipt verifier.

> [!IMPORTANT]
> pcbex verifies the exact v1.512 report, complete admission log, v1.514
> checkpoint, and independently pinned checkpoint key before it reads a Bearer
> token or sends any request. Invalid public evidence never reaches the remote
> witness.

## Key Features

- **Verifies First:** Re-runs the production v1.514 checkpoint verifier before
  credential access or network I/O.

- **Bounds Transport:** Requires HTTPS, disables redirects, rejects URL
  credentials and queries, limits the deadline to 1–600 seconds, and accepts
  only `application/json`.

- **Pins the Responder:** Verifies the canonical v1.515 witness with either one
  direct public key or one current v1.516 trust state.

- **Separates Key Roles:** Rejects any witness key that reuses the v1.514
  checkpoint signing key.

- **Preserves Compatibility:** Writes the unchanged v1.515 witness, ready for
  the existing 2–100 witness-quorum verifier.

- **Retains the Exchange:** Binds semantic and raw evidence digests, endpoint,
  request, response, selected keys, trust generation, and evaluation time.

- **Replays Offline:** Re-verifies the receipt against every retained input and
  the exact response without contacting the endpoint.

- **Drops Credentials:** Never writes the Bearer token to either output.

## Quick Start

Use a directly pinned final-witness key:

```bash
export FINAL_FACTORY_WITNESS_TOKEN='replace-me'

pcbex request-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness \
  checkpoint-witness-receipts.log.json \
  --quorum-report checkpoint-witness-receipts.quorum.json \
  --checkpoint checkpoint-witness-receipts.dedicated-checkpoint.json \
  --checkpoint-public-key checkpoint-witness-receipts.quorum.public.hex \
  --endpoint https://witness.example/v1/factory-receipt-quorum-checkpoint-witness \
  --witness-public-key final-witness-a.public.hex \
  --bearer-token-env FINAL_FACTORY_WITNESS_TOKEN \
  --output final-witness-a.json \
  --receipt-output final-witness-a.remote-receipt.json
```

Use retained rotatable trust instead:

```bash
pcbex request-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness \
  checkpoint-witness-receipts.log.json \
  --quorum-report checkpoint-witness-receipts.quorum.json \
  --checkpoint checkpoint-witness-receipts.dedicated-checkpoint.json \
  --checkpoint-public-key checkpoint-witness-receipts.quorum.public.hex \
  --endpoint https://witness.example/v1/factory-receipt-quorum-checkpoint-witness \
  --witness-trust-state final-witness-a.trust.3.json \
  --output final-witness-a.json \
  --receipt-output final-witness-a.remote-receipt.json
```

> [!TIP]
> Inject tokens through deployment-owned environment configuration. Omit
> `--bearer-token-env` when the endpoint uses mutual TLS or needs no Bearer
> authentication.

## Build the Final Quorum

Acquire each witness independently, then pass the unchanged response files to
the v1.515 verifier. Choose direct keys or trust states for the entire quorum.

```bash
pcbex verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witnesses \
  checkpoint-witness-receipts.log.json \
  --quorum-report checkpoint-witness-receipts.quorum.json \
  --checkpoint checkpoint-witness-receipts.dedicated-checkpoint.json \
  --checkpoint-public-key checkpoint-witness-receipts.quorum.public.hex \
  --witnesses final-witness-a.json \
  --witnesses final-witness-b.json \
  --witness-trust-states final-witness-a.trust.3.json \
  --witness-trust-states final-witness-b.trust.0.json \
  --minimum-witnesses 2 \
  --output final-witness-quorum.json
```

## HTTP Contract

pcbex sends one compact JSON object:

```json
{
  "schema_version": 1,
  "protocol": "pcbex-remote-factory-release-registry-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-v1",
  "quorum_report": {},
  "approval_log": {},
  "checkpoint": {}
}
```

The nested values are the locally verified public artifacts. A successful
endpoint returns one canonical pretty-JSON v1.515 witness with a trailing LF.

| Boundary | Limit |
| --- | ---: |
| Complete admission log source | 128 MiB |
| v1.512 quorum report | 128 KiB |
| v1.514 dedicated checkpoint | 64 KiB |
| Checkpoint or direct witness key file | 65 bytes |
| v1.516 witness trust state | 32 KiB |
| Serialized request | 129 MiB |
| Transport response | 1 MiB |
| Accepted canonical v1.515 witness | 64 KiB |
| Canonical transport receipt | 64 KiB |
| End-to-end timeout | 1–600 seconds; default 30 |

Redirects fail. URL user information and query strings fail. Plain HTTP is not
available in production commands.

## Receipt Bindings

The receipt records what pcbex verified, not what the endpoint claims.

| Field group | Binding |
| --- | --- |
| Public evidence | Semantic and raw-source report digests, complete admission-log identity and digests, registry checkpoint, prior factory checkpoint, and v1.514 checkpoint digests |
| Transport | Endpoint, exact compact request digest, raw response digest, and response byte count |
| Trust | Checkpoint key, witness key, optional raw trust-state digest, and trust generation |
| Decision | Evaluation time, witness time and identity, semantic witness digest, and `verified: true` |

Discover the closed receipt schema:

```bash
pcbex remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-receipt-schema
```

## Re-verify Offline

The validator is a full evidence replay, not a structural formatter. Supply the
exact files retained during acquisition:

```bash
pcbex validate-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-log-checkpoint-witness-receipt \
  final-witness-a.remote-receipt.json \
  --log checkpoint-witness-receipts.log.json \
  --quorum-report checkpoint-witness-receipts.quorum.json \
  --checkpoint checkpoint-witness-receipts.dedicated-checkpoint.json \
  --checkpoint-public-key checkpoint-witness-receipts.quorum.public.hex \
  --response final-witness-a.json \
  --witness-trust-state final-witness-a.trust.3.json \
  --output final-witness-a.remote-receipt.verified.json
```

Use `--witness-public-key` instead for direct trust. The two modes are mutually
exclusive, and the normalized output remains byte-identical to a valid receipt.

## Verification Flow

1. Validate endpoint syntax, timeout, evaluation time, and key-role separation.
2. Parse the canonical v1.512 report, complete duplicate-free admission log,
   and v1.514 checkpoint.
3. Re-run the exact report/log/suffix and checkpoint-signature verification.
4. Serialize the bounded request, then read the optional Bearer token.
5. POST once with redirects disabled and bound the JSON response.
6. Parse one canonical v1.515 witness and verify its signature, evidence
   binding, direct key or current trust state, identity, and 24-hour freshness.
7. Re-read every local input by identity, byte count, and SHA-256.
8. Publish the witness and receipt as one alias-free, no-clobber output set.

## Failure Semantics

The request command returns nonzero and creates neither output when public
evidence, transport metadata, response bytes, signature, freshness, trust, or
output paths fail validation. Existing outputs are never overwritten.

The offline validator returns nonzero and creates no normalized output when any
retained source, response, key, trust generation, digest, or decision differs.

The endpoint can observe the public report, admission log, checkpoint, source
IP, and request timing. Do not place secrets in those public artifacts.

## MCP

This transport remains CLI-only. No MCP network tool is added; the MCP
inventory and its network authority stay unchanged.

## Trust Boundary

Passing proves that one configured final-witness key signed the exact locally
verified v1.514 checkpoint and that pcbex received those signature bytes
through one bounded exchange. The receipt lets another verifier replay the
same retained evidence offline.

It does not protect local files, trust states, or private keys; establish
trusted time, legal identity, or independent operation; guarantee endpoint
availability or idempotency; publish evidence globally; prevent equivocation
between consumers; place an order; approve payment; or guarantee exactly-once
execution.

The unchanged v1.515
[final witness boundary](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESSES.md)
defines the response and quorum contracts. The v1.516
[key-rotation boundary](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_ROTATION.md)
defines the optional current trust state.
