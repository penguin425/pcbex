# Parallel Final Receipt-quorum Checkpoint Witness Acquisition

Acquire a v1.524 witness quorum in one bounded run. Keep the evidence when an
endpoint fails or the configured threshold is not met.

The v1.527 boundary preserves every v1.521–v1.526 wire contract. It adds a
closed manifest, a credential-free acquisition report, and full offline replay.

> [!IMPORTANT]
> pcbex validates the complete manifest and production-verifies the shared
> v1.521 report, final log, and v1.523 checkpoint before any worker reads a
> credential or opens a connection.

## Key Features

- **Runs in Parallel:** Uses 2–16 bounded workers across 2–100 sorted members.

- **Mixes Trust Modes:** Lets each member select a direct v1.524 key or an
  embedded current v1.525 trust state.

- **Reuses the Existing Adapter:** Every worker calls the unchanged v1.526
  request and receipt-verification path.

- **Keeps Verified Evidence:** Retains each unchanged v1.524 witness and its
  unchanged v1.526 receipt.

- **Reduces Failures:** Stores one coarse failure code without credential
  values, variable names, or raw transport diagnostics.

- **Builds the Existing Quorum:** Passes the verified subset to the production
  v1.524 verifier.

- **Preserves Threshold Failures:** Publishes both bounded reports before
  returning nonzero when the threshold is missed.

- **Replays Offline:** Rechecks every retained success and recomputes the final
  quorum without credentials, current time, or network access.

## Quick Start

Create a canonical manifest. Sort members by `witness_id` and select exactly one
key mode per member.

```json
{
  "schema_version": 1,
  "minimum_witnesses": 2,
  "maximum_parallelism": 2,
  "members": [
    {
      "endpoint": "https://witness-a.example/v1/final-checkpoint",
      "witness_id": "witness-a",
      "witness_public_key": "64-lowercase-hex-characters",
      "witness_trust_state": null,
      "bearer_token_env": "FINAL_WITNESS_A_TOKEN",
      "timeout_seconds": 30
    },
    {
      "endpoint": "https://witness-b.example/v1/final-checkpoint",
      "witness_id": "witness-b",
      "witness_public_key": "64-lowercase-hex-characters",
      "witness_trust_state": null,
      "bearer_token_env": null,
      "timeout_seconds": 30
    }
  ]
}
```

Validate it before deployment:

```bash
pcbex validate-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-quorum-manifest \
  final-witnesses.manifest.json \
  --output final-witnesses.manifest.normalized.json
```

Acquire the witnesses and build the unchanged quorum:

```bash
export FINAL_WITNESS_A_TOKEN='replace-me'

pcbex request-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-quorum \
  final-receipts.log.json \
  --quorum-report final-receipts.quorum.json \
  --checkpoint final-receipts.quorum.checkpoint.json \
  --checkpoint-public-key final-receipts.quorum.checkpoint.public.hex \
  --manifest final-witnesses.manifest.json \
  --output final-witnesses.acquisition.json \
  --quorum-output final-witnesses.quorum.json
```

The command succeeds only when the unchanged v1.524 quorum contains
`"quorum_met": true`.

> [!TIP]
> Keep manifests public. Store only environment-variable names in
> `bearer_token_env`, then inject token values through deployment configuration.

## Manifest Contract

| Field | Contract |
| --- | --- |
| `minimum_witnesses` | 2 through the member count |
| `maximum_parallelism` | 2–16; no greater than the member count |
| `endpoint` | HTTPS URL without user information, query, or fragment |
| `witness_id` | Stable lowercase slug; members sort strictly by this field |
| `witness_public_key` | Direct non-weak Ed25519 key hex, or `null` |
| `witness_trust_state` | Embedded canonical current v1.525 state, or `null` |
| `bearer_token_env` | Environment-variable name, or `null` |
| `timeout_seconds` | End-to-end deadline from 1 through 600 seconds |

Witness IDs, effective keys, and endpoints must each be globally distinct. A
witness key may not reuse the v1.523 checkpoint-signing key.

Discover the recursively closed schema:

```bash
pcbex remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-quorum-manifest-schema
```

## Acquisition Report

The report binds the exact manifest, v1.521 report, complete final log, v1.523
checkpoint, checkpoint key, evaluation time, members, counts, and final quorum.

| Member status | Retained evidence |
| --- | --- |
| `verified` | Endpoint, identity, effective key, optional trust digest/generation, unchanged v1.524 witness, and unchanged v1.526 receipt |
| `failed` | Endpoint, identity, effective key, optional trust digest/generation, and one coarse failure code |

Failure codes are `credential`, `transport`, `http_status`, `content_type`,
`response_limit`, `invalid_response`, `identity_mismatch`, or `verification`.

Each successful v1.526 request commits its own identity and key. The report
therefore requires a distinct request SHA-256 for every verified member.

```bash
pcbex remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-quorum-acquisition-report-schema
```

## Replay Offline

Supply the exact retained inputs. The validator uses the acquisition report's
declared evaluation time and never contacts an endpoint.

```bash
pcbex validate-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-quorum-acquisition-report \
  final-witnesses.acquisition.json \
  --manifest final-witnesses.manifest.json \
  --log final-receipts.log.json \
  --quorum-report final-receipts.quorum.json \
  --checkpoint final-receipts.quorum.checkpoint.json \
  --checkpoint-public-key final-receipts.quorum.checkpoint.public.hex \
  --output final-witnesses.acquisition.replayed.json \
  --quorum-output final-witnesses.quorum.replayed.json
```

A valid replay emits byte-identical acquisition and quorum documents. It
reconstructs every successful request, replays each v1.526 receipt, and invokes
the production v1.524 quorum verifier again.

> [!NOTE]
> Failed members receive structural replay only. Retained files cannot prove
> that a historical credential, connection, HTTP exchange, or endpoint failure
> happened as recorded.

## Failure and Publication Semantics

Invalid configuration, role reuse, or shared public evidence creates no output.
Those checks finish before credential lookup and network access.

Member failures do not cancel verified peers. pcbex publishes the acquisition
report and quorum as one distinct no-clobber set, then returns nonzero if the
verified subset misses the threshold.

Every local input is re-read by identity, byte count, and SHA-256 before
publication. This detects sequential mutation but is not a globally atomic
filesystem transaction or an atomic same-principal snapshot.

## Limits

| Boundary | Limit |
| --- | ---: |
| Canonical manifest | 1 MiB |
| Members | 2–100 |
| Parallel workers | 2–16 |
| Canonical acquisition report | 16 MiB |
| Complete final admission log | 128 MiB |
| v1.521 quorum report | 128 KiB |
| v1.523 checkpoint | 64 KiB |
| v1.524 witness | 64 KiB per success |
| v1.525 trust state | 32 KiB per configured member |
| v1.526 receipt | 64 KiB per success |
| Endpoint | 2,048 bytes |
| Credential-variable name | 128 bytes |
| Bearer token | 8 KiB |
| Response headers | 16 KiB per request |
| Timeout | 1–600 seconds per member |

Production endpoints require HTTPS. Redirects, URL credentials, queries, and
fragments fail; loopback HTTP exists only behind a hidden test flag.

## Trust Boundary

Passing proves that the configured keys produced fresh valid v1.524 signatures
over one exact, locally verified v1.523 checkpoint and met the selected
threshold. It does not prove trusted time, endpoint identity or availability,
operator independence, protected state or key custody, global publication or
non-equivocation, ordering, payment, or exactly-once execution.

This boundary remains CLI-only. It adds no MCP network authority, so the MCP
inventory remains 186 tools.

See the [single-witness transport guide](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_REMOTE_WITNESSES.md)
for each retained v1.526 receipt and the [witness guide](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESSES.md)
for the unchanged v1.524 signature and quorum contracts. Successful member
receipts can enter the [v1.528 transparency chain](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_TRANSPARENCY.md).
