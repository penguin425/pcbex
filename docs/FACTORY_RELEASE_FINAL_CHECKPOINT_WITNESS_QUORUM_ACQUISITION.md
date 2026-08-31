# Parallel Final Checkpoint Witness Acquisition

Acquire a final witness quorum in one bounded run—even when some endpoints fail.

The v1.518 boundary fans one verified checkpoint context out to 2–100 remote
witnesses. It keeps the v1.512 report, v1.514 checkpoint, v1.515 witness and
quorum, v1.516 trust state, and v1.517 receipt formats unchanged.

> [!IMPORTANT]
> pcbex validates every endpoint, key, trust state, timeout, and credential
> reference, then production-verifies the shared public evidence before any
> worker reads a credential or opens a connection.

## Key Features

- **Acquires in Parallel:** Runs 2–16 bounded workers across a sorted manifest
  of up to 100 witnesses.

- **Mixes Trust Modes:** Pins one member directly and another through its
  current v1.516 trust state in the same run.

- **Keeps Partial Evidence:** Retains each verified v1.515 witness and unchanged
  v1.517 receipt while reducing failures to credential-free categories.

- **Builds the Existing Quorum:** Invokes the production v1.515 verifier and
  writes its unchanged final report.

- **Preserves Threshold Failures:** Writes both reports before returning
  nonzero when valid witnesses do not meet the configured threshold.

- **Replays Offline:** Re-verifies every successful receipt, signature, trust
  binding, source digest, and the complete final quorum without network access.

- **Drops Sensitive Detail:** The acquisition report never copies Bearer
  values, credential-variable names, raw transport errors, or response bodies
  from failed endpoints.

## Quick Start

Create a canonical two-witness manifest from directly pinned keys:

```bash
jq -n \
  --arg key_a "$(tr -d '\r\n' < final-witness-a.public.hex)" \
  --arg key_b "$(tr -d '\r\n' < final-witness-b.public.hex)" \
  '{
    schema_version: 1,
    minimum_witnesses: 2,
    maximum_parallelism: 2,
    members: [
      {
        endpoint: "https://witness-a.example/v1/final-checkpoint-witness",
        witness_id: "final-witness-a",
        witness_public_key: $key_a,
        witness_trust_state: null,
        bearer_token_env: "FINAL_WITNESS_A_TOKEN",
        timeout_seconds: 30
      },
      {
        endpoint: "https://witness-b.example/v1/final-checkpoint-witness",
        witness_id: "final-witness-b",
        witness_public_key: $key_b,
        witness_trust_state: null,
        bearer_token_env: "FINAL_WITNESS_B_TOKEN",
        timeout_seconds: 30
      }
    ]
  }' > final-witnesses.manifest.json
```

Validate the manifest before deployment:

```bash
pcbex validate-remote-factory-release-final-checkpoint-witness-quorum-manifest \
  final-witnesses.manifest.json \
  --output final-witnesses.manifest.normalized.json
```

Acquire the witnesses and build the final quorum:

```bash
export FINAL_WITNESS_A_TOKEN='replace-me'
export FINAL_WITNESS_B_TOKEN='replace-me'

pcbex request-remote-factory-release-final-checkpoint-witness-quorum \
  checkpoint-witness-receipts.log.json \
  --quorum-report checkpoint-witness-receipts.quorum.json \
  --checkpoint checkpoint-witness-receipts.dedicated-checkpoint.json \
  --checkpoint-public-key checkpoint-witness-receipts.quorum.public.hex \
  --manifest final-witnesses.manifest.json \
  --output final-witnesses.acquisition.json \
  --quorum-output final-witnesses.quorum.json
```

The command exits successfully when the unchanged v1.515 quorum reports
`quorum_met: true`.

> [!TIP]
> Keep the manifest public and inject token values through deployment-owned
> environment configuration. Set `bearer_token_env` to `null` for endpoints
> that use mutual TLS or require no Bearer token.

## Manifest

Members must be sorted by `witness_id`. Witness IDs, effective keys, and
endpoints must each be unique.

| Field | Contract |
| --- | --- |
| `minimum_witnesses` | Integer from 2 through the member count |
| `maximum_parallelism` | Integer from 2 through 16, no greater than the member count |
| `endpoint` | HTTPS URL without user information, query, or fragment |
| `witness_id` | Canonical configured witness identity |
| `witness_public_key` | Direct lowercase Ed25519 public-key hex, or `null` |
| `witness_trust_state` | Embedded canonical v1.516 current trust state, or `null` |
| `bearer_token_env` | Environment-variable name only; never its value |
| `timeout_seconds` | Per-request end-to-end deadline from 1 through 600 |

Select exactly one of `witness_public_key` and `witness_trust_state` per member.
Unlike the standalone v1.515 quorum CLI, one acquisition manifest may mix those
two modes because pcbex normalizes every verified member to its effective key
before calling the unchanged production verifier.

Discover the closed schema:

```bash
pcbex remote-factory-release-final-checkpoint-witness-quorum-manifest-schema
```

## Acquisition Report

One closed report binds the exact manifest and every shared public source by
SHA-256. Its members remain sorted in manifest order.

| Status | Retained fields |
| --- | --- |
| `verified` | Endpoint, identity, effective key, optional trust digest/generation, unchanged v1.515 witness, and unchanged v1.517 receipt |
| `failed` | Endpoint, identity, effective key, optional trust digest/generation, and one coarse failure code |

Failure codes are deliberately small:

- `credential`
- `transport`
- `http_status`
- `content_type`
- `response_limit`
- `invalid_response`
- `identity_mismatch`
- `verification`

The report also embeds the unchanged v1.515 quorum and repeats its threshold,
verified count, evaluation time, and result. Any mismatch fails validation.

```bash
pcbex remote-factory-release-final-checkpoint-witness-quorum-acquisition-report-schema
```

## Re-verify Offline

Replay the complete retained result with no endpoint or credential access:

```bash
pcbex validate-remote-factory-release-final-checkpoint-witness-quorum-acquisition-report \
  final-witnesses.acquisition.json \
  --manifest final-witnesses.manifest.json \
  --log checkpoint-witness-receipts.log.json \
  --quorum-report checkpoint-witness-receipts.quorum.json \
  --checkpoint checkpoint-witness-receipts.dedicated-checkpoint.json \
  --checkpoint-public-key checkpoint-witness-receipts.quorum.public.hex \
  --output final-witnesses.acquisition.replayed.json \
  --quorum-output final-witnesses.quorum.replayed.json
```

A valid replay produces byte-identical acquisition and quorum documents. It
reconstructs each successful v1.517 request, replays its receipt, validates the
v1.515 signature and current trust binding, then recomputes the final quorum.

> [!NOTE]
> Offline replay proves the structure and configured identity of failed
> entries. It cannot independently prove that a credential was absent, a
> connection failed, or a remote service returned a particular error earlier.

## Verification Flow

| Stage | Action |
| --- | --- |
| 1. Global configuration | Parse the canonical manifest; reject duplicate identities, keys, endpoints, weak keys, and checkpoint-signer key reuse |
| 2. Shared preflight | Re-run the production v1.512 report/log/suffix and v1.514 checkpoint verification |
| 3. Bounded fan-out | Process members in batches capped by `maximum_parallelism`; each worker uses the unchanged v1.517 adapter |
| 4. Evidence reduction | Keep verified witness/receipt pairs; map failed exchanges to coarse codes |
| 5. Final authority | Pass verified witnesses and effective keys to the production v1.515 quorum verifier |
| 6. Publication | Re-read every local input, then publish the acquisition report and quorum as one alias-free no-clobber set |

## Failure Semantics

Invalid configuration or shared public evidence creates no output. Those
failures occur before credential lookup and network access.

Member failures do not cancel valid peers. pcbex retains them in the acquisition
report and lets the verified subset reach the final quorum verifier.

If the subset misses the threshold, pcbex atomically writes both bounded
reports and then returns nonzero. Existing files are never overwritten; input
and output aliases fail before acquisition begins.

## Limits

| Boundary | Limit |
| --- | ---: |
| Canonical manifest | 1 MiB |
| Witness members | 2–100 |
| Minimum witnesses | 2–100; no greater than member count |
| Parallel workers | 2–16; no greater than member count |
| Endpoint | 2,048 bytes |
| Credential-variable name | 128 bytes |
| Per-member timeout | 1–600 seconds |
| Canonical acquisition report | 16 MiB |
| v1.512 quorum report | 128 KiB |
| Complete admission log | 128 MiB |
| v1.514 dedicated checkpoint | 64 KiB |
| v1.515 witness | 64 KiB each |
| v1.516 trust state | 32 KiB each |
| v1.517 transport response | 1 MiB each |

All production endpoints require HTTPS. Redirects, URL credentials, query
strings, and fragments fail.

## MCP

This acquisition path stays CLI-only. It adds no MCP network authority; the MCP
inventory remains unchanged.

## Trust Boundary

Passing proves that the configured verified keys signed one exact, locally
verified v1.514 checkpoint and that the unchanged v1.515 verifier accepted the
resulting threshold. Retained successes can be replayed from exact public
evidence without contacting any endpoint.

It does not protect local files, trust states, environment variables, or private
keys; establish trusted time, legal identity, separate operators, or independent
key custody; prove historical network failures; guarantee endpoint availability;
publish evidence globally; prevent cross-consumer equivocation; establish
ordering; place an order; approve payment; or guarantee exactly-once execution.

The [single-witness transport guide](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_REMOTE_WITNESSES.md)
defines each retained v1.517 receipt. The [final witness guide](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESSES.md)
remains authoritative for the unchanged v1.515 signature and quorum contracts.

Version 1.519 adds a [structural transparency boundary](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_TRANSPARENCY.md)
for any retained canonical success receipt. It does not change this acquisition
report or independently reproduce historical failure conditions.

Version 1.520 adds a [verifier-bound admission boundary](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_ADMISSION.md)
for one retained success. It replays exact public evidence, response, signature,
freshness, and trust without changing this acquisition report.
