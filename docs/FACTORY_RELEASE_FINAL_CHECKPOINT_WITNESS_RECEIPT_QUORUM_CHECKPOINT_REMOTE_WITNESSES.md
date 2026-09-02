# Remote Final Receipt-quorum Checkpoint Witnesses

Acquire one independent v1.524 witness over bounded HTTPS, verify it locally,
and retain a credential-free receipt for complete offline replay.

The v1.526 boundary preserves every v1.521–v1.525 report, log, checkpoint,
witness, quorum, trust-state, and rotation wire contract. It adds one CLI-only
request path, one closed receipt, and one full receipt verifier.

> [!IMPORTANT]
> pcbex production-verifies the exact v1.521 quorum report, complete final
> admission log, v1.523 checkpoint, and independently pinned checkpoint key
> before reading a Bearer token or opening a network connection.

## Key Features

- **Verifies First:** Rejects invalid public evidence before credential access
  or network I/O.

- **Bounds Transport:** Sends one no-redirect HTTPS POST with a 1–600 second
  deadline, 16 KiB response-header ceiling, and 64 KiB response-body ceiling.

- **Pins Identity:** Commits the expected witness ID and key to the request,
  then rejects a response from any other identity or key.

- **Supports Rotation:** Accepts either one direct v1.524 key pin or one current
  v1.525 generation-chained trust state.

- **Separates Roles:** Rejects a witness key that reuses the v1.523 checkpoint
  signing key.

- **Preserves Bytes:** Publishes the unchanged canonical v1.524 witness for the
  existing quorum verifier.

- **Records the Exchange:** Binds semantic and raw evidence digests plus exact
  request, response, and trust identities, then records the selected endpoint
  and freshness evaluation time.

- **Replays Offline:** Reconstructs the request and reruns the production
  signature, freshness, evidence, identity, and trust checks without contacting
  the endpoint.

## Quick Start

Use one directly pinned witness key:

```bash
export FINAL_CHECKPOINT_WITNESS_TOKEN='replace-me'

pcbex request-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness \
  final-receipts.log.json \
  --quorum-report final-receipts.quorum.json \
  --checkpoint final-receipts.quorum.checkpoint.json \
  --checkpoint-public-key final-receipts.quorum.checkpoint.public.hex \
  --endpoint https://witness.example/v1/final-receipt-quorum-checkpoint-witness \
  --witness-id witness-a \
  --witness-public-key witness-a.public.hex \
  --bearer-token-env FINAL_CHECKPOINT_WITNESS_TOKEN \
  --output final-checkpoint.witness-a.json \
  --receipt-output final-checkpoint.witness-a.remote-receipt.json
```

Use current rotatable trust instead:

```bash
pcbex request-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness \
  final-receipts.log.json \
  --quorum-report final-receipts.quorum.json \
  --checkpoint final-receipts.quorum.checkpoint.json \
  --checkpoint-public-key final-receipts.quorum.checkpoint.public.hex \
  --endpoint https://witness.example/v1/final-receipt-quorum-checkpoint-witness \
  --witness-id witness-a \
  --witness-trust-state witness-a.trust.3.json \
  --output final-checkpoint.witness-a.json \
  --receipt-output final-checkpoint.witness-a.remote-receipt.json
```

> [!TIP]
> Inject tokens through deployment-owned environment configuration. Omit
> `--bearer-token-env` when the endpoint needs no Bearer authentication.

## Build the Existing Quorum

Acquire each witness independently. Then pass the unchanged response files to
the v1.524 quorum verifier using either direct keys or trust states for the
entire invocation.

```bash
pcbex verify-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witnesses \
  final-receipts.log.json \
  --quorum-report final-receipts.quorum.json \
  --checkpoint final-receipts.quorum.checkpoint.json \
  --checkpoint-public-key final-receipts.quorum.checkpoint.public.hex \
  --witnesses final-checkpoint.witness-a.json \
  --witnesses final-checkpoint.witness-b.json \
  --witness-trust-states witness-a.trust.3.json \
  --witness-trust-states witness-b.trust.0.json \
  --minimum-witnesses 2 \
  --output final-checkpoint.witness-quorum.json
```

Remote acquisition does not weaken quorum policy. The unchanged verifier still
requires 2–100 fresh witnesses with distinct IDs and keys, and it keeps the
checkpoint signing key outside the witness role.

## HTTP Contract

pcbex sends one compact JSON object. The expected identity, key mode, and exact
public evidence are part of the request rather than ambient endpoint state.

```json
{
  "schema_version": 1,
  "protocol": "pcbex-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-v1",
  "expected_witness_id": "witness-a",
  "expected_witness_public_key": "64-lowercase-hex-characters",
  "witness_key_trust_state_sha256": null,
  "witness_key_generation": null,
  "quorum_report": {},
  "approval_log": {},
  "checkpoint": {}
}
```

Trust-state mode fills both optional trust fields. A successful endpoint returns
one canonical v1.524 witness as `application/json`; any other status, media type,
identity, signature, freshness result, or canonical representation fails.

| Boundary | Limit |
| --- | ---: |
| Complete final admission log source | 128 MiB |
| v1.521 quorum report | 128 KiB |
| v1.523 dedicated checkpoint | 64 KiB |
| Checkpoint or direct witness key file | 65 bytes |
| v1.525 witness trust state | 32 KiB |
| Serialized request | 129 MiB |
| Endpoint URL | 2,048 bytes |
| Response headers | 16 KiB |
| Response / canonical v1.524 witness | 64 KiB |
| Canonical transport receipt | 64 KiB |
| Bearer token | 8 KiB |
| End-to-end timeout | 1–600 seconds; default 30 |

Redirects fail. URL user information and query strings fail. Production
commands require HTTPS; the loopback HTTP escape is hidden and test-only.

## Receipt Bindings

The receipt records what local verification accepted. It does not authenticate
the endpoint merely because its URL appears in the document.

`endpoint` and `evaluated_at_unix` are receipt-declared replay inputs. Offline
validation checks their internal consistency; it cannot authenticate who
created the receipt or reconstruct historical transport behavior.

| Field group | Exact binding |
| --- | --- |
| Public evidence | Semantic and raw-source v1.521 report digests; complete log identity, head, count, semantic digest, and raw digest; registry and both prior checkpoint digests; semantic and raw v1.523 checkpoint digests |
| Transport | Declared endpoint, compact request SHA-256, raw response SHA-256, and response byte count |
| Trust | Independently pinned checkpoint key, expected and returned witness identity/key, optional raw trust-state SHA-256, and trust generation |
| Decision | Recorded evaluation time, witness time, canonical witness SHA-256, and `verified: true` |

Discover the closed schema:

```bash
pcbex remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-receipt-schema
```

## Re-verify Offline

Supply the exact files retained during acquisition. The validator reconstructs
the original request and uses the receipt's evaluation time; it does not read
the current clock or contact the endpoint.

```bash
pcbex validate-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-receipt \
  final-checkpoint.witness-a.remote-receipt.json \
  --log final-receipts.log.json \
  --quorum-report final-receipts.quorum.json \
  --checkpoint final-receipts.quorum.checkpoint.json \
  --checkpoint-public-key final-receipts.quorum.checkpoint.public.hex \
  --response final-checkpoint.witness-a.json \
  --witness-id witness-a \
  --witness-trust-state witness-a.trust.3.json \
  --output final-checkpoint.witness-a.remote-receipt.verified.json
```

Use `--witness-public-key` for direct trust. The two trust modes are mutually
exclusive, and a valid normalized output is byte-identical to the receipt.

## Verification Flow

1. Validate endpoint syntax, timeout, evaluation time, expected identity, and
   key-role separation.
2. Parse the canonical v1.521 report, complete duplicate-free final admission
   log, and v1.523 checkpoint.
3. Rerun the production report/log/suffix and checkpoint-signature verifier.
4. Serialize the bounded request, then read the optional Bearer token.
5. POST once with redirects disabled and read one bounded JSON response.
6. Parse the canonical v1.524 witness and verify its signature, evidence,
   identity, direct or current trust, role separation, and 24-hour freshness.
7. Reread every local input by identity, byte count, and SHA-256.
8. Publish the witness and credential-free receipt as one alias-free,
   no-clobber output set.

## Failure Semantics

The request fails before publication when configuration, public evidence,
credentials, transport, response, trust, freshness, or final input revalidation
fails. Existing files are never overwritten.

Both outputs are staged before publication, and a later publication failure
triggers best-effort removal of any file created earlier in the set. This is not
a global filesystem transaction or an atomic same-principal snapshot.

Offline replay returns nonzero and creates no normalized output when any source,
response, identity, key, generation, digest, or decision differs. The endpoint
can still observe the public evidence, source IP, and request timing.

## MCP

This transport remains CLI-only. v1.526 adds no MCP network authority, so the
MCP inventory remains 186 tools.

## Trust Boundary

Passing proves that one configured v1.524 witness key signed the exact locally
verified v1.523 checkpoint and that pcbex accepted those signature bytes during
one bounded exchange. The receipt lets another verifier reproduce that local
decision from the retained evidence.

It does not prove historical network behavior, endpoint legal identity or
availability, trusted time, separate operators, protected files or key custody,
global publication, or non-equivocation. It does not place an order, approve
payment, or guarantee exactly-once execution.

The unchanged v1.524
[witness boundary](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESSES.md)
defines the signed response and quorum. The v1.525
[rotation boundary](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_ROTATION.md)
defines the optional current trust state. Publish a successful receipt through
the [v1.528 transparency boundary](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_TRANSPARENCY.md),
or replay every retained input during
[v1.529 verifier-bound admission](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_ADMISSION.md).
