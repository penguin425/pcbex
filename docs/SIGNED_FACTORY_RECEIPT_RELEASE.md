# Signed factory-receipt release

Authenticate one exact normalized factory receipt before release.

Version 1.480 extends the executable-pinned v1.479 boundary with a dedicated
Ed25519 receipt attestation. It binds the receipt, manufacturing package, and
organization policy to one factory key selected by an independently supplied
canonical policy digest.

> [!IMPORTANT]
> A valid signature authenticates the configured key—not a factory's legal
> identity, TLS session, raw HTTP response, current capacity, order, or payment.
> Load the expected policy digest from protected deployment configuration.

## What it adds

- **Pins factory keys:** The organization policy maps each `factory_id` to one
  provider and one non-weak Ed25519 public key.

- **Signs exact evidence:** The signature covers the normalized receipt, exact
  manufacturing ZIP identity, policy identity, attestation ID, challenge, and
  bounded validity window.

- **Replays the release:** The Python boundary freshly runs v1.479 twice and
  requires the same time-invariant release subject around signature checking.

- **Aligns decision windows:** A positive outer result also requires the
  receipt verifier's retained evaluation instant to fall inside the exact
  fabrication-authorization window.

- **Keeps valid negatives:** An inactive or policy-overlong signature produces
  a retained `not_authenticated` report before the optional final gate fails.

- **Stays offline:** Verification invokes only the digest-pinned local pcbex
  binary. It performs no supplier or factory network request.

## Configure the policy

Add one optional `factory_receipt_attestation_policy` to the organization
policy pack. Existing packs remain byte-compatible when the field is absent.

```json
{
  "factory_receipt_attestation_policy": {
    "maximum_validity_seconds": 3600,
    "trusted_keys": [
      {
        "factory_id": "factory-primary",
        "provider": "generic",
        "public_key": "<64-lowercase-hex Ed25519 public key>"
      }
    ]
  }
}
```

`provider` accepts `jlcpcb`, `pcbway`, or `generic`. Factory IDs and public keys
must be unique and disjoint from AI, escalation, fabrication, and procurement
roles. The policy accepts 1–100 factory keys and a validity ceiling from 1 to
604,800 seconds.

## Quick start

Generate a dedicated key, then sign the exact package and normalized receipt:

```sh
pcbex approval-keygen \
  --private-key factory-receipt.key \
  --public-key factory-receipt.pub

pcbex sign-factory-receipt-attestation \
  build/manufacturing/manufacturing.zip \
  --factory-receipt factory-receipt.json \
  --policy-pack organization-policy.json \
  --expected-policy-pack-canonical-sha256 "$POLICY_DIGEST" \
  --private-key factory-receipt.key \
  --factory-id factory-primary \
  --attestation-id release-2026-08-23 \
  --challenge "$RELEASE_CHALLENGE" \
  --issued-at-unix "$ISSUED_AT" \
  --expires-at-unix "$EXPIRES_AT" \
  --output factory-receipt.attestation.json
```

Verify the signature directly when you need the narrow cryptographic result:

```sh
pcbex verify-factory-receipt-attestation \
  build/manufacturing/manufacturing.zip \
  --factory-receipt factory-receipt.json \
  --policy-pack organization-policy.json \
  --expected-policy-pack-canonical-sha256 "$POLICY_DIGEST" \
  --signed-attestation factory-receipt.attestation.json \
  --output factory-receipt.attestation-report.json \
  --require-authenticated
```

For release authority, rerun the complete v1.479 command and add the receipt
inputs to the outer consumer:

```sh
pcbex-agent replay-signed-factory-receipt-release \
  board.placed.kicad_pcb board.routed.kicad_pcb \
  --convergence-report board.convergence.json \
  --routing-verification-report board.routing-verification.json \
  --manufacturing-package build/manufacturing/manufacturing.zip \
  --routing-manufacturing-handoff-report board.routing-manufacturing.json \
  --native-drc-report board.native-drc.json \
  --routing-drc-manufacturing-handoff-report board.routing-drc-manufacturing.json \
  --deterministic-pipeline-plan factory-required-plan.json \
  --deterministic-pipeline-report factory-required-report.json \
  --approval fabrication-a.json \
  --approval fabrication-b.json \
  --routing-drc-fabrication-release-report board.fabrication-release.json \
  --executable-pinned-fabrication-release-report board.executable-pinned-release.json \
  --factory-receipt factory-receipt.json \
  --policy-pack organization-policy.json \
  --signed-factory-receipt-attestation factory-receipt.attestation.json \
  --expected-policy-pack-canonical-sha256 "$POLICY_DIGEST" \
  --expected-routing-pcbex-sha256 "$ROUTING_PCBEX_SHA256" \
  --expected-authorization-pcbex-sha256 "$AUTHORIZATION_PCBEX_SHA256" \
  --expected-kicad-cli-sha256 "$KICAD_CLI_SHA256" \
  --pcbex /opt/pcbex/bin/pcbex \
  --authorization-pcbex /opt/pcbex/bin/pcbex \
  --kicad-cli /opt/kicad/bin/kicad-cli \
  --kicad-project board.kicad_pro \
  --kicad-rules board.kicad_dru \
  --output board.signed-factory-receipt-release.json \
  --require-authenticated
```

## Architecture

| Boundary | Owner | Responsibility |
| --- | --- | --- |
| Receipt signing | Rust `pcbex` | Validate public evidence and policy before reading the private key; emit one domain-separated Ed25519 envelope |
| Receipt verification | Rust `pcbex` | Verify policy pin, exact evidence, key, signature, and local validity window |
| Release replay | Python agent | Freshly replay v1.479 twice, require its pinned authorization binary, cross-bind every identity, and publish the outer result |
| External trust | Deployment | Supply the expected policy and executable digests, protect keys, and decide when to consume the result |

The Python layer never reads, copies, hashes, or stages private-key bytes. On
Unix, the Rust signer requires the key file to be owned by the effective UID
with mode exactly `0400` or `0600`.

## Outcomes

| Status | Meaning |
| --- | --- |
| `release_authenticated` | Fresh v1.479 is authorized and the exact receipt signature is active under the pinned policy |
| `not_authenticated` | The exact evidence is valid, but v1.479 is negative or the receipt attestation is inactive |

A third valid-negative gate records a receipt attestation that was active at a
different instant but outside the signed fabrication-authorization window.

Malformed JSON, duplicate keys, a wrong policy pin, package/receipt mismatch,
an invalid signature, an untrusted factory key, unsafe aliases, mutation,
deadline failure, or child failure produces no outer report.

`--require-authenticated` runs last. A valid negative remains on disk for audit.

## Limits

| Input or output | Maximum |
| --- | ---: |
| Manufacturing package | 128 MiB |
| Normalized factory receipt | 64 MiB |
| Organization policy pack | 64 MiB |
| Signed factory-receipt attestation | 1 MiB |
| Rust attestation report | 4 MiB |
| Outer signed-receipt release report | 16 MiB |
| Whole Python operation | 1–600 seconds; default 300 |

The outer direct-input ceiling is derived from the complete v1.479 closure plus
the retained v1.479 report and the three new receipt inputs. Every file is
bounded, stable-read, alias-checked, and reread at its defined boundary.

## What it does not prove

The report keeps these claims false:

- trusted time or global challenge one-time use;
- factory legal identity, endpoint, TLS, or raw-response authenticity;
- source, executable origin, toolchain, or policy provenance;
- manufacturability beyond the retained checks;
- external submission, capacity reservation, order placement, or payment.

The result is a point-in-time offline authentication snapshot. A side-effecting
consumer must freshly replay it, reserve the release durably, and enforce its
own credentials, idempotency, retry, and reconciliation policy.

## Schema discovery

```sh
pcbex signed-factory-receipt-attestation-schema \
  --output signed-factory-receipt-attestation-v1.schema.json

pcbex factory-receipt-attestation-report-schema \
  --output factory-receipt-attestation-report-v1.schema.json

pcbex-agent signed-factory-receipt-release-report-schema \
  --output signed-factory-receipt-release-v1.schema.json
```

All three schemas are closed. Treat the installed schema commands—not this
example—as the wire-format authority.
