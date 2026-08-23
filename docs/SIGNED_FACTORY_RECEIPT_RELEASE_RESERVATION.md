# Signed factory-receipt release reservation

Consume one authenticated release challenge in one trusted local ledger.

Version 1.481 adds durable admission immediately after the v1.480 signed
factory-receipt boundary. The agent freshly replays the retained release, then
a hidden Rust helper installs one challenge-derived marker without replacement.

> [!IMPORTANT]
> This is at-most-once only inside the selected ledger. It does not reserve
> factory capacity, submit files, place an order, perform payment, or establish
> global exactly-once execution.

## What it adds

- **Replays before commit:** The agent requires the retained and fresh v1.480
  reports to bind the same time-invariant signed-release subject.

- **Checks both windows:** The signed receipt attestation and the underlying
  fabrication authorization must remain active at ledger commit.

- **Pins ledger identity:** A fixed manifest must match the caller-supplied
  64-hex ledger ID before any marker is installed.

- **Commits durably:** Rust pins the directory, checks the local filesystem and
  mode, then uses synchronized descriptor-relative no-replace publication.

- **Burns collisions:** Any existing challenge filename blocks reuse even when
  its bytes are corrupt or unrelated.

- **Keeps state compact:** The marker retains exact report and subject
  identities, not the multi-gigabyte replay closure.

## Prepare the ledger

The ledger is an explicit trust root. Create it outside every replay input
directory, keep it on a reviewed local filesystem, and protect it with mode
`0700`.

```sh
LEDGER=/var/lib/pcbex/signed-release-reservations
LEDGER_ID="$(openssl rand -hex 32)"

install -d -m 0700 "$LEDGER"
printf '%s\n' \
  "{\"schema_version\":1,\"ledger_scope\":\"pinned-local-signed-factory-receipt-release-ledger-at-most-once-v1\",\"ledger_id\":\"$LEDGER_ID\"}" \
  > "$LEDGER/.pcbex-signed-factory-receipt-release-reservation-ledger-v1.json"
chmod 0600 "$LEDGER/.pcbex-signed-factory-receipt-release-reservation-ledger-v1.json"
```

Store `LEDGER_ID` in protected deployment configuration. A marker-provided or
ledger-provided value is not an independent pin.

> [!NOTE]
> The durable ledger boundary is Unix-only. Windows still compiles and tests
> the public surface, but direct reservation fails closed.

## Reserve the release

Start with the exact successful v1.480 replay inputs. Add the retained outer
report as the first argument and replace its output gate with ledger options.

```sh
pcbex-agent reserve-signed-factory-receipt-release \
  board.signed-factory-receipt-release.json \
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
  --reservation-ledger "$LEDGER" \
  --expected-ledger-id "$LEDGER_ID"
```

Success prints one line after durable completion. The marker appears at:

```text
signed-factory-receipt-release-reservation-v1-<signed-challenge>.json
```

Run the same command again and it fails. The existing file remains untouched.

## Architecture

| Boundary | Owner | Responsibility |
| --- | --- | --- |
| Fresh release replay | Python agent | Capture the retained report, rerun v1.480, compare stable subjects, and require a fresh positive decision |
| Compact marker | Python agent | Bind retained/fresh report identities, signed challenge, package, receipt, policy, signer, verifier, and both windows |
| Ledger trust gate | Rust `pcbex` | Pin the directory and manifest; require effective-UID ownership, mode `0700`, and an accepted local filesystem |
| Durable commit | Rust `pcbex` | Recheck marker, inputs, manifest, and time; install one derived name without replacement and synchronize it |
| External execution | Later boundary | Supply credentials, submit an idempotent request, and reconcile transport uncertainty |

Direct use of the hidden helper is not an authorization boundary. It cannot
replay the original v1.480 closure; only the public agent performs that fresh
replay before creating an eligible marker.

## Marker contents

The closed marker retains:

- the externally expected ledger ID;
- retained and fresh v1.480 byte counts, SHA-256 digests, and bindings;
- one domain-separated stable release-subject digest;
- the attestation ID, challenge, factory ID, provider, and active window;
- the underlying fabrication authorization ID, challenge, and active window;
- exact package, receipt, policy, signed-attestation, and verifier digests; and
- explicit false claims for network, submission, capacity, order, payment,
  trusted time, legal identity, provenance, and global one-time use.

The marker is limited to 16 KiB. The fixed manifest is limited to 4 KiB, and
the public helper accepts at most 128 protected input paths.

## Failure semantics

Malformed, noncanonical, oversized, aliased, mutated, expired, mismatched, or
negative evidence produces no marker. An insecure or remote ledger also fails
before publication.

Once no-replace publication commits, a later synchronization or completion
error reports that the challenge remains reserved. Operators must reconcile
the deterministic marker path instead of retrying with a new challenge. A
timeout, crash, or unrecognized helper failure after invocation is
conservatively reported as uncertain because the marker may already exist.

> [!WARNING]
> Deleting or copying ledger files changes the local replay guarantee. Back up
> and restore the entire ledger as one protected operational unit.

## What it does not prove

The reservation does not prove:

- global challenge uniqueness or cross-host coordination;
- trusted wall-clock time or clock authenticity;
- factory legal identity, TLS, raw-response, or current-capacity authenticity;
- source, executable, toolchain, or policy provenance;
- manufacturing acceptance, external submission, or capacity reservation;
- order placement, payment, spend enforcement, or exactly-once execution; or
- protection from an independently concurrent process with the same local
  principal and access to trusted files.

The next boundary may use this marker as an idempotency prerequisite. It must
still own adapter credentials, bounded transport, retry policy, and explicit
reconciliation states.

## Schema discovery

```sh
pcbex signed-factory-receipt-release-reservation-schema \
  --output signed-factory-receipt-release-reservation-v1.schema.json

pcbex signed-factory-receipt-release-reservation-ledger-schema \
  --output signed-factory-receipt-release-reservation-ledger-v1.schema.json
```

Both schemas are closed. Treat the installed commands as the wire-format
authority.
