# Executable-pinned fabrication release

Freshly reassess one fabrication-release subject with deployment-owned binary pins.

Version 1.479 adds a strict outer boundary to the v1.478 fabrication-release
flow. It resolves the three selected native command entrypoints, checks their
bytes against independent SHA-256 pins, and then requires v1.478 to freshly
reassess the time-invariant subject of one retained report with those resolved
commands.

> [!IMPORTANT]
> Load the expected digests from protected deployment configuration. Computing
> a digest from the same untrusted executable immediately before this command
> checks consistency, not trust.

## Key properties

- **Pins three roles:** Routing pcbex, authorization pcbex, and KiCad CLI each
  carry an explicit expected digest.

- **Rejects wrappers:** Routing and authorization commands contain exactly one
  native executable. Script paths and extra wrapper arguments stay outside this
  contract and therefore fail closed.

- **Replays everything:** The existing v1.478 authority captures and replays
  the complete routing, DRC, manufacturing, pipeline, policy, receipt, and
  approval closure. It samples a new authorization time instead of reusing the
  historical report's decision.

- **Keeps negatives:** A valid nested `not_authorized` result remains useful
  evidence. The optional final gate runs only after the outer report is saved.

- **Avoids path leakage:** The report records role, native format, byte count,
  observed digest, and expected digest. It never records an executable path.

## Quick start

Start with the exact inputs and retained report produced by the
[v1.478 release boundary](ROUTING_DRC_FABRICATION_RELEASE.md). Supply all three
digests from a separately controlled deployment source:

```sh
export ROUTING_PCBEX_SHA256='<protected 64-lowercase-hex digest>'
export AUTHORIZATION_PCBEX_SHA256='<protected 64-lowercase-hex digest>'
export KICAD_CLI_SHA256='<protected 64-lowercase-hex digest>'

pcbex-agent replay-executable-pinned-fabrication-release \
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
  --expected-policy-pack-canonical-sha256 "$POLICY_DIGEST" \
  --expected-routing-pcbex-sha256 "$ROUTING_PCBEX_SHA256" \
  --expected-authorization-pcbex-sha256 "$AUTHORIZATION_PCBEX_SHA256" \
  --expected-kicad-cli-sha256 "$KICAD_CLI_SHA256" \
  --pcbex /opt/pcbex/bin/pcbex \
  --authorization-pcbex /opt/pcbex/bin/pcbex \
  --kicad-cli /opt/kicad/bin/kicad-cli \
  --kicad-project board.kicad_pro \
  --kicad-rules board.kicad_dru \
  --output board.executable-pinned-release.json \
  --require-authorized
```

Discover the closed schema without reading evidence or executables:

```sh
pcbex-agent executable-pinned-fabrication-release-report-schema \
  --output executable-pinned-fabrication-release-v1.schema.json
```

## What a positive result proves

A `release_authorized` report establishes all of these facts at one local
verification run:

- the retained v1.478 report was canonical and its stable evidence,
  authorization scope, policy, and approval subject matched the fresh replay;
- v1.478 independently accepted the routing/native-DRC/manufacturing gate and
  the policy-pinned fabrication quorum;
- each selected command resolved to one native executable for the current
  host;
- each entrypoint's captured bytes matched its role-specific external digest;
  and
- the exact resolved entrypoints remained equal at the verifier's stated
  reread points.

The outer authorization remains conjunctive. Digest agreement never converts
a negative v1.478 decision into a positive one.

## Entrypoint contract

| Role | CLI selector | Expected pin | Maximum |
| --- | --- | --- | ---: |
| Routing authority | `--pcbex` | `--expected-routing-pcbex-sha256` | 128 MiB |
| Fabrication crypto/policy authority | `--authorization-pcbex` | `--expected-authorization-pcbex-sha256` | 128 MiB |
| Native KiCad DRC | `--kicad-cli` | `--expected-kicad-cli-sha256` | 128 MiB |

The executable aggregate is capped at 384 MiB. The complete v1.478 closure,
retained v1.478 report, and executable maxima form a derived 1,857 MiB input
ceiling. The outer report is capped at 8 MiB.

Bare command names resolve once through the current `PATH`. Relative paths
resolve against the caller's initial working directory. The verifier resolves
links to an absolute target, requires a bounded stable regular file with execute
permission, and recognizes only PE on Windows, Mach-O on macOS, or ELF on
Linux. It supplies that resolved target to v1.478.

Routing and authorization commands must contain only the executable token.
This excludes `python wrapper.py`, shell fragments, command prefixes, and
option-bearing launchers whose additional code would not have a dedicated pin.

## Replay order

1. **Capture v1.478 evidence.** The existing boundary captures every direct,
   plan-selected, firmware, and approval input before command observation.
2. **Capture the retained outer report.** Its canonical bytes join the
   caller-source reread and alias set, while a domain-separated digest binds
   its time-invariant replay subject.
3. **Resolve entrypoints.** Each single-token command resolves to an absolute
   native file after evidence capture and before the first selected tool runs.
4. **Match external pins.** Exact bytes, format, size, and expected digest must
   agree for all three roles. Any mismatch is a hard failure.
5. **Replay v1.478.** The unchanged routing and authorization authorities use
   those resolved command paths under the existing aggregate deadline.
6. **Match the stable subject.** Fresh and retained v1.478 reports must bind the
   same source identities, routing projection, approvals, authorization scope,
   pipeline, package, receipt, policy, and policy pin. The fresh verifier keeps
   its newly sampled time and resulting decision.
7. **Reread and bind.** Entrypoint bytes are reread after replay; the outer
   report embeds the complete nested result and path-free pin observations.

Custom monotonic-clock callbacks are treated as caller-controlled hooks. After
each such callback returns, the verifier rereads every captured entrypoint
before continuing. The default monotonic clock does not trigger redundant
full-binary reads; ordinary lasting changes are still caught by the final
reread.

## Outcomes

| Status | Gate failures | Meaning |
| --- | --- | --- |
| `release_authorized` | `[]` | Fresh v1.478 reassessment is authorized and all three entrypoint pins matched |
| `not_authorized` | `routing_drc_fabrication_release_not_authorized` | Pins matched, but the exact nested v1.478 decision was negative |

Wrong or malformed pins, non-native or oversized entrypoints, wrappers,
unsafe aliases, malformed retained evidence, replay-subject mismatch, observed
mutation, deadline failure, or child failure produces no outer report.

`--require-authorized` is only a final gate. It returns nonzero after a valid
negative report has been published with no overwrite.

## Report contract

The schema-v1 report uses scope
`fresh-exact-executable-pinned-fabrication-release-v1` and retains:

- the full fresh normalized v1.478 report, the retained report's exact raw
  byte/SHA-256 identity, and their shared replay-subject SHA-256;
- one fixed descriptor for each of the three executable roles;
- `executable_digest_pins_verified: true`;
- the copied nested authorization decision and one stable outer failure;
- eight exact validation flags; and
- one domain-separated SHA-256 over every preceding field.

The replay subject deliberately excludes the volatile child-report identity,
`evaluated_at_unix`, authorization status/decision/gates, and dependent outer
binding fields. A retained positive can therefore become a fresh negative when
its approval window expires; the fresh decision is authoritative.

The renderer validates nested v1.478 semantics, replay-subject equality,
role-complete pin equality, decision/gate relationships, every false claim,
and the outer binding. The Draft 2020-12 schema is closed and bounded, but
runtime fresh replay remains the authority for the retained raw identity.

## Nonclaims

Only these decision fields may become true:

- `routing_drc_fabrication_release_authorized`
- `executable_digest_pins_verified`
- `release_authorized`

These fields always remain false:

- `source_authenticity_verified`
- `executable_origin_authenticity_verified`
- `toolchain_authenticity_verified`
- `policy_pack_authenticity_verified`
- `factory_receipt_authenticity_verified`
- `manufacturability_verified`
- `external_submission_performed`
- `capacity_reserved`
- `order_placed`
- `payment_performed`
- `challenge_one_time_use_enforced`

A SHA-256 match does not prove who built, signed, reviewed, or distributed an
executable. It does not cover dynamic libraries, frameworks, plugins, KiCad
resources, configuration, environment variables, the OS loader, kernel,
hardware, or network state. It also does not provide a sandbox or defeat a
concurrent same-principal writer in the final observation-to-exec window.

> [!TIP]
> Treat digest pins as protected deployment policy. Combine them with signed
> release metadata, package-manager verification, OS code-signing policy, and
> a separately controlled executor when provenance or isolation matters.
