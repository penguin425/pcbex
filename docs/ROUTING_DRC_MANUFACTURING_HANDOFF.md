# Fresh routing, native DRC, and manufacturing handoff

Prove one complete local relationship.

The routed KiCad board accepted by fresh routing replay must reproduce one
exact manufacturing ZIP and one exact normalized native KiCad DRC report. The
v1.477 boundary composes the released v1.476 handoff with the existing native
DRC verifier; it does not replace either authority.

## Quick start

Create the retained v1.476 handoff and native DRC evidence first:

```sh
pcbex run-native-kicad-drc board.routed.kicad_pcb \
  --project board.kicad_pro \
  --rules-file board.kicad_dru \
  --output board.native-drc.json \
  --require-approved

pcbex-agent replay-routing-manufacturing-handoff \
  board.placed.kicad_pcb board.routed.kicad_pcb \
  --convergence-report board.convergence.json \
  --routing-verification-report board.routing-verification.json \
  --manufacturing-package build/manufacturing/manufacturing.zip \
  --kicad-project board.kicad_pro \
  --kicad-rules board.kicad_dru \
  --output board.routing-manufacturing.json \
  --require-ready
```

Replay the combined boundary:

```sh
pcbex-agent replay-routing-drc-manufacturing-handoff \
  board.placed.kicad_pcb board.routed.kicad_pcb \
  --convergence-report board.convergence.json \
  --routing-verification-report board.routing-verification.json \
  --manufacturing-package build/manufacturing/manufacturing.zip \
  --routing-manufacturing-handoff-report board.routing-manufacturing.json \
  --native-drc-report board.native-drc.json \
  --kicad-project board.kicad_pro \
  --kicad-rules board.kicad_dru \
  --output board.routing-drc-manufacturing.json \
  --require-ready
```

> [!IMPORTANT]
> Use the same routed board, project, rules, routing options, and manufacturing
> profile selection used to create the retained reports. Equivalent settings
> are not inferred; byte identities must match.

## What it proves

The positive report establishes five facts:

- **Fresh routing and package replay:** The complete retained v1.476 handoff is
  reproduced byte for byte from its original closure.

- **One routed board:** The v1.476 routed-board identity equals the native DRC
  source identity.

- **One companion set:** Project and custom-rules identities match across both
  replays, including explicit absence.

- **Fresh normalized DRC:** `verify-native-kicad-drc-report` reproduces the
  retained compact report exactly and returns its digest-bound summary.

- **Strict clean decision:** Native DRC has no error or warning findings before
  `native_kicad_drc_verified` can become `true`.

`pcbex fabricate` already runs KiCad DRC before publishing manufacturing
artifacts. This boundary adds an independently retained, normalized, freshly
replayed report with stable findings and `ignored_checks`; it does not claim a
second DRC engine.

## Inputs and limits

| Role | Limit |
| --- | ---: |
| Original KiCad board | 128 MiB |
| Routed KiCad board | 128 MiB |
| Retained convergence report | 16 MiB |
| Retained v1.475 routing verification | 32 MiB |
| Retained manufacturing ZIP | 128 MiB |
| Retained v1.476 handoff | 4 MiB |
| Retained native DRC report | 32 MiB |
| Explicit project or custom rules | 128 MiB each |
| External DFM or physical profile | 4 MiB |

The complete direct source union is capped at 724 MiB. All file roles must be
nonempty, stable, regular, link-free inputs and must not alias each other.

Exactly one of `--fab`, `--fab-profile`, and `--physical-profile` may be
selected. The selection must reproduce the retained v1.476 bytes.

## Replay sequence

1. **Capture once.** Freeze and bounded-read the complete caller-visible source
   union before invoking clock or command hooks.
2. **Validate retained evidence.** Strictly decode the canonical v1.476 and
   native DRC reports and validate their domain-separated bindings.
3. **Freeze tools and start one deadline.** Validate the bounded `pcbex` and
   `kicad-cli` arguments, then start a finite `0 < seconds <= 600` deadline for
   both fresh boundaries and every subsequent comparison, reread, and cleanup.
4. **Replay v1.476 privately.** Preserve caller basenames, rerun the complete
   routing/manufacturing handoff, and require exact retained bytes.
5. **Branch honestly.** If routing is incomplete, skip native DRC and retain a
   `routing_incomplete` negative.
6. **Replay native DRC.** For a ready handoff, invoke the Rust verifier against
   the same staged routed board, project, rules, and retained DRC bytes.
7. **Cross-bind and publish.** Require exact board and companion identities,
   reread every staged and caller input, then publish one no-clobber report.

The v1.476 child receives half of the remaining deadline. Native DRC receives
the later remaining interval minus a cleanup and final-reread reserve. Child
processes run without a shell under bounded stdout and stderr capture.

These checks are sequential. They do not create an atomic multi-file snapshot,
authenticate the selected executables, or sandbox KiCad.

## Outcomes

| Status | Gate failures | Meaning |
| --- | --- | --- |
| `verified_ready` | `[]` | Routing and package replay are ready, and the exact native DRC report is freshly approved |
| `not_ready` | `routing_incomplete` | The v1.476 replay is valid but incomplete; native DRC was not invoked |
| `not_ready` | `native_drc_rejected` | Both reports replayed exactly, but native DRC retained an error or warning |

`--require-ready` runs only after a valid `not_ready` report is retained.
Malformed, duplicate-key, noncanonical, oversized, aliased, substituted, or
observably changed evidence is a hard failure and produces no outer report.

## Report contract

The closed path-free schema-v1 report retains:

- byte count and SHA-256 for every direct source;
- a bounded projection of the exact v1.476 status, source closure, and binding;
- native DRC versions, source identities, counts, approval, and run binding;
- eight explicit validation flags;
- at most one stable gate failure; and
- one domain-separated binding over every preceding field.

Discover the Draft 2020-12 schema at runtime:

```sh
pcbex-agent routing-drc-manufacturing-handoff-report-schema \
  --output routing-native-drc-manufacturing-handoff-v1.schema.json
```

The report is limited to 1 MiB and ends with exactly one LF.

## Nonclaims

Only `native_kicad_drc_verified` may become `true`. These claims always remain
`false`:

- `source_authenticity_verified`
- `manufacturability_verified`
- `fabrication_authorized`
- `release_authorized`

The report does not authenticate source control, policy provenance, pcbex,
KiCad, plugins, or the host. It does not prove signal integrity, fabrication
yield, panelization, factory acceptance, component availability, or physical
manufacturability. It does not submit a package, reserve capacity, place an
order, or perform payment.

> [!TIP]
> Treat `verified_ready` as a fresh local release-evidence candidate. Apply an
> authenticated organization policy and rerun
> [Fabrication Authorization](FABRICATION_AUTHORIZATION.md) at the actual
> external handoff boundary.
