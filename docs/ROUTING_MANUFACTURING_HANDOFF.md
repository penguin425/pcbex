# Fresh routing-to-manufacturing handoff

Prove one narrow transition: the KiCad board accepted by fresh routing replay
also reproduces one exact retained manufacturing ZIP.

The v1.476 handoff composes two existing boundaries. It freshly reruns the
v1.475 KiCad routing verifier first, then invokes the v1.455 manufacturing
replay only when routing is complete.

## Quick start

Retain routing convergence and its fresh verification:

```sh
pcbex route-kicad board.kicad_pcb \
  --output board.routed.kicad_pcb \
  --convergence-report board.convergence.json

pcbex verify-kicad-routing-convergence board.kicad_pcb \
  --routed board.routed.kicad_pcb \
  --report board.convergence.json \
  --output board.routing-verification.json \
  --require-complete
```

Build the retained package, then replay the combined handoff:

```sh
pcbex fabricate board.routed.kicad_pcb \
  --output-dir build/manufacturing

pcbex-agent replay-routing-manufacturing-handoff \
  board.kicad_pcb board.routed.kicad_pcb \
  --convergence-report board.convergence.json \
  --routing-verification-report board.routing-verification.json \
  --manufacturing-package build/manufacturing/manufacturing.zip \
  --pcbex pcbex \
  --kicad-cli kicad-cli \
  --output board.routing-manufacturing.json \
  --require-ready
```

> [!IMPORTANT]
> Use the same routing numbers, project, rules, and profile selection in both
> routing commands and the handoff. The composer requires exact source and
> artifact identities; it does not infer equivalent settings.

## What it proves

The report establishes four exact relationships:

- **Fresh routing:** The selected `pcbex` command regenerates the retained
  v1.475 verification byte for byte from the original board, routed board, and
  convergence report.

- **One routed board:** The routed-board identity in the fresh verification is
  the identity passed to manufacturing replay.

- **Shared sidecars:** Project, rules, and the selected DFM or physical profile
  have the same identities in both children.

- **Exact package:** Fresh `pcbex fabricate` output equals the retained
  `manufacturing.zip` byte for byte.

This closes an evidence-composition gap. It does not turn either child report
into fabrication approval or release authority.

## Inputs

The public command accepts KiCad only:

| Role | Required | Limit |
| --- | --- | ---: |
| Original KiCad board | yes | 128 MiB |
| Routed KiCad board | yes | 128 MiB |
| Retained convergence report | yes | 16 MiB |
| Retained v1.475 routing verification | yes | 32 MiB |
| Retained manufacturing ZIP | yes | 128 MiB |
| Explicit KiCad project | no | 128 MiB |
| Explicit custom rules | no | 128 MiB |
| External DFM or physical profile | no | 4 MiB |

The manufacturing sub-closure retains its existing 512 MiB aggregate ceiling.
The complete outer source union is capped at 688 MiB. Every selected file must
be nonempty, regular, stable, and free of symbolic-link or Windows reparse
components under the shared bounded reader.

Select at most one of `--fab`, `--fab-profile`, and `--physical-profile`.
Organization policy-pack DFM is not accepted by this v1 composition because
the standalone manufacturing replay has no matching raw policy-pack role.

## Replay sequence

1. **Capture the closure.** Freeze every source role, reject cross-role aliases,
   and copy each file under its individual and aggregate bounds before invoking
   the caller-supplied clock or command hooks.
2. **Start one deadline.** A finite `0 < seconds <= 600` aggregate budget then
   covers both children, comparisons, rereads, and cleanup. The initial bounded
   file capture is intentionally outside that injected-clock budget.
3. **Stage routing privately.** Write the exact board, routed board,
   convergence report, and selected sidecars into a private temporary tree.
4. **Replay v1.475.** Invoke `verify-kicad-routing-convergence` without a shell
   and require the fresh bytes to equal the retained verification.
5. **Validate the decision.** Strictly parse the retained result, recompute its
   domain-separated binding, and cross-bind every projected source identity.
6. **Branch truthfully.** Skip manufacturing when routing is incomplete. When
   complete, pass the already captured routed board and shared sidecars to the
   existing manufacturing replay.
7. **Reread and publish.** Recheck every caller source, render the outer binding,
   and publish the report without replacing an existing destination.

The routing child receives half of the remaining outer budget. The
manufacturing child then uses the remaining time while preserving its own
cleanup and final-reread reserve.

These are sequential mutation checks, not an atomic filesystem snapshot. The
selected `pcbex` and `kicad-cli` executables are caller-controlled,
unauthenticated, and unsandboxed.

## Outcomes

| Status | Meaning |
| --- | --- |
| `verified_ready` | Fresh routing is complete and the same routed board reproduces the exact manufacturing ZIP |
| `not_ready` | Fresh routing is valid but incomplete; manufacturing was not invoked |

`--require-ready` applies only after a valid `not_ready` report is retained.
That report contains `gate_failures: ["routing_incomplete"]` and a null
`manufacturing_replay`.

Malformed, duplicate-key, noncanonical, aliased, oversized, substituted, or
observably changed inputs are hard failures. A routing-verification mismatch,
routed-board mismatch, sidecar mismatch, or manufacturing-package mismatch
produces no public handoff report.

## Report contract

The closed, path-free schema-v1 report retains:

- exact byte-count and SHA-256 identities for every selected source;
- the retained routing-verification identity, binding, status, routed decision,
  and cross-bound source projection;
- the complete normalized manufacturing replay result when ready;
- one bounded gate-failure list;
- seven explicit validation results; and
- a domain-separated SHA-256 binding over every preceding field.

Discover the Draft 2020-12 schema at runtime:

```sh
pcbex-agent routing-manufacturing-handoff-report-schema \
  --output routing-manufacturing-handoff-report-v1.schema.json
```

The report is limited to 4 MiB and ends with exactly one LF.

## Nonclaims

The report keeps these fields `false`:

- `source_authenticity_verified`
- `native_kicad_drc_verified`
- `manufacturability_verified`
- `release_authorized`

It does not authenticate source control, policy provenance, executables,
plugins, KiCad, or the host. It does not rerun a separately retained normalized
native KiCad DRC report, prove signal integrity or manufacturability, authorize
fabrication, submit a package, reserve capacity, place an order, or approve
payment.

> [!TIP]
> Treat `verified_ready` as a fresh artifact-consistency result. Apply
> [Native KiCad PCB DRC](NATIVE_KICAD_DRC.md), organization policy, and
> [Fabrication Authorization](FABRICATION_AUTHORIZATION.md) as separate
> boundaries before any external side effect.
