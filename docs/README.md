# pcbex documentation

This directory contains the operational and wire-format contracts behind
`pcbex`. Start with a task-oriented guide, then follow its links to the exact
boundary document for the artifact you plan to produce or trust.

## Start here

| Goal | Read |
| --- | --- |
| Install pcbex and route the first board | [Getting Started](GETTING_STARTED.md) |
| Choose an end-to-end hardware flow | [Workflow Guide](WORKFLOWS.md) |
| Understand crate and boundary ownership | [Architecture](ARCHITECTURE.md) |
| Configure GitHub Actions, MCP, KiCad, or Python | [Integrations](INTEGRATIONS.md) |
| Decide what an artifact actually proves | [Trust Model](TRUST_MODEL.md) |
| Inspect release history and current direction | [Product Roadmap](ROADMAP.md) |

> [!NOTE]
> The task guides explain how documents fit together. The focused contract
> pages remain authoritative for exact schemas, limits, replay rules, and
> nonclaims.

## Board, routing, and physical design

- [Physical Constraint Profiles](PHYSICAL_CONSTRAINT_PROFILE.md) — bind board
  geometry, placement, and construction requirements.

- [Native KiCad PCB DRC](NATIVE_KICAD_DRC.md) — run and freshly replay normalized
  KiCad DRC evidence.

- [KiCad S-expression Limits](KICAD_SEXP_LIMITS.md) — parser byte, token, depth,
  list, and span ceilings.

- [Numeric and Raster Limits](NUMERIC_RASTER_LIMITS.md) — coordinate, topology,
  raster, and allocation bounds.

- [A* Work Budget](ASTAR_WORK_BUDGET.md) — deterministic routing work limits.

- [Routing Convergence](ROUTING_CONVERGENCE.md) — bounded strategy portfolios,
  validity-first selection, and closed convergence evidence.

- [Fresh Routing Convergence Verification](ROUTING_CONVERGENCE_VERIFICATION.md)
  — replay retained decisions from raw sources and require exact routed bytes.

- [Fresh Routing-to-Manufacturing Handoff](ROUTING_MANUFACTURING_HANDOFF.md) —
  bind the freshly verified routed KiCad board to an exactly reproduced
  manufacturing ZIP.

- [Fresh Routing, Native DRC, and Manufacturing Handoff](ROUTING_DRC_MANUFACTURING_HANDOFF.md)
  — require the same routed board and sidecars to reproduce both the retained
  package and normalized native DRC evidence.

- [Policy-pinned Routing, DRC, and Fabrication Release](ROUTING_DRC_FABRICATION_RELEASE.md)
  — cross-bind that fresh package to a factory-required pipeline and dedicated
  fabrication approval quorum under an externally expected policy digest.

- [Executable-pinned Fabrication Release](EXECUTABLE_PINNED_FABRICATION_RELEASE.md)
  — freshly reassess that release subject while matching three selected native
  entrypoint files to deployment-owned SHA-256 pins.

- [Signed Factory-receipt Release](SIGNED_FACTORY_RECEIPT_RELEASE.md) — bind the
  exact normalized factory receipt to a dedicated policy-pinned Ed25519 key and
  freshly replay the executable-pinned release before authentication.

- [Signed Release Reservation](SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION.md) —
  freshly replay that authenticated release and durably consume its challenge
  once inside one pinned local Unix ledger.

- [Durable Signed Factory-release Submission](SIGNED_FACTORY_RELEASE_SUBMISSION.md)
  — commit one adapter intent before POST and reconcile uncertain results
  without retransmitting the manufacturing ZIP.

- [Authenticated Factory-release Adapter Responses](AUTHENTICATED_FACTORY_RELEASE_ADAPTER_RESPONSES.md)
  — verify signed POST and GET responses against exact organization-policy
  keys while preserving the durable v1.482 intent and receipt contracts.

- [Monotonic Factory-release Adapter State](MONOTONIC_FACTORY_RELEASE_ADAPTER_STATE.md)
  — bind each signed response to the retained local head and reject rollback,
  equivocation, gaps, forks, or mutation after acceptance or rejection.

- [Factory-release State Transparency](FACTORY_RELEASE_STATE_TRANSPARENCY.md) —
  verify the exact current v1.484 head in one separately policy-pinned signed
  Merkle view without claiming global non-equivocation or trusted time.

- [Factory-release State Transparency Consistency](FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY.md)
  — prove strict append-only extension between retained signed views and keep a
  bounded no-replace checkpoint chain without claiming global non-equivocation.

- [Factory-release State Transparency Witness Quorum](FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_QUORUM.md)
  — require distinct policy-pinned organizations to sign the exact latest
  consistency report and tree head without claiming global non-equivocation.

- [Factory-release State Transparency External Anchor](FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR.md)
  — prove the exact latest witness-quorum report appears in one separately
  policy-pinned external signed Merkle view without claiming external-log
  consistency or selected-ledger rollback resistance.

- [Factory-release State Transparency External Consistency](FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY.md)
  — prove later signed views strictly extend the retained external anchor and
  retain a bounded no-replace chain without claiming global non-equivocation.

- [Zone-fill Work Budget](ZONE_FILL_WORK_BUDGET.md) — deterministic fill limits
  across all zones.

- [Benchmarks](BENCHMARKS.md) — run and interpret routing benchmarks.

- [Regression Corpus](REGRESSION_CORPUS.md) — reproduce stable routing and KiCad
  regression artifacts.

## Circuit generation, KiCad handoff, and electrical checks

- [Text-to-Circuit](TEXT_TO_CIRCUIT.md) — validate circuit specifications before
  generating deterministic SKiDL.

- [Bounded Circuit Generation](CIRCUIT_GENERATION.md) — constrain provider-driven
  natural-language generation behind Rust checks.

- [Catalog Selection](CATALOG_SELECTION.md) — bind deterministic part selection
  to a retained catalog snapshot.

- [KiCad Schematic Writer](CIRCUIT_KICAD_SCHEMATIC_WRITER.md) — materialize an
  approved circuit specification as a deterministic schematic.

- [Multi-unit Circuit Spec](MULTI_UNIT_CIRCUIT_SPEC.md) — model explicit KiCad
  units while preserving one physical component identity.

- [Circuit-to-KiCad Handoff](CIRCUIT_KICAD_HANDOFF.md) — verify exact electrical
  equivalence between specification and schematic.

- [KiCad Board Writer](CIRCUIT_KICAD_BOARD_WRITER.md) — generate a deterministic
  board from the approved circuit handoff.

- [Circuit-to-Board Binding](CIRCUIT_KICAD_BOARD_BINDING.md) — bind specification,
  schematic, and board identities.

- [Circuit Handoff Bundle](CIRCUIT_HANDOFF_BUNDLE.md) — package, verify, replay,
  and extract the complete handoff chain.

- [Electrical Power Safety](ELECTRICAL_POWER_SAFETY.md) — explain deterministic
  rail, input-voltage, and decoupling checks.

- [Immutable ERC Safety Floor](ERC_SAFETY_FLOOR.md) — identify electrical rules
  that policy cannot disable, demote, or waive.

- [Native KiCad Schematic ERC](NATIVE_KICAD_ERC.md) — normalize and freshly replay
  native KiCad ERC evidence.

- [AI Review Artifact Binding](AI_REVIEW_ARTIFACT_BINDING.md) — bind review
  requests and decisions to exact generated artifacts.

## Manufacturing, firmware, and pipeline evidence

- [Manufacturing Package](MANUFACTURING_PACKAGE.md) — gate Gerber, drill, BOM,
  CPL, manifest, and ZIP publication.

- [Final CPL Verification](FINAL_CPL.md) — compare exact board placement with the
  canonical package CPL.

- [Factory Connector](FACTORY_CONNECTOR.md) — submit exact packages through a
  bounded quote and DFM adapter.

- [Firmware Generator](FIRMWARE_GENERATOR.md) — generate schematic-bound C, C++,
  and Python firmware artifacts.

- [Firmware Build Verification](FIRMWARE_BUILD_VERIFICATION.md) — freshly rebuild
  and test an exact retained firmware bundle.

- [Hardware Pipeline Gate](PIPELINE_GATE.md) — cross-bind electrical, analysis,
  manufacturing, firmware, and optional factory evidence.

- [Deterministic Pipeline Runner](DETERMINISTIC_PIPELINE_RUNNER.md) — execute a
  closed plan under one bounded replay boundary.

## Procurement and assembly evidence

- [Procurement Intent](PROCUREMENT_INTENT.md) — bind exact final BOM lines to
  replayed catalog selections without contacting a supplier.

- [Supplier Offer Acquisition](SUPPLIER_OFFER_ACQUISITION.md) — retain one bounded
  supplier response and its transport observations.

- [Supplier Offer Coverage](SUPPLIER_OFFER_COVERAGE.md) — correlate an offer with
  the exact procurement intent and component-line subtotal.

- [Assembly Evidence](ASSEMBLY_EVIDENCE.md) — compose handoff, board,
  manufacturing, procurement, and placement evidence.

- [Assembly and Supplier Offer Evidence](ASSEMBLY_SUPPLIER_OFFER_EVIDENCE.md) —
  combine complete assembly evidence with acquired-offer coverage.

- [Procurement Authorization](PROCUREMENT_AUTHORIZATION.md) — require a
  policy-pinned, dual-control decision over one exact retained release.

- [Procurement Authorization Reservation](PROCUREMENT_AUTHORIZATION_RESERVATION.md)
  — admit one freshly replayed challenge to one trusted local ledger.

## Review, authorization, and CI

- [AI Schematic Approval Action](AI_SCHEMATIC_APPROVAL_ACTION.md) — run focused
  evidence-bound AI review in GitHub Actions.

- [Fabrication Authorization](FABRICATION_AUTHORIZATION.md) — require signed human
  decisions over exact fabrication evidence.

- [Fabrication Authorization Action](FABRICATION_AUTHORIZATION_ACTION.md) — retain
  and gate fabrication authorization in CI.

- [Fabrication Authorization Reservation](FABRICATION_AUTHORIZATION_RESERVATION.md)
  — reserve a verified challenge in a trusted local ledger.

- [GitHub Actions Supply Chain](GITHUB_ACTIONS_SUPPLY_CHAIN.md) — enforce immutable
  action references and audit workflow dependencies.

- [CI Execution Limits](CI_EXECUTION_LIMITS.md) — bound workflow time, jobs,
  artifacts, release work, and subprocesses.

## Runtime limits and project assurance

- [CLI I/O Limits](CLI_IO_LIMITS.md) — Rust file, subprocess, publication, and MCP
  boundaries.

- [Python Agent Limits](PYTHON_AGENT_LIMITS.md) — Python file, child-process,
  staging, and cleanup boundaries.

- [Completion Audit](COMPLETION_AUDIT.md) — requirement-level test evidence and
  exact release counts.

- [Product Roadmap](ROADMAP.md) — human-readable capability history and current
  milestone.

- [Roadmap Data](ROADMAP.json) — machine-readable milestone state used by release
  audits.

## Command discovery

The installed binary is the authority for its command surface:

```sh
pcbex --help
pcbex <command> --help
pcbex capabilities --output capabilities.json
```

The Python surface follows the same pattern:

```sh
pcbex-agent --help
pcbex-agent <command> --help
```

Schema-producing commands write closed JSON Schemas for automated consumers.
Do not infer a wire contract from an example alone.
