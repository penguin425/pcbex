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

- [Factory-release State Transparency External Gossip](FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP.md)
  — compare the exact latest external-log head with a separately pinned
  observer receipt and reject selected split views.

- [Factory-release State Transparency External Gossip Quorum](FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM.md)
  — acquire canonical observations over bounded remote transport and require
  distinct configured organizations to agree on one exact signed external head.

- [External-gossip Observer Key Rotation](FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_ROTATION.md)
  — dual-sign generation- and digest-chained successor keys, retain the latest
  histories, and derive the unchanged v1.491 quorum policy used in production.

- [External-gossip Organization Registry](FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY.md)
  — admit exact current observer trust and suspend or permanently revoke
  organizations through an independently pinned authority-signed history.

- [External-gossip Registry Authority Rotation](FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_AUTHORITY_ROTATION.md)
  — require old/new dual signatures, reject historical authority-key reuse, and
  replay transitions plus rotations as one selected-ledger generation chain.

- [External-gossip Registry Threshold Governance](FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_THRESHOLD_GOVERNANCE.md)
  — root-authorize a fixed authority set, require distinct-key threshold
  approval for every organization decision, and reject root-only bypasses.

- [External-gossip Registry Governance Rotation](FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNANCE_ROTATION.md)
  — require both retained and successor quorums before changing governance
  membership, authority keys, or threshold.

- [Governed External-gossip Registry-root Rotation](FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GOVERNED_ROOT_ROTATION.md)
  — require prospective-root possession plus retained and successor governance
  quorums before atomically replacing the root and active governance.

- [Portable External-gossip Registry History Audit](FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_HISTORY_AUDIT.md)
  — export exact selected-ledger evidence and independently replay all five
  event kinds from empty genesis to a computed final registry.

- [Witnessed and Remote External-gossip Registry History Checkpoints](FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_HISTORY_CHECKPOINT.md)
  — retain root-signed audited heads, reject rollback or equivocation against a
  local baseline, require fresh distinct checkpoint witnesses, and rotate each
  identity-bound witness key through a dual-signed trust chain.

- [Factory-release Registry Witness Receipt Transparency](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_TRANSPARENCY.md)
  — normalize canonical verified remote-witness receipts into the existing
  signed, anchored, consistency-proved, gossiped, and witnessed hash chain.

- [Verifier-bound Factory-release Registry Receipt Admission](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_ADMISSION.md)
  — replay complete registry history, retained checkpoint trust, exact
  response bytes, and current witness trust before immutable log admission.

- [Factory-release Registry Receipt Quorum Admission](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_ADMISSION.md)
  — require a configurable set of distinct independently reverified receipts
  and bind the canonical members to the exact resulting log.

- [Factory-release Receipt-quorum Log Signing](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_LOG_SIGNING.md)
  — issue a generic approval-log checkpoint only when the complete log and its
  factory-receipt suffix exactly match one successful quorum report.

- [Domain-separated Factory Receipt-quorum Checkpoints](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT.md)
  — bind the exact quorum report, registry checkpoint, threshold, and log state
  under a factory-specific signature domain.

- [Independent Factory Receipt-quorum Checkpoint Witnesses](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESSES.md)
  — re-verify the dedicated checkpoint and require a fresh quorum of distinct,
  role-separated witness keys.

- [Factory Checkpoint-witness Key Rotation](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_ROTATION.md)
  — advance identity-bound dedicated witness trust through dual-signed,
  generation- and digest-chained key transitions.

- [Remote Factory Receipt-quorum Checkpoint Witnesses](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_REMOTE_WITNESSES.md)
  — acquire unchanged dedicated witnesses over bounded HTTPS, verify them
  against direct or rotated trust, and retain hash-bound transport receipts.

- [Factory Receipt-quorum Checkpoint Witness Receipt Transparency](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_TRANSPARENCY.md)
  — normalize canonical verified remote checkpoint-witness receipts into the
  existing signed, anchored, consistency-proved, gossiped, and witnessed log.

- [Verifier-bound Factory Checkpoint-witness Receipt Admission](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_ADMISSION.md)
  — replay the exact quorum report, complete approval log, dedicated
  checkpoint, response bytes, and current witness trust before append.

- [Factory Checkpoint-witness Receipt Quorum Admission](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_QUORUM_ADMISSION.md)
  — re-verify one shared checkpoint context and a distinct receipt threshold,
  then bind the sorted unchanged event suffix to the resulting log.

- [Factory Checkpoint-witness Receipt-quorum Log Signing](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_SIGNING.md)
  — issue the existing generic checkpoint only when the complete admission log
  and sorted checkpoint-witness receipt suffix match one successful report.

- [Domain-separated Factory Checkpoint-witness Receipt-quorum Checkpoints](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT.md)
  — sign the normalized admission report, prior factory checkpoint, threshold,
  and exact admission-log state beneath a dedicated Ed25519 domain.

- [Independent Factory Checkpoint-witness Receipt-quorum Checkpoint Witnesses](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESSES.md)
  — re-verify the dedicated checkpoint and require a fresh quorum of distinct,
  role-separated witness keys.

- [Final Factory Checkpoint-witness Key Rotation](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_ROTATION.md)
  — advance identity-bound final witness trust through dual-signed,
  generation- and digest-chained key transitions.

- [Remote Final Factory Checkpoint Witnesses](FACTORY_RELEASE_REGISTRY_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_REMOTE_WITNESSES.md)
  — acquire unchanged final witnesses over bounded HTTPS, verify direct or
  rotated trust, and retain receipts that replay every exact input offline.

- [Parallel Final Checkpoint Witness Acquisition](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_QUORUM_ACQUISITION.md)
  — acquire mixed direct/trust-state witnesses concurrently, retain coarse
  partial failures, and reproduce the unchanged final quorum offline.

- [Final Checkpoint-witness Receipt Transparency](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_TRANSPARENCY.md)
  — normalize one canonical final transport receipt into the existing signed,
  anchored, consistency-proved, gossiped, and witnessed approval log.

- [Verifier-bound Final Checkpoint-witness Receipt Admission](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_ADMISSION.md)
  — replay the exact report, admission log, final checkpoint, raw response,
  signature, freshness, and direct or rotated trust before append.

- [Final Checkpoint-witness Receipt Quorum Admission](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_ADMISSION.md)
  — verify one shared checkpoint context and a distinct final-receipt threshold,
  then bind the sorted unchanged event suffix to the resulting log.

- [Quorum-bound Final Checkpoint-witness Receipt-log Signing](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_SIGNING.md)
  — issue a generic approval checkpoint only for the exact successful v1.521
  report, complete log, and sorted final-receipt suffix.

- [Domain-separated Final Checkpoint-witness Receipt-quorum Checkpoints](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT.md)
  — sign the exact v1.521 report, both prior factory checkpoints, threshold,
  and final log under a dedicated Ed25519 domain.

- [Independent Final Receipt-quorum Checkpoint Witnesses](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESSES.md)
  — re-verify the dedicated final checkpoint and require a fresh quorum of
  distinct, role-separated witness keys.

- [Dedicated Final-checkpoint Witness Key Rotation](FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_CHECKPOINT_WITNESS_ROTATION.md)
  — preserve the v1.524 witness and quorum contracts while advancing retained
  identity-bound trust through dual-signed generation chains.

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
