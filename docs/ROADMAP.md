# Product roadmap

pcbex has completed the first production-pipeline roadmap. Each milestone was
integrated through a focused pull request and published as an independently
auditable release.

| Release | Capability | Operational outcome |
| --- | --- | --- |
| v1.297.0 | Integrated KiCad analysis | One deterministic analysis bundle and manifest |
| v1.298.0 | Bundle comparison | Baseline regression gates for quality and violations |
| v1.299.0 | GitHub Actions reporting | PR summaries, SARIF, and retained evidence artifacts |
| v1.300.0 | Versioned DFM profiles | Stable fabrication constraints and aliases |
| v1.301.0 | MCP server | Agent-facing bounded hardware-analysis tools |
| v1.302.0 | Asynchronous MCP tasks | Pollable, cancellable long-running operations |
| v1.303.0 | Placement candidates | Deterministic Pareto placement portfolios |
| v1.304.0 | Routing candidates | Deterministic Pareto routing portfolios |
| v1.305.0 | Schematic IR | Closed KiCad schematic import boundary |
| v1.306.0 | Electrical approval | Policy-controlled deterministic schematic gate |
| v1.307.0 | Simulation evidence | Artifact-bound, simulator-neutral measurements |
| v1.308.0 | AI schematic approval | Evidence-constrained review with Ed25519 signatures |
| v1.309.2 | Release audit | Machine-checked roadmap, assets, checksums, and protection |
| v1.310.0 | Installation doctor | Machine-readable local and CI readiness diagnostics |
| v1.311.0 | Capability inventory | Versioned discovery for commands and integration contracts |
| v1.312.0 | Electrical rule explanations | Policy-bound triggers and remediation for every finding |
| v1.313.0 | Expiring electrical waivers | Audited exceptions that fail closed after a fixed date |
| v1.314.0 | Electrical JUnit reporting | Native rule results for standard CI test viewers |
| v1.315.0 | Electrical baseline gate | Fail CI only for new or severity-escalated electrical errors |
| v1.316.0 | Electrical SARIF reporting | Stable schematic findings for code-scanning review tools |
| v1.317.0 | Idempotent PR comments | Update one stable hardware-analysis comment per PR |
| v1.318.0 | Distributable DFM profiles | Strict organization-owned manufacturing constraints with provenance |
| v1.319.0 | Review-provider command adapter | Bounded shell-free AI execution with hash-bound audit receipts |
| v1.320.0 | Organization policy packs | One strict contract for physical, electrical, AI, simulation, and signer policy |
| v1.321.0 | Signed policy-pack distribution | Ed25519-authenticated organization policy before CI application |
| v1.322.0 | Monotonic policy trust state | Reject signed-pack rollback, equivocation, and identity substitution |
| v1.323.0 | Manufacturing feedback ingestion | Bind fabrication findings and measurements to exact analyzed boards |
| v1.324.0 | Schematic semantic diff | Gate electrical-intent changes independently of drawing edits |
| v1.325.0 | Multi-reviewer AI approval quorum | Require independently signed provider/model-diverse schematic reviews |
| v1.326.0 | Risk-based AI reviewer routing | Assign every semantic change to policy-selected specialist or fallback reviewers |
| v1.327.0 | Profile-aware AI approval quorum | Prove every routed specialist profile is satisfied by matching signed reviewers |

`ROADMAP.json` is the canonical machine-readable milestone ledger. The release
audit rejects duplicate or unordered milestones, a version mismatch, missing
tags, malformed release metadata, missing or extra assets, invalid SPDX JSON,
and archive checksum mismatches. An optional repository audit also verifies
that `main` has strict required checks, linear history, conversation
resolution, and force-push/deletion protection.

The next roadmap should focus on production adoption: managed
provider-specific adapters, centralized policy-pack retrieval, and governed
feedback-to-policy recommendations. Those are intentionally not marked
complete until each has an executable acceptance contract and its own release.
