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
| v1.328.0 | Time-bound AI review sessions | Prevent approval replay with expiring request-bound random challenges |
| v1.329.0 | Dual-control human AI escalation | Govern AI uncertainty without permitting safety-gate overrides |
| v1.330.0 | Signed approval transparency log | Detect deletion, reordering, mutation, truncation, and stale checkpoints across approval evidence |
| v1.331.0 | Approval transparency witness quorum | Require independent trusted observers to attest the exact signed log checkpoint |
| v1.332.0 | Remote approval transparency witness | Acquire and immediately verify checkpoint attestations from bounded HTTPS services |
| v1.333.0 | Approval transparency witness key rotation | Advance witness trust through dual-signed, generation- and digest-chained key transitions |
| v1.334.0 | Approval transparency public-log anchoring | Verify checkpoint inclusion under a trusted signed Merkle tree head |
| v1.335.0 | Central policy-pack retrieval | Fetch signed organization policy over bounded HTTPS and retain verified monotonic trust evidence |
| v1.336.0 | Managed AI provider adapters | Normalize OpenAI, Anthropic, and Gemini structured reviews through one bounded secret-safe contract |
| v1.337.0 | Governed feedback-to-policy recommendations | Propose evidence-bound DFM tightening without automatic mutation or constraint relaxation |
| v1.338.0 | Multi-project policy rollout simulation | Re-analyze exact boards under a proposal-derived simulation profile before any policy deployment |
| v1.339.0 | Dual-control canary rollout authorization | Require two trusted human signatures for a time-bound, 10%-bounded canary with mandatory rollback |
| v1.340.0 | Bound canary monitoring evidence | Compare observed canary analyses with exact authorized baselines and fail closed to rollback |
| v1.341.0 | Dual-control canary completion | Finalize promotion or rollback only with unanimous trusted human signatures over exact monitoring evidence |
| v1.342.0 | Monotonic policy deployment state | Re-verify final signatures, reject revision replay, and retain hash-chained active and rollback revisions |
| v1.343.0 | Fleet-wide post-deployment verification | Bind complete production evidence to the approved candidate and require dual-control rollback on regression |
| v1.344.0 | Verification-bound dual-control rollback | Restore only the retained predecessor after two trusted humans sign exact failed production evidence |
| v1.345.0 | Verified rollback-incident closure | Verify the complete restored fleet and require an independent trusted operator signature before closure |
| v1.346.0 | Hash-chained policy incident ledger | Retain closed rollbacks, recovery metrics, and repeated-revision suspension candidates without automatic suspension |
| v1.347.0 | Signed policy suspension decision | Bind dual-control human suspension to repeated incidents and deny exact suspended digests at promotion |
| v1.348.0 | Independently verified policy remediation | Require an accepted clean successor and a new independent quorum before lifting one suspension for one exact digest |
| v1.349.0 | Append-only policy lifecycle ledger | Reconstruct blocked, released, superseded, and pending suspension decisions at every retained generation |
| v1.350.0 | Monotonic signed lifecycle checkpoints | Reject valid-but-stale, equivocated, or forked policy lifecycle ledgers across independent CI consumers |
| v1.351.0 | Dual-signed lifecycle key rotation | Advance lifecycle signing trust only through an old-and-new-key authorized, generation-chained transition |
| v1.352.0 | Independent lifecycle checkpoint witnesses | Require a fresh quorum of distinct externally trusted observers over one exact lifecycle head |
| v1.353.0 | Remote lifecycle checkpoint witnesses | Acquire and immediately verify lifecycle observations from bounded HTTPS services with hash-bound transport receipts |
| v1.354.0 | Lifecycle witness key rotation | Advance identity-bound witness trust through dual-signed, generation- and digest-chained key transitions |
| v1.355.0 | Lifecycle public-log anchoring | Verify lifecycle-checkpoint inclusion under a separately trusted signed Merkle tree head |
| v1.356.0 | Lifecycle public-log consistency | Reject signed tree rollback, equivocation, and non-prefix split views across retained anchors |
| v1.357.0 | Lifecycle public-log gossip | Compare independent signed tree-head observations without requiring a shared retained baseline |
| v1.358.0 | Remote lifecycle public-log gossip quorum | Acquire bounded remote observations and require fresh consistent views from distinct organizations |
| v1.359.0 | Lifecycle gossip observer key rotation | Bind each organization observer to generation-chained trust and require dual-signed key transitions |
| v1.360.0 | Lifecycle gossip organization trust registry | Authority-sign observer admission, organization suspension, and permanent revocation before quorum eligibility |
| v1.361.0 | Lifecycle gossip registry authority key rotation | Preserve registry history while old and new authority keys jointly authorize each one-generation trust-root change |
| v1.362.0 | Threshold lifecycle gossip registry governance | Require a configurable quorum of distinct root-authorized identities for every admission, suspension, and revocation |
| v1.363.0 | Dual-quorum registry governance rotation | Require both retained and successor authority quorums for threshold, membership, or governance-key changes |
| v1.364.0 | Retained active registry governance | Pin the active governance digest in registry state and reject stale validly root-signed policies or root-only bypasses |
| v1.365.0 | Governed registry root rotation | Require retained and new-root successor quorums to atomically replace the registry root and active governance |
| v1.366.0 | Complete registry history audit | Replay mixed legacy, threshold, governance, and governed-root events from genesis without trusting copied snapshots |
| v1.367.0 | Witnessed registry history checkpoints | Pin root-signed complete-history heads and require fresh distinct witnesses over one exact audited generation |
| v1.368.0 | Registry history witness key rotation | Advance identity-bound checkpoint-witness trust through dual-signed generation- and digest-chained key transitions |
| v1.369.0 | Remote registry history checkpoint witnesses | Acquire and immediately verify independent checkpoint witnesses from bounded HTTPS services with hash-bound receipts |
| v1.370.0 | Registry witness receipt transparency | Append verified remote witness receipts to signed, anchored, independently witnessed hash-chain logs |
| v1.371.0 | Approval transparency public-log consistency | Prove that newer receipt-log checkpoints extend retained signed Merkle trees without transferring the complete log |
| v1.372.0 | Approval transparency public-log gossip | Compare fresh independently signed tree-head observations and reject split views across CI consumers |
| v1.373.0 | Remote approval public-log gossip quorum | Acquire bounded remote observations and require fresh consistent views from distinct organizations |
| v1.374.0 | Approval gossip observer key rotation | Bind organization observers to generation-chained trust with dual-signed key transitions |
| v1.375.0 | Approval gossip organization trust registry | Authority-sign observer admission, organization suspension, and permanent revocation before quorum eligibility |
| v1.376.0 | Approval gossip registry authority key rotation | Preserve organization decisions while retained and successor keys dual-sign a chained trust-root change |
| v1.377.0 | Approval gossip registry threshold governance | Require a distinct-key authority quorum for admission, suspension, and revocation |
| v1.378.0 | Approval gossip registry governance rotation | Require independent retained and successor quorums before changing authority membership, keys, or threshold |
| v1.379.0 | Governed approval gossip registry root rotation | Replace the registry root and active governance atomically under retained and successor quorums |
| v1.380.0 | Complete approval gossip registry history audit | Replay mixed root, threshold, governance, and governed-root events from genesis without trusting copied snapshots |
| v1.381.0 | Witnessed approval gossip registry history checkpoints | Pin retained-root signed complete-history heads and require fresh distinct witnesses over one exact audited generation |
| v1.382.0 | Approval registry history witness key rotation | Advance identity-bound checkpoint-witness trust through dual-signed generation- and digest-chained key transitions |
| v1.383.0 | Remote approval registry history checkpoint witnesses | Acquire and immediately verify independent checkpoint witnesses from bounded HTTPS services with hash-bound receipts |
| v1.384.0 | Approval registry witness receipt transparency | Append verified remote witness receipts to signed, anchored, independently witnessed hash-chain logs |
| v1.385.0 | Verifier-bound approval registry receipt admission | Re-verify retained checkpoint, witness trust, exact response bytes, and signature before append |
| v1.386.0 | Verifier-bound approval registry receipt admission quorum | Require a configurable minimum of distinct independently reverified registry-history witness receipts before atomic append |
| v1.387.0 | Quorum-bound approval receipt-log signing | Bind the exact resulting approval log to its admission report and refuse checkpoint signing for partial, extended, or unrelated logs |
| v1.388.0 | Domain-separated signed receipt-quorum checkpoints | Sign the exact quorum-report digest, registry checkpoint, threshold, and approval-log state under a dedicated cryptographic domain |
| v1.389.0 | Independent receipt-quorum checkpoint witnesses | Re-verify exact approval evidence and require a fresh quorum of distinct trusted witnesses over its dedicated checkpoint |
| v1.390.0 | Receipt-quorum checkpoint witness key rotation | Advance identity-bound witness trust through dual-signed generation- and digest-chained key transitions |
| v1.391.0 | Deterministic Text-to-Circuit SKiDL | Convert a closed circuit specification into executable, namespace-isolated SKiDL with deterministic catalog selection |
| v1.392.0 | Deterministic power-safety ERC | Reject conflicting rails, over-voltage power inputs, and missing required decoupling from explicit schematic metadata |
| v1.393.0 | Reproducible manufacturing packages | Gate and stage KiCad manufacturing outputs with complete copper/Paste layers, strict BOM/CPL metadata, hash manifests, and deterministic ZIP publication |
| v1.394.0 | Bounded factory quote and DFM connector | Submit exact manufacturing archives through secret-safe HTTPS adapters and retain hash-bound normalized quote/DFM receipts |
| v1.395.0 | Bounded factory DFM repair loop | Revalidate and resubmit complete manifest-bound ZIPs through a deadline-bounded, deployment-owned repair wrapper while retaining failure evidence and the last known-good package |
| v1.396.0 | Hash-bound hardware pipeline gate | Recompute and bind schematic/ERC, board analysis, routing quality, the exact final manufacturing ZIP, and firmware evidence into one fail-closed digest manifest |
| v1.397.0 | Factory-bound hardware pipeline gate | Bind a strict normalized factory receipt and fail-closed DFM result to the exact final manufacturing ZIP without network resubmission |
| v1.398.0 | Canonical-IR C/C++17 firmware bundle generator | Generate a v2 manifest with seven hash-bound source artifacts from the canonical KiCad schematic IR, compile/link and smoke-test C11/C++17, run Python compile/self-tests, publish only clean source bundles, and make zone/placement serialization deterministic |
| v1.399.0 | Trusted PR comment publisher | Keep PR code execution without comment-write permission or persisted checkout credentials, publish only a small hash-bound result artifact, and have a default-branch `workflow_run` publisher bind repository IDs, sanitize untrusted Markdown, and revalidate the exact run, attempt, artifact, PR head/base, and newest-run status before updating a bot-owned comment |
| v1.400.0 | Immutable GitHub Actions supply chain | Pin every external workflow and composite-action dependency to a reviewed commit SHA, reject mutable or malformed references in tests and repository policy, retain weekly Dependabot updates, and provide a fail-closed live audit of SHA-pinning enforcement |
| v1.401.0 | Bounded KiCad S-expression parser | Replace token-buffered recursive parsing with a typed iterative parser, enforce fixed byte/token/atom/depth/list/span ceilings across every KiCad consumer, preserve quoted parentheses, and parse custom-rule sequences without copying the input |
| v1.402.0 | Fail-closed numeric and raster bounds | Reject non-finite, out-of-range, or malformed KiCad physical values and enforce checked board/grid/layer, topology, raster candidate/edge, segment/via, and zone cell/blocker ceilings before covered geometry, allocation, narrowing, or mutation |

`ROADMAP.json` is the canonical machine-readable milestone ledger. The release
audit rejects duplicate or unordered milestones, a version mismatch, missing
tags, malformed release metadata, missing or extra assets, invalid SPDX JSON,
and archive checksum mismatches. An optional repository audit also verifies
that `main` has strict required checks, linear history, conversation
resolution, and force-push/deletion protection.

The current release bounds the numeric domain and per-board statically
derivable physical work before the covered rasterization and geometry loops.
The exact boundary and its runtime non-goals are documented in
[`NUMERIC_RASTER_LIMITS.md`](NUMERIC_RASTER_LIMITS.md). The next roadmap
candidates are fail-closed input and execution hardening, in order: add
per-search A* and BFS runtime budgets; make generic CLI I/O and subprocess
execution atomic and bounded; and enforce an immutable ERC safety floor.
Bounded natural-language circuit generation with a deterministic ERC correction
loop follows that safety boundary.
