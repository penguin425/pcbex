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
| v1.403.0 | Deterministic A* work budget | Bound aggregate heap-pop and successful-relaxation work across differential, normal, retry, and shove routing while preserving deterministic parallel results and fail-closed public compatibility |
| v1.404.0 | Deterministic zone-fill work budget | Bound aggregate queue-pop and successful-discovery work across every zone in one atomic fill while eliminating duplicate queue entries and preserving deterministic output |
| v1.405.0 | Bounded CLI I/O and subprocess execution | Limit generic Rust CLI files and MCP frames, atomically publish per-file outputs, and enforce deadlines, output ceilings, cancellation, and process-tree cleanup for doctor, KiCad, and MCP children |
| v1.406.0 | Bounded Python agent I/O and subprocess execution | Route every Python agent file through regular-file, link-safe, size-limited atomic I/O; cap provider input and all child output; reject ambiguous KiCad DRC reports; and supervise provider, pcbex, and KiCad process trees under one deadline |
| v1.407.0 | Immutable ERC safety floor | Keep every built-in error rule enabled at error severity across direct policies and signed packs, reject waivers for floor findings, and prevent baseline gates from accepting retained floor errors |
| v1.408.0 | Supervised firmware and factory subprocesses | Run firmware validation and factory repair children through one deadline- and output-bounded process-tree supervisor while preserving deterministic evidence and last-known-good manufacturing packages |
| v1.409.0 | Manufacturing package and workspace quotas | Bound manufacturing file count, depth, per-file, aggregate, archive, normalization, repair-workspace, and publication work while preserving deterministic atomic packages and last-known-good evidence |
| v1.410.0 | Bounded release and CI execution | Enforce workflow time and parallelism policy, supervise composite-action and audit children, bound release/API/file work, and gate publication on finite output trees |
| v1.411.0 | Rust-gated natural-language circuit generation | Generate a closed circuit-spec v2 through a bounded correction loop and accept only the existing immutable native ERC floor |
| v1.412.0 | Digest-bound catalog selection | Resolve MPNs from a bounded local catalog snapshot, retain a closed selection receipt, and run a second Rust ERC gate on the resolved circuit |
| v1.412.1 | Hardened manufacturing filesystem boundaries | Pin manufacturing publication directories, double-read bounded sources, stream BOM/CPL output, cap extracted parts, and reserve complete-workspace quotas before package creation |
| v1.413.0 | Digest-bound physical-profile injection | Apply one bounded geometry/DFM authority across placement, routing, analysis, and fabrication while binding its exact and canonical digests through manufacturing and pipeline verification |
| v1.414.0 | MCP/Action hardware pipeline parity | Expose schematic, circuit-spec, and complete pipeline checks through MCP and opt-in composite Action inputs/outputs, retaining rejection reports before the final CI gate |
| v1.415.0 | Verified circuit-to-KiCad handoff | Verify a closed flat/single-unit circuit-spec v2 against an existing KiCad schematic with source/canonical identities and retained ERC evidence; do not generate or mutate either input |
| v1.416.0 | Circuit-spec/KiCad schematic-board binding | Recalculate the raw v1.415 handoff and bind exact references, footprint metadata, pin/pad connectivity, no-connect states, and complete net/footprint/pad coverage to the actual `.kicad_pcb`, with source/canonical/binding digests and retained deterministic rejection evidence |
| v1.417.0 | Bounded-input deterministic pipeline runner | Snapshot one closed relative-path/byte/SHA plan, compose raw circuit/schematic/board binding with the existing pipeline gate in process, cross-bind identities, and retain one deterministic no-side-effect report |
| v1.418.0 | MCP deterministic pipeline runner parity | Expose the v1.417 closed runner through synchronous MCP and optional Tasks, retain rejected reports, and return a digest-verified bounded summary without embedding a potentially 128 MiB report in the 16 MiB MCP frame |
| v1.419.0 | Composite-Action deterministic pipeline runner parity | Opt in the root Action with a closed plan, retain a fixed deterministic report and seven revalidated outputs, and publish valid rejection evidence before the optional final approval failure |
| v1.420.0 | Bounded supplier inventory snapshot ingestion | Fetch one closed HTTPS catalog feed under deadline, byte, secret, and no-clobber bounds, then bind the exact response to a replayable local snapshot and receipt while selection stays offline |
| v1.421.0 | Catalog-to-generation provenance | Bind one retained supplier fetch receipt and normalized snapshot to the recomputed catalog selection, exact circuit-generation bundle bytes, and generated SKiDL in a closed replay-verifiable sidecar without adding network access or changing generation bundle v2 |
| v1.422.0 | Deterministic KiCad schematic writer | Convert an immutable-ERC-approved circuit-spec v2 into a bounded, deterministic flat/single-unit `.kicad_sch`, then re-import and verify the exact semantic handoff before atomic no-clobber publication |
| v1.423.0 | KiCad schematic writer MCP/Action parity | Expose deterministic circuit-spec schematic generation through optional MCP Tasks and the root Action while retaining ERC evidence and returning only bounded path/byte/SHA identities instead of embedding schematic bytes |
| v1.424.0 | Exact AI review artifact binding | Bind request-schema-v2 approvals to one exact generated schematic and approved deterministic plan/report/run, then live-rerun and cross-check the artifacts before CLI, MCP, and Action signing or verification while preserving request-schema-v1 workflows |
| v1.425.0 | Native KiCad schematic ERC evidence | Run fixed error-only KiCad ERC under bounded private staging, retain deterministic normalized evidence, and bind fresh replay into request-schema-v3 approvals across CLI, MCP, Python, and Action while preserving v1/v2 workflows |
| v1.426.0 | Native KiCad ERC warning policy | Gate explicit error-and-warning KiCad runs with closed fail-closed budgets, bind exact policy and report identities into request-schema-v4 approvals, and preserve the error-only v1/v3 contracts |
| v1.426.1 | Darwin process-group cleanup race | Preserve the primary bounded-process failure when Darwin reports a transient `killpg` `EPERM` only after the direct child is reaped and a signal-zero probe proves the process group is gone; retain every live or ambiguous cleanup failure |
| v1.427.0 | Standalone native KiCad ERC Action gate | Run error-only or warning-policy native schematic ERC from the root Action without AI or deterministic-pipeline inputs, authenticate retained report/source/policy identities, and publish rejection evidence before optional approval enforcement |
| v1.428.0 | Boardless native KiCad ERC Action | Provide a focused public composite Action that runs authenticated native schematic ERC without a board, preserves the root Action contract, publishes the same twelve identities, and retains bounded rejection evidence before its final approval gate |
| v1.429.0 | Native KiCad PCB DRC evidence gate | Run canonical, digest-bound `drc.v1` PCB DRC evidence through CLI, MCP, and focused/root Actions with private staging, real KiCad 10 reproducibility coverage, strict error/warning approval, and retained rejected evidence |
| v1.430.0 | Native KiCad PCB DRC fresh replay | Re-run exact retained `drc.v1` evidence through read-only CLI/MCP and focused Action verify mode, while making anchor-qualified board-edge and region placement constraints panic-free |
| v1.431.0 | MCP native KiCad task cancellation propagation | Run `run_native_kicad_drc` and `run_native_kicad_erc` directly in the MCP worker, with Unix Task cancellation reaching the KiCad process-group leader and descendants; preserve MCP responses and publish no incomplete report while leaving CLI and Action behavior unchanged |
| v1.432.0 | Standalone native KiCad ERC fresh replay | Expose read-only fresh replay for standalone native KiCad schematic ERC v1/v2 through CLI, MCP, and focused Action; retain rejected evidence before optional approval gates, propagate Task cancellation, stable-read the original schematic, and preserve AI/run contracts |
| v1.433.0 | Closed deterministic pipeline intent compiler | Compile a closed intent with explicit output-plan-parent-relative role paths into a canonical digest-bound deterministic pipeline plan, computing bytes/SHA identities without LLM, network, or path discovery; keep the existing runner as final authority and defer MCP/Action compiler parity |
| v1.434.0 | MCP deterministic pipeline intent compiler parity | Expose the closed intent compiler synchronously and through optional MCP Tasks, authenticate retained plan and intent identities through a strict bounded child summary, and keep the runner and composite Action contracts unchanged |
| v1.435.0 | Composite-Action deterministic pipeline intent compiler parity | Accept an explicit intent/output pair, compile before analysis, authenticate exact intent/plan bytes and SHA identities, reuse the effective plan with the unchanged runner, and publish bounded metadata while preserving legacy plan and analysis-only behavior |
| v1.436.0 | Deterministic firmware-bundle compiler preflight | Stable-preflight an exact eight-entry firmware bundle (manifest plus seven fixed source artifacts) before publishing a plan, validating strict manifest/artifact bytes, hashes, and link/extra rejection while keeping the v1 plan, runner, and pipeline authorities unchanged |
| v1.437.0 | Deterministic firmware-bundle gate re-snapshot | Reopen every exact-eight firmware entry and compare complete bytes/SHA-256 snapshots immediately before and after the deterministic pipeline gate, retaining a rejected report for observed bundle mutation while preserving plan schema v1 and manifest v2 |
| v1.438.0 | Deterministic pipeline required CI check | Run the real Rust deterministic-pipeline binary on every normal PR and push, retain accepted and rejected reports, authenticate compiler source/report bindings, and publish bounded scalar Job Summary and scanned artifacts without changing schema v1 |
| v1.439.0 | Semantic BOM/CPL package validation | Enforce one shared bounded RFC 4180 CSV validator for exact manufacturing headers, BOM quantity/type/layer/count semantics, and unique finite checked-decimal CPL references/layer/counts across fabrication, factory submission/repair, and pipeline verification without changing schema versions or adding a Gerber semantic parser |
| v1.440.0 | Boardless AI schematic approval Action | Bind a live KiCad schematic to an existing schema-v1 AI review request, re-verify signed reviewer/provider/model quorum evidence without PCB, provider, or signing-secret inputs, and retain bounded JSON/Markdown evidence before the optional final quorum gate |
| v1.441.0 | AI schematic approval CLI/MCP parity | Extend schema-v1 live KiCad schematic binding to single approval verification and MCP single/quorum tools; semantically equivalent formatting is accepted while semantic or fresh electrical-review mismatches fail closed |
| v1.442.0 | AI schematic approval live signing parity | Extend the bounded schema-v1 live KiCad schematic binding to `sign-ai-review --schematic` and MCP `sign_schematic_approval`, completing semantic and fresh electrical-review verification before private-key access while leaving wire schemas and schema-v2 through v4 artifact paths unchanged |
| v1.443.0 | AI schematic approval signing preflight | Validate every public response, signer, optional session, selected evidence, and destination before private-key access; sign and atomically publish legitimate rejected approvals, refuse output clobbering while preserving existing files/symlinks, and leave schemas and schema-v2 through v4 artifact paths unchanged |
| v1.444.0 | Root Action live AI schematic quorum | Add an explicit schema-v1 live-schematic quorum input to the root Action, freshly verify semantic and electrical-review binding, publish a distinct live verification result, and reject mixing with schema-v2-through-v4 artifact, native-ERC, or deterministic-pipeline review inputs |
| v1.445.0 | Bounded external DFM profile loader | Route every external fabrication-profile entry point through one 4 MiB stable regular-file reader, reject direct or ancestor symlinks and duplicate JSON keys, and preserve built-in and policy-pack profile behavior without changing DFM or manifest schemas; the embedded DFM object in a policy pack remains on its separate parser/size contract |
| v1.446.0 | Strict SKiDL no-connect adapter | Preserve checked circuit-spec v2 no-connect pins through the compatibility SKiDL renderer with the native `NC` singleton, reject forged null/type or pin/net coverage relationships before source generation, and leave schema-v1 output byte-identical |
| v1.447.0 | Cross-phase DFM manufacturing binding | Bind external and built-in DFM profile identity (canonical digest plus origin/source) into fabricate schema-v3 packages, reject binding changes during factory repair, and require exact analysis-to-package matching in the unchanged deterministic pipeline gate; physical-profile v2, policy-pack analysis, receipt v1, and runner schemas remain compatible |
| v1.448.0 | Atomic circuit-generation KiCad handoff bundle | Revalidate one saved generation bundle, replay its immutable Rust ERC, deterministic KiCad writer, and semantic handoff under one deadline, then atomically publish the exact evidence set and closed digest graph as one deterministic no-clobber ZIP without claiming AI, board, or manufacturing approval |
| v1.449.0 | Verified circuit handoff bundle consumer | Offline-verify the canonical six-entry v1.448 ZIP, complete digest/semantic graph, and optional external identities before safely extracting fixed names to a newly reserved no-clobber directory with a manifest-last commit boundary |
| v1.450.0 | Exact circuit handoff chain replay | Re-run the complete deterministic handoff producer chain from a verified bundle and accept only byte-for-byte reproduction of the canonical archive, including catalog-input ERC when required, while keeping offline verify/extract and the archive format unchanged |
| v1.451.0 | Native KiCad ERC handoff replay | Optionally bind a retained native KiCad ERC v1 or warning-policy v2 report to the exactly reproduced handoff schematic, freshly replay it with one nested deadline and path-free evidence, while leaving the six-entry archive and v1 replay result unchanged when omitted |
| v1.452.0 | Exact AI schematic quorum handoff replay | Bind a non-session schema-v1 AI quorum to the exactly reproduced handoff schematic, require an exact retained report replay, optionally compose native KiCad ERC evidence, and emit closed path-free v3 evidence while preserving v1/v2 results when AI evidence is omitted |

`ROADMAP.json` is the canonical machine-readable milestone ledger. The release
audit rejects duplicate or unordered milestones, a version mismatch, missing
tags, malformed release metadata, missing or extra assets, invalid SPDX JSON,
and archive checksum mismatches. An optional repository audit also verifies
that `main` has strict Rust/Python/KiCad/Deterministic Pipeline checks pinned
to the GitHub Actions app (`app_id: 15368`), linear history, conversation
resolution, and force-push/deletion protection.

The v1.413.0 release added a closed physical constraint profile for board
dimensions/outlines, fixed components, keepouts, and manufacturing minima.
Profile loading is size- and topology-bounded, rejects duplicate JSON keys,
applies atomically, and cannot relax existing manufacturing rules. Exact-source
and domain-separated canonical SHA-256 identities are carried by schema-v2
analysis and manufacturing manifests; pipeline verification reopens the
authorized profile and rejects source, semantic, or cross-phase substitution.
No-profile schema-v1 artifacts remain compatible. The v1.415.0 handoff and
v1.416.0 board-binding releases are retained as standalone boundaries. The
v1.417.0 release composes the latter with the existing pipeline gate through
one closed digest-bound plan and report without changing either pipeline
report schema. The v1.418.0 release exposed that runner through MCP without
relaxing its closed inputs, no-clobber output, or retained-rejection contract.
The v1.419.0 release adds root composite-Action parity: an empty
`deterministic-pipeline-plan` keeps analysis-only behavior, while an explicit
plan uses the fixed `${output-dir}/deterministic-pipeline-report.json` report
and revalidates the seven schema/decision/digest/count/size outputs before
publishing them. `deterministic-pipeline-require-approved` makes the final
Action step fail only after a valid rejected report is retained and published.
The integration adds no discovery, mutation, repair, AI/network/factory call,
submission, or ordering behavior. The v1.416.0 boundary added the standalone
`verify-circuit-kicad-board-binding` CLI/API boundary plus MCP
`verify_circuit_kicad_board_binding`. It recalculates the handoff from raw
circuit and schematic bytes, then compares exact reference/footprint
identifier, value, MPN, assembly metadata, pin-to-pad number/net/no-connect
state, and complete net/footprint/pad coverage against the actual board.  Raw
terminal-less nets remain visible, while net 0 is validated as the board's
reserved no-net identifier rather than a circuit terminal.  Board-net matching
uses canonical names from the imported schematic.  Declared no-connect pins
remain unconnected on their same-numbered pads; only an empty unconnected NPTH
mechanical pad may be added without a pin number.  Source, canonical, and
binding digests, bounded input checks, deterministic findings, atomic
no-clobber outputs, and retained rejection reports are part of the closed
contract.  Hierarchy, buses,
multi-unit/nested handoffs, geometry, routing, DRC, and DFM remain outside it,
and existing pipeline v1/v2 phases are unchanged.

The v1.420.0 release added one explicit network pre-step before catalog
selection. It fetches a closed `catalog-snapshot-v1` document from a caller-
selected HTTPS endpoint, disables redirects, bounds the complete deadline and
decoded response, sources an optional bearer token only from a named
environment variable, reuses the authoritative snapshot/TTL validator, and
atomically publishes both the normalized snapshot and a secret-free digest-
bound fetch receipt. Existing catalog selection, circuit generation, and the
deterministic pipeline remain network-free and consume only retained local
evidence. Supplier-native search/SDK adapters, autonomous substitution,
reservation, purchase, datasheet truth, and qualification remain later
boundaries.

The v1.421.0 milestone closes the evidence gap between that explicit
fetch and offline circuit generation. An opt-in, closed provenance sidecar
revalidates the retained fetch receipt and normalized snapshot, reconstructs
and recomputes the catalog selection receipt embedded in generation bundle v2,
and binds the exact published bundle and SKiDL bytes. Existing generation
invocations and bundle bytes remain compatible when the provenance inputs are
not supplied. The bridge performs no fetch, supplier-native translation,
substitution, reservation, purchase, datasheet validation, or fabrication.

The v1.422.0 release closed the next downstream gap with a
deterministic `.kicad_sch` writer for the same closed circuit-spec v2 subset.
Only immutable-ERC-approved flat, single-unit designs are emitted. Synthetic
embedded symbol definitions, fixed grid placement, stable domain-separated
UUIDs, net labels, no-connect markers, and circuit metadata make the result
self-contained and replayable. The writer re-imports its own bytes and runs
the existing semantic handoff verifier before the CLI atomically publishes a
new file. Hierarchy, buses, multi-unit symbols, external library resolution,
placement/routing, DRC/DFM, and existing-schematic mutation remain later
boundaries.

The v1.423.0 milestone exposes that exact writer through two bounded
integration surfaces. MCP supports synchronous calls and optional Tasks,
preflights an absent destination, revalidates the retained file under the
writer's 64 MiB ceiling, and returns only its path, byte count, and SHA-256 so
the 16 MiB protocol frame never contains the schematic body. The root Action
accepts an opt-in `circuit-spec`, retains its immutable ERC report, emits the
fixed `${output-dir}/circuit-spec.kicad_sch` artifact only after approval, and
publishes the same byte and digest identity. Neither surface substitutes the
generated file for `schematic`, changes the deterministic pipeline, performs
network access, or authorizes placement, routing, or fabrication.

The v1.424.0 milestone closed the exact-artifact approval boundary. An opt-in AI
review request schema v2 binds the exact generated schematic bytes, raw and
normalized deterministic plan identities, retained report bytes, and run
identity. Prepare, sign, single-approval verification, and quorum verification
all rerun the plan, require its report to be approved and byte-identical, and
cross-check the request's electrical review with the runner handoff. MCP
forwards the same complete path groups, the Python adapter treats the new
identities as evidence, and the root Action generates its fresh report before
quorum verification. Request schema v1 remains unchanged.

The v1.425.0 milestone adds KiCad's independent schematic ERC as
replayable approval evidence. A shell-free bounded runner stages only the exact
schematic under a fixed basename, isolates KiCad configuration/profile paths,
uses a fixed error-only JSON invocation, validates exit/report consistency,
removes volatile timestamp/path fields, and atomically retains a deterministic
report before an optional approval failure. Request schema v3/artifact binding
v2 covers the exact report and native run digest; prepare, signing, single
verification, and quorum rerun KiCad and compare fresh normalized bytes. MCP
supports the runner synchronously and through optional Tasks, the Python
adapter validates the closed v3 boundary, and the root Action forwards and
publishes verified native identities. Native warnings remain an explicit later
policy boundary; request schemas v1 and v2 remain byte-compatible.

The v1.426.0 milestone closes that warning-policy boundary without
reinterpreting earlier evidence. Supplying an explicit bounded policy selects
only KiCad error and warning severities, rejects every error, and treats
unlisted warning types or ignored-check keys as policy failures. Global and
per-type warning ceilings, normalized findings, exact policy-source identity,
the domain-separated policy digest, policy failures, and approval are covered
by a v2 native run digest. Retained reports are accepted only after stable
reads and byte-identical fresh replay. Request schema v4/artifact binding v3
accepts only native identity v2; request schema v3 remains restricted to the
error-only native identity v1. CLI, MCP, Python review validation, and the root
Action expose the same opt-in policy path and leave older workflows unchanged.
Static policy files do not establish organization authority, expiry, or
distribution trust; those remain a separate signed-governance boundary.

The v1.426.1 maintenance milestone closes a Darwin process-group
cleanup race in the Python supervisor. A `killpg(SIGKILL)` `EPERM` is treated
as benign only when `poll()` confirms and reaps the exited direct child and a
single `killpg(pid, 0)` probe returns `ESRCH`, proving the group is gone. Live
children, existing groups, unauthorized probes, non-Darwin platforms, and all
other errors continue to fail closed as cleanup failures; the supervisor does
not retry group termination after the probe.

The v1.427.0 milestone exposes native KiCad schematic ERC as a root
composite-Action gate independent of AI approval and deterministic-pipeline
inputs. A dedicated schematic input selects error-only report v1 or, with an
explicit warning policy, report v2. The Action runs the existing bounded Rust
runner under the CI process supervisor, then independently revalidates the
compact child summary against canonical retained report bytes, the exact
schematic, the optional policy source, counts, decisions, and domain-separated
identities before publishing twelve outputs. Valid rejection evidence remains
in the bounded artifact tree, Job Summary, and optional trusted PR comment;
approval enforcement occurs only in the final `always()` gate. Missing,
stale, linked, malformed, noncanonical, mutated, or digest-inconsistent
evidence fails closed. The root Action continues to require a board, and the
standalone report is not automatically connected to the separate AI review
artifact flow.

The v1.428.0 milestone adds a focused public Action at
`actions/native-kicad-erc` for schematic-only repositories. It accepts one
required schematic plus an optional closed warning policy and never requests
or analyzes a board. The dedicated runner reuses the existing bounded process,
filesystem, canonical-report, source, policy, and digest authentication
boundaries; it publishes the same twelve `native-kicad-erc-*` identities as
the root Action. Caller inputs are confined to regular workspace-relative
files, and literal output components exclude artifact glob interpretation.
The output tree is scanned before its pinned artifact upload,
and a separate final `always()` gate enforces execution, scan, upload, and
optional approval only after valid evidence is observable. Unit tests exercise
approved, rejected, malformed, fatal, option-like, stale, linked, and escaping
inputs, while the KiCad 10 E2E workflow invokes both an approved and a rejected
local composite Action. The root Action remains board-required,
and neither Action automatically joins native evidence to the separate AI
approval flow.

The v1.429.0 milestone adds the standalone `native-kicad-pcb-drc-evidence`
boundary. Its CLI, MCP tool, focused Action, and opt-in root Action path run
KiCad `drc.v1`-compatible native PCB DRC in private staging without mutating
the caller's board, project, or rules file. Optional same-stem project and
rules identities are auto-discovered only when the caller leaves them empty;
explicit paths are also bound and both forms retain exact source bytes and
SHA-256 identities.
Volatile KiCad dates, paths, and generated UUIDs are removed before findings
are canonicalized to integer nanometres. The closed vocabulary reserves three
native categories, but v1 disables schematic parity and therefore requires its
category/count to be absent/zero. The report retains ignored checks, invocation
identity, and source/project/rules/run hashes; MCP and Action summaries expose
the exact normalized-report digest. The raw report is validated in private
staging and discarded. Native DRC is approved only
when both errors and warnings are zero; `--require-approved` and equivalent
Action/MCP gates fail after retaining a valid rejected report. Real KiCad 10
two-run reproducibility,
regular-file/link-safe staging, bounded resources, atomic no-clobber output,
and rejected-evidence retention are part of the contract. Native `drc.rpt`,
the existing internal DRC, native ERC, AI approval, and the broader
pipeline/manufacturing boundaries remain explicit later integrations rather
than being connected automatically by this release.

The v1.430.0 milestone adds a fresh-replay boundary for retained native PCB
DRC evidence. `verify-native-kicad-drc-report` snapshots the exact board,
optional project/rules companions, and canonical retained report, runs the
same fixed bounded KiCad invocation in private staging, and requires the newly
normalized bytes to match the retained bytes exactly. The verifier never
rewrites its retained input. MCP exposes the same read-only, task-compatible
operation with the existing 17-field digest-bound compact summary and passes
task cancellation directly to the bounded KiCad process group. The focused
native DRC Action adds a backward-compatible `mode: verify`; after successful
replay it publishes only an independently re-authenticated, atomic no-clobber
copy under the fresh bounded artifact directory so existing outputs and the
final approval gate retain their contract. The root Action remains run-only.
This release also removes the panic path for valid anchor-qualified
board-edge and region placement constraints: board-edge distance uses the
transformed anchor, while region containment continues to apply to the owning
component's complete body.

The v1.431.0 milestone hardens native KiCad execution for MCP Tasks.
`run_native_kicad_drc` and `run_native_kicad_erc` invoke their Rust runners
directly for synchronous and Task MCP calls instead of routing through a
shell-free child CLI. Task calls pass cancellation into the bounded supervisor
and, on Unix, terminate the KiCad process-group leader and its descendants
together. Output publication remains atomic and occurs only after a complete
normalized report has been validated, so a cancelled or interrupted run never
exposes an incomplete report. MCP responses, CLI commands, and composite
Actions keep their existing external contracts; this release changes the MCP
implementation path.

The v1.432.0 milestone adds a standalone native KiCad schematic ERC fresh-
replay boundary. The CLI command `verify-native-kicad-erc-report`, MCP tool
`verify_native_kicad_erc_report`, and focused Action `mode: verify` replay both
closed report schema v1 (error-only) and schema v2 (warning-policy) without
modifying the retained input. Each replay stable-reads the original schematic
before and after the bounded KiCad run, compares the canonical bytes with the
retained report, and keeps valid rejected evidence available before an
optional `require-approved` gate. MCP Tasks propagate cancellation to the
bounded KiCad process group. Existing native run outputs, AI request/binding
schemas, and prepare/sign/verify/quorum contracts remain unchanged.

The v1.433.0 milestone adds a closed intent-to-plan compiler for the
deterministic pipeline. A CLI compiler accepts one closed intent and explicit
paths for every required role, with optional roles represented by explicit
paths or `null`; every role path is relative to the generated output plan's
canonical parent, so the intent file may live elsewhere but every role source
must remain a descendant of that output parent; `..` rebasing is rejected. It
rejects unsafe or linked paths, stable-reads each bounded source, computes the
exact descriptor bytes and SHA-256 identities, and emits canonical existing
plan-schema-v1 JSON through a no-clobber output boundary.
The compiler performs no LLM call, network access, or path discovery and does
not run a gate or grant approval. `run-deterministic-pipeline` reopens and
revalidates the compiled plan and remains authoritative for snapshots,
board-binding, `pipeline-verify`, reports, and optional approval failure.
MCP and composite-Action parity for compilation are intentionally deferred in
v1.433.0; their existing runner contracts are unchanged.

The v1.434.0 milestone exposes that compiler as the closed MCP tool
`compile_deterministic_pipeline_plan`. It accepts only explicit `intent` and
`output` paths, rejects stale output before starting the bounded shell-free
child, and supports synchronous calls plus optional Tasks with cancellation
and expiry. After atomic publication, the child returns a strict five-field
identity summary; the MCP wrapper stable-reads the current intent and retained
plan and verifies their exact byte counts and SHA-256 digests before returning
metadata-only structured content. Plan and role-source bodies never enter the
MCP response. The compiler still performs no LLM, network, path discovery,
gate, approval, design mutation, or manufacturing action, and the existing
runner remains final authority. Composite-Action compiler parity remains
deferred in v1.434.0.

The v1.435.0 milestone adds composite-Action parity for the same closed intent
compiler. The root Action accepts the paired workspace-relative inputs
`deterministic-pipeline-intent` and `deterministic-pipeline-plan-output`; they
are mutually exclusive with the legacy `deterministic-pipeline-plan`, and a
partial or mixed selection fails before analysis. The compiler runs before
analysis through the bounded shell-free process path and publishes only to a
new no-clobber output. Explicit role paths are portable forward-slash values
resolved from the canonical parent of the plan-output path, not the intent's
parent; every source must be a descendant of that parent, while absolute,
traversal, link, special-file, duplicate, stale, or concurrently changed
evidence is rejected fail-closed.

The Action authenticates the exact five-field compiler summary—schema version,
intent source bytes, intent source SHA-256, plan source bytes, and plan source
SHA-256—where plan bytes include compact canonical JSON and its one trailing
newline. It passes the resulting effective plan to the unchanged
`run-deterministic-pipeline` runner. After runner EOF, the Action stable-reads
the intent and effective plan again, matches them against the compiler
metadata, and requires the report's raw plan-source identity to match that
compiled plan, closing post-compilation substitution races before attribution.
The runner remains authoritative for snapshots, board binding, gates, report
retention, and optional approval failure. The Action publishes only
`deterministic-pipeline-effective-plan`,
`deterministic-pipeline-intent-source-bytes`,
`deterministic-pipeline-intent-source-sha256`,
`deterministic-pipeline-plan-source-bytes`, and
`deterministic-pipeline-plan-source-sha256`; the four source-identity outputs
are empty outside compiler mode. `deterministic-pipeline-effective-plan` is
the legacy plan path in legacy plan mode and is empty only in analysis-only
mode. This milestone adds no LLM, network, discovery, gate, approval, design
mutation, or manufacturing behavior. Empty new inputs preserve analysis-only
behavior, and legacy plan-only callers retain the existing runner contract.

The v1.436.0 milestone adds a deterministic firmware-bundle preflight to the
closed intent compiler. The plan schema remains v1 and still carries only the
single `firmware_manifest` descriptor; the compiler does not publish the
seven source descriptors or their hashes into the plan. Before atomically
publishing that plan, it stable-reads `manifest.json`, requires its parent to
contain exactly the manifest plus the seven fixed v2 source artifacts, rejects
symbolic links, special files, unsafe names, and extras, and verifies every manifest
entry's bounded bytes and lowercase SHA-256 against the corresponding sibling.
Each snapshot rescans the directory after its reads, and a final complete
snapshot comparison makes any observed content or entry change fail closed.

This is a structural and identity preflight only. The compiler does not run
firmware builds or smoke tests, approve build evidence, bind the canonical
schematic, call an LLM or network service, or change the plan schema. The
deterministic runner and `pipeline-verify` reopen the original bundle, repeat
their own exact-eight checks and artifact verification, and remain the final
authorities for staging, schematic binding, build evidence, gates, reports,
and approval.

The v1.437.0 milestone hardens the runner's remaining firmware TOCTOU window
around the deterministic pipeline gate. After the initial exact-eight input
preflight and staging checks, the runner takes a complete byte/SHA-256 snapshot
of `manifest.json` and all seven fixed v2 artifacts immediately before the
gate, then takes the same complete snapshot after the gate returns. Any added,
removed, replaced, or content-mutated entry observed by those snapshots causes
the run to be rejected; a well-formed rejected report remains retained before
an optional approval failure. The plan remains schema v1 and the firmware
manifest remains v2. Regular hardlinks are allowed and are bound by the bytes
and SHA-256 read from the named paths; this release does not pin inodes or
claim a race-free filesystem boundary.

The released v1.438.0 milestone promotes the closed deterministic pipeline to an
independent `Deterministic Pipeline` GitHub Actions job on normal pull requests
and pushes. The job builds and invokes the real Rust binary against a closed
compiler fixture, verifies the accepted circuit/schematic/board chain and the
semantic manufacturing rejection path, and retains the ordinary rejected report
before a separate `--require-approved` invocation exits nonzero with its own
report. It authenticates the compiler's source identities and the runner report
binding, publishes only bounded scalar values in the Job Summary, and uploads
scanned report artifacts for review. The deterministic pipeline plan and report
schemas remain v1; the firmware phase validates manifest evidence and does not
replay the recorded firmware builds.

The manufacturing archive is a deterministic synthetic gate fixture. It covers
manifest-bound acceptance and rejection semantics; real KiCad fabrication
export remains covered by the separate `KiCad E2E` check.

The job's success is a normal status check on the latest commit and can be made
required by branch protection. Confirm a successful run on the latest commit
before adding the `Deterministic Pipeline` context to `main`; the release audit
also verifies that this context is pinned to the GitHub Actions app
(`app_id: 15368`) alongside the other required checks. A workflow controlled by
a pull request is not an authorization boundary against a malicious write
collaborator; repository permissions and protected-branch policy remain
necessary. The check does not discover files, invoke an LLM or network service,
mutate a design, submit to a factory, or place an order.

The released v1.439.0 milestone makes manufacturing CSV semantics a single shared,
fail-closed boundary. The package writer and every consumer use a bounded RFC
4180 reader that accepts quoted commas, doubled quotes, and embedded newlines
only within the resource contract. BOM and CPL headers are exact and closed;
BOM quantities, `SMD`/`THT` types, `F`/`B` layers, and aggregate counts are
checked, while CPL references are non-empty and unique and its X/Y/rotation
values are finite checked decimals with valid layers and bounded counts. No
vendor-specific CPL origin/axis/rotation transform is performed, and the gate
does not require CPL designators to be a BOM subset or impose a canonical
BOM/CPL row order. `factory-submit`, each feedback-loop candidate, local and
factory-bound `pipeline-verify`, and deterministic-pipeline verification all
inherit this validator before accepting manufacturing evidence. Manifest,
receipt, plan, and report schema versions remain unchanged; Gerber validation
remains structural and does not gain a semantic parser in this release.

The released v1.440.0 milestone exposes a focused public Action for boardless
AI schematic approval verification. It semantically binds a live `.kicad_sch` to
an artifact-path-unbound schema-v1 request, freshly recomputes the
deterministic electrical review, and then applies the existing signature,
trusted-key, reviewer, provider, model, and optional session quorum checks.
The Action does not call an AI provider and has no board, provider-endpoint,
API-key, or signing-
private-key input. It retains bounded closed quorum JSON/Markdown before an
optional final threshold gate, while source substitution or invalid approval
evidence fails before publication. Schema-v2 through v4 generated-schematic/
pipeline/native-ERC bindings remain on their existing CLI, MCP, and root-Action
paths.

The released v1.441.0 milestone extends the same schema-v1 live binding to the
single `verify-ai-approval --schematic` command and the MCP
`verify_schematic_approval` and `verify_schematic_approval_quorum` tools. Each
path imports the bounded live schematic, freshly recomputes the deterministic
electrical review, and rejects semantic substitution or a fresh-review
mismatch before accepting signatures or quorum evidence. Formatting-only
changes that preserve semantic IR remain accepted; schema-v2 through v4
artifact-bound workflows are unchanged.

The released v1.442.0 milestone extends that live binding to signing. The CLI
`sign-ai-review --schematic` command and MCP `sign_schematic_approval` import
the bounded live KiCad schematic, compare its semantic IR and freshly
recompute the deterministic electrical review before reading the
private key or creating an approval. The live source is a schema-v1 semantic
input, not an artifact-path binding; schema-v2 through v4 continue to require
their complete generated-schematic, deterministic-pipeline, and native-ERC
artifact paths, with no wire-schema changes. Run signing in an isolated
workspace: bounded stable reads detect replacements observed around
verification, but verification, private-key access, and output publication are
not one atomic filesystem transaction and no race-free filesystem boundary is
claimed.

The released v1.443.0 milestone hardens the trusted signing preflight. Before
the private key is opened, CLI and MCP signing validate the complete public
input set: request and selected live or artifact-bound evidence, response
schema and bytes, signer identity, optional active session and request binding, and
the output destination. A valid response that fails a review gate remains a
legitimate signed rejection; its approval is staged and atomically published
before `--require-approved` may return a non-zero status. The no-clobber
boundary rejects an existing regular file, symbolic link, or other non-regular
destination without modifying it. Request, response, session, and signed-
approval schemas are unchanged, and schema-v2 through v4 retain their
existing artifact paths and replay rules. Destination publication is atomic,
but input verification, private-key access, and publication are not one
atomic filesystem transaction. Root-Action live quorum input remains a later
v1.444 boundary.

The released v1.444.0 milestone adds that explicit live-source boundary to the
root composite Action. The optional `ai-review-schematic` input selects the
schema-v1 `verify-ai-quorum --schematic` path and publishes the distinct
`ai-review-live-schematic-verified` result only after the live schematic's
semantic IR and freshly recomputed electrical review match the request. The
input requires the complete signed quorum and policy set and is mutually
exclusive with generated-schematic, deterministic-pipeline artifact, and
native-ERC evidence used by schemas v2 through v4. The existing
`ai-review-artifacts-verified` output keeps its v2-through-v4 meaning, and the
focused verification-only Action remains unchanged.

The released v1.445.0 milestone hardens external DFM profile ingestion before
the profile reaches analysis, routing, candidate generation, or standalone DFM
checks. Every `--fab-profile` path and `validate-dfm-profile` uses one bounded
stable reader with a 4 MiB ceiling, rejects empty, non-regular, directly or
ancestor-symlinked, and changing inputs, and parses JSON with duplicate object
key rejection before the existing closed semantic validator. Built-in
profiles and organization policy-pack resolution retain their existing
behavior. The embedded DFM object inside a policy pack is intentionally not
treated as an external profile file and remains on the policy-pack parser/size
contract. This release does not yet add a DFM identity to fabrication or
manufacturing manifests; v1.447.0 adds that bounded cross-phase binding while
leaving policy-pack embedding on its existing analysis-only provenance path.

The released v1.446.0 milestone closes the v2-to-SKiDL no-connect boundary. The
native envelope validator now rejects null/type mismatches, connected
no-connect pins, declared-net mismatches, duplicate or cross-net membership,
and missing declared-pin coverage before rendering. Explicit no-connect pins
are carried through the compatibility adapter as deterministic `NC` singleton
assignments before ordinary nets; no synthetic `NC` net is created, and the
schema-v1 generator remains byte-compatible. SKiDL stays an optional runtime
dependency.

The released v1.447.0 milestone adds a closed `DfmProfileBinding` contract for
external and built-in fabrication profiles. `fabricate --fab` and
`fabricate --fab-profile` apply the selected rules before DRC/export and write
schema-v3 manufacturing manifests with canonical profile identity and either
the exact external basename/bytes/raw-SHA descriptor or a built-in origin tag.
Physical profiles remain mutually exclusive and retain schema-v2 bytes. The
factory package validator and repair loop reject DFM binding add/drop/
substitution, while `pipeline-verify` requires exact external/built-in binding
equality between analysis and manufacturing. Policy-pack DFM, receipt v1,
MCP/Action inputs, and deterministic plan/report schemas are intentionally
unchanged.

The released v1.448.0 milestone connects a retained schema-v2 circuit-generation
result to the existing native circuit checker, deterministic KiCad schematic
writer, and semantic handoff verifier. It stable-reads the saved bundle and
revalidates its closed shape plus every retained or reconstructable
relationship, treats provider metadata and SKiDL as inert evidence, and
requires the freshly replayed check to equal the retained approved check before
running the writer and explicit handoff under the same monotonic deadline.
Success publishes one deterministic no-clobber ZIP containing the exact source
bundle, normalized spec, check, schematic, handoff report, and a closed
domain-separated manifest; every failed gate publishes no partial archive.
This boundary deliberately does not perform AI signing/quorum, native KiCad
ERC, supplier snapshot/catalog-provenance authentication, board binding,
layout, DRC/DFM, manufacturing export, or fabrication authorization.

The released v1.449.0 milestone adds the matching offline consumer. A bounded
stable read is accepted only when the archive has one canonical six-record
central directory, fixed ordered ASCII names, stored payloads, fixed regular
file metadata, no comments/extras/flags/ZIP64/data descriptors, valid CRCs and
role-specific size bounds, and byte-for-byte deterministic ZIP framing. The
consumer strictly reparses every JSON artifact, revalidates the closed
manifest and domain-separated bundle identity, and cross-checks the retained
generation, spec, immutable check, schematic, and semantic handoff graph.
Verify-only writes nothing. Extraction uses only fixed names in a newly
reserved private no-clobber directory and writes `manifest.json` last; caught
write or fsync failures roll back only identities proven to be created by the
invocation, and an uninspectable reservation is left untouched.
Both operations emit a closed path-free result with the outer archive digest
and optionally require expected archive and logical bundle digests. Because
the archive remains unsigned and omits the catalog pre-selection check bytes,
this proves internal consistency, not producer authenticity or fresh replay;
AI, supplier, native KiCad, board, pipeline, manufacturing, and fabrication
authorization remain separate gates.

The released v1.450.0 milestone adds an explicit fresh handoff-chain replay
without changing the canonical six-entry archive or the offline verifier. It
first completes the v1.449 structural, digest, semantic, and optional expected-
identity checks, then reuses the exact retained generation source with a
caller-selected `pcbex` command under one aggregate monotonic deadline. The
producer chain reruns the reconstructed catalog-input ERC when applicable, the
final immutable ERC, deterministic KiCad schematic writer, and semantic
handoff verifier. Success requires the newly generated manifest and complete
ZIP bytes to equal the retained archive exactly; otherwise no replay result is
emitted. The closed path-free replay result distinguishes a required and
completed catalog-input replay and explicitly records that native KiCad CLI ERC
was not run.

Exact reproduction intentionally requires an engine whose deterministic output
matches the engine retained by the archive; older archives may therefore need
their matching released `pcbex` binary. The supplied executable remains a
caller trust boundary and is not authenticated by this command. Supplier
snapshot/provenance, AI reviewer quorum, real KiCad native ERC, board, pipeline,
manufacturing, and fabrication authorization remain separate later gates.

The released v1.451.0 milestone adds an optional native KiCad ERC assertion to
that exact replay. A retained schema-v1 report, or schema-v2 report plus its
exact warning-policy bytes, is stable-read before producer replay and privately
staged only after the canonical six-entry archive has been reproduced exactly.
The existing Rust verifier reruns `kicad-cli sch erc`, requires report equality
and exact schematic/policy source binding, and optionally requires approval.
Its child timeout is derived from the remaining Python aggregate deadline so
Rust terminates and reaps KiCad before the outer supervisor expires. Success
emits a closed path-free replay-result-v2 report with the report, run, policy,
decision, and approval-gate identities. Omitting native evidence preserves the
v1.450 replay result and starts no KiCad child; the archive and manifest remain
unchanged. The caller-selected `pcbex` and `kicad-cli` executables remain
unauthenticated trust boundaries, and AI, supplier, board, pipeline,
manufacturing, and fabrication authorization remain later gates.

The current v1.452.0 milestone optionally composes a non-session schema-v1 AI
schematic quorum with that exact handoff replay. The retained request, policy
pack, signed approvals, review responses, and quorum report are stable-read
under per-file and aggregate bounds. Only after the canonical six-entry archive
is reproduced exactly does the existing Rust quorum verifier bind those
sidecars to the exact reproduced schematic and generate a fresh report; success
requires that report to equal the retained report byte for byte. Native KiCad
ERC replay remains optional and, when supplied, is included in the same closed,
path-free replay-result-v3 evidence. Omitting all AI evidence preserves the
existing v1 result without native ERC and v2 result with native ERC. The
caller-selected `pcbex` and optional `kicad-cli` executables remain
unauthenticated trust boundaries; quorum success does not by itself authorize
supplier, board, pipeline, manufacturing, or fabrication stages.
