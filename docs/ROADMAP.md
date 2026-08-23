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
| v1.453.0 | Catalog-provenance-bound exact handoff replay | Revalidate an all-or-nothing retained provenance/fetch-receipt/snapshot graph after exact handoff replay, optionally compose independent native and AI evidence, and emit closed path-free v4 evidence while preserving the unchanged six-entry archive and exact v1/v2/v3 results when catalog evidence is omitted |
| v1.454.0 | Retained-board electrical handoff replay | Bind an optional retained KiCad board and exact board-binding report, with an optional custom electrical-policy replay source, to the exactly reproduced handoff after prior optional assertions; emit closed path-free v5 `board_binding` evidence with bounded board/report plus raw replay-source and effective-policy identities while preserving v1–v4 result bytes and the unchanged six-entry archive, without claiming layout, DRC/DFM, manufacturing/fabrication, procurement, or tool provenance |
| v1.455.0 | Fresh manufacturing-package replay | Capture one board, retained manufacturing ZIP, optional explicit KiCad project/rules sidecars, and one optional manufacturing profile under closed bounds; run the existing `fabricate` producer privately with explicit pcbex/KiCad commands and nested aggregate deadlines, accept only a byte-identical fresh ZIP, reread every staged and caller-visible source, and emit closed path-free `manufacturing-package-fresh-replay-v1` evidence without changing pipeline/MCP/Action or authorizing fabrication |
| v1.456.0 | Fresh deterministic-pipeline report replay | Capture one closed plan, one retained report, every present source in the fixed 16-role contract, and all seven firmware siblings; run the existing deterministic-pipeline runner privately through a caller-selected pcbex command, require exact retained/fresh report bytes including the final LF, reread staged and caller-visible sources, emit closed path-free `deterministic-pipeline-fresh-replay-v1` evidence with verification distinct from the retained approval decision, close the residual bounded Darwin exited-group observation race, and make native firmware smoke execution plus short-lived Windows Job assignment portable without leaking private paths into evidence |
| v1.457.0 | Shared-board circuit-to-manufacturing replay | Extend exact circuit-handoff replay only when a complete v5 board-binding pair is present, reuse that one captured raw board for a private manufacturing-package replay, require the fresh ZIP to equal the retained ZIP byte-for-byte, and emit closed path-free v6 evidence under one outer deadline and one final union caller-source reread while preserving exact v1–v5 results when omitted and never treating reproduction as fabrication authorization |
| v1.458.0 | Pipeline-bound circuit-to-manufacturing replay | Extend only a complete v6 replay with a pre-child captured plan/report/input closure, replay the deterministic pipeline last, cross-bind exact circuit/schematic/board/package bytes, effective policy, the complete canonical board-binding report, and canonical schematic/raw-board identities, preserve truthful rejected evidence, and emit closed path-free v7 under ordered subdeadlines and a final union plus firmware-directory reread while preserving exact v1–v6 results when omitted |
| v1.459.0 | Dual-control exact fabrication release authorization | Freshly reproduce one approved factory-required deterministic pipeline, revalidate its exact manufacturing ZIP, passing factory receipt, and selected organization policy pack, then require domain-separated approvals from at least two dedicated trusted human keys over one bounded quantity/currency/value/window/challenge scope; retain full signed evidence without contacting a factory, placing an order, spending funds, or claiming factory authenticity or one-time use |
| v1.460.0 | MCP fabrication authorization verification parity | Expose the v1.459 fresh verifier synchronously and through optional MCP Tasks, retain truthful authorized/not-authorized reports, and return a digest-authenticated bounded summary without exposing signing keys or embedding the complete authorization report |
| v1.461.0 | Focused fabrication authorization verification Action | Add a standalone verification-only composite Action that freshly invokes the v1.459 verifier, authenticates and retains its exact report, exposes the compact bridge as 23 scalar outputs, optionally uploads the one-file evidence artifact, and applies an authorization gate only after retention without exposing signing keys or placing an order |
| v1.462.0 | Local fabrication authorization challenge reservation | On Unix, freshly require an authorized fabrication quorum before installing one challenge-keyed, closed path-free compact marker through a descriptor-pinned no-replace and file/directory synchronization boundary in an explicitly trusted pre-provisioned local ledger, while retaining the existing false one-time-use flag and making no global, cross-host, permission, factory, order, payment, or exactly-once claim |
| v1.463.0 | Deterministic circuit-to-KiCad board producer | Create a new placed-but-unrouted KiCad board from one approved circuit/schematic handoff plus exact embedded footprint, construction, and physical-profile artifacts; require the generated bytes to pass the existing board-binding gate and publish a closed three-file no-clobber bundle without host-library discovery, routing, DRC/DFM, manufacturing, procurement, or MCP/Action authority |
| v1.464.0 | Exact final BOM and offline procurement intent | Reuse the complete manufacturing-package validator and canonical BOM renderer to compare one exact board with one retained ZIP, then optionally replay one retained catalog selection into closed per-board SKU intent without claiming electrical binding, manifest input-name binding, live supplier facts, procurement authority, network access, or order placement |
| v1.465.0 | Exact final CPL board-bound placement evidence | Reuse the complete manufacturing-package validator and production CPL renderer to compare one exact board with one retained ZIP, retain exact board-coordinate placement evidence, and reject canonical CPL or board-source mismatches without claiming circuit-authored coordinates, vendor transforms, assembly execution, fabrication/procurement authority, or order placement |
| v1.466.0 | Fresh exact firmware-bundle build verification | Capture one exact-eight manifest-v2 firmware bundle, privately rerun the six fixed C11, C++17, and Python compile/smoke checks, retain a closed path-free rejection before an optional final gate, and reject unsafe input, observed mutation, or cancellation without a report while preserving every manifest, pipeline, and fabrication schema and adding no downstream composition or authority |
| v1.467.0 | Exact per-board assembly evidence composition | Freshly reproduce one schema-v6 handoff/manufacturing chain, semantically replay one exact catalog-backed procurement intent from the handoff generation entry and supplied snapshot, byte-replay one exact final-CPL report, and hard-cross-bind shared board/package/handoff-generation identities plus the final-BOM/final-CPL manifest and package-board-source identities into one closed Python-only per-board result; retain truthful incomplete evidence before an optional final gate without claiming assembly readiness, authorization, live supplier facts, vendor transforms, or an atomic multi-input snapshot |
| v1.468.0 | Exact offline supplier-offer coverage | Freshly replay one exact retained procurement intent from its board, manufacturing package, generation bundle, and historical catalog snapshot; bind one caller-normalized local offer to the exact intent bytes; multiply only explicit per-board quantities by an explicit requested board count; and retain covered or not-covered component-line evidence using fixed-scale integer subtotals, without claiming current availability, offer or supplier authenticity, landed cost, reservation, authorization, payment, or ordering |
| v1.469.0 | Bounded supplier-offer HTTPS acquisition receipt | Explicitly fetch one already-normalized supplier offer through a bounded no-redirect HTTPS GET, preserve exact response-entity and canonical-offer identities in a closed local receipt, and publish the normalized offer for unchanged v1.468 offline coverage without claiming supplier, offer, price, transport, or time authenticity, current availability, reservation, authorization, ordering, or payment |
| v1.470.0 | Exact assembly and acquired supplier-offer evidence composition | Capture one shared source union, validate the exact acquisition receipt and offer offline, freshly replay the complete v1.467 assembly and v1.468 coverage children from the same staged board/package/handoff-generation/snapshot/intent closure, and retain their full cross-bound results with truthful incomplete evidence before an optional gate, without claiming current supplier facts, trusted time, assembly readiness, authorization, ordering, or payment |
| v1.471.0 | Dual-control exact procurement release authorization | Freshly validate one exact retained v1.470 result from its complete original closure before and after a separate trusted Rust cryptographic child, pin the expected canonical procurement policy digest, and require at least two distinct role-disjoint Ed25519 approvals over one exact offer-bound quantity/currency/component-subtotal/window/challenge scope before retaining truthful authorized or not-authorized evidence, without claiming policy authenticity, trusted time, current supplier facts, reservation, ordering, payment, or spend |
| v1.471.1 | Task-oriented documentation architecture | Replace the release-history-sized root README with a compact project entry point, add task-oriented getting-started, workflow, architecture, integration, and trust guides, and index every focused contract without weakening any implementation or evidence boundary |
| v1.472.0 | Local procurement authorization challenge reservation | Freshly replay one exact retained v1.471 authorization from its complete original closure, then admit its verified challenge to one externally identified Unix 0700 local ledger through descriptor-pinned durable no-replace publication and commit-time window checks, while leaving the v1.471 one-time-use claim false and making no global, supplier-inventory, order, payment, or exactly-once claim |
| v1.473.0 | Deterministic multi-unit KiCad handoff | Add an opt-in closed circuit-spec v3 whose physical parts contain explicit symbol units and whose connections bind reference, unit, and package pin; generate and freshly verify real KiCad multi-unit schematics, then collapse only globally unique physical pins into the unchanged board/BOM/manufacturing model while keeping existing circuit-spec v2 documents and workflows migration-free |
| v1.474.0 | Bounded deterministic routing convergence | Opt into validity-first multi-round JSON/KiCad routing under one deterministic aggregate A* allocation, accept only strict improvements with no checker finding beyond explicit unrouted nets, retain every bounded strategy and decision in a closed Board-bound report, and preserve unchanged single-pass behavior and design rules |
| v1.475.0 | Fresh exact routing convergence verification | Capture the raw JSON or KiCad routing source closure, freshly reproduce one canonical retained v1.474 convergence decision with its producer version, regenerate the selected routed artifact byte for byte, and retain a closed hash-bound complete/partial verification before an optional complete gate without claiming source authenticity, native KiCad DRC, manufacturability, or release authority |
| v1.476.0 | Fresh routing-to-manufacturing handoff (bundled) | Freshly reproduce one exact retained v1.475 KiCad routing verification, then use the same captured routed board and sidecars to reproduce one retained manufacturing ZIP; retain incomplete routing without invoking fabrication and keep authenticity, native DRC, manufacturability, and release authority false. This contract milestone first ships inside v1.477.0 and has no standalone tag |
| v1.477.0 | Fresh routing/native-DRC/manufacturing handoff | Freshly reproduce the exact retained v1.476 handoff, replay one retained normalized native KiCad DRC report against the same routed board and companions, and retain routing-incomplete or DRC-rejected evidence before a ready gate while keeping manufacturability, fabrication approval, and release authority false |
| v1.478.0 | Policy-pinned routing/DRC fabrication release | Freshly reproduce one exact v1.477 handoff, require the same package in a factory-required pipeline, and cross-check a dedicated fabrication quorum against an externally expected canonical policy digest before a conjunctive offline release decision, without claiming tool, policy, receipt, or source authenticity, external submission, capacity, ordering, payment, or one-time use |
| v1.479.0 | Externally digest-pinned release entrypoints | Freshly reassess the stable evidence, scope, policy, and approval subject of one canonical retained v1.478 release while requiring the resolved routing pcbex, authorization pcbex, and KiCad CLI native entrypoint bytes to match three independent deployment-supplied SHA-256 pins; retain the fresh point-in-time decision and path-free executable observations without claiming historical-decision reuse, binary origin, signatures, libraries, plugins, loader state, sandboxing, source authenticity, external submission, capacity, ordering, or payment |
| v1.480.0 | Policy-pinned signed factory-receipt release | Bind one exact normalized accepted factory receipt and manufacturing package to a dedicated role-disjoint Ed25519 factory key selected by an externally pinned organization policy, then freshly replay the complete executable-pinned v1.479 subject around signature verification before retaining an authenticated or valid negative release snapshot without claiming legal identity, TLS or raw-response authenticity, trusted time, capacity reservation, ordering, or payment |
| v1.481.0 | Local signed factory-receipt release reservation | Freshly replay one exact retained v1.480 subject, require a currently authenticated receipt and active fabrication/attestation windows, then durably admit its signed challenge to one externally identified Unix 0700 local ledger through descriptor-pinned no-replace publication without claiming global one-time use, capacity, submission, ordering, or payment |
| v1.482.0 | Durable idempotency-keyed signed factory-release submission and reconciliation | Consume one exact v1.481 ledger marker and manufacturing ZIP, durably commit a deterministic adapter intent before one POST, retain the bounded result, and reconcile pending or uncertain outcomes through GET without retransmitting the ZIP or claiming server-side idempotency, legal identity, capacity, order, payment, or exactly-once execution |
| v1.483.0 | Policy-pinned signed factory-release adapter responses | Preserve the exact v1.482 intent and receipt while authenticating each bounded POST or GET response with a strict RFC 9421 Ed25519 profile, RFC 9530 content digest, covered request context, and role-disjoint factory key from an externally pinned policy; retain positive or closed negative evidence before gating without claiming trusted time, TLS, legal identity, capacity, order, payment, or exactly-once execution |
| v1.484.0 | Authenticated monotonic factory-release adapter state | Preserve every v1.482/v1.483 wire contract while adding a separate signed sequence/predecessor/state profile that binds the client's accepted head, admits only genesis, exact replay, or one linked successor, rejects rollback/equivocation/gaps/forks/terminal mutation, and durably repairs a bounded local chain without claiming global non-equivocation, ledger rollback resistance, trusted time, capacity, order, payment, or exactly-once execution |

`ROADMAP.json` is the canonical machine-readable milestone ledger. A `bundled`
milestone remains ordered and documented but intentionally has no standalone
tag; `released` and `current` milestones require tags. The release audit rejects
duplicate or unordered milestones, a version mismatch, missing required tags,
malformed release metadata, missing or extra assets, invalid SPDX JSON, and
archive checksum mismatches. An optional repository audit also verifies
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

The v1.426.1 maintenance milestone introduced strict proof for a Darwin
process-group cleanup race in the Python supervisor. The v1.456.0 hardening
also covers the residual observation race seen when the child or zombie-only
group transition lags the initial `killpg(SIGKILL)` `EPERM`. The direct-child
kill fallback runs first, then bounded `poll()` and signal-zero observations
continue for at most one second, clipped to the caller's active deadline. The
pending error is treated as benign only when the child is reaped and
`killpg(pid, 0)` returns `ESRCH`, proving the group is gone. Live children,
existing groups, unauthorized probes that remain ambiguous at the deadline,
non-Darwin platforms, and all other errors continue to fail closed; the
supervisor never retries group termination.

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

The released v1.452.0 milestone optionally composes a non-session schema-v1 AI
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

Version 1.453.0 optionally binds the retained v1.421 catalog
generation provenance to that same exact handoff replay. Provenance, fetch
receipt, and normalized snapshot inputs are required all together, bounded to
1 MiB, 1 MiB, and 4 MiB respectively and to 6 MiB in aggregate, and accepted
only for a catalog-backed archive. They are captured before any producer child.
The unchanged canonical six-entry archive reproduces byte-for-byte first;
optional native KiCad ERC and AI quorum remain independent assertions and run
in their existing order. The caller sources are then reread, the existing
offline provenance validator recomputes the retained fetch-time snapshot,
selection, generation, bundle, and SKiDL graph, and every source is reread again
before success.

The result is the closed path-free schema v4 with exact scope
`deterministic-electrical-handoff-chain-catalog-provenance-replay-v4`, a true
`validation.catalog_generation_provenance_replayed` flag, the validated v1.421
13-field object directly under `catalog_generation_provenance`, and closed
`{bytes, sha256}` identities for each of its three `sources`, without a
`binding` wrapper. Its schema ID basename is
`circuit-generation-kicad-handoff-bundle-catalog-provenance-replay-result-v4.json`.
Omitting the complete catalog set preserves the exact prior v1, v2, or v3
result; catalog evidence is not added to the archive. This is historical
offline linkage only. It does not authenticate a supplier, TLS connection,
endpoint, raw HTTP response, or the caller toolchain; establish current
inventory, price, or reservation; authorize procurement or fabrication; or
approve a board, placement/layout/routing, PCB DRC/DFM, manufacturing package,
or manufacturing operation.

The released v1.454.0 milestone optionally binds a retained KiCad board and
retained compact board-binding report to the exact handoff replay. The CLI/API
names are `--kicad-board`/`kicad_board` and
`--board-binding-report`/`retained_board_binding_report`; an optional
`--board-binding-policy`/`board_binding_policy` carries the exact custom
electrical-policy source for the fresh replay, and `--require-board-binding-approved`/
`require_board_binding_approved` is a final gate requiring the complete pair.
The board, report, and policy are stable-read before any producer child under
128 MiB, 12 MiB, and 4 MiB per-source bounds (144 MiB plus one byte aggregate)
and reread after the existing board-binding child. The canonical report is
12 MiB plus one trailing newline byte. The
canonical six-entry archive and manifest reproduce first, existing
v1.451–v1.453 assertions retain their order, and the geometry-free
`verify-circuit-kicad-board-binding` gate then compares a private fresh report
to the retained report byte-for-byte. One aggregate monotonic deadline (1–600
seconds, default 120) covers reads, children, report validation, rereads, and
cleanup; the standalone Rust board command has no timeout flag.

The closed path-free v5 `board_binding` result (scope
`deterministic-electrical-handoff-chain-board-binding-replay-v5`) contains only bounded
schema/engine, decision/approval, compact finding counts, board/report, raw
replay-policy source and effective-policy identity, plus board-electrical,
circuit-handoff, and binding identities. It has no host
paths or raw sidecar bodies. Omitting every board option preserves v1–v4
result bytes, schemas, the canonical six-entry ZIP, and existing pipeline
boundaries exactly. A successful binding is electrical identity evidence only:
it does not approve placement or footprint geometry, copper/routing/zones,
PCB DRC/DFM, Gerber/BOM/CPL, manufacturing/fabrication, procurement, supplier
facts, or pcbex/KiCad/tool provenance. Geometry-only source changes may leave
the electrical digest unchanged while changing raw/binding identity and do not
constitute layout approval.

The released v1.455.0 milestone adds a standalone exact replay for one retained
manufacturing package. The Python API is `replay_manufacturing_package`; the
CLI and schema commands are `pcbex-agent replay-manufacturing-package` and
`pcbex-agent manufacturing-package-replay-result-schema`. The replay captures
one portable-basename `.kicad_pcb`, the retained `manufacturing.zip`, optional
explicit `--kicad-project` and `--kicad-rules` sources, and at most one of a
built-in `--fab`, external `--fab-profile`, or `--physical-profile` selection.
The board, project, rules, and each retained/fresh ZIP read are limited to
128 MiB, while an external profile is limited to 4 MiB. Caller-visible board,
project, rules, retained ZIP, and profile captures share one 512 MiB aggregate
input ceiling; the fresh output is checked separately.

All caller files are stable-read before native execution and written under
their required names in one private temporary workspace. The adapter invokes
the caller-selected pcbex command without a shell and passes `fabricate` the
private board, output directory, explicit `--kicad-cli`, selected profile, and
an inner aggregate timeout. `fabricate` now accepts direct `--kicad-cli` and a
finite positive `--timeout-seconds` through 600 seconds only when representable
as a positive Rust `Duration`. Its four KiCad children share one absolute
deadline and retain their per-child caps. Publication checks before each
visible persist and commits ordinary siblings, `manifest.json`, then the
canonical archive; a failed deadline can leave intermediate siblings but no
new complete-package evidence, while non-preemptible work after the final
archive commit can cross the direct command's nominal deadline.

The Python replay has its own finite `0 < seconds <= 600` deadline (default 120)
and subtracts up to 15 seconds, or half the remaining time when smaller, from
the child budget. Its hidden outer-supervision mode keeps pcbex and all four
KiCad children in one Python-owned process group on Unix or outer Job on
Windows, while direct `fabricate` retains isolated child groups/Jobs. Python
performs cleanup and final rereads and checks its deadline immediately before
success. External profile staging preserves its
validated portable source basename because that name is part of the
manufacturing manifest;
project/rules staging uses the board-derived same-stem names expected by
`fabricate`.

Success requires the freshly generated `manufacturing.zip` to equal the
retained bytes exactly. The adapter then rereads every staged source, the fresh
ZIP, and every caller-visible source before emitting closed path-free result
schema v1 with verification scope `manufacturing-package-fresh-replay-v1`,
board/project/rules/profile/package identities, an explicit identical-package
decision, and completed validation flags. It publishes no regenerated Gerber,
BOM, CPL, DRC, or ZIP outside its temporary workspace. Caller-selected pcbex
and KiCad executables remain unauthenticated, unsandboxed trust boundaries;
exact output equality does not establish their provenance. This standalone
replay does not alter deterministic-pipeline schemas, add MCP or Action
integration, submit to a factory, authorize fabrication/procurement, or place
an order.

The released v1.456.0 milestone adds a standalone exact replay for one retained
deterministic-pipeline report. The Python API and CLI are
`replay_deterministic_pipeline` and
`pcbex-agent replay-deterministic-pipeline`; the closed result schema is exposed
by `pcbex-agent deterministic-pipeline-replay-result-schema`. Before native
execution the adapter captures the exact plan and retained report, every source
selected by the plan's fixed 16-role contract, and the seven fixed firmware
siblings. It preserves the plan's relative tree in one private workspace so
the original plan bytes and identity-sensitive source names remain
authoritative.

The caller-selected pcbex command is invoked directly without a shell to run
the existing `run-deterministic-pipeline` command against that private closure.
Success requires the fresh report to equal the retained bytes exactly,
including the canonical final LF. The adapter then rereads every staged and
caller-visible source before returning a closed, path-free schema-v1 result
with verification scope `deterministic-pipeline-fresh-replay-v1`. The result
also requires the complete closed nested Rust report graph, strict integer
bounds, and independently recomputed plan/run domain hashes. One aggregate
deadline reserves up to 30 seconds (or half the remaining time), divided
between bounded child cleanup and post-child validation/cleanup. The result
binds the plan and retained/fresh report identities while keeping exact replay
verification separate from the report's `approved` decision: an exactly
reproduced downstream-gate rejection is verified evidence, not an approved
pipeline. The private replay requires descriptor-exact regular inputs and an
exact-eight firmware closure, so reports rejected for an input-boundary failure
remain retained evidence outside this adapter's safe staging contract.

The selected pcbex executable remains an unauthenticated, unsandboxed trust
boundary, and exact equality requires an engine capable of reproducing the
retained report bytes. This command does not invoke a circuit, KiCad,
manufacturing-package, or firmware producer; run KiCad or `fabricate`; rebuild
firmware; make an AI, supplier, network, or factory request; change existing
runner/plan/report schemas; add MCP or Action integration; submit a package;
or authorize fabrication, procurement, deployment, or ordering.

The same release hardens the shared Python process supervisor on Darwin. If an
initial process-group `SIGKILL` returns the platform's transient `EPERM`, the
supervisor attempts the direct-child kill and uses only deadline-clipped
`poll()` and signal-zero probes to wait for a positive `ESRCH` absence proof.
It never resends the group signal, and every live, existing, unauthorized, or
deadline-ambiguous group remains a cleanup failure that takes precedence over
the original child failure.

The released v1.457.0 milestone composes the v1.454 exact circuit-to-board
electrical binding with the v1.455 exact manufacturing-package producer replay.
Manufacturing options are accepted only with the complete v5 board-binding
pair: one `--kicad-board` and one `--board-binding-report`, with the optional
custom board policy retaining its existing meaning. There is deliberately no
second manufacturing board input. The adapter captures the raw board once,
uses those exact bytes for both replay stages, and requires the board byte count
and SHA-256 reported by the nested manufacturing replay to equal the v5 binding
identity. A geometry-only edit therefore fails this composition even when its
electrical digest is unchanged.

After exact six-entry handoff reproduction and any independently requested
native-ERC, AI-quorum, or catalog-provenance assertions, the v5 board-binding
report is freshly reproduced. The existing `--require-board-binding-approved`
gate still prevents `fabricate` from starting when approval is required and the
exact report is rejected; without that flag, the rejected decision remains
visible evidence. The manufacturing stage then privately invokes the existing
fresh-package replay with explicit project/rules sidecars and an optional
profile selected from mutually exclusive built-in DFM, external DFM, or
physical-profile modes. Success requires the
fresh `manufacturing.zip` to equal the retained ZIP byte-for-byte.

One outer monotonic deadline covers all captures, children, nested cleanup,
cross-binding checks, result construction, and cleanup. The manufacturing child
receives a strictly shorter remaining budget, and success is returned only
after the nested staged-source checks and one final union reread of every
caller-visible input across both replay stages. The closed, path-free schema-v6 result uses scope
`deterministic-electrical-handoff-chain-manufacturing-package-replay-v6`, adds
the complete closed `manufacturing-package-fresh-replay-v1` result, and records
completed package replay and shared-board identity validation. Omitting all
manufacturing options preserves exact v1–v5 result serialization, schemas, and
the unchanged six-entry handoff archive.

The release also aligns the board-binding parser with KiCad 10's `20251028`
file-format boundary. It preserves quoted-token identity, keeps legacy numeric
ID/name cross-checks intact, rejects mixed dialects, and builds the modern net
inventory from every supported connected object rather than pads alone. This
lets the real KiCad 10 upgraded board flow through the shared-board replay
without weakening `extra_net` detection or confusing an unquoted netcode with
a quoted net name. Connected fields are restricted to their native ancestry,
legacy zone `net_name` must match its numeric ID, modern obsolete `net_name`
fields are rejected, and quoted empty free-track nets retain KiCad 10's
implicit unconnected semantics without entering the named-net inventory.

This composition proves deterministic reproduction under caller-selected,
unauthenticated pcbex and KiCad executables. It does not authenticate toolchain
provenance, a supplier, factory, or network receipt; establish current parts or
fabrication availability; submit an archive; authorize layout, procurement,
manufacturing, fabrication, deployment, or ordering; add MCP/Action/pipeline
schema parity; or generate/build firmware.

The v1.458.0 milestone closes the next composition gap by binding one
exact retained deterministic-pipeline report to the complete v1.457 chain. A
plan/report pair is accepted only with every v6 board/manufacturing input, and
the plan, report, selected role files, and exact-eight firmware bundle are
captured before any producer. After archive, board-binding, and manufacturing
replay, the pipeline runs last from those captured bytes.

The v7 result requires raw circuit/schematic/board/manufacturing-package
identity equality, effective policy equality, byte-for-byte canonical equality
of the complete nested board-binding report, and matching canonical schematic
and raw-board pipeline identities. Supplied review content and plan-relative
filename spelling remain evidence under test so a genuine rejected report can
be reproduced; when a report claims approval, strict review equality and board
basename equality are independently enforced. Exact verification therefore
remains separate from the retained approval decision.

Manufacturing and pipeline execution receive ordered, strictly earlier
absolute deadlines under the existing outer handoff deadline. A final union
reread covers every earlier and pipeline caller source and rescans the firmware
directory for exact membership. The closed path-free v7 scope is
`deterministic-electrical-handoff-chain-manufacturing-pipeline-replay-v7`, and
omitting the plan/report pair preserves v1–v6 bytes. This milestone adds no
fresh producer beyond those already in v6, firmware rebuild, MCP/Action parity,
network/factory call, toolchain authentication, fabrication/procurement
authorization, or order placement.

The released v1.459.0 milestone adds a separate Rust-native authorization
boundary rather than changing the v7 replay or deterministic-pipeline schemas.
`sign-fabrication-approval` first re-runs one factory-required plan in-process,
requires its retained report to reproduce byte-for-byte with `approved: true`,
and independently validates the exact manufacturing ZIP, passing normalized
factory receipt, and exact organization policy pack selected by that report.
Only then may a dedicated fabrication signer approve or reject one explicit
authorization ID, random 32-byte challenge, quantity, uppercase currency,
maximum total in minor units, validity window, reason, and ticket.

The optional policy-pack field `fabrication_authorization_policy` requires two
to 100 dedicated public keys, a minimum quorum of at least two, and a validity
limit no greater than seven days. Signer IDs and public keys must be disjoint
from AI-review and human-escalation roles. `verify-fabrication-authorization`
freshly repeats the evidence replay and validates every signature under a new
domain before retaining the complete policy pack and signer-sorted signed
approvals. A valid submitted human rejection, insufficient quorum, inactive
time, or a policy-window excess produces truthful `not_authorized` evidence;
the optional final gate fails only after that report is atomically retained.

This is an offline authorization to release only the exact signed package and
scope to a separately controlled fabrication handoff. The normalized receipt
has no factory signature and its raw response cannot be reconstructed, the
organization policy pack remains an externally selected trust root, and a
static challenge has no durable consumption ledger. The milestone therefore
does not authenticate a factory or current quote, guarantee one-time use,
contact a network, submit files, reserve inventory, place an order, execute
fabrication, or authorize payment/spend.

The released v1.460.0 milestone exposes only the fresh
`verify_fabrication_authorization` boundary through MCP. Synchronous calls and
optional Tasks invoke the existing CLI verifier against the original plan,
retained pipeline report, manufacturing package, factory receipt, policy pack,
and submitted approvals. The complete authorization report remains in the
caller-selected no-clobber output file; MCP returns only a closed compact
summary authenticated against the retained report's exact bytes and SHA-256.
Valid `not_authorized` evidence is retained before an optional
`require_authorized` gate reports failure.

MCP never accepts a caller-selected evaluation time and does not expose
`sign-fabrication-approval`, private keys, scope construction, network access,
factory submission, ordering, payment, or challenge consumption. Signing stays
CLI-only.

The released v1.461.0 milestone adds that verification boundary as a focused,
boardless composite Action. It accepts only paths to the original verifier
inputs and a newline-delimited approval set, writes one fixed no-clobber report
inside its output directory, authenticates the compact bridge and exposes its
23 values only as scalar outputs, and optionally uploads that one report before
applying `require-authorized` as the final gate. A valid `not_authorized` result remains retained evidence;
structural, replay, signature, mutation, or publication failures expose no
artifact path.

The Action does not sign approvals, read private keys, accept caller-selected
scope or evaluation time, contact a factory, order, pay, reserve inventory, or
turn the point-in-time report into reusable current authority. The retained
report contains the complete policy and signed envelopes, including human
reasons and tickets, so confidentiality-sensitive callers can disable artifact
upload. Near-limit 128 MiB publication remains an independently enforced bound,
not a claimed adversarial end-to-end upload fixture.

The released v1.462.0 milestone adds a separate Unix-only cooperative
reservation boundary without changing verification, MCP, or either Action.
`reserve-fabrication-authorization` consumes the original plan, retained
pipeline report, manufacturing package, factory receipt, policy pack, and one
to 100 signed approvals. It freshly requires the complete in-memory
authorization report to be authorized, then commits only a bounded path-free
23-field summary under a filename keyed by the exact signed challenge.

The caller must select an already existing effective-UID-owned mode-`0700`
ledger by absolute path and supply the expected 64-hex ledger identity from its
fixed closed manifest. On Unix the ledger directory remains pinned while a
complete marker is synchronized, installed without replacement relative to
that descriptor, and followed by directory synchronization. Local window
checks bracket installation and confirm validity again after durability;
expiry after installation burns the challenge and returns an error. Any
existing entry blocks reuse, and an error after installation never removes the
final marker automatically. The marker has the exact five-key
`pinned-local-ledger-at-most-once-v1` contract and retains the nested verifier's
`challenge_one_time_use_enforced: false` value.

This is deliberately not global one-time use or a permission boundary. The
same UID or an administrator can delete or replace state; a ledger path can be
swapped or rolled back between invocations; another ledger, host, or runner has
independent state; and Windows plus network, distributed, overlay, and
ephemeral filesystems are outside the durability claim. The command does not
discover revocations or withheld rejections, authenticate a factory or clock,
retain the full signed report, expose MCP/Action parity, submit a package,
order, pay, or make an external side effect exactly once. Enforcement requires
a separately controlled credential-holding executor that makes this local
reservation mandatory.

The released v1.463.0 milestone closes the missing producer between the
approved flat circuit/schematic handoff and pcbex's existing board placement,
routing, and manufacturing consumers. `generate-circuit-kicad-board` accepts
the exact circuit-spec v2 and generated schematic together with a closed
embedded footprint closure, a closed board-construction profile, and the
existing physical-constraint profile. It creates a new deterministic KiCad
board rather than requiring a caller or GUI to supply a template board.

The footprint closure binds every used library identifier to bounded exact
`.kicad_mod` source bytes and requires the complete circuit pad-number set.
Closure v1 reproduces only a strict circle/oval/rectangular pad subset and
omits source artwork and courtyard data; arbitrary local rules and custom or
trapezoid pads are rejected. The construction profile binds a two-to-32-layer
stackup plus routing and placement defaults. The physical-profile subset is an
empty or full rectangular outline, front-side fixed components at cardinal
rotations without fixed keepout extents, and track/via/zone keepouts without per-keepout routing
overrides. The writer reruns the
circuit-to-schematic gate, places the newly instantiated footprints under the
physical profile, reimports the exact final board, and requires the existing
circuit/schematic/board binding report to be approved. A successful
no-clobber publication contains only `board.kicad_pcb`,
`board-binding.json`, and a path-free `manifest.json` binding every raw and
canonical input plus both retained outputs. Byte identity is asserted for
repeated runs of the same compiled executable on one supported target, not
across platform libm implementations or independently built binaries.

The result is explicitly placed but unrouted. This milestone does not resolve
or authenticate installed footprint libraries, fetch supplier or datasheet
data, merge a hand-edited board, route tracks or add vias/copper zones, run native DRC/DFM,
manufacture, authorize or reserve procurement, place an order, or add
MCP/Action parity. Those operations remain explicit downstream boundaries.

The released v1.464.0 milestone adds a narrow final-BOM evidence boundary and a
separate offline catalog composition. `verify-final-bom` first validates one
manufacturing ZIP through the complete existing package boundary, extracts the
exact manufacturing parts from the supplied KiCad board, and regenerates
`bom.csv` with the same canonical renderer used by `fabricate`. Its closed
`final_bom_source_and_canonical_bom_v1` report identifies the supplied board,
package, manifest, actual package BOM, regenerated canonical BOM, and package
board source; retains at most 256 reference-sorted populated parts; and is
approved only when both BOM bytes and board source identities match. A valid
mismatch retains stable path-free findings before the optional gate fails,
while malformed or unsafe inputs produce no report.

The report's board basename is informational. Approval compares exact board
byte count and SHA-256 with the manifest descriptor and deliberately makes no
claim that the package manifest's recorded input filename equals the supplied
basename. The verifier does not prove electrical circuit/schematic/board
binding, connectivity, placement, routing, DRC/DFM, or manufacturability.

`build-procurement-intent` captures that exact board/package pair together
with one catalog-backed retained circuit-generation bundle and its exact local
snapshot. It fully replays the historical catalog selection, invokes the Rust
final-BOM verifier privately, and requires reference sets, footprints, and
MPNs to match across the final BOM, resolved circuit, and selection. Values
match between the final BOM and resolved circuit because selection records have
no value field. The closed result retains the complete validated Rust report
plus its raw artifact identity. Approval requires complete sets, present and
unambiguous supplier part numbers, and an approved final BOM. It emits
deterministic grouped line items only on complete
approval; any semantic mismatch retains a closed rejected result with no
partial lines. Quantities are populated-reference counts for one board only,
never an assembly, panel, build, or order multiplier.

This adapter starts no network request; the selected pcbex executable is
unauthenticated and unsandboxed, so its independent I/O remains outside that
claim. Retained snapshot replay does not establish current
stock, price, lifecycle, lead time, reservation, supplier/manufacturer
authenticity, datasheet truth, or transport provenance. Both reports are
technical evidence only: they do not authorize procurement, reserve inventory,
submit a cart, place an order, spend funds, or approve fabrication. Their JSON
Schemas are closed structural contracts; runtime validators remain
authoritative for UTF-8 byte and aggregate bounds, duplicate keys, exact source
identities, canonical replay, sorting, and cross-field approval invariants.

The released v1.465.0 milestone adds the parallel exact final-CPL boundary.
`verify-final-cpl` completely validates one retained manufacturing ZIP,
extracts the exact manufacturing-part inventory from the supplied KiCad board,
and regenerates canonical `cpl.csv` bytes with the same production plan and
renderer used by `fabricate`. Its closed
`final_cpl_source_and_canonical_placement_v1` report identifies the board,
package, manifest, actual CPL, regenerated canonical CPL, and package board
source; retains at most 256 reference-sorted in-position parts with exact
integer-nanometre X/Y, milli-degree rotation, and `F`/`B` side; and is approved
only when both the CPL bytes and board-source byte count/SHA-256 match.

The board basename is informational, and the manifest's recorded input name is
not an approval input. A well-formed mismatch retains path-free
`canonical_cpl_mismatch` or `package_board_source_mismatch` evidence before the
optional final gate fails. Malformed or unsafe board/package input is a hard
error with no report. Input capture plus a final stable reread detects an
observed sequential change, but it is not a snapshot transaction: another
process with the same principal can change and restore bytes between checks.

This evidence states exactly what the supplied board and vendor-neutral package
say at this boundary. It does not establish that a circuit, schematic, or other
upstream author chose those coordinates; authenticate the pcbex or KiCad
toolchain; prove connectivity, routing, DRC/DFM, manufacturability, panelization,
or assembly; apply a factory-specific origin, axis, bottom-side, or rotation
transform; drive a feeder/nozzle/machine; contact a vendor; authorize fabrication
or procurement; reserve inventory; submit a package; place an order; or spend
funds. Runtime validation remains authoritative for byte and aggregate limits,
exact identities, canonical rendering, sorting, and approval invariants; the
JSON Schema is a closed structural contract.

The released v1.466.0 milestone adds the standalone
`verify-firmware-build` boundary. It captures `manifest.json` and the seven
fixed firmware-manifest-v2 source artifacts as one exact-eight closure before
starting a child, validates the manifest in memory, recreates only the seven
captured source artifacts in a private workspace, and freshly attempts the fixed
`c_compile`, `c_smoke`, `cpp_compile`,
`cpp_smoke`, `python_compile`, and `python_self_test` checks. The closed
`fresh_firmware_bundle_build_v1` report contains no host paths and records the
captured manifest/source identities, bounded process policy, ordered check
outcomes, an explicit false toolchain-provenance flag, and the approval
decision. A valid build or smoke rejection is published before
`--require-approved` returns nonzero.

The original directory must contain exactly the manifest and seven nonempty
regular, non-symlink artifacts. Ordinary hardlinks remain allowed and
content-bound without inode-uniqueness or link-count enforcement. Malformed,
symbolic-link or junction/name-surrogate-reparse-point, special, missing,
extra, oversized, descriptor-mismatched, or observed-mutated input, output
preflight failure, and cancellation are hard errors with no report. A final exact-eight
reread must still equal the captured bytes before publication. These are
sequential change-detection checkpoints, not an atomic snapshot against a
same-principal path/content change-and-restore race. Unix pinned-directory,
no-follow/nonblocking entry reads promptly reject observed leaf link/FIFO
races; non-Unix retains the adversarial leaf-race and blocking-open denial-of-
service nonclaim. Use a private isolated bundle directory. A change after the
last checkpoint may make the caller path differ from the captured bytes after
publication; the report authenticates the captured snapshot, not later path
state.

This verifier runs caller-selected PATH compilers and interpreter, the C and
C++ programs they build, and the supplied `host.py` self-test. Shell-free argv,
deadlines, output ceilings, private staging, and ordinary managed-process-tree
cleanup are not a sandbox; processes can access host files, credentials, and
networks, and deliberately detached or privilege-escaping descendants are
outside the cleanup claim. Use only a trusted bundle and trusted toolchain, or
put the entire command in a separate OS sandbox. The result does not
authenticate a producer or toolchain, establish provenance or reproducibility,
validate target-MCU behavior or hardware safety, prove cross-compilation, or
compose with the deterministic pipeline, fabrication authorization, MCP, an
Action, procurement, or ordering. Firmware manifest v2 and all pipeline and
fabrication schema versions and serialization contracts remain unchanged.

The released v1.467.0 milestone closes the next per-board composition gap in a
separate Python-only boundary. `build-assembly-evidence` first requires a fresh
base schema-v6 replay of the canonical handoff archive, exact retained
board-binding report, shared raw board, and exact manufacturing ZIP. It then
extracts the exact `generation-bundle.json` entry from that verified archive,
uses it with the supplied historical catalog snapshot to semantically and fully
replay the retained procurement intent, and freshly requires the retained
final-CPL report to reproduce byte-for-byte for the same captured board and
package.

The closed `offline-exact-board-assembly-evidence-v1` result cross-binds the
shared board and package identities, the exact handoff generation entry, the
common package manifest, and the final-BOM/final-CPL package-board-source
identities. The last two must agree with each other; equality to the supplied
board remains each child decision's approval condition so a valid source-
mismatch rejection stays representable. Completion requires positive
board-binding, procurement-intent, and final-CPL decisions. A valid negative
decision is retained before `--require-complete` fails, while malformed,
forged, mismatched, unsafe, mutable, or over-limit evidence produces no result.
The deterministic BOM/CPL reference membership partition is informational and
does not impose an otherwise invalid subset policy. The complete procurement
and nested final-BOM graph is validated during construction, but the retained
outer projections are compact: `final_bom` omits `in_bom_parts`, procurement
omits nested final BOM and its now-non-recomputable original binding digest,
and populated BOM references remain only in membership plus approved
procurement-line references rather than standalone BOM value/type/layer
records. The exact nested final-CPL evidence separately keeps its original
in-position reference and coordinate records. Exact raw procurement identity,
full fresh replay, and the outer binding remain.

This is exact evidence composition, not assembly readiness or authorization.
It does not prove BOM/CPL subset completeness; component polarity; fiducials;
panelization; vendor origin, axis, bottom-side, or rotation transforms; feeder,
nozzle, or machine programming/operation; batch, yield, loss, spare, or order
quantity; current supplier facts; ordering or payment. The adapter itself makes
no network request, authenticates neither pcbex nor KiCad, provides no process
sandbox or producer/tool provenance, takes no atomic multi-input snapshot, and
adds no manifest-filename or firmware claim. All previous handoff,
manufacturing, procurement, final-CPL, pipeline, and firmware schemas remain
unchanged.

The released v1.468.0 milestone adds a narrower Python-only commercial-line
boundary without changing that assembly composition. One normalized local
offer identifies the exact raw retained procurement-intent bytes and supplies
one supplier, half-open validity interval, syntactic currency, and at most 256
strictly supplier-part-number-sorted MPN/SKU/catalog-digest lines. Each line
carries only a quoted quantity and an integer subtotal at a fixed 10^-6
major-currency scale. The boundary captures the exact board, package,
generation bundle, historical snapshot, intent, and offer, then freshly reruns
the complete v1.464 procurement-intent validator before comparing any
commercial line.

Coverage requires an approved replayed intent, exact supplier and line
identity/set agreement, checked per-board multiplication by an explicit
requested board count, sufficient quoted quantities, and an explicit caller
evaluation instant within the declared half-open window. A valid mismatch is
retained before `--require-covered` fails; exact intent-byte misbinding,
malformed/unsafe/aliased/oversized input, failed replay, deadline/cleanup
failure, or observed mutation produces no result. The report keeps exact six-
source identities, the same compact procurement projection used by v1.467,
the complete normalized offer, covered-only line evidence and component
subtotal, stable findings/validation, and a domain-separated binding.

This is offline coverage of a caller assertion, not current or authenticated
supplier evidence. It does not interpret unit prices, rounding, price tiers,
MOQ, order multiples, discounts, shipping, tax, duty, fees, exchange rates,
landed cost, panels, yield, loss, or spares. It provides no trusted time,
supplier/offer/price authenticity, inventory reservation, procurement or
assembly authorization, order readiness, ordering, payment, network side
effect, producer provenance, sandbox, or atomic multi-input snapshot. The
catalog, procurement-intent, and assembly-evidence schemas and serialized-byte
contracts remain unchanged.

The released v1.469.0 milestone adds an explicit network pre-step for the same
closed normalized offer contract. `fetch-supplier-offer` performs exactly one
bounded no-redirect GET against a credential-free absolute HTTPS endpoint,
strictly validates the response as `offline-normalized-supplier-offer-v1`,
requires its supplier and procurement-intent digest to match the caller's
declared expectations, and publishes canonical offer bytes followed by a
separate closed acquisition receipt. The receipt retains the credential-free
endpoint, a domain-separated request digest, the response status, exact
entity-body byte/SHA-256 observations, the local fetch time, and exact
canonical-offer byte/SHA-256 identity.

Production use accepts HTTPS only; an API-only literal-loopback HTTP switch is
reserved for tests. DNS, TCP, platform-default TLS, headers, and entity-body
reads share one monotonic network deadline. Redirects, retries, queries,
fragments, user information, ambiguous framing, non-JSON media, non-identity
content encoding, oversized headers or bodies, malformed offers, supplier or
intent misbinding, exact bearer-token bytes reflected in the entity body or
canonical offer, and unsafe or occupied output paths fail without a valid
receipt. Offer and receipt publication are two
atomic no-clobber operations rather than one transaction, so a canonical offer
remains if the later receipt publication loses a race.

This is bounded acquisition provenance, not an authenticated supplier
statement. The local receipt is unsigned and retains neither the raw response
body nor an HTTP/TLS transcript, certificate chain, signature, or trusted
clock. It cannot prove on replay that the request occurred, authenticate the
supplier, offer, endpoint, transport, price, or time, establish current stock,
reservation, procurement authority, order readiness, ordering, payment, or
spend, or interpret unit prices, tiers, MOQ, shipping, tax, duty, fees,
discounts, exchange rates, or landed cost. v1.468 remains offline and keeps
its exact schemas, serialized bytes, and `adapter_network_performed: false`;
the acquisition receipt's independent network-observation flag is true.

The released v1.470.0 milestone closes both deliberately deferred correlation
gaps in one new offline Python-only boundary. It captures the complete caller
source union once, validates the v1.469 receipt against the exact canonical
offer without contacting the endpoint, freshly validates the full retained
v1.467 assembly result, and freshly validates the full retained v1.468
coverage result from the same privately staged board, manufacturing package,
historical snapshot, procurement intent, and offer. The coverage replay uses
the exact `generation-bundle.json` entry extracted from the validated handoff;
the composer accepts no independent generation path.

The closed `offline-exact-board-assembly-supplier-offer-evidence-v1` result
retains all three complete child objects and exact canonical child-source
identities. It hard-cross-binds the named board, manufacturing package,
handoff generation, snapshot, raw procurement intent, identical compact
procurement projections, normalized offer, receipt request/offer bindings, and
the explicit coverage evaluation timestamp to the receipt's recorded fetch
timestamp. Timestamp equality is untrusted correlation, not a freshness or
clock-authenticity claim. The nested network states remain deliberately
different: assembly and coverage are false, the unsigned receipt observation
is true, and the outer offline composer is false.

Completion is exactly the conjunction of complete assembly evidence and
covered supplier-offer evidence. A valid incomplete assembly child or
not-covered offer remains in the full result before `--require-complete`
fails; a malformed receipt, fresh replay mismatch, cross-binding mismatch,
unsafe/oversized/aliased source, deadline/cleanup failure, or observed
mutation produces no result. One absolute deadline covers capture, both fresh
child validations, cleanup, composition, and final staged/caller union
rereads. The existing v1.467, v1.468, and v1.469 schemas and bytes remain
unchanged.

This is not an authenticated or current quote, landed-cost calculation,
assembly-readiness decision, or procurement workflow. It cannot authenticate
the receipt's historical response/network/TLS/time observations, establish
stock or supplier/offer/price authenticity, reserve inventory, validate
polarity/panel/vendor-machine transforms, multiply technical evidence into a
batch, authorize assembly/fabrication/procurement, order, pay, or spend. Its
caller-selected tools remain unauthenticated and unsandboxed, and sequential
rereads are not an atomic multi-input snapshot.

The released v1.471.0 milestone adds a new Python-orchestrated procurement
authorization boundary over one exact retained v1.470 result. The caller must
provide that result's complete original board, manufacturing package, handoff,
board-binding, historical catalog snapshot, procurement intent, final-CPL,
assembly, normalized offer, acquisition receipt, and coverage closure. Python
freshly validates the retained v1.470 bytes against that entire closure before
and after a separate trusted Rust cryptographic child. The ordinary `--pcbex`
replay child remains distinct, caller-selected, unauthenticated, and
unsandboxed; the `--authorization-pcbex` child is part of the trusted computing
base and emits only an internal cryptographic/policy assessment. Python alone
constructs the public authorization report after the second replay and final
source checks.
After its first replay, Python stages and verifies the cryptographic inputs,
rereads the caller sources, and samples one local evaluation instant. A
bounded post-hook path-stability reread follows before the trusted assessment.
The mandatory second replay is an unchanged-evidence guard, not a new time
assessment: a positive public claim means the exact release satisfied the
submitted policy at the retained assessment instant only.

The optional closed organization-policy field
`procurement_authorization_policy` fixes an exact three-uppercase-letter
currency, a component-lines-only subtotal ceiling, maximum approval duration,
maximum receipt-observation age, quorum of at least two, and 2–100 Ed25519
keys whose identifiers and public keys are disjoint from AI-review,
human-escalation, and fabrication roles. A mandatory externally expected
canonical policy digest pin prevents the unsigned evidence from selecting a
different trust root. The match does not authenticate who selected or
distributed either pack or pin, so policy authenticity remains false unless a
deployment establishes it independently.

Every domain-separated approval binds the exact raw v1.470 identity and outer
binding; complete and covered decisions; supplier/offer identity, currency,
declared half-open window, requested boards, component subtotal, and receipt
observation; policy raw/canonical/ID/revision identity; authorization ID;
64-lowercase-hex challenge; component-subtotal ceiling; inclusive approval
window; signer; decision; reason; and ticket. The complete signed interval must
fit inside the offer interval, including an expiry strictly before the offer's
exclusive end. Distinct trusted approvals must meet the policy quorum without
a submitted valid rejection. Reason and ticket contain non-whitespace text
after trimming, reject NUL, and are bounded at 4,096 and 256 UTF-8 bytes.
Distinct trusted IDs and keys do not prove that different natural people or
operators control them; that separation remains a deployment custody rule.

Incomplete or uncovered upstream evidence, insufficient quorum, a valid
submitted rejection, a local evaluation instant outside either interval, a
future or over-age receipt observation, component subtotal above the signed or
policy ceiling, a signed ceiling above policy, or an overlong signed interval
is retained as a truthful `not_authorized` result before the optional final
gate. Malformed, mixed, unpinned, incorrectly signed, aliased, oversized, or
observably mutated evidence produces no public report. The local time and
receipt-age comparisons are untrusted correlation rather than a trusted
timestamp.

Only the public outer `procurement_authorized` field may be true. Network and
current availability, supplier/offer/price/receipt/policy authenticity,
trusted time, reservation, assembly/fabrication/order readiness, order
placement, payment, machine execution, and one-time challenge use remain
false. The authorization does not establish current stock, landed or invoice
cost, shipping, tax, MOQ, tiers, spend, order acceptance, or any external side
effect. A retained report is an audit snapshot rather than reusable current
authority; the complete verifier must run again at the actual handoff.

The released v1.471.1 maintenance milestone turns the root README back into a
project entry point. It keeps quick-start commands, representative workflows,
configuration, architecture, integration, security, and development guidance
scannable while moving contract discovery into a complete categorized index.
Five task-oriented guides explain installation, workflow selection, component
ownership, integration setup, and trust boundaries without copying the exact
schemas, limits, replay rules, or nonclaims from their authoritative focused
documents. A documentation regression suite bounds README growth, requires the
navigation set, checks every repository-relative Markdown target, and requires
the index to cover every focused Markdown document.

The released v1.472.0 milestone adds local at-most-once admission for one exact
procurement authorization challenge. The public `pcbex-agent` command accepts
the retained v1.471 report, its complete original v1.470 closure, the selected
policy and canonical digest pin, and every approval. It freshly replays that
historical authorization before it builds any reservation marker.

The command requires a pre-created absolute Unix ledger owned by the effective
UID with exact mode `0700`. A fixed closed manifest binds a deployment-supplied
64-lowercase-hex expected ledger ID. The Rust helper pins that directory,
rejects unknown, network, clustered, and FUSE filesystems, rejects overlap with
the replay closure, and installs
`procurement-authorization-reservation-v1-<challenge>.json` without
replacement through the retained directory descriptor.

The compact marker retains authorization ID, challenge, supplier and offer,
requested boards, currency, actual component-line subtotal, signed ceiling,
offer/receipt/authorization timing, approval count, and the exact retained
report byte count, SHA-256, and binding. It copies the report's false
authenticity, currentness, trusted-time, and one-time-use claims. The outer
marker asserts only `local_challenge_reserved:true`; global one-time use,
inventory reservation, order placement, and payment remain false.

Every existing deterministic marker leaf burns the challenge even if its
contents are malformed. Before installation, immediately around installation,
and after file/directory durability, the helper revalidates ledger identity,
source stability, the inclusive authorization interval, the half-open offer
interval, and the receipt-observation age. A post-install error never removes
the marker and reports that the challenge remains reserved. Windows and
unreviewed Unix targets fail closed.

This local ledger is not a supplier idempotency service. A same-UID principal
can still alter ledger state, another ledger or host can admit the same
challenge, and sequential source checks are not an atomic world snapshot. No
network request, inventory hold, landed-cost calculation, cart, order,
payment, or global exactly-once execution is introduced.

The released v1.473.0 milestone removes the flat-symbol restriction without
changing circuit-spec v2. A new opt-in circuit-spec v3 keeps one physical part
per reference and nests one or more explicit symbol units beneath it. Every
logical connection names the reference, unit number, and physical package pin.
The normalizer bounds and sorts that graph, rejects duplicate units and
cross-unit package-pin reuse, and runs the same immutable electrical floor.

The deterministic schematic writer emits unit-specific embedded KiCad symbol
definitions and one instance per `(reference, unit)`. The handoff verifier now
compares exact unit-aware symbol, pin, metadata, label, and net membership.
Real KiCad independently imports the result and exports a native netlist in
which the units merge into one physical component.

Board, BOM, CPL, and manufacturing consumers retain their existing physical
model. They accept v3 only after its validator proves that package pin numbers
are globally unique within each part; the graph can then collapse losslessly
to one footprint per reference. Hierarchical sheets, interchangeable/gated
unit assignment, hidden common pins, alternate De Morgan conversions, and
automatic library-symbol discovery remain outside this closed v3 contract.

The released v1.474.0 milestone adds an opt-in convergence boundary to `route`
and `route-kicad`. It schedules balanced, shortest, via-minimized,
bend-minimized, and alternate-order candidates under stable round/candidate
IDs. Every declared slot receives a deterministic share of one aggregate A*
work ceiling; unused shares are not reassigned, so parallel scheduling cannot
change later opportunity or exceed the declared portfolio budget.

Each completed candidate restores the exact input `Rules` value and passes the
authoritative checker. Only explicit `unrouted` findings are compatible with a
partial candidate. Any other violation remains visible in the report but makes
the candidate ineligible, so a fully routed invalid Board can never outrank a
clean partial Board. Admissible candidates use a fixed unrouted, selection-cost,
length, via, bend, and stable-ID ordering. Only a strict improvement becomes the
next round input; complete routing, stagnation, no admissible candidate, or the
round ceiling stops the loop.

The closed path-free schema-v1 report retains the producing version, options,
canonical byte/SHA-256 identities for the effective input and selected internal
Board models, aggregate allocation, every candidate strategy/status/metric,
duplicate and selection decisions, and the terminal outcome. The CLI requires
an explicit new report path, rejects overlap with routing inputs/outputs, and
publishes the synchronized report without replacement. A valid partial report
and Board are retained before the existing unrouted gate fails.

This milestone does not loosen clearance, width, via, drill, layer, DFM,
keepout, or electrical rules; switch via policy; claim global optimality; bind
raw-source authenticity; run native KiCad DRC; establish manufacturability; or
grant release authority. Omitting `--convergence-report` preserves the existing
single-pass APIs and CLI behavior.

The released v1.475.0 milestone adds a separate fresh consumer for that retained
evidence. `verify-routing-convergence` captures Board JSON, the exact routed
Board, the canonical v1.474 report, and an optional physical profile.
`verify-kicad-routing-convergence` captures the equivalent KiCad board pair,
same-stem or explicit project/custom rules, and exactly one selected DFM,
policy-pack DFM, or physical profile source.

The verifier reconstructs the effective internal Board, reruns the retained
schema-v1 options under the current deterministic implementation, preserves
the retained producer version in the nested report, and requires every typed
field to match. It then regenerates the selected Board JSON or KiCad text and
requires exact routed bytes. The outer closed report binds each raw source by
byte count and SHA-256, retains the full reproduced convergence report, and
domain-separates one binding over the complete result.

Inputs cross regular non-link bounded reads, role-alias rejection, strict
duplicate-key parsing, canonical retained-report comparison, and final exact
rereads. The no-clobber output is reserved before source contents are read. A
freshly reproduced partial or no-candidate outcome remains valid evidence and
is retained before `--require-complete` returns nonzero; malformed, substituted,
or changed evidence produces no report.

This verification snapshot is not an atomic filesystem transaction. It does
not authenticate sources or policy origins, rerun native KiCad DRC, establish
manufacturability or global routing optimality, approve fabrication, or grant
release authority. Those remain focused downstream boundaries.

The v1.476.0 contract milestone is bundled into v1.477.0 rather than published
under a standalone tag. It composes the KiCad half of v1.475 with the existing
fresh manufacturing-package replay. One Python-owned boundary captures
the original board, routed board, retained convergence and v1.475 reports,
retained manufacturing ZIP, optional project/rules, and exactly one built-in
DFM, external DFM, or physical-profile selection. It rejects cross-role aliases
and runs both children under one finite aggregate deadline.

The first private stage invokes `verify-kicad-routing-convergence` and requires
the resulting bytes to equal the retained v1.475 report. The composer strictly
validates its binding, status, false claims, and raw-source projection. When
routing is complete, the already captured routed board and shared sidecars pass
to the v1.455 replay; only a byte-identical freshly generated
`manufacturing.zip` yields `verified_ready`. A valid incomplete routing result
skips fabrication and is retained as `not_ready` before the optional gate.

The closed path-free outer report binds source identities, the routing
projection, the full normalized manufacturing replay when present, validation
flags, and one domain-separated digest. Its sequential capture and rereads do
not form an atomic filesystem snapshot. The selected pcbex and KiCad tools
remain unauthenticated and unsandboxed. Source authenticity, separate native
KiCad DRC evidence, manufacturability, fabrication approval, external
submission, ordering, payment, and release authority remain false or outside
scope.

The released v1.477.0 milestone consumes that complete retained v1.476 report
and one retained normalized native KiCad DRC report. One Python-owned boundary
captures their original routing/manufacturing closure plus the DRC report under
a 724 MiB direct-input ceiling, rejects cross-role aliases, and validates both
retained bindings before starting native work.

The first private stage reruns v1.476 and requires its rendered bytes to equal
the retained report. A valid routing-incomplete decision skips native DRC and
remains `not_ready`. For a ready handoff, the existing Rust
`verify-native-kicad-drc-report` command reruns the fixed KiCad invocation
against the same staged routed board, project, and custom rules. Its compact
summary must match the captured canonical report, whose source identities,
counts, approval decision, and run digest are independently cross-checked.

Only a ready v1.476 handoff plus an approved exact DRC replay yields
`verified_ready` and `native_kicad_drc_verified:true`. A valid DRC rejection is
retained before the optional ready gate. The closed 1 MiB report binds every
direct source, bounded child projections, eight validation flags, at most one
gate failure, and one domain-separated digest. Source/tool authenticity,
manufacturability, fabrication approval, external submission, ordering,
payment, and release authority remain false or outside scope.

The released v1.478.0 milestone consumes the complete v1.477 closure plus one
factory-required deterministic pipeline plan/report and 1–100 signed
fabrication approvals. It captures every plan-selected role and exact firmware
entry before consuming the approval sequence, rejects approval-to-pipeline
aliases, caps the complete union at 1,469 MiB, and requires both closures to
name byte-identical manufacturing packages before invoking selected tools.

After v1.477 reproduces exactly, the explicit trusted Rust fabrication verifier
checks the pipeline, normalized receipt, organization policy, Ed25519
signatures, quorum, and authorization window. Python requires the complete
child report and compact summary to bind the captured sources, exact submitted
approval envelopes, and a caller-supplied expected canonical policy digest.
Only positive routing readiness and fabrication authorization together yield
`release_authorized`; either valid negative is retained before the optional
gate.

The closed 4 MiB report keeps path-free identities, bounded projections, eight
validation flags, stable conjunctive failures, and one domain-separated
binding. Source, tool, policy, factory-receipt, and time authenticity,
manufacturability, external submission, capacity reservation, ordering,
payment, and one-time challenge use remain false. The result is a sequential
point-in-time offline snapshot, not an atomic filesystem transaction or an
external factory action.

The released v1.479.0 milestone adds a separate strict consumer for the v1.478
boundary. It captures the complete v1.478 closure and retained outer
report before selected tools run, resolves the routing pcbex, authorization
pcbex, and KiCad CLI commands to absolute native entrypoints, and requires each
bounded byte stream to equal an independently supplied lowercase SHA-256 pin.
Routing and authorization commands contain exactly one executable; wrapper
arguments are rejected rather than leaving a second script or interpreter
outside the pin set.

The same resolved absolute entrypoints are supplied to the unchanged v1.478
replay. The retained and fresh reports must share a domain-separated digest of
their stable sources, routing projection, approval identities/counts, scope,
pipeline, package, receipt, policy, and policy pin. The fresh verifier samples
a new authorization time; volatile child-report identity, time, decision,
gates, and dependent outer binding are not copied from the historical report.
A custom monotonic-clock callback cannot substitute and later restore
an entrypoint between observation and a process boundary: every such callback
return triggers an exact reread, and all three entrypoints are reread after the
nested replay. A retained positive may therefore become a truthful fresh
negative after expiry. Digest, format, canonical-report, alias, mutation, or
replay-subject mismatch is a hard error
with no outer report; a valid nested authorization negative remains inspectable
before the optional final gate.

The closed path-free schema-v1 report retains the full normalized v1.478
result, the retained report's exact raw identity and shared subject digest,
three fixed role-specific native format/size/observed/expected digest records,
eight validation flags, one stable outer
gate, and a domain-separated binding. A positive decision establishes only
that the verifier observed the selected native entrypoint files matching the
external pins around the point-in-time replay. It does not authenticate who
built or distributed them, attest signatures, libraries, loaders, plugins,
environment or operating-system state, defeat an independently concurrent
same-principal writer, provide a sandbox, prove manufacturability, contact a
factory, reserve capacity, submit files, place an order, or perform payment.

The released v1.480.0 milestone authenticates the exact normalized factory
receipt already selected by that release. A dedicated optional organization
policy role binds each factory ID to one provider and one non-weak Ed25519 key;
the caller must independently pin the policy's canonical SHA-256. The signed
payload covers the manufacturing-package and receipt identities, normalized
receipt projection, raw and canonical policy identities, factory ID,
attestation ID, 64-hex challenge, and bounded validity window.

Rust owns public-evidence validation, hardened private-key access, strict
signature verification, policy matching, and the point-in-time attestation
report. Python captures the complete v1.479 closure, freshly replays its stable
subject before and after the digest-pinned Rust verifier, cross-binds the same
package, receipt, and policy, requires the receipt assessment instant to lie
inside the fabrication-authorization window, and publishes one closed path-free outer report.
An inactive signature or negative v1.479 decision remains inspectable before
the optional final gate; malformed, mismatched, unpinned, invalidly signed,
aliased, changed, or unreplayable evidence produces no outer report.

Only `factory_receipt_authenticity_verified` and the conjunctive outer
`release_authenticated` decision can become true. They authenticate the
configured signing key over the exact normalized receipt—not a legal factory,
TLS session, raw response, trusted clock, current capacity, source or toolchain
provenance, external submission, inventory or capacity reservation, order,
payment, or one-time challenge use. A side-effecting executor remains a later,
separately credentialed and durably idempotent boundary.

The released v1.481.0 milestone consumes one canonical retained v1.480 report
and freshly replays the same time-invariant signed-release subject. A positive
replay must retain the exact manufacturing package, normalized receipt,
policy, signed attestation, and digest-pinned verifier while both the receipt
attestation and fabrication-authorization windows remain active.

The public agent reduces the retained and fresh reports to one closed compact
marker. It binds both report identities and bindings, the stable release
subject, package, receipt, policy, signer, verifier, authorization window, and
signed receipt challenge. A hidden Rust helper accepts that marker only into a
pre-created absolute Unix ledger whose fixed manifest matches an independently
supplied ledger ID. The ledger must be local, owned by the effective user, and
mode `0700`; every replay input stays outside it.

The helper installs the challenge-derived marker name through pinned-directory
durable no-replace publication. It rechecks the manifest, input separation,
marker bytes, and both active windows around commit. An existing destination
burns the challenge in that ledger regardless of its contents.

This is at-most-once admission within one selected local ledger. It does not
prove global challenge uniqueness, trusted time, legal factory identity,
current capacity, external submission, order placement, payment, or exactly
once execution. The bounded adapter call and reconciliation boundary remains
separate.

The released v1.482.0 milestone adds that adapter boundary without weakening the
v1.481 ledger contract. It reads the exact challenge marker through the pinned
ledger, revalidates the bound manufacturing ZIP, derives one deterministic
idempotency key from the ledger, signed release, marker, factory, and package
identities, then durably installs a closed intent before network I/O. The
intent separately binds the nonce and endpoint, so changing either cannot mint
a second key for the same reservation.

Submit performs one bounded no-redirect POST. A completed result is replayed
locally, while an intent without a result blocks retransmission and directs the
operator to reconciliation. GET reconciliation sends only bound request
headers, writes one durable observation per caller-selected reconciliation ID,
and never includes manufacturing ZIP bytes.

The adapter accepts only a duplicate-free closed acknowledgement that echoes
the complete request binding and a bounded accepted, rejected, or pending
status. Transport, response-size, content-type, JSON, credential-reflection,
and binding failures become a retained `outcome_unknown` receipt. Each receipt
binds the local attempt-start instant while keeping trusted time false. The
Bearer credential never enters the intent, receipt, filename, or normal error.

This milestone records a local intent and one adapter observation. It does not
authenticate the endpoint or raw response beyond the host TLS stack, prove
that the server enforced its idempotency key, establish legal factory identity
or capacity, authenticate when the server processed the request, place an
order, authorize payment, or verify globally exactly-once execution. Those
claims stay false in every receipt.

The released v1.483.0 milestone authenticates the application response without
changing a byte of the v1.482 intent, acknowledgement, or receipt contracts.
The adapter opts into one strict RFC 9421 Ed25519 profile and returns an RFC
9530 `Content-Digest`, `Signature-Input`, and `Signature`. The signature covers
the response status, digest, media type, request method and target URI, and all
pcbex request-binding headers, including the reconciliation ID for GET.

An exact organization-policy source and independently supplied canonical digest
pin role-disjoint response keys to one factory and provider. pcbex verifies the
body digest, signer, request context, signature, and bounded validity window,
then durably stores the outer authentication report before the compatible
v1.482 receipt. A crash between those writes is repaired from the authenticated
report without another POST or GET. Missing, duplicated, malformed, expired,
untrusted, reflected-credential, or cryptographically invalid response evidence
becomes a closed negative report with no positive signer or signature claim.

Only application-response authenticity can become true. The local clock is not
a trusted timestamp, the HTTP signature does not authenticate legal identity or
TLS, and server-side idempotency, capacity, order placement, payment, and global
exactly-once execution remain false.

The current v1.484.0 milestone authenticates state history without changing a
byte of the v1.482 intent, acknowledgement, or receipt formats or the v1.483
signature profile. A separate RFC 9421 profile signs response sequence,
predecessor, and semantic state digests together with the client's exact
accepted head. An initial request accepts only generation zero; reconciliation
accepts only an exact replay or one successor linked to the retained digest.

The closed transition verifier distinguishes rollback, same-generation
equivocation, skipped generations, predecessor forks, submission-identity
changes, and mutation after accepted or rejected terminal state. An invalid
transition may remain cryptographically authenticated, but cannot set state
continuity or acceptance. The adapter must return the earliest unseen event so
a new client receives genesis rather than trusting an unprovable recent
snapshot.

Each authenticated observation commits before its sequence-keyed state entry,
and that entry commits before the unchanged compatible receipt. A replay repairs
either later record locally without another POST or GET. Complete chain loading
re-verifies every referenced observation, signature, policy binding, transition,
and no-replace state entry under a fixed 10,000-state ceiling. Terminal heads
make all later reconciliation local.

This is continuity relative to one selected, retained Unix ledger. It does not
prove global non-equivocation or protect against rollback of the ledger itself.
Legal identity, TLS authenticity, trusted time, server-side idempotency,
capacity, order placement, payment, and exactly-once execution remain false.
Transparency receipts, trusted timestamps, transport identity, and actual order
authority remain later independent milestones.
