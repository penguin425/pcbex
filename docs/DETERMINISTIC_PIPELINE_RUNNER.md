# Bounded-input deterministic pipeline runner

Version 1.417 adds one side-effect-free orchestration boundary around the
standalone circuit/KiCad board-binding gate and the existing hardware pipeline
gate. The runner consumes only files named by a closed plan, snapshots their
exact bytes, executes both Rust verifiers in process, cross-checks their
canonical schematic and raw board identities, and retains one deterministic
aggregate report.
It does not generate or repair a design, start external tools, call an AI or a
network service, submit a package, or place an order.
Version 1.418 exposes the same boundary through synchronous MCP calls and
optional MCP Tasks without changing the plan or report schemas. Version 1.419
adds the same contract to the root composite GitHub Action as an explicit
opt-in; the CLI, MCP, and Action all retain the same report bytes and decision.

## Commands

Emit the closed plan and report schemas:

```sh
pcbex deterministic-pipeline-plan-schema \
  --output deterministic-pipeline-plan.schema.json
pcbex deterministic-pipeline-report-schema \
  --output deterministic-pipeline-report.schema.json
```

Run a plan and require complete approval after retaining the report:

```sh
pcbex run-deterministic-pipeline pipeline-plan.json \
  --output build/deterministic-pipeline-report.json \
  --require-approved
```

Without `--require-approved`, a well-formed plan produces a report even when an
input identity or downstream gate is rejected. With the flag, the same report
is atomically persisted before the command returns a failing status. Malformed,
oversized, duplicate-key, or path-unsafe plans fail before a report can be
meaningfully constructed. Existing, aliased, or symlinked output destinations
are rejected and never overwritten. The report output must be outside the
firmware bundle directory: that directory is an exact eight-file input contract,
and a report or atomic output reservation inside it would become an unauthorized
ninth entry.

## Closed intent compiler (v1.433.0)

Version 1.433.0 adds a CLI-only compiler from a closed pipeline intent to the
existing digest-bound plan. Emit the compiler's closed intent schema and
compile one intent with explicit role paths:

```sh
pcbex deterministic-pipeline-intent-schema \
  --output deterministic-pipeline-intent.schema.json

pcbex compile-deterministic-pipeline-plan \
  config/pipeline-intent.json \
  --output pipeline-plan.json
```

The intent is a closed object carrying its schema/`require_factory` decision
and one explicit path field per runner role; for example, required fields name
`hardware/circuit-spec-v2.json`, `hardware/controller.kicad_sch`,
`build/electrical-review.json`, `hardware/controller.kicad_pcb`,
`build/analysis-manifest.json`, `build/analysis-checks.json`, `build/quality.json`,
`build/manufacturing.zip`, and `firmware/manifest.json` for this example.
Those role values are portable forward-slash paths resolved from the generated
output plan's canonical parent (the repository root here), not from `config/`,
where the intent lives; the intent may be elsewhere, but every role source must
be a descendant of the output parent. `..` rebasing is rejected by the portable
path contract. Optional role fields are explicit paths or `null`. The intent
contains no model prompt, free-form path list, or implicit role discovery. The
compiler rejects absolute/traversal/link/non-regular paths, stable-reads each
bounded source, and computes the descriptor's exact byte count and lowercase
SHA-256 itself. Caller-provided bytes or digests are not trusted.
The output plan is compact canonical JSON followed by exactly one trailing
newline, in the existing plan-schema-v1 shape, and is published only through
the bounded no-clobber output boundary. The runner's `plan_source_sha256`
binds those raw output bytes (including that newline), while its separate
`plan_sha256` binds the semantic plan object with a domain-separated digest.
This preserves the distinction between exact source bytes and semantic plan
identity.

Compilation performs no LLM call, network request, path discovery, child gate,
design mutation, or manufacturing action. It only materializes authorization
descriptors. `run-deterministic-pipeline` remains the final authority: it
reopens and revalidates the compiled plan, snapshots every authorized source,
runs the existing circuit/KiCad board-binding and `pipeline-verify` gates, and
retains the aggregate report before an optional approval failure. A compiled
plan cannot bypass those checks or manufacture approval. Composite-Action
parity for intent compilation remains later work.

## MCP intent compiler parity (v1.434.0)

The MCP server exposes `compile_deterministic_pipeline_plan` with the same
closed `intent` and `output` arguments. Protocol 2025-11-25 clients may request
an optional Task and use the standard task lifecycle; older negotiated
protocols execute the same operation synchronously. The wrapper rejects a
pre-existing output before it starts the bounded shell-free child, while the
compiler remains authoritative for intent parsing, source paths and limits,
stable reads, alias rejection, and atomic no-clobber publication.

The MCP response never embeds plan or role-source contents. It returns only a
strict identity summary containing schema version plus the intent and retained
plan paths, exact byte counts, and lowercase SHA-256 digests. The child echoes
the five scalar identity fields after publication; the wrapper stable-reads the
current intent and retained plan within their command-specific limits and
matches their exact bytes and digests before trusting the summary. Unknown,
missing, malformed, oversized, changed, or mismatched evidence fails closed.
Task cancellation and expiry terminate the child through the existing bounded
process path; they do not publish or authenticate an incomplete plan.

The MCP tool adds no LLM, network, path discovery, gate, approval, design
mutation, or manufacturing action. `run_deterministic_pipeline` remains a
separate final-authority operation. Composite-Action compiler parity was
deferred through v1.434.0 and is added in v1.435.0 below.

## Composite-Action intent compiler parity (v1.435.0)

The root composite Action accepts `deterministic-pipeline-intent` and
`deterministic-pipeline-plan-output` as an explicit pair. Both values are
workspace-relative paths. The pair is mutually exclusive with the legacy
`deterministic-pipeline-plan` input, and a partially specified pair is invalid;
these argument errors are reported before analysis starts. If both new values
are empty, the Action remains analysis-only. If only the legacy plan is set,
the existing v1.419 runner path is used unchanged.

When the new pair is selected, the Action runs the same bounded shell-free
intent compiler before analysis. The output destination must be a new regular
file under the workspace: an existing file, alias, symlink, special file,
intent/output alias, or unsafe parent is rejected and never overwritten. The
compiler output is canonical plan-schema-v1 JSON with exactly one trailing
newline. Its role paths use portable forward slashes and are resolved from the
canonical parent of the plan-output path, never from the intent's parent. The
intent may live elsewhere, but every required source must be a descendant of
that plan parent; optional roles are explicit paths or `null`, while absolute
paths, `..` rebasing, links, non-regular files, duplicate role paths, and
source changes during compilation fail closed.

After publication, the Action stable-reads both inputs and authenticates the
compiler's exact five-field identity summary: schema version, intent source
bytes, intent source SHA-256, plan source bytes, and plan source SHA-256. The
plan-source identity covers the compact JSON and its final newline. The
effective plan is then passed to the unchanged `run-deterministic-pipeline`
runner. After runner EOF, the Action stable-reads the intent and effective plan
again, requires their identities to remain equal to the compiler metadata, and
requires the retained report's raw plan-source identity to match that same
compiled plan. A post-compilation substitution therefore fails closed before
attribution. The runner remains final authority for revalidation, snapshots,
board binding, pipeline gates, report retention, and optional approval
failure. The Action publishes only metadata, never plan or role-source bodies:

- `deterministic-pipeline-effective-plan`;
- `deterministic-pipeline-intent-source-bytes`;
- `deterministic-pipeline-intent-source-sha256`;
- `deterministic-pipeline-plan-source-bytes`; and
- `deterministic-pipeline-plan-source-sha256`.

The four source-identity outputs are empty outside compiler mode;
`deterministic-pipeline-effective-plan` is the legacy plan path in legacy plan
mode and is empty only in analysis-only mode. The existing runner outputs,
including semantic `deterministic-pipeline-plan-sha256`, keep their previous
meaning. This parity adds no LLM, network, path discovery,
design mutation, gate, approval, or manufacturing behavior; stale, malformed,
changed, or substituted evidence is rejected before attribution.

## Firmware-bundle compiler preflight (v1.436.0)

The intent compiler now performs a bounded structural preflight whenever the
explicit `firmware_manifest` role is present. The plan schema remains v1 and
continues to carry only that one manifest descriptor; the compiler does not
add the seven source artifacts or their hashes to the plan. The descriptor
must name `manifest.json`, and its parent directory must contain exactly the
manifest plus the seven fixed v2 source names. Every entry must be a regular
file with no symlink or special-file component, and no extra, missing, or
unsafe entry is accepted.

The compiler stable-reads the manifest and each fixed source under the
published per-file limits, rejects duplicate/unknown manifest fields and
malformed artifact descriptors, and compares every bounded byte count and
lowercase SHA-256 to the bytes it read. It rescans the directory after those
reads, then compares a second complete bundle snapshot after confirming every
explicit role. Any observed replacement, removal, link, addition, or content
change fails closed. The no-clobber plan publication occurs only after this
exact-eight identity check succeeds.

This check is deliberately narrower than final approval. The compiler does
not run C/C++/Python builds or smoke tests, approve build evidence, bind the
canonical schematic, or perform a pipeline gate; it also makes no LLM,
network, open-ended path-discovery, mutation, or manufacturing call. The deterministic runner
and `pipeline-verify` reopen the original bundle, repeat their own exact-eight
and artifact checks, and remain final authorities for staging, schematic
binding, build evidence, reports, gates, and approval. The historical firmware
generator contract still describes seven source artifacts; “exact eight” here
means that manifest plus those seven sources as one input directory.

## Firmware-bundle gate re-snapshot (v1.437.0)

The runner now hardens the firmware bundle's gate-time substitution window
without changing the plan or manifest contracts. After the initial exact-eight
preflight and private staging, it reopens `manifest.json` and all seven fixed
v2 artifacts immediately before entering the deterministic pipeline gate and
records each entry's complete bytes and SHA-256. When the gate returns, it
reopens the same eight paths and requires an identical complete byte/SHA-256
snapshot. Any added, removed, replaced, or content-mutated entry observed by
those snapshots therefore makes the run rejected; a valid rejected report is
retained before an optional `--require-approved` failure.

Plan schema v1 and firmware manifest v2 remain unchanged, and the runner still
does not execute firmware builds or grant firmware approval. Regular hardlinks
are accepted and remain content-bound by the bytes and SHA-256 read through
each named path. The boundary does not pin inodes or claim to be race-free
against an adversarial filesystem.

## Standalone fresh firmware build verification (v1.466.0)

The separate Rust `verify-firmware-build` command can capture one exact-eight
manifest-v2 bundle and freshly run the fixed C11, C++17, and Python compile and
smoke checks. It emits a new closed path-free report under scope
`fresh_firmware_bundle_build_v1`; a valid negative build outcome is retained
before its optional final approval gate. Unsafe input, observed mutation, and
cancellation produce no report.

This command is not called by the compiler, deterministic runner, pipeline
gate, pipeline replay adapter, circuit/manufacturing composition, or
fabrication authorization. Plan schema v1, deterministic report schema v1,
firmware manifest v2, and the existing pipeline/fabrication serialization
contracts remain unchanged. Consumers that require both evidence sets must run and retain them
separately; neither report upgrades the authority of the other.

Fresh verification executes selected PATH tools, the C/C++ smoke programs they
build, and captured `host.py`. Its shell-free bounded process supervisor is not
a sandbox, so use a trusted private bundle directory and trusted tools or
isolate the entire command separately. It does not establish producer or
toolchain provenance, reproducibility, cross-compilation, target-MCU behavior,
hardware safety, MCP/Action parity, procurement, fabrication authority, or an
order. See [`FIRMWARE_BUILD_VERIFICATION.md`](FIRMWARE_BUILD_VERIFICATION.md).

## Required CI check (v1.438.0)

The repository runs an independent `Deterministic Pipeline` job on every normal
pull request and push. The job compiles a closed intent fixture with the real
Rust `pcbex` binary, then exercises two bounded paths: an accepted circuit,
schematic, board, manufacturing, and firmware-evidence chain, and a semantic
manufacturing rejection. The normal rejected run retains its report. A second
invocation uses `--require-approved`; it exits nonzero only after retaining and
authenticating a separate rejected report, so the failure cannot erase the
evidence from the first run.

The manufacturing archive used here is a deterministic synthetic gate fixture,
not a replay of KiCad Gerber generation. Real KiCad fabrication export remains
the responsibility of the separate `KiCad E2E` check.

Before accepting either result, the fixture checks the compiler's exact intent
and plan byte/SHA-256 identities and requires the runner report's raw plan
binding to match the compiled plan. The job exposes only bounded scalar
identities, counts, and decisions in the GitHub Job Summary, and uploads the
retained reports as scanned artifacts. It does not embed full report bodies in
workflow metadata.

Version 1.456.0 additionally replays both retained accepted and rejected
reports through the Python adapter and the just-built real Rust binary. The CI
marker requires each replay to be verified and byte-identical, preserves the
opposite `approved` decisions, and checks the retained report SHA-256 against
the fixture summary. It also fixes the v1 replay scope and all six completed
validation flags. The accepted replay exercises the optional post-result
`--require-approved` gate. This is validation inside the existing repository
job, not a new composite-Action surface. The Windows fixture explicitly selects
the runner-provided GNU `gcc` and `g++` names because the Unix defaults `cc` and
`c++` are not portable executable names.

This check keeps plan schema v1 and deterministic report schema v1. The plan
schema's portable-path pattern and shared runtime validator now also reject
the Windows console device stems `CONIN$` and `CONOUT$`, matching the private
cross-platform staging boundary without changing the schema version.
The firmware phase validates the exact manifest and seven source-artifact
evidence; it does not replay the build commands recorded by that manifest. The
workflow performs no path discovery, LLM/network call, design mutation, factory
submission, or order. Its successful conclusion is a status check for the latest
commit and may be selected by branch protection. Confirm a successful run on the
latest commit before adding the `Deterministic Pipeline` context to `main`; the
release audit verifies that the context is required and pinned to the GitHub
Actions app (`app_id: 15368`). A pull-request-controlled workflow is not an
authorization boundary against a malicious write collaborator; repository
permissions and protected-branch policy remain required.

## Exact retained-report replay (v1.456.0)

Version 1.456.0 adds a standalone Python API and CLI around the existing Rust
runner:

```sh
pcbex-agent replay-deterministic-pipeline \
  pipeline-plan.json build/deterministic-pipeline-report.json \
  --pcbex target/release/pcbex \
  > deterministic-pipeline-replay.json
pcbex-agent deterministic-pipeline-replay-result-schema \
  --output deterministic-pipeline-replay.schema.json
```

`replay_deterministic_pipeline` stable-captures the exact plan and retained
report, every source selected by the plan's fixed 16-role contract, and the
seven fixed firmware siblings. It reconstructs the authorized relative tree
in one private workspace without rewriting the plan, then directly invokes the
caller-selected pcbex command to run the existing
`run-deterministic-pipeline` authority. Flattening role paths or regenerating a
plan would change the raw `plan_source_sha256`, semantic `plan_sha256`, evidence
paths, and final `run_sha256`, so neither is permitted.

The safe private closure is intentionally narrower than every report Rust can
retain. Each present descriptor must name a nonempty regular file whose bytes
and SHA-256 match the plan, and the firmware directory must contain exactly its
manifest and seven fixed artifacts. Rejected replay therefore covers failures
from the downstream binding or pipeline gates after that boundary. Reports
whose rejection was caused by a missing, linked, empty, oversized,
digest-mismatched, or inexact firmware input cannot be reconstructed by this
adapter and fail before child execution.

The child report is read only from a private destination and must equal the
retained bytes exactly, including the one canonical trailing LF. Success then
requires final byte-for-byte rereads of every staged source and every
caller-visible plan, report, role, and firmware source. The fresh report body,
role contents, filesystem paths, and child output are not returned. Instead,
the adapter emits a closed path-free schema-v1 result with verification scope
`deterministic-pipeline-fresh-replay-v1` and exact plan/report identities.
The adapter independently recomputes the plan-v1 and run-v1 domain hashes,
requires canonical bounded failure ordering and approval relationships, and
accepts only a bounded SemVer engine string before returning it. It also
validates the complete closed Rust report-v1 shape: the nested board binding,
KiCad handoff, electrical reviews, pipeline identities, fixed phases, evidence,
counts, decisions, and every integer bound are checked without relying on
Python's Boolean/float-compatible equality.

The result contains only `schema_version`, `verification_scope`, `verified`,
the retained `engine_version`, a `plan` object, a `report` object, aggregate
`inputs`, and completed `validation` flags. `plan` retains the raw source
byte/SHA-256 identity, semantic `plan_sha256`, and `factory_required` decision.
`report` retains the retained/fresh byte/SHA-256 identities, `run_sha256`,
`approved`, bounded `failure_count`, and `identical: true`. `inputs` records
only the captured count, aggregate bytes, and a domain-separated digest over
the fixed role/path/byte/SHA identities. The validation object contains six
constant-true fields: `plan_captured_before_replay`,
`inputs_captured_before_replay`, `fresh_report_reproduced`,
`retained_report_identical`, `staged_inputs_unchanged`, and
`caller_inputs_unchanged`; it contains no copied path or diagnostic text.

Replay verification and pipeline approval remain separate decisions. Exact
reproduction of a rejected report may return `verified: true` with
`approved: false`; verification must not be interpreted as approval. The
caller-selected pcbex executable is unauthenticated and unsandboxed, and exact
equality normally requires the producer-compatible engine because the retained
engine version participates in the report and run identity.

The CLI's optional `--require-approved` gate is evaluated only after the exact
result has been printed. It can therefore fail the command for a reproduced
rejection without turning that truthful rejected report into a replay failure
or suppressing its path-free identity evidence. The Python API always returns
the reproduced approval decision and leaves policy enforcement to its caller.

One aggregate deadline starts before capture. Before invoking the runner, up
to 30 seconds (or half the remaining time) is reserved and split evenly: one
half caps process-tree termination, direct-child reaping, and pipe-worker
joins; the other remains for report validation, rereads, and private-workspace
cleanup. A final deadline check prevents success after expiry, while ordinary
synchronous filesystem calls retain the documented non-preemptible limitation.

This adapter invokes no circuit, KiCad, manufacturing-package, or firmware
producer. It does not run KiCad or `fabricate`, rebuild firmware, re-fetch a
factory response, make an AI/supplier/network/factory request, change the Rust
plan/report or pipeline schemas, add MCP or Action integration, submit a
package, or authorize deployment, procurement, fabrication, or ordering.

## Circuit/manufacturing composition (v1.458.0)

The handoff replay can reuse the standalone adapter internally when both
`--deterministic-pipeline-plan` and `--deterministic-pipeline-report` accompany
the complete v6 board/manufacturing input set. It captures the plan, retained
report, every selected role, and the exact-eight firmware bundle before any
producer runs, then invokes the deterministic runner only after the archive,
board-binding report, and manufacturing ZIP have reproduced exactly.

The v7 result cross-binds raw circuit/schematic/board/package bytes, the
effective policy identity, the complete canonical nested board-binding report,
and the pipeline's canonical schematic/raw-board identities to those earlier
stages. A reproduced downstream rejection remains `verified: true` with
`approved: false`; supplied review and filename failures are evidence under
test. For `approved: true`, the composition independently requires a strict
review match and matching manufacturing board basename. The optional approval
flag fails after exact replay rather than changing the decision.

The composition passes absolute subdeadlines into the captured manufacturing
and pipeline helpers instead of starting new clocks. A final union reread
covers every earlier and pipeline caller source and rechecks firmware-directory
membership. The standalone API/CLI/schema and the Rust plan/report schemas are
unchanged. This new surface has no MCP or Composite Action parity and adds no
fresh producer, firmware build, network/factory call, or fabrication authority.

## Fabrication release authorization (v1.459.0 CLI / v1.460.0 MCP / v1.461.0 Action)

The standalone Rust CLI can now use a stricter subset of runner evidence as an
offline authorization prerequisite. The plan must explicitly select an
`analysis_policy_pack`, set `require_factory: true`, and select a factory
receipt. pcbex reruns the plan in-process, requires a byte-identical retained
report with `approved: true`, and additionally requires pipeline schema v2 plus
exactly one passing `factory-dfm` phase. Human approval cannot make a rejected
runner report eligible.

The authorization layer then reopens and independently validates the exact
manufacturing ZIP, factory receipt, and organization policy pack whose
identities appear in the fresh report. It signs the raw plan/report identities,
semantic plan/run identities, package and receipt identities, normalized
provider/endpoint and opaque quote digest, raw/canonical pack identities, and
the bounded fabrication scope. The authorization layer final-rereads the plan,
retained report, ZIP, receipt, pack, and submitted approvals and rechecks the
output against the same in-memory replayed plan before publication; the
verification clock is sampled only after those source rereads.

This is a separate schema-v1 approval/report family. It does not add fields or
phases to deterministic plan v1, deterministic report v1, pipeline v1/v2,
factory receipt v1, or the Python handoff result v7. Valid policy rejection,
quorum shortage, or temporal failure remains a `not_authorized` authorization
report; invalid signatures or mixed evidence are operational errors. See
[`FABRICATION_AUTHORIZATION.md`](FABRICATION_AUTHORIZATION.md) for the dedicated
key policy, commands, bounds, and non-claims.

Version 1.460 exposes only fresh authorization verification as the optional-
Task MCP tool `verify_fabrication_authorization`. It routes the original plan,
retained pipeline report, ZIP, receipt, policy pack, and approvals through the
same CLI verifier and samples no caller-provided time. The complete report is
retained at a new no-clobber output path; a compact summary is accepted only
after its exact byte count, SHA-256, decision, scope, and evidence identities
match a stable read of that output. Signing and private-key access remain
CLI-only. Version 1.461 routes the same fresh verifier through a standalone
boardless composite Action, retains one fixed bounded report, and applies
`require-authorized` only after optional artifact upload. It does not change
the runner, add a pipeline phase, contact a fabrication API, submit to a
factory, place an order, or add a payment boundary. The Action may still
download its toolchain and upload the retained GitHub artifact. See
[`FABRICATION_AUTHORIZATION_ACTION.md`](FABRICATION_AUTHORIZATION_ACTION.md).

## MCP parity

The MCP server exposes `run_deterministic_pipeline` with the same explicit
`plan`, `output`, and optional `require_approved` arguments. Protocol
2025-11-25 clients may request optional Tasks and use the normal `tasks/get`,
`tasks/result`, `tasks/list`, and `tasks/cancel` methods; older negotiated
protocols execute the same tool synchronously.

A runner report may approach 128 MiB while one MCP request or response is
limited to 16 MiB. The tool therefore retains the complete report only at the
authorized `output` and returns a compact `report_summary` containing
`schema_version`, `approved`, `plan_sha256`, `run_sha256`, `failure_count`,
`report_bytes`, and `report_sha256`. The MCP bridge stable-reads the retained
regular file within the runner limit and verifies its exact byte count,
SHA-256, decision, failure count, and plan/run identities against a compact
child-process echo. Unknown or malformed summary fields, a changed file, or a
digest mismatch produce no trusted summary. With `require_approved: true`, a
rejected run returns `isError: true` only after the full report has been
atomically retained and its summary verified.

The MCP wrapper adds no discovery, mutation, network, AI, factory submission,
or ordering behavior. Existing output paths are rejected before execution,
and the runner's stronger alias, symlink, firmware-directory, and no-clobber
checks remain authoritative.

## Composite Action parity

The root composite Action keeps the runner disabled unless either
`deterministic-pipeline-plan` names a legacy plan file or the paired
`deterministic-pipeline-intent` and `deterministic-pipeline-plan-output`
inputs compile an effective plan through the v1.435 boundary above. Leaving
all three inputs empty preserves the ordinary analysis-only Action behavior. Set
`deterministic-pipeline-require-approved: "true"` to make the final Action
step fail when the retained runner report is not approved; the default
`"false"` publishes a valid rejected report and completes the Action so a
caller can inspect it.

When enabled, the Action always reserves the fixed no-clobber destination
`${output-dir}/deterministic-pipeline-report.json`. It invokes the same
bounded runner with the selected effective plan and publishes that complete report and
the following seven verified outputs:

- `deterministic-pipeline-schema-version`;
- `deterministic-pipeline-approved`;
- `deterministic-pipeline-plan-sha256`;
- `deterministic-pipeline-run-sha256`;
- `deterministic-pipeline-failure-count`;
- `deterministic-pipeline-report-bytes`; and
- `deterministic-pipeline-report-sha256`.

The outputs are derived from the retained report only after its byte count,
SHA-256, plan/run identities, failure count, schema version, and approval
decision have been revalidated. A rejected valid report is therefore retained
and exposed before a required-approval failure; stale, aliased, symlinked,
malformed, or digest-mismatched output is never attributed to the Action.

The v1.419 runner integration by itself adds no implicit file discovery,
design mutation, repair, AI/network/factory call, package submission, or
ordering behavior. The
plan's closed relative-path descriptors, firmware eight-file contract, staged
basenames, per-input limits, aggregate limits, cross-binding checks, and
no-clobber output rules remain authoritative.

## AI approval binding

Version 1.424 lets AI review request schema v2 cover one exact approved runner
execution. The binding records the raw plan byte/SHA identity, normalized
`plan_sha256`, retained report byte/SHA identity, `run_sha256`, and the exact
generated schematic bytes. It does not record filesystem paths.

Preparation, signing, single-approval verification, and quorum verification
all parse and execute the plan again. The retained report must equal the fresh
compact serialization plus its final newline byte-for-byte, and both the
runner's schematic input evidence and nested circuit handoff must equal the
separately supplied generated schematic. The schematic is also imported and
must equal the request's reviewed semantic document. Final bounded rereads of
the schematic, raw plan, and retained report detect changes during validation.
The AI request's raw electrical review digest and recomputed review must also
match the plan and handoff. This rejects a fabricated report and any cross-run
mixture of otherwise valid artifacts.

The complete request/CLI/Action/MCP contract is documented in
[AI review artifact binding](AI_REVIEW_ARTIFACT_BINDING.md).

## Closed input plan

The schema-v1 plan has no implicit file discovery. It contains
`schema_version`, `require_factory`, and these descriptor fields:

- `circuit_spec`, `schematic`, `electrical_review`, `board`,
  `analysis_manifest`, `analysis_checks`, `quality`,
  `manufacturing_package`, and `firmware_manifest`;
- optional `electrical_policy`, `analysis_project`, `analysis_rules`,
  `analysis_dfm_profile`, `analysis_policy_pack`,
  `analysis_physical_profile`, and `factory_receipt` fields, each explicitly
  set to either a descriptor or `null`.

Every descriptor is a closed object:

```json
{
  "path": "hardware/controller.kicad_sch",
  "bytes": 18432,
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

Paths are portable forward-slash relative paths resolved from the plan's real
parent directory. Absolute paths, empty components, `.`/`..`, backslashes,
symlinks, non-regular files, and duplicate role paths fail closed. The declared
byte count and lowercase SHA-256 must match a stable double-read snapshot before
any gate that consumes that input runs. Plans are limited to 4 MiB, the
aggregate staged input set to 512 MiB, and the retained report to just under
128 MiB; each role also keeps the stricter limit of its underlying verifier.

For wire compatibility, schema-v1 keeps `analysis_dfm_profile` under the
shared `analysis_descriptor` definition and its published 64 MiB maximum.
The compiler and runner apply an additional 4 MiB runtime preflight when that
role is actually read; this tightening is not represented as a new `$defs`
entry or schema version. The embedded DFM object inside an organization
policy pack remains on the policy-pack loading/validation path and is not
treated as an external profile file by this preflight. When the analysis
manifest selects an external or built-in DFM profile, the in-process pipeline
gate additionally requires the exact matching schema-v3 manufacturing
binding. Policy-pack DFM keeps its existing analysis-only behavior; plan and
runner-report schemas remain v1.

The firmware descriptor must name `manifest.json`. Its original directory must
contain exactly that manifest and the seven v2 source artifacts—no extra file,
directory, or link is accepted. The runner validates this original directory
before copying the same eight snapshots into an isolated private stage. It also
preserves the exact board basename required by the manufacturing manifest and
the exact physical-profile basename required by its source binding. Role-owned
staging directories prevent unrelated equal basenames from colliding.

## Aggregate verification

After each gate's own required identities match, the runner independently
performs:

1. `verify_circuit_kicad_board_binding` over the staged circuit-spec v2,
   KiCad schematic, board, and selected electrical policy;
2. the existing `pipeline-verify` v1 or factory-bound v2 gate over the staged
   review, analysis, quality, manufacturing, firmware, and optional factory
   evidence, with its diagnostics kept within the published schema bounds; and
3. explicit cross-binding of the board-binding report's canonical imported
   schematic SHA-256 and raw board-source SHA-256 to the corresponding
   identities recomputed by the pipeline gate.

The closed aggregate report retains sorted input evidence, the nested
board-binding and pipeline reports when they could be computed, deterministic
bounded failure messages, the final `approved` decision, and domain-separated
canonical `plan_sha256` and `run_sha256` identities. Approval requires every
declared input identity, both gates, and both cross-bindings to pass. A failure
in one independently runnable gate does
not erase evidence from the other.

The runner does not add a phase to `pipeline-verify` and does not change its
schema-v1 or factory-bound schema-v2 reports. Those reports remain independently
usable and auditable. Version 1.418 adds MCP parity, and version 1.419 adds
root composite-Action parity without changing the runner plan or report
schemas.
