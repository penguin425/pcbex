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
optional MCP Tasks without changing the plan or report schemas.

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
usable and auditable. Version 1.418 adds MCP parity; composite-Action parity is
planned for v1.419.
