# Native KiCad PCB DRC evidence

`native-kicad-pcb-drc-evidence` is a standalone, deterministic evidence
boundary for KiCad's native PCB design-rules checker. It turns one exact
`.kicad_pcb` input and the result of a fixed, `drc.v1`-compatible KiCad
invocation into a bounded normalized JSON report that can be authenticated and
reproduced in CI. Real KiCad 10 E2E covers byte-identical reruns; KiCad 9's
schema shape (which omits `ignored_checks`) has a dedicated compatibility test.
The boundary is available in release `v1.429.0` through the Rust CLI, the MCP
server, the focused composite Action, and an opt-in path in the root Action.

## Scope

The gate is intentionally narrow:

- stage the board, optional project, and optional custom rules file in a
  private temporary directory;
- run native `kicad-cli pcb drc` with a fixed JSON invocation;
- normalize the report into stable categories and integer-nanometre positions;
- retain source, companion, run, and normalized-report identities;
- make a zero-error/zero-warning decision and retain rejected evidence before
  an optional required-approval failure.

It does not edit a board, refill zones, save a board, repair findings, or
discover manufacturing policy. It does not automatically connect native
`drc.rpt`, the existing `pcbex` internal DRC, native schematic ERC, AI review,
the deterministic pipeline, or manufacturing export. Those are separate
boundaries that can consume this evidence in a later integration.

## CLI

Print the closed report schema:

```sh
pcbex native-kicad-drc-report-schema \
  --output build/native-kicad-drc.schema.json
```

Run native DRC and retain the normalized report. The output must be new; an
existing file, symlink, or path alias is refused.

```sh
pcbex run-native-kicad-drc hardware/controller.kicad_pcb \
  --output build/native-kicad-drc.json \
  --require-approved
```

Companion files are optional. When `--project` or `--rules-file` is omitted,
the runner may discover a same-stem `.kicad_pro` or `.kicad_dru` beside the
board. Discovery is only used for the exact same-stem companion; the selected
file is snapshotted and its bytes/SHA-256 are bound to the report. Explicit
paths use the same regular-file, link-safe, size-bounded snapshot boundary:

```sh
pcbex run-native-kicad-drc hardware/controller.kicad_pcb \
  --project hardware/controller.kicad_pro \
  --rules-file hardware/controller.kicad_dru \
  --kicad-cli kicad-cli \
  --output build/native-kicad-drc.json
```

`--require-approved` changes only the outer process result after the report has
been written. A valid report is retained even when the gate rejects it. The
child KiCad invocation exits `0` for a clean report and `5` when findings are
present; the runner validates that relationship and then returns successfully
with either valid report when `--require-approved` is absent. Malformed,
inconsistent, timed-out, or otherwise unsafe evidence exits with a non-native
error. `--require-approved` maps a valid non-approved report to a command
failure after publication.

## Fixed native invocation

The child is started directly, without a shell, using the equivalent of:

```text
kicad-cli pcb drc \
  --format json \
  --units mm \
  --severity-error --severity-warning \
  --exit-code-violations \
  --output drc.json input.kicad_pcb
```

The four disabled policy switches (`all_track_errors`, `schematic_parity`,
`refill_zones`, and `save_board`) are represented by their omission from this
fixed argument vector; they are not passed as ad-hoc boolean values.

The report records this invocation as:

```json
{
  "command": "pcb drc",
  "format": "json",
  "units": "mm",
  "severities": ["error", "warning"],
  "exit_code_violations": true,
  "all_track_errors": false,
  "schematic_parity": false,
  "refill_zones": false,
  "save_board": false
}
```

KiCad's date, absolute source/report paths, and generated finding UUIDs are
volatile and are not part of the canonical report. The runner rejects a
report whose status, counts, or invocation cannot be reconciled with the
child result.

## Normalized report

The closed JSON object has these top-level fields:

```json
{
  "schema_version": 1,
  "engine": "pcbex",
  "engine_version": "...",
  "kicad_version": "...",
  "source": {"bytes": 1234, "sha256": "..."},
  "project": null,
  "rules_file": null,
  "invocation": {"command": "pcb drc", "format": "json", "units": "mm",
    "severities": ["error", "warning"], "exit_code_violations": true,
    "all_track_errors": false, "schematic_parity": false,
    "refill_zones": false, "save_board": false},
  "ignored_checks": [],
  "findings": [],
  "violation_count": 0,
  "unconnected_item_count": 0,
  "schematic_parity_count": 0,
  "error_count": 0,
  "warning_count": 0,
  "approved": true,
  "run_sha256": "..."
}
```

`project` and `rules_file` are either `null` or an exact companion identity
`{"bytes": number, "sha256": "lowercase-hex"}`. The closed category vocabulary
reserves `violation`, `unconnected-item`, and `schematic-parity`. The fixed v1
invocation disables schematic parity, so accepted v1 evidence contains only
the first two categories and requires `schematic_parity_count == 0`. Every item
contains only a description and an integer nanometre position:

```json
{
  "category": "violation",
  "description": "Clearance violation",
  "severity": "error",
  "type": "clearance",
  "items": [
    {"description": "U1 pad 1", "position_nm": {"x": 12500000, "y": 8000000}}
  ]
}
```

The exact normalized bytes have a SHA-256 identity in the retained evidence
metadata and Action/MCP outputs. KiCad's raw JSON is validated in private
staging and then discarded; only the normalized report is retained. Raw dates,
paths, and UUIDs cannot influence the normalized bytes or `run_sha256`.
Re-running the same inputs with a deterministic KiCad build produces
byte-identical normalized evidence; the KiCad 10 E2E checks this directly.

Approval is strict: `error_count == 0` **and** `warning_count == 0` are both
required. Ignored checks remain visible in `ignored_checks`; they are evidence
only and do not by themselves fail v1, so review them explicitly.

## MCP

The MCP server exposes the same runner as `run_native_kicad_drc`. Its arguments
are the CLI inputs expressed as JSON (`input`, `output`, optional `project`,
optional `rules_file`, `kicad_cli`, and `require_approved`). The subprocess
bridge returns a compact, digest-bound summary rather than embedding the full
report in the MCP frame. The server reopens the retained report, recomputes
its canonical bytes and source/companion identities, and rejects stale,
linked, malformed, aliased, or digest-mismatched evidence. Optional MCP Tasks
use the same allow-list and cancellation/resource limits as the existing
bounded tools.

## GitHub Actions

For a board-focused repository, the focused Action can be used directly. It
requires a board and keeps its output under an empty,
literal, caller-relative directory:

```yaml
- id: native-drc
  uses: penguin425/pcbex/actions/native-kicad-drc@v1.429.0
  with:
    board: hardware/controller.kicad_pcb
    # project: hardware/controller.kicad_pro
    # rules-file: hardware/controller.kicad_dru
    require-approved: "true"
```

The focused Action also accepts `kicad-cli`, `output-dir`, `upload-artifact`,
`artifact-name`, and `retention-days`. A valid run retains
`${output-dir}/native-kicad-drc.json` and publishes the verified report path,
schema-version metadata,
approval/count, ignored-check, board/project/rules/report byte/SHA, and run
SHA outputs (the focused names are `schema-version`, `approved`,
`violation-count`, `unconnected-item-count`, `schematic-parity-count`,
`error-count`, `warning-count`, `ignored-check-count`, source byte/SHA pairs,
`run-sha256`, `report-bytes`, and `report-sha256`, along with `status` and
`artifact-dir`). When artifact upload is enabled, a rejected but valid run is
uploaded and summarized before the final `always()` approval gate fails;
upload can be explicitly disabled without changing report validation.
The output directory is scanned for bounded regular files before upload;
literal path components cannot become artifact globs.

The root `penguin425/pcbex` Action keeps its existing required `board` input.
Set `native-kicad-drc-enabled: "true"` to opt into the same evidence gate, and
use `native-kicad-drc-kicad-cli` and `native-kicad-drc-require-approved` for the
corresponding controls. Requiring approval while leaving the gate disabled is
rejected as a configuration error. The root Action does not infer approval
from its internal DRC or from any other pipeline phase.

## Reproducibility and security contract

The runner snapshots all authorized inputs before starting KiCad, uses a
private fixed-basename staging directory, and performs a fresh bounded read
before publication. The CLI/MCP input boundary requires bounded regular files,
rejects symlinks and aliases, and refuses an existing or aliased output. It
does not impose a workspace-relative rule on CLI paths. The focused Action
confines board/companion inputs to caller-workspace-relative regular files;
the root Action retains its existing board-path semantics, including absolute
paths. The focused Action requires portable literal output
components. The root Action preserves spaces in its existing relative
output-directory contract while rejecting artifact-glob syntax before any
output is written or uploaded.
KiCad is invoked without a
shell under the shared process-tree supervisor with fixed timeout,
stdout/stderr, raw-report, finding, item, and aggregate resource limits.
The 32 MiB raw-report limit is enforced when the trusted KiCad child exits and
the report is read; it is not a filesystem quota against an untrusted
executable. Atomic publication happens only after canonical validation;
rejected reports are preserved, but malformed or unsafe evidence is never
accepted as a report.

The hashes establish reproducibility and artifact identity, not trust in the
KiCad executable or in the board's design intent. CI must pin or otherwise
trust the KiCad binary and Action revision, review project/rules provenance,
and treat `ignored_checks` as an explicit review input. Native DRC also does
not prove electrical correctness, firmware behavior, manufacturability, or
AI review quality. Those claims require the separate ERC, internal DRC,
simulation, manufacturing, and approval boundaries.
