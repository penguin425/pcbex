# pcbex

[![CI](https://github.com/penguin425/pcbex/actions/workflows/ci.yml/badge.svg)](https://github.com/penguin425/pcbex/actions/workflows/ci.yml)

`pcbex` is a deterministic PCB physical-design engine written in Rust. The
current implementation routes placed multilayer boards from a small, stable JSON
model. It uses integer nanometre coordinates and multi-layer A* with eight-way
movement, bend/via/congestion/proximity costs, clearance-inflated obstacles,
route simplification, Steiner-style multi-terminal branching, and SVG
inspection output.
An optional native KiCad PCB DRC evidence gate is exposed separately; it
normalizes the `drc.v1` JSON shapes used by KiCad 9 and 10 (with real KiCad 10
E2E coverage) but does not replace internal DRC, repair boards, or imply
electrical, manufacturing, or AI approval.

The core crate keeps geometry, checking, placement, schema/migration, and
routing-quality analysis in separate modules. Stable root-level re-exports
preserve the public API while keeping format contracts and reporting logic out
of the routing engine.
Normal DRC requires positive board width and height even when invoked directly,
matching the router's geometry precondition.
The configured routing grid must also be positive so direct DRC callers receive
the same early diagnostic as the router.
Base routing rules require a positive track width and via drill, non-negative
clearance, and a via diameter larger than the drill in both DRC and routing.
The copper-layer table must also be non-empty, duplicate-free, and limited to
the supported front, back, and first 30 internal copper layers.
Every net terminal must reference a non-empty, duplicate-free subset of that
declared copper stackup before connectivity checks or routing consume it.
Rectangular, round, capsule, polygon, and keepout obstacles must each reference
a non-empty, duplicate-free subset of that declared copper stackup.
When those objects carry optional net ownership, the identifier must resolve to
the board net table.
Rectangular obstacles must use strictly ordered minimum and maximum coordinates
on both axes so they always describe positive-area geometry.
Round and capsule obstacles must likewise have strictly positive diameters in
both direct DRC and Router construction.
Polygon obstacles must be simple, non-degenerate polygons before routing or
clearance checks consume their edges.
Keepouts additionally require at least one prohibition or local rule, positive
minimum track widths, and non-negative minimum clearances.
When an explicit board outline is supplied, it must be a simple,
non-degenerate polygon; an empty outline retains the rectangular fallback.
Every board cutout must likewise be a simple, non-degenerate polygon before
boundary and copper-edge checks consume it.
Valid cutouts must additionally keep every vertex inside the effective board
outline, including the rectangular fallback.
Explicit board-outline vertices must remain within the declared board width
and height, matching the router's coordinate-domain precondition.

The requirement-by-requirement evidence is recorded in
[`docs/COMPLETION_AUDIT.md`](docs/COMPLETION_AUDIT.md).

## Run

```sh
cargo run -p pcbex -- route examples/simple.json \
  --output simple.routed.json --svg simple.svg
cargo run -p pcbex -- check simple.routed.json
```

Generate completion definitions for Bash, Zsh, Fish, Elvish, or PowerShell:

```sh
pcbex completion bash > ~/.local/share/bash-completion/completions/pcbex
pcbex completion zsh > "${fpath[1]}/_pcbex"
pcbex completion fish > ~/.config/fish/completions/pcbex.fish
```

By default `route` fails when any net cannot be routed, making it suitable for
CI. Pass `--allow-unrouted` to retain a partial result. Every completed route is
checked internally for full copper-graph connectivity, orphan copper, supported
angles, track/via dimensions, board boundaries, obstacle clearance, and
cross-net copper clearance. These checks use integer geometry predicates,
including exact collinear overlap, endpoint contact, and clearance-boundary
comparisons without floating-point rounding.

Routes already present in the JSON input are preserved and reserved while only
missing nets are routed. Running the router again on its output is therefore
idempotent.

New and selectively rerouted tracks pass through a deterministic post-router
optimizer. It replaces contiguous detours with direct horizontal, vertical, or
45-degree segments only when the complete board remains clean; imported locked
routes are never rewritten.

Repair checker violations without disturbing clean routes:

```sh
pcbex repair board.json --output repaired.json
pcbex repair board.json --output repaired.json --net-id 12 --net-id 15
```

With no explicit IDs, `repair` selects the nets named by the internal checker.
Selected tracks are ripped up and rerouted; every other route is locked and
verified byte-for-byte, and owned zones survive the replacement.

For nets with three or more terminals, the router chooses a central root and
repeatedly connects the cheapest remaining terminal to any point in the routed
tree. This avoids the input-order-dependent detours of terminal-to-terminal
chain routing.

When a net cannot be routed, the failed A* search records which committed nets
blocked its frontier. Only those conflicting routes are ripped up and retried,
with the failed net ordered first; unrelated and imported locked routes remain
in place. The route report separates preserved, newly routed, rerouted, and
unrouted nets and includes the number of rip-up events.

For interactive repair, `shove_route` applies a grid-aligned offset only to a
route's interior vertices, vias, teardrops, and zones while keeping terminal
anchors fixed. The edit is atomic: boundary, angle, clearance, connectivity,
and every other board check must pass or the original route is restored.
During autorouting, a failed net now tries one- and two-grid local shoves of
only the generated routes identified as blockers before escalating to rip-up.
Each combined shove-and-route candidate is accepted only after full-board
checking, and `RouteReport.shove_events` records successful recoveries.

## JSON model

All coordinates and dimensions use integer nanometres. Layers are `F.Cu` and
`B.Cu`. An optional ordered `outline` defines a simple, concave or convex board
polygon; an empty outline uses the width/height rectangle. `keepouts` use exact
polygons and layer sets, with independent `tracks_not_allowed`,
`vias_not_allowed`, and `zones_not_allowed` flags. KiCad Rule Area
`tracks`/`vias`/`copperpour` restrictions map to those flags without collapsing
selective areas into a blanket prohibition. `footprints_not_allowed` is also
imported, while JSON Rule Areas may set local `minimum_track_width_nm` and
`minimum_clearance_nm`; nets whose class cannot satisfy those local dimensions
route around the area and existing copper/footprints receive dedicated DRC
violations. Legacy `obstacles` remain
axis-aligned rectangles. Copper envelopes are expanded by width/via radius plus clearance.
Terminals declare the layers on which they may be reached. See
[`examples/simple.json`](examples/simple.json).

Board documents use `schema_version: 2`. Inputs without a version are migrated
from the legacy shape before strict deserialization; unsupported versions and
unknown top-level fields are rejected. Inspect the current JSON Schema or
upgrade a file with:

```sh
pcbex schema --output board-v2.schema.json
pcbex migrate old-board.json --output board-v2.json
```

The Rust CLI reads generic inputs through a shared 128 MiB, regular-file-only
boundary and publishes generic outputs with per-file atomic replacement.
Symlink path components are rejected. Purpose-specific pipeline, firmware, and
factory limits may be smaller; see
[`docs/CLI_IO_LIMITS.md`](docs/CLI_IO_LIMITS.md) for exact subprocess and MCP
limits as well as the explicit sandbox exclusions.
The Python agent applies a separate 32 MiB generic-file boundary, permits
128 MiB KiCad repair candidates, rejects symlink/reparse paths, atomically
publishes its outputs, and gives provider, pcbex, and KiCad children fixed
input/output, deadline, and process-tree controls; see
[`docs/PYTHON_AGENT_LIMITS.md`](docs/PYTHON_AGENT_LIMITS.md).

Optional `net_classes` define per-class track width, clearance, via dimensions,
and allowed layers. Assign a class by setting a net's `class` field. Routing and
internal rule checking both apply the class; unspecified nets use board defaults.

## Native KiCad schematic ERC

Run KiCad's deterministic schematic ERC and retain a normalized report for CI
or AI approval. Omitting a warning policy preserves the error-only report v1:

```sh
pcbex run-native-kicad-erc hardware/generated.kicad_sch \
  --output build/native-kicad-erc.json --require-approved
pcbex native-kicad-erc-report-schema \
  --output build/native-kicad-erc.schema.json

pcbex run-native-kicad-erc hardware/generated.kicad_sch \
  --warning-policy examples/native-kicad-warning-policy.json \
  --output build/native-kicad-erc-warning.json --require-approved
```

The runner uses a private staged input with no `.kicad_pro` sidecar, bounds
KiCad and report I/O, refuses output overwrite/symlinks, and retains a
rejected report before `--require-approved` fails. Report v1 gates errors only.
The opt-in report v2 retains errors and warnings, denies unlisted warning types
and ignored checks, and applies closed global/per-type budgets; errors remain
unwaivable. Error-only evidence maps to AI request/binding/native identity
v3/v2/v1, while warning-policy evidence maps to v4/v3/v2. Older flows remain
compatible. See
[`docs/NATIVE_KICAD_ERC.md`](docs/NATIVE_KICAD_ERC.md).

Version 1.428.0 adds a focused public composite Action for schematic-only
repositories. It does not accept or analyze a board and does not enable AI
review or a deterministic pipeline plan. Install a trusted KiCad CLI on the
runner, then select error-only report v1 by omitting `warning-policy`, or the
closed warning-policy report v2 by supplying it:

```yaml
- id: native-erc
  uses: penguin425/pcbex/actions/native-kicad-erc@v1.428.0
  with:
    schematic: hardware/controller.kicad_sch
    require-approved: "true"
    # warning-policy: hardware/native-kicad-warning-policy.json
```

The root `penguin425/pcbex` Action remains board-required and keeps its
v1.427.0 native ERC inputs and outputs unchanged. In the focused Action, a
valid report is retained at the fixed
`${output-dir}/native-kicad-erc.json` path. The Action publishes rejection
evidence to a bounded artifact and the Job Summary before the final `always()`
gate fails for an unapproved report. Fatal, malformed, stale, aliased, or
digest-mismatched evidence fails closed. Its twelve root-compatible
`native-kicad-erc-*` outputs expose the report path, schema/approval/count
fields, warning-policy identities, run identity, and report byte/SHA
identities; warning-policy fields are empty for report v1. Neither Action
automatically populates the separate `ai-review-*` retained-report flow.

## Native KiCad PCB DRC evidence

Release v1.430.0 adds fresh replay for the standalone, canonical and
digest-bound native KiCad PCB DRC evidence gate introduced in v1.429.0. It
runs `drc.v1`-compatible KiCad in private staging, strips volatile dates,
paths, and generated UUIDs, and canonicalizes findings to integer nanometres.
CI proves byte-identical generation and retained-report replay with real
KiCad 10.
Approval requires both native error and warning counts to be zero; rejected
reports are retained before an optional required-approval failure. Optional
same-stem `.kicad_pro` and `.kicad_dru` companions are auto-discovered when
not supplied, and explicit `--project`/`--rules-file` paths are bound by the
same snapshot and digest rules. See
[`docs/NATIVE_KICAD_DRC.md`](docs/NATIVE_KICAD_DRC.md) for the closed schema,
reproducibility, and security contract.

```sh
pcbex native-kicad-drc-report-schema \
  --output build/native-kicad-drc.schema.json
pcbex run-native-kicad-drc hardware/controller.kicad_pcb \
  --output build/native-kicad-drc.json --require-approved
pcbex verify-native-kicad-drc-report \
  hardware/controller.kicad_pcb build/native-kicad-drc.json \
  --require-approved
```

The focused Action can be used without enabling the root hardware-analysis
flow:

```yaml
- id: native-drc
  uses: penguin425/pcbex/actions/native-kicad-drc@v1.431.0
  with:
    board: hardware/controller.kicad_pcb
    # project: hardware/controller.kicad_pro
    # rules-file: hardware/controller.kicad_dru
    require-approved: "true"
```

To re-verify a report restored from an earlier job or trusted artifact, use
the same focused Action in verify mode. It reruns KiCad and publishes a newly
authenticated no-clobber copy under the new output directory:

```yaml
- id: replay-native-drc
  uses: penguin425/pcbex/actions/native-kicad-drc@v1.431.0
  with:
    mode: verify
    board: hardware/controller.kicad_pcb
    report: retained/native-kicad-drc.json
    output-dir: build/native-drc-replay
    require-approved: "true"
```

The root Action keeps its required board contract and native PCB DRC remains
opt-in; set `native-kicad-drc-enabled: "true"` when using its corresponding
DRC inputs. Unsafe artifact-glob output paths fail during preflight while
ordinary relative paths, including spaces, remain supported. This evidence
boundary does not automatically connect `drc.rpt`, the existing internal DRC,
native ERC, AI approval, or manufacturing/pipeline phases.
The root Action remains run-only; retained-report replay is exposed by the
focused Action and MCP tool.

Release v1.431.0 hardens cancellation for native KiCad MCP Tasks.
`run_native_kicad_drc` and `run_native_kicad_erc` now execute their Rust
runners directly in the MCP worker for synchronous and Task calls. Task calls
also pass cancellation to the bounded supervisor. On Unix, cancelling a Task
terminates the KiCad process-group leader and all descendants together;
publication stays atomic and waits for complete, validated report bytes, so an
interrupted run never exposes an incomplete report. The MCP response contract,
CLI commands, and composite Actions retain their existing external contracts;
this release changes the MCP implementation path.

## KiCad boards

Route a placed KiCad board with a closed, straight-segment `Edge.Cuts` outline:

```sh
cargo run -p pcbex -- route-kicad examples/simple.kicad_pcb \
  --output simple.routed.kicad_pcb --svg simple.kicad.svg \
  --json-output simple.ipc-routes.json
```

When a sibling `.kicad_pro` file exists, `route-kicad` imports its modern
net-class dimensions and exact net assignments automatically. Use
`--project path/to/board.kicad_pro` when the project has a different basename.
Numeric net IDs and scalar net names in a `.kicad_pcb` must be present and
valid; malformed declarations, duplicate IDs, and duplicate names are rejected
instead of silently dropping or overwriting a declaration or retaining
ambiguous nets. Except for KiCad's reserved `net 0 ""` entry, net names must
also be non-blank; reserved net 0 must retain its exact empty name.
Connected pads must reference a declared nonzero net ID; stale references are
rejected instead of silently discarding the terminal and connection request.
When a pad contains a net record, its ID must also be a valid non-negative
integer, its name must be scalar, and the ID/name pair must match the board
declaration. The record must not be repeated; malformed, duplicate, or
contradictory records are rejected instead of treating the pad as unconnected or
attaching it to a differently named net.
Board segments, routed arcs, and vias with a nonzero net ID must likewise
reference a declared net; stale routed copper is rejected instead of creating
an ownerless route candidate.
Project net-class dimensions must be non-negative and fit the signed nanometer
range; oversized values are rejected instead of saturating at the integer limit.
Legacy net classes embedded in `.kicad_pcb` files follow the same finite,
non-negative, signed-nanometer range contract; `trace_width` and `via_drill`
must be positive, `via_dia` must be greater than `via_drill`, and an optional
`diff_pair_width` must be positive while a zero `diff_pair_gap` remains valid.
Their names must be present as scalar values, non-blank, and unique, and their
descriptions must be scalar values (an empty description remains valid). All
following values must be setting lists, and each supported dimension setting
must contain exactly one finite scalar value and appear at most once. Missing,
malformed, blank, duplicate, trailing, or stray scalar values are rejected
instead of being ignored, retaining an unusable class, or silently selecting
the first or last value.
Legacy `add_net` assignments must contain exactly one non-blank scalar name for
a nonzero net present in the board; malformed, trailing, stale, blank, reserved,
or misspelled references are rejected instead of being silently ignored. Each
net may appear only once and belong to only one embedded class; duplicate or
conflicting assignments are rejected instead of silently overwriting or
repeating the assignment.
Project settings are applied atomically, so an invalid class, pattern, or exact
assignment cannot leave new classes or partial net assignments behind.
Exact project assignments must use a non-blank name for a net present in the
board and reference a non-blank class; blank, stale, or misspelled targets and
blank class references are rejected instead of being silently ignored.
Each project `classes` entry must have a non-blank, unique name; blank or
duplicate definitions are rejected instead of retaining an unusable class or
silently selecting the last one. Project track widths and via drills must be
positive, and each via diameter must be greater than its drill; zero or
physically inconsistent dimensions are rejected before any project settings
are applied. Differential-pair widths must likewise be positive, while a zero
gap remains valid. Optional project minimum and maximum track lengths must also
be positive when present, and the minimum must not exceed the maximum.
Ordered `netclass_patterns` support hierarchical names, `*`/`?` wildcards, and
regular expressions; patterns and their class references must be non-blank,
exactly repeated patterns are rejected, and exact assignments retain
precedence. A sibling
`.kicad_dru` is also discovered automatically. NetClass-conditioned clearance,
track/via/hole dimensions, differential gap, and length constraints are applied
to routing; use `--rules-file` to select another rules file. Custom-rule
dimensions in either mm or mil must also fit the signed nanometer range.
Effective custom-rule track widths and hole sizes must be positive, while zero
clearance and differential gap remain valid. After all applicable rules are
combined, each modified via diameter must be greater than its hole size.
Custom-rule minimum and maximum length bounds must be positive when present,
at least one supported bound is required, and the minimum must not exceed the
maximum. A custom constraint may specify each supported `min`, `max`, or `opt`
value at most once; repeated values are rejected instead of silently selecting
the first, and each value must contain exactly one dimension. Custom-rule
types supported by pcbex may each appear only once within a rule, while later
rules may deliberately override earlier rules. Every custom constraint must
name one non-blank scalar type; missing, blank, or structured type fields and
extra scalar values are rejected. Each rule may contain at most one `condition`;
repeated conditions are rejected instead of silently selecting the first. A
custom rule must contain one scalar name; missing or structured names are
rejected, blank names are invalid, and extra scalar values are not permitted. A
condition field must contain one scalar expression and no extra expressions. A
blank condition is rejected. A recognized NetClass condition must close its
quoted class name and end immediately afterward; the class name must be
present, quoted, and non-blank,
and trailing condition fragments are rejected rather than partially applied.
Only direct `A.NetClass` or `B.NetClass` selectors using the `==` operator are
interpreted; malformed direct operators are rejected, while compound conditions
remain KiCad's authority. Custom-rule application is atomic, so an invalid later
constraint or unknown net class cannot leave earlier rule updates partially
applied.

[`examples/nonrect.kicad_pcb`](examples/nonrect.kicad_pcb) demonstrates a
five-sided outline that routes and passes KiCad DRC.
[`examples/keepout.kicad_pcb`](examples/keepout.kicad_pcb) exercises a
polygonal copper keepout and an embedded net class. CI routes all three example
boards twice with KiCad 10, requires zero DRC violations, checks that the second
pass is byte-for-byte idempotent, and retains routed boards and DRC reports as
workflow artifacts.

The importer reads polygonal board outlines and copper keepouts without reducing
them to bounding boxes, plus pad positions (including footprint rotation).
Circular pads retain their exact copper envelope instead of being expanded to
their bounding rectangles. Oval pads are represented as rotated capsule shapes
and use exact segment-to-capsule clearance. Rotated rectangular pads retain
their four copper corners as polygons. The importer also reads
copper layers, net assignments, legacy board-embedded net classes, existing
segments and vias.
Line, rectangle, and three-point arc primitives on `Edge.Cuts` are joined into a
polygonal outline; arcs use a maximum chord deviation of 0.01 mm.
All three arc points must be distinct before circle fitting, so repeated
endpoints or midpoints are rejected as malformed rather than merely collinear.
Arc sampling is capped at 16,384 segments per primitive before allocation,
matching the resource bounds applied to circles and cubic curves.
Arc collinearity is classified with exact integer geometry; extreme noncollinear
inputs that lose precision during circle fitting report a separate error.
Intermediate arc samples must remain within the signed nanometer coordinate
range, preventing saturated points from distorting a bulging arc.
Circle primitives use the same chord-deviation bound and can define either the
outer board outline or an inner cutout. Their complete radius must fit within
the signed nanometer coordinate range, preventing saturated samples from
distorting circles near a coordinate limit.
Cubic curve primitives are adaptively subdivided to the same deviation bound.
They must contain exactly four finite `xy` points before subdivision.
Polygon primitives preserve their exact vertices and can likewise define an
outer outline or cutout, with at most 16,384 input points per primitive.
Apart from an optional closing point equal to the first, every polygon vertex
must be distinct so a single primitive cannot create a branched contour.
An imported board may contain at most 65,536 generated `Edge.Cuts` segments in
total across all supported primitives.
Every generated edge passes a shared zero-length check before insertion, so new
or adaptively sampled primitives cannot introduce collapsed contour segments.
Line, rectangle, circle, and arc coordinates must be finite before conversion
to nanometers, matching the validation applied to polygons and cubic curves.
All supported Edge.Cuts coordinates must also fit the signed nanometer range;
oversized finite values are rejected instead of saturating at integer limits.
Board-level line, rectangle, circle, and arc points reject trailing values
instead of silently ignoring malformed coordinate-list elements.
Polygon and cubic-curve `xy` entries likewise contain exactly two coordinates,
so every supported outline point has strict arity.
Board-level Edge.Cuts primitives reject repeated `start`, `mid`, `end`, or
`center` fields instead of selecting the first ambiguous value.
Polygon and cubic-curve primitives also require a single `pts` list, rejecting
ambiguous duplicate point collections.
Each Edge.Cuts primitive must declare exactly one `layer` field, preventing
ambiguous mixed-layer graphics from being treated as board outlines.
That field must contain only the `Edge.Cuts` layer value; trailing values are
rejected rather than ignored.
Additional closed contours inside the largest outline are imported as board
cutouts and excluded from routing with the same copper-to-edge clearance.
Geometry invariants run as property tests in the normal Rust suite. Dedicated
libFuzzer targets exercise arbitrary KiCad input, migrated/serialized board
models, constrained multi-section length tuning, and grid/ring BGA escape.
Criterion benchmarks cover obstacle, multi-net, and board-cutout routing
scenarios. Every pull request also enforces deterministic search and
rasterization operation budgets; see `docs/BENCHMARKS.md`.
The generated summary in `docs/COMPLETION_AUDIT.md` is kept current with
`python3 scripts/update-completion-audit.py`; CI rejects stale versions or test
totals.
Fully connected existing nets are preserved as locked routes; incomplete copper
remains an obstacle and is not mistaken for a completed route. Generated tracks
and through vias are appended at board level without duplicating locked routes,
while preserving the source document.
The route model also preserves KiCad three-point copper arcs and can emit
native pad/via teardrop zones from explicit polygon geometry.
New via-to-track junctions automatically receive tapered teardrop polygons
when sufficient straight length is available. Each candidate is accepted only
after complete-board clearance checking and generation is idempotent.
Arc length is calculated from the circumcircle and sweep angle. Connectivity,
clearance, and boundary checks use a conservative adaptive curve envelope with
1 µm maximum chord deviation, and SVG output renders the complete curve.
Matched two-terminal differential pairs use a simultaneous A* search that
evaluates both track positions for every move. The resulting pair is accepted
only when connectivity, clearance, skew, and coupling checks pass; more general
terminal arrangements retain the independently routed fallback.
Net-owned polygonal copper zones can be supplied in route JSON and are emitted
as native KiCad zones with clearance and minimum-thickness settings. Both
unfilled outlines and filled zone polygons are imported as owned copper.
The internal zone filler rasterizes conservative grid cells, removes clearance
conflicts, creates cross-shaped pad thermal reliefs, and discards islands not
connected to the owning net before exporting explicit filled polygons.
Use `--drc` to run `kicad-cli pcb drc` on the result when KiCad is installed.
After DRC passes, generate an isolated manufacturing package from the
metadata-complete multilayer example. It includes all declared copper layers,
paste/mask/silkscreen, Excellon drill data, deterministic BOM/CPL CSV, a
SHA-256 manifest, and a reproducible ZIP:

```sh
cargo run -p pcbex -- route-kicad examples/multilayer.kicad_pcb \
  --output multilayer.routed.kicad_pcb --drc
cargo run -p pcbex -- fabricate multilayer.routed.kicad_pcb \
  --output-dir manufacturing
```

Source boards are not modified, and pre-existing output file contents are not
read or included in the package. See [the manufacturing package
contract](docs/MANUFACTURING_PACKAGE.md) for metadata validation and the
vendor-neutral CPL coordinate convention. Manufacturing staging, normalization,
ZIP creation, factory repair, and publication share finite file-count, depth,
per-file, aggregate-workspace, archive, and portable-name quotas.

Submit that exact archive to a deployment-owned JLCPCB, PCBWay, or generic
quote/DFM adapter without putting credentials in argv:

```sh
export PCBEX_FACTORY_TOKEN=replace-with-secret
pcbex factory-submit manufacturing/manufacturing.zip \
  --provider jlcpcb \
  --endpoint https://factory-gateway.example/v1/quote \
  --bearer-token-env PCBEX_FACTORY_TOKEN \
  --output factory-receipt.json \
  --require-dfm-pass
```

The connector accepts no redirects, verifies every manifest-listed artifact,
bounds compressed/expanded upload and response sizes, and writes a hash-bound
normalized receipt without the token. Receipt publication is atomic and the
path must not already exist. See [the factory connector
contract](docs/FACTORY_CONNECTOR.md) for the adapter request and response
boundary.

Run a bounded feedback loop only with a trusted, deployment-owned repair
wrapper:

```sh
pcbex factory-feedback-loop manufacturing/manufacturing.zip \
  --provider jlcpcb \
  --endpoint https://factory-gateway.example/v1/quote \
  --bearer-token-env PCBEX_FACTORY_TOKEN \
  --repair-command /opt/pcbex/bin/repair-dfm-package \
  --max-attempts 4 \
  --output factory-loop.json \
  --final-receipt factory-final-receipt.json \
  --final-package manufacturing-final.zip
```

The loop allows at most four submissions in 900 seconds and gives its direct
repair child at most 600 seconds. It revalidates a complete manifest ZIP with
BOM/CPL/DRC/drill and Gerber-job-bound copper, profile, mask, and legend layers
before every submission, keeps the last structurally valid package as a
fallback, and retains a report for submission or repair failures after the
initial package validates; a transport failure can leave no final receipt. The
wrapper runs without a shell in a private temporary area with a cleared caller
environment and only documented platform/process variables, but it is trusted
code: pcbex does not provide a full sandbox for the wrapper or its descendants.
It must write a complete, valid manifest ZIP, not a partial patch. Provider
acceptance must be explicit, and responses reflecting the Bearer token are
rejected. Loop outputs are atomic, refuse overwrite and symlink components,
and must be distinct from the input. Report `passed` describes DFM only; CLI
success additionally requires publication of every requested artifact. A
copied final ZIP does not update a downstream pipeline manifest. Rebuild the
pipeline manifest against the exact selected ZIP. For production, require the
receipt-bound factory phase as well:

```sh
pcbex pipeline-verify \
  --schematic design.kicad_sch \
  --electrical-review build/electrical-review.json \
  --board multilayer.routed.kicad_pcb \
  --analysis-manifest build/analysis/run.json \
  --analysis-checks build/analysis/checks.json \
  --quality build/analysis/quality.json \
  --manufacturing-package manufacturing-final.zip \
  --firmware-manifest build/firmware/manifest.json \
  --factory-receipt factory-final-receipt.json \
  --require-factory \
  --output build/pipeline-gate.json
```

The gate recomputes electrical approval from the exact schematic and policy,
cross-checks analysis and routing evidence against the exact board, performs
the complete manufacturing ZIP validation, and verifies every firmware source
digest plus successful C11/C++17 compile/link and smoke evidence and the
Python compile/self-test. A source-only `--skip-build` bundle is rejected.
With `--factory-receipt`, it also validates the strict normalized
receipt against the same ZIP bytes and SHA-256; `--require-factory` makes a
missing receipt a retained failure. Production jobs should use both flags.
The factory phase performs no network submission or response re-fetch, and
unknown DFM severities continue to fail closed. When `run.json` declares
project settings, custom rules, an external DFM profile, or a policy pack,
authorize each source with the matching `--analysis-*` option; embedded
descriptor paths are never opened. The gate writes a no-clobber digest
manifest even when a phase is rejected. See [the hardware pipeline gate
contract](docs/PIPELINE_GATE.md).

For local-only compatibility, omit both factory options. That retains the
v1 report (`pcbex-hardware-v1`) and its exact five phases. Supplying a receipt
alone enables the v2 report (`pcbex-hardware-v2`) and verifies that receipt;
`--require-factory` alone enables v2 and records a retained failure when the
receipt is absent. `pcbex pipeline-schema` prints the v1 schema, while
`pcbex pipeline-schema --factory` prints the closed v2 schema.

Generate a canonical-schematic-bound firmware bundle with strict C11, C++17,
and Python build/smoke evidence:

```sh
mkdir -p build
pcbex generate-firmware design.kicad_sch --mcu-reference U1 \
  --output-dir build/firmware
```

The bundle contains exactly seven source artifacts and a closed v2 manifest; a
`--skip-build` source-only bundle is intentionally rejected by
`pipeline-verify`. See the [firmware generator contract](docs/FIRMWARE_GENERATOR.md)
for the staging, subprocess, and no-overwrite boundaries.

## Component placement

The placement engine combines graph-clustered initialization with deterministic
simulated annealing. Its score covers weighted HPWL, overlap area, board
boundary overflow, coarse routing congestion, and declarative constraints.
Graph-clustered initialization uses saturating spacing and cursor arithmetic
for extreme board grids and component dimensions.
Untrusted KiCad coordinates and physical dimensions are checked before these
derived internal operations; saturation here is not an input-normalization
policy for malformed, non-finite, or out-of-range source values.
Annealing moves also multiply grid steps and update coordinates with saturating
arithmetic before clamping each component to the board.
Placement HPWL scoring widens both coordinate differences and their Manhattan
sum, including connections spanning the full signed coordinate range.
Board-boundary scoring likewise widens negative and positive overflow distances
before aggregating courtyard penalties.
`near` placement constraints widen Manhattan distance and allowed-distance
subtraction before calculating their excess penalty.
Decoupling anchor-to-power-pin distance uses the same full-range-safe excess
calculation before applying its board-side penalty.
Board-edge constraints widen left, right, top, and bottom distances before
subtracting the permitted edge offset.
`keep_together` constraints widen both point-cloud spans and their sum before
subtracting the permitted group span.
Axis-aligned component bounds use saturating half-dimension offsets at the
signed board-coordinate limits.
Custom courtyard transforms saturate back-side mirroring and rotated center
offsets at the same coordinate limits.
Placement pin coordinates also saturate board-side mirroring, right-angle
rotation negation, and center-offset addition.
Region constraints widen all four component-to-region overflow distances before
aggregating their placement penalty.
Placement overlap scoring widens rectangle intersection widths and heights
before calculating their area.
Final placement grid snapping widens rounding arithmetic and stays on a
representable grid multiple at coordinate limits.
BGA escape-via grid snapping uses exact integer rounding beyond floating-point
precision and at signed coordinate limits.
BGA escape-group centroids widen terminal-coordinate sums before averaging.
BGA escape direction selection widens centroid differences before comparing
axis distances.
BGA escape candidate coordinates widen ring-distance products and saturate
directional offsets at signed coordinate limits.
BGA escape stub shape detection widens endpoint differences before comparing
axis distances.
KiCad board extents and origin-relative coordinates widen endpoint differences
and saturate them at signed coordinate limits.
KiCad courtyard width and height derivation also saturates full-range coordinate
spans before creating placement components.
KiCad placement fallback bounds saturate pad-relative differences, half-size
offsets, and final component spans.
KiCad placement and copper writers saturate board-origin translation at signed
coordinate limits.
KiCad track-segment obstacle envelopes saturate half-width expansion at signed
coordinate limits.
KiCad route-arc obstacle envelopes saturate half-width expansion at signed
coordinate limits.
KiCad via obstacle envelopes saturate half-diameter expansion at signed
coordinate limits.
KiCad oval-pad capsule endpoints saturate rotated center offsets at signed
coordinate limits.
KiCad generated pad-polygon vertices saturate rotated center offsets at signed
coordinate limits.
KiCad custom-pad primitive vertices saturate rotated center offsets at signed
coordinate limits.
KiCad board-cutout containment checks handle polygons spanning signed coordinate
limits without overflowing intermediate edge differences.
KiCad Edge.Cuts contour ordering and zero-area validation use wide signed area
accumulation across the full coordinate range.
KiCad Edge.Cuts arc fitting uses start-relative coordinates so small arcs remain
stable near signed coordinate limits.
KiCad Edge.Cuts arcs retain an intermediate sample even when their radius is
smaller than the chord tolerance.
KiCad three-point Edge.Cuts arc sampling preserves the declared midpoint for
asymmetric sweeps.
KiCad board-cutout containment uses exact wide-integer ray crossings, including
points one nanometer from signed coordinate limits.
KiCad Edge.Cuts primitives are assembled through an endpoint index, keeping
large unordered and mixed-direction outlines linear in the number of segments.
Every Edge.Cuts contour vertex must join exactly two primitives, so branched or
touching contours are rejected instead of being folded into ambiguous outlines.
Cutout edges are checked exactly against the outer contour, preventing an
all-vertices-inside cutout from crossing outside a concave board outline.
Non-adjacent edges within every Edge.Cuts contour are also checked exactly, so
asymmetric self-intersections cannot pass merely because their area is nonzero.
Edge.Cuts polygon primitives reject self-intersections during parsing, before
their invalid edges enter contour assembly. They also require nonzero exact
wide-integer area, so collinear polygons cannot enter contour assembly.
Multiple Edge.Cuts cutouts must be disjoint and unnested because the board model
represents a flat set of holes rather than alternating material islands.
Edge.Cuts line primitives must declare both endpoints; malformed lines are
rejected instead of being silently omitted from the imported board outline.
Their endpoints must also be distinct, preventing zero-length primitives from
entering contour assembly.
Edge.Cuts rectangle primitives likewise require both opposite corners, so an
incomplete rectangle cannot disappear from the imported board geometry.
Those corners must span nonzero width and height, rejecting collapsed
rectangles before contour assembly.
Duplicate Edge.Cuts edges are detected independent of direction across line,
arc, and rectangle primitives without changing linear contour-import scaling.

```sh
cargo run -p pcbex -- place examples/placement.json \
  --output placement.result.json --iterations 20000
```

Components may be fixed, moved on the placement grid, swapped, or rotated by 90
degrees. Supported constraints are `near`, `board_edge`, and `keep_together`.
KiCad footprints can be optimized and written back without reformatting the
rest of the board:

```sh
cargo run -p pcbex -- place-kicad input.kicad_pcb \
  --output placed.kicad_pcb --json-output placement.result.json
```

Footprints marked `locked` remain fixed. Pad nets become weighted placement
connections, and `Reference`, position, rotation, and the board origin survive
the KiCad round trip.

Generate several deterministic trade-off candidates in parallel:

```sh
pcbex place-candidates examples/placement.json \
  --output-dir placement-candidates --candidates 10 --workers 4

pcbex place-kicad-candidates input.kicad_pcb \
  --output-dir kicad-candidates --candidates 10 --workers 4
```

Candidates cycle through balanced, wirelength, routability, constraint, and
legalization objectives with distinct reproducible seeds. `candidates.json`
records every objective, seed, weight set, raw score, base-weight comparison
score, Pareto membership, and the deterministically selected candidate.
Per-candidate JSON files and `selected.json` are emitted alongside the manifest;
KiCad mode also writes each candidate board and `selected.kicad_pcb`. Candidate
generation accepts 1–32 candidates and 1–8 workers. Worker count does not change
candidate geometry, scores, Pareto membership, or selection.

## Multilayer routing

Boards may declare `F.Cu`, `In1.Cu` through `In30.Cu`, and `B.Cu` in
`copper_layers`. The KiCad importer reads the board layer table, wildcard
through-hole pads span every copper layer, and generated through vias connect
the full stack. Net-class layer restrictions continue to constrain which
layers the router may use.

## Differential-pair rules

JSON boards may declare `differential_pairs` with positive/negative net IDs,
nominal gap, gap tolerance, maximum skew, and minimum coupled percentage.
Normal DRC rejects negative geometry constraints and coupled percentages above
100 before evaluating routed pair geometry.
The checker reports skew, layer/via asymmetry, and insufficient coupling.
KiCad net classes containing `diff_pair_width` and `diff_pair_gap` automatically
pair `_P`/`_N` or `+`/`-` nets and apply the differential trace width.
Pairs may additionally set `minimum_length_nm`, `tuning_amplitude_nm`,
`tuning_pitch_nm`, and `max_tuning_sections`. The router adds each meander to
both members in one transaction, retaining equal length and accepting only
whole-board DRC-clean geometry. Tuning dimensions must be positive and the
section count must be between 1 and 16.
Set `target_differential_impedance_ohms` together with
`differential_impedance_tolerance_ohms` to check edge-coupled microstrip
impedance. The estimate combines routed width, pair gap, copper thickness,
dielectric height, and permittivity and reports missing/invalid stackup data
separately.
Normal DRC also reports incomplete, non-finite, or negative impedance
constraints before evaluating routed geometry.
`maximum_differential_impedance_step_ohms` additionally limits the largest
stackup-derived impedance change around any via on either member, even when no
absolute differential target is configured.

## Length constraints and tuning

Length groups require unique non-empty names and at least two unique declared
net IDs; normal DRC reports malformed groups before evaluating routed skew.
Maximum skew must be non-negative, optional tuning dimensions must be positive,
and the supported tuning-section range is 1 through 16.
Net classes may set `minimum_length_nm` and `maximum_length_nm`. The checker
reports routes outside that interval. After routing, pcbex deterministically
adds an orthogonal meander to short routes and accepts it only when the complete
board remains free of boundary, obstacle, connectivity, and clearance errors.
For parallel buses, `length_groups` declares a name, member net IDs, and maximum
skew. The checker reports group skew and the router tunes shorter members toward
the longest route while retaining every normal board constraint.

## Copper zones

Filled KiCad copper-zone polygons are imported as exact, layer-specific,
net-owned copper geometry. They block foreign nets with the normal clearance
while remaining enterable by their owning net. Existing zone definitions and
fills are preserved when routed tracks are written back to the board.

## PDN checks

Each declared power-net rule must reference a distinct net present in the board
net table. Expected current and maximum permitted voltage drop must both be
positive, finite values.

`power_net_rules` declares a power net's expected current in mA, maximum
permitted DC drop in mV, and optional minimum parallel-via count. The checker
uses each routed segment's real length and width plus per-layer stackup copper
thickness (35 µm fallback) to estimate copper resistance and reports
`pdn_voltage_drop` or `pdn_via_count` violations.

## Via types and layer ranges

Vias carry an explicit `through`, `blind_buried`, or `micro` kind plus start and
end copper layers. KiCad blind/buried and microvias retain their ranges during
import and write-back. Connectivity and clearance checks only consider layers
actually spanned by the via, and microvias are restricted to adjacent layers.
Set `via_strategy` to `auto` to let the router choose microvias for adjacent
layers, blind/buried vias for partial non-adjacent spans, and through vias for
the complete stack. Partial-span Via costs discourage unnecessary deep drills.

## Extended pad geometry

KiCad round-rectangle, trapezoid, and custom polygon pads retain their shape in
the board model. Rounded corners, trapezoid deltas, rotation, and custom
`gr_poly` primitives are converted to polygon obstacles instead of rectangular
bounding-box approximations.

## Practical placement constraints

Placement components carry front/back side and optional allowed 90-degree
rotations. `region` constraints keep a complete component body inside a
specified rectangle. KiCad placement derives component dimensions from
`F.CrtYd`/`B.CrtYd` geometry when available instead of pad extents alone.
Polygon courtyards are transformed with component rotation and side mirroring,
so non-overlapping concave space is not rejected by bounding boxes. Side flips
swap all footprint front/back layers atomically during KiCad write-back.
The `decoupling` constraint measures transformed capacitor and IC-pin anchors,
enforces a maximum connection distance, and can require both parts on the same
board side.

## Routing scalability

Obstacle rasterization uses conservative grid-cell windows derived from each
circle, capsule, polygon, and keepout bounding envelope. Exact geometry remains
the final predicate, while distant board cells are no longer scanned once per
obstacle. The Criterion suite includes a 100 mm board with 200 round obstacles.
CI also routes an anonymized practical corpus covering a USB differential pair,
a four-layer power/inner-signal board, and an eight-net BGA fanout. Each fixture
has a deterministic search budget and must remain clean and byte-idempotent;
see `docs/REGRESSION_CORPUS.md`. A reproducible generator also creates a
100-net, six-layer backplane; CI checks full routing, DRC, byte-idempotence, and
a 100,000-state ceiling.

Independent first-pass A* candidates are explored concurrently by up to eight
workers. Results are validated and committed in the original deterministic net
order. A candidate that conflicts with an earlier commit is discarded and
searched again against the updated board, retaining byte-identical output.
One top-level routing call also has a deterministic 2,000,000-unit A* budget
shared by coupled pairs, normal nets, retries, validation reroutes, and
automatic shove. Parallel searches use stable per-net leases instead of racing
for the final unit; checked callers can select a smaller limit with
`route_board_with_work_budget`. Exact accounting and fail-closed compatibility
behavior are documented in
[`docs/ASTAR_WORK_BUDGET.md`](docs/ASTAR_WORK_BUDGET.md).

Copper-zone island removal has its own deterministic 1,048,576-unit work
budget shared by every zone in one fill operation. The filler enqueues only
previously undiscovered candidate cells and charges each queue removal and
successful neighbor insertion. Checked callers can tighten the cap with
`try_fill_copper_zones_with_work_budget`; exhaustion leaves every existing
filled polygon unchanged. See
[`docs/ZONE_FILL_WORK_BUDGET.md`](docs/ZONE_FILL_WORK_BUDGET.md).

Generate an N-best routing portfolio for board JSON or a placed KiCad board:

```sh
pcbex route-candidates placed.json \
  --output-dir routing-candidates --candidates 10 \
  --workers 4 --router-workers 2

pcbex route-kicad-candidates placed.kicad_pcb \
  --output-dir kicad-routing-candidates --candidates 10 \
  --workers 4 --router-workers 2
```

Candidates cycle through balanced, shortest-route, via-minimized,
bend-minimized, and alternate-net-order searches. The versioned
`candidates.json` manifest records the effective search costs, route report,
quality metrics, duplicate identity, Pareto membership, and deterministic
selection. The Pareto front minimizes unrouted nets, total length, vias, and
bends; selection then applies the caller's original routing costs. Every board
and report is retained, together with `selected.board.json` and
`selected.report.json`; KiCad mode also writes each candidate board and
`selected.kicad_pcb`.

Generation accepts 1–32 candidates, 1–8 portfolio workers, and 1–8 router
workers per candidate, with a combined ceiling of 16 threads. Parallel worker
counts do not change candidate geometry, metrics, duplicate detection, Pareto
membership, or selection. Unless `--allow-unrouted` is given, artifacts are
written first and the command then fails if the selected candidate is not
fully routed.

Generate a stable quality report for review or CI:

```sh
pcbex quality routed.json --output quality.json --max-unrouted 0
pcbex quality candidate.json --baseline quality.json
pcbex quality candidate.json --baseline quality.json --format sarif \
  --output quality.sarif
```

Quality-report total route length uses saturating accumulation, so large
multi-net designs cannot wrap the reported aggregate.

Reports include per-net length, segments, arcs, vias, bends, used layers, board
totals, unrouted count, and differential-pair skew/coupling. Baseline gates
reject increases in total length, vias, bends, or unrouted nets.

Analyze a KiCad board directly and produce one self-contained artifact bundle
for CI, MCP, or later candidate comparison:

```sh
pcbex analyze-kicad board.kicad_pcb --output-dir build/pcbex-analysis
```

The bundle contains the normalized board JSON, SVG, quality and internal
DRC/DFM JSON, SARIF, a Markdown summary, and `run.json`. The run manifest records
the engine version, SHA-256 and byte length of every applied input, effective
routing defaults, applied custom-rule count, result totals, and artifact names.
Sibling `.kicad_pro` and `.kicad_dru` files are discovered automatically or may
be selected with `--project` and `--rules-file`. Add `--fail-on-violations` to
write the complete bundle and then fail a CI job when internal checks are not
clean.

Compare a baseline bundle with the current bundle:

```sh
pcbex compare-analysis build/baseline build/current \
  --output-dir build/comparison --fail-on-regressions
```

The comparison writes `delta.json`, `summary.md`, `report.sarif`, and a
SHA-256-addressed `run.json` before applying the optional failure gate. Signed
changes cover total length, vias, bends, routed and unrouted nets, and violation
count. Violations are compared by rule, message, and normalized net IDs so a
new finding cannot be hidden by resolving an unrelated finding. Resolved
violations are retained separately for review.

Bind fabrication and inspection results back to the exact analyzed source
board:

```sh
pcbex analyze-kicad examples/simple.kicad_pcb \
  --output-dir build/manufacturing-analysis

pcbex record-manufacturing-feedback \
  examples/manufacturing-feedback-declaration.json \
  --analysis-dir build/manufacturing-analysis \
  --board examples/simple.kicad_pcb \
  --artifact examples/manufacturing-inspection.csv \
  --output build/manufacturing-feedback.json \
  --summary-output build/manufacturing-feedback.md \
  --sarif-output build/manufacturing-feedback.sarif
```

The closed declaration records manufacturer, process, optional lot,
disposition, stable finding IDs, measurements, and the SHA-256 of the submitted
board. The command independently hashes the board, `analyze-kicad` run
manifest, and every raw inspection artifact. It rejects a manifest for another
board, unknown fields, duplicate IDs, non-finite or reversed measurement
bounds, duplicate artifact basenames, and missing evidence citations before
writing the bound result. A rejected disposition or error finding makes
`passed` false; `--require-passed` writes all requested evidence and then fails.

Compare newly manufactured feedback with an accepted result:

```sh
pcbex compare-manufacturing-feedback \
  accepted-feedback.json current-feedback.json \
  --output manufacturing-comparison.json \
  --summary-output manufacturing-comparison.md \
  --sarif-output manufacturing-comparison.sarif \
  --fail-on-regressions
```

Comparison requires the same manufacturer and reports new, escalated, and
resolved findings. New warning/error findings, severity escalation,
disposition degradation, or pass-to-fail transition are regressions. Closed
contracts are emitted by `manufacturing-feedback-declaration-schema`,
`manufacturing-feedback-schema`, and
`manufacturing-feedback-comparison-schema`.

Generate a governed proposal from recurring feedback without allowing
manufacturing data to mutate policy directly:

```sh
pcbex recommend-policy organization-policy-pack.json \
  --feedback accepted-lot-41.json \
  --feedback accepted-lot-42.json \
  --analysis-manifest lot-41/run.json \
  --analysis-manifest lot-42/run.json \
  --generated-on 2026-07-29 \
  --minimum-occurrences 2 \
  --output policy-recommendation.json \
  --summary-output policy-recommendation.md

pcbex policy-recommendation-schema \
  --output policy-recommendation.schema.json
pcbex validate-policy-recommendation policy-recommendation.json
```

Each exact `run.json` must match the SHA-256 descriptor in its paired feedback,
the feedback board identity, and the complete DFM profile in the target policy
pack. Duplicate feedback IDs or content, future-dated evidence, mismatched
profiles, more than 10,000 findings, and unpaired inputs fail before output.
The default threshold requires the same rule to recur in two independently
bound feedback records.

Only warning/error measurements for track width, clearance, drill, and annular
ring can produce a machine suggestion. The measurement must state a supported
`nm`, `um`/`µm`, or `mm` minimum, show an actual shortfall, and yield a value
strictly greater than the current policy minimum. Every other finding is
retained with an explicit skip reason. The closed report always states
`status: proposal_only`, `requires_human_approval: true`, and
`may_relax_constraints: false`; it contains no patched or automatically
applicable policy pack. Outputs refuse overwrite and must enter the normal
protected review, signing, and monotonic policy-distribution flow.

The MCP server exposes the same `recommend_policy` boundary. In the composite
Action, set `policy-recommendation-generated-on` to opt in; the Action uses the
exact effective policy pack applied to analysis, includes the current bound
feedback automatically, accepts paired historical feedback/manifests, and
publishes `policy-recommendation` as a retained artifact.

Before promoting a recommendation, derive its deterministic simulation-only
profile and compare exact baseline/candidate analyses across projects:

```sh
pcbex policy-rollout-profile organization-policy-pack.json \
  policy-recommendation.json \
  --generated-on 2026-07-29 \
  --output policy-rollout-profile.json

pcbex analyze-kicad hardware/controller.kicad_pcb \
  --policy-pack organization-policy-pack.json \
  --output-dir build/controller-baseline
pcbex analyze-kicad hardware/controller.kicad_pcb \
  --fab-profile policy-rollout-profile.json \
  --output-dir build/controller-candidate

pcbex simulate-policy-rollout organization-policy-pack.json \
  policy-recommendation.json \
  --project-id controller \
  --board hardware/controller.kicad_pcb \
  --baseline-analysis build/controller-baseline \
  --candidate-analysis build/controller-candidate \
  --project-id sensor \
  --board hardware/sensor.kicad_pcb \
  --baseline-analysis build/sensor-baseline \
  --candidate-analysis build/sensor-candidate \
  --generated-on 2026-07-29 \
  --output policy-rollout.json \
  --summary-output policy-rollout.md

pcbex policy-rollout-schema --output policy-rollout.schema.json
pcbex validate-policy-rollout policy-rollout.json
```

Every pair must identify the same board, project file, custom rules, and
effective design rules. The baseline must use the exact organization policy
pack; the candidate must use only the recommendation-derived profile. Manifest
result counts are checked against the bound `checks.json` and `quality.json`,
duplicate project IDs or board digests are rejected, and all inputs are
size-bounded. The closed report always states `status: simulation_only`,
`deployable: false`, and `requires_human_approval: true`. It reports compatible
and affected projects plus every new violation, but cannot promote a policy.

The MCP tools `policy_rollout_profile` and `simulate_policy_rollout` expose the
same boundary. A repository Action can set `policy-rollout-project-id` and
`policy-rollout-generated-on`, together with either recommendation generation
or `policy-rollout-recommendation`, to rerun the current board, retain the
simulation profile and candidate analysis, and publish `policy-rollout`.

Two independent trusted humans can authorize only a bounded canary over the
exact normalized rollout report:

```sh
pcbex sign-rollout-approval policy-rollout.json \
  --canary-project controller \
  --valid-from-unix 1785283200 \
  --expires-at-unix 1785888000 \
  --private-key engineer-a.key \
  --signer-id engineer-a \
  --decision approve \
  --reason "Compatible simulation; bounded canary approved." \
  --ticket HW-ROLLOUT-42 \
  --output rollout-approval-a.json

pcbex verify-rollout-approvals policy-rollout.json \
  --policy-pack organization-policy-pack.json \
  --approval rollout-approval-a.json \
  --approval rollout-approval-b.json \
  --evaluated-at-unix 1785286800 \
  --output canary-rollout-authorization.json \
  --summary-output canary-rollout-authorization.md \
  --require-authorized
```

The signatures bind the rollout digest, policy identity and revision, sorted
project scope, decision, signer, reason, ticket, and validity window. Signers
must be distinct trusted human keys, approvals must agree exactly, the window
cannot exceed seven days, and the canary cannot exceed 10% of projects. Any
simulated regression or new violation prevents authorization. The closed
authorization always requires automatic rollback on regression, analysis
failure, new violations, or missing monitoring evidence; automatic promotion
is forbidden and post-canary human review is mandatory.

MCP exposes `sign_rollout_approval` and `verify_rollout_approvals`. The
repository Action accepts `canary-rollout-report`,
`canary-rollout-approval-files`, and
`canary-rollout-evaluated-at-unix`, publishes the retained authorization and
boolean result, and gates only when
`fail-on-canary-rollout-authorization: "true"` is selected.

After the bounded canary runs, retain a fresh analysis produced with the exact
authorized candidate profile and compare it with the exact simulated baseline:

```sh
pcbex record-canary-monitoring policy-rollout.json \
  canary-rollout-authorization.json \
  --project-id controller \
  --board hardware/controller.kicad_pcb \
  --baseline-analysis build/controller-baseline \
  --observed-analysis build/controller-canary \
  --observed-at-unix 1785287200 \
  --output canary-monitoring.json \
  --summary-output canary-monitoring.md \
  --require-passed
```

The report binds every analysis artifact digest to the rollout and
authorization. Any new violation or quality regression requires rollback.
Passing evidence only sets `promotion_eligible: true`; it always retains
`automatic_promotion: false` and `requires_human_decision: true`. MCP exposes
`record_canary_monitoring`, and the Action provides equivalent retained outputs
and an opt-in `fail-on-canary-monitoring` gate.

Promotion or rollback is then finalized by a separate unanimous human quorum:

```sh
pcbex sign-canary-completion policy-rollout.json \
  canary-monitoring.json \
  canary-rollout-authorization.json \
  --decision promote \
  --decided-at-unix 1785287300 \
  --private-key engineer-a.key \
  --signer-id engineer-a \
  --reason "Bound monitoring passed without regression." \
  --ticket HW-ROLLOUT-42 \
  --output completion-a.json

pcbex verify-canary-completion policy-rollout.json \
  canary-monitoring.json \
  canary-rollout-authorization.json \
  --policy-pack organization-policy-pack.json \
  --decision completion-a.json \
  --decision completion-b.json \
  --output canary-completion.json \
  --summary-output canary-completion.md \
  --require-finalized
```

Each Ed25519 signature binds the exact monitoring and authorization digests,
rollout and policy identities, final action, decision time, reason, ticket, and
signer. Signers and keys must be distinct and trusted. Promotion is impossible
when monitoring requires rollback; mixed promotion/rollback votes never
finalize. The completion report continues to declare
`automatic_promotion: false`. MCP and the repository Action expose the same
two-stage signing and verification boundary.

The finalized signatures can then advance a separately protected deployment
state:

```sh
pcbex advance-policy-deployment policy-rollout.json \
  canary-monitoring.json \
  canary-rollout-authorization.json \
  --policy-pack organization-policy-pack.json \
  --candidate-policy-pack organization-policy-pack.next.json \
  --source-policy-trust-state organization-policy-pack.trust.json \
  --candidate-policy-trust-state organization-policy-pack.next.trust.json \
  --decision completion-a.json \
  --decision completion-b.json \
  --baseline-state previous-policy-deployment.json \
  --recorded-at-unix 1785287400 \
  --output policy-deployment.json \
  --summary-output policy-deployment.md \
  --require-promotion
```

The command verifies the original completion signatures again rather than
trusting a derived report. The source and candidate trust states must bind
their exact packs and retain the same policy signer and public key. Each state
generation binds its predecessor, both accepted trust states, rollout,
authorization, monitoring, completion, active revision, highest considered
revision, and explicit rollback target.
A deployment candidate must have a higher revision, contain the exact
rollout-derived DFM profile, and retain the source pack's electrical policy, AI
requirements, simulation requirement, and trusted keys unchanged.
A candidate revision must be strictly newer than every previously considered
revision, including one that was rolled back, so old decisions and repaired
content under a reused revision cannot be replayed. Bootstrap promotion is
allowed; rollback requires a prior active state. Automatic application remains
false, and every new state is retained with post-deployment verification
`pending`. MCP exposes `advance_policy_deployment`. The repository Action opts
in with `policy-deployment-recorded-at-unix`, publishes the new state, status,
and active revision, and can gate promotion with
`fail-on-policy-deployment-promotion`.

After rollout, verify every production project against the exact retained
candidate evidence:

```sh
pcbex verify-policy-deployment policy-deployment.json policy-rollout.json \
  --candidate-policy-pack organization-policy-pack.next.json \
  --project-id controller \
  --board controller.kicad_pcb \
  --expected-analysis rollout/controller-candidate \
  --observed-analysis production/controller \
  --verified-at-unix 1785291000 \
  --output policy-deployment-verification.json \
  --summary-output policy-deployment-verification.md \
  --require-passed
```

Project coverage must exactly equal the rollout scope. Every expected bundle
must be the simulation evidence retained by that rollout, while every observed
bundle must use the exact active organization policy pack and unchanged board,
engine, rules, and analysis settings. Missing projects, mismatched evidence,
new violations, or quality regressions prevent verification. A failed report
sets `rollback_required` and `requires_dual_control_rollback` without executing
an automatic rollback. MCP exposes `verify_policy_deployment`; the Action
accepts `policy-deployment-verification-*` inputs and can enforce the result
with `fail-on-policy-deployment-verification`.

When verification requires rollback, each trusted human signs the exact failed
state, verification report, failed revision, and immutable restore target:

```sh
pcbex sign-policy-deployment-rollback policy-deployment.json \
  policy-deployment-verification.json \
  --approved-at-unix 1785291600 \
  --private-key engineer-a.key \
  --signer-id engineer-a \
  --reason "Production clearance regressed after promotion." \
  --ticket HW-ROLLBACK-42 \
  --output rollback-a.json

pcbex apply-policy-deployment-rollback policy-deployment.json \
  policy-deployment-verification.json \
  --active-policy-pack organization-policy-pack.failed.json \
  --approval rollback-a.json \
  --approval rollback-b.json \
  --recorded-at-unix 1785291800 \
  --output policy-deployment-rollback.json \
  --summary-output policy-deployment-rollback.md \
  --require-applied
```

The command accepts only failed, digest-bound production verification with a
previously retained active revision. At least two distinct trusted human
signers and keys must agree within the bounded 24-hour review window. The
failed active pack supplies the unchanged human trust root; arbitrary restore
targets, bootstrap rollback, stale approval, key reuse, and insufficient
quorum fail closed. The resulting state binds the predecessor deployment,
failed verification, failed and restored revisions, highest considered
revision, and every approval digest. `automatic_rollback` remains false. MCP
exposes signing and application tools, and the Action accepts
`policy-deployment-rollback-*` inputs.

After rollback, verify every restored project against the production baseline
retained by the rollout:

```sh
pcbex verify-policy-rollback-recovery policy-deployment-rollback.json \
  policy-rollout.json \
  --deployment policy-deployment.failed.json \
  --failed-verification policy-deployment-verification.failed.json \
  --previous-deployment policy-deployment.previous.json \
  --baseline-verification policy-deployment-verification.previous.json \
  --restored-policy-pack organization-policy-pack.previous.json \
  --project-id controller \
  --board controller.kicad_pcb \
  --expected-analysis rollout/controller-baseline \
  --observed-analysis production/controller-restored \
  --verified-at-unix 1785292200 \
  --output policy-rollback-recovery.json \
  --summary-output policy-rollback-recovery.md \
  --require-passed

pcbex sign-rollback-incident-acknowledgment \
  policy-deployment-rollback.json policy-rollback-recovery.json \
  --acknowledged-at-unix 1785292300 \
  --private-key operator.key \
  --operator-id incident-operator \
  --reason "Restored fleet is complete and clean." \
  --ticket HW-ROLLBACK-42 \
  --output rollback-incident-acknowledgment.json

pcbex close-rollback-incident \
  policy-deployment-rollback.json policy-rollback-recovery.json \
  --restored-policy-pack organization-policy-pack.previous.json \
  --acknowledgment rollback-incident-acknowledgment.json \
  --closed-at-unix 1785292400 \
  --output rollback-incident-closure.json \
  --summary-output rollback-incident-closure.md \
  --require-closed
```

Recovery first verifies the rollback, failed deployment, failed verification,
previous deployment, previous clean fleet verification, and rollout as one
continuous digest chain. Coverage must exactly equal that retained baseline
and the failed rollout scope. Expected evidence is the observed production
evidence from the clean pre-promotion verification; new observations must use
the exact restored policy pack without changing the board, engine, rules, or
analysis settings. Missing projects, new violations, or quality regressions
keep the incident open. Closure then requires a fresh Ed25519 acknowledgment
from a trusted operator who did not approve the rollback, within 24 hours of
clean recovery. The acknowledgment binds the exact rollback and recovery
digests; tampering, replay against another incident, stale signatures, and
rollback-approver self-closure fail closed. Automatic incident closure is
always false. MCP exposes all three operations, and the Action accepts
`policy-rollback-recovery-*` and `rollback-incident-*` inputs.

Retain each closed rollback in an append-only operational ledger:

```sh
pcbex append-policy-incident-ledger policy-deployment-rollback.json \
  --failed-verification policy-deployment-verification.failed.json \
  --recovery policy-rollback-recovery.json \
  --closure rollback-incident-closure.json \
  --baseline-ledger policy-incident-ledger.previous.json \
  --suspension-threshold 2 \
  --output policy-incident-ledger.json \
  --summary-output policy-incident-ledger.md
```

Every entry binds the failed verification, rollback, recovery, and closure
digests, then chains to the previous entry. The ledger recomputes time to
rollback, clean recovery, and closure, plus per-revision incident counts.
Repeated failure of the same revision and policy digest produces a human
suspension-review candidate at the retained threshold. It never suspends a
policy automatically. Duplicate incidents, reordered or truncated entries,
duration tampering, policy identity changes, and threshold changes fail
closed. MCP exposes `append_policy_incident_ledger`; the Action can opt in with
`record-policy-incident` and retain the resulting ledger as evidence.

Resolve a repeated-incident candidate with a signed dual-control decision:

```sh
pcbex sign-policy-suspension-decision policy-incident-ledger.json \
  --failed-revision 7 \
  --failed-policy-pack-sha256 "$FAILED_POLICY_SHA256" \
  --decision suspend \
  --decided-at-unix 1785300000 \
  --private-key reviewer-a.key \
  --signer-id reviewer-a \
  --reason "Repeated production clearance regression" \
  --ticket HW-421 \
  --output suspension-a.json

pcbex apply-policy-suspension-decision policy-incident-ledger.json \
  --policy-pack organization-policy.json \
  --failed-revision 7 \
  --failed-policy-pack-sha256 "$FAILED_POLICY_SHA256" \
  --decision suspension-a.json \
  --decision suspension-b.json \
  --recorded-at-unix 1785300060 \
  --output policy-suspension.json \
  --require-suspended
```

Each Ed25519 signature binds the complete ledger digest and head, exact failed
revision and policy digest, incident count, threshold, decision, reason, ticket,
and review time. Applying a decision requires at least two distinct trusted
human signers and keys, unanimous `suspend` or `continue` votes, and a bounded
24-hour review window. The retained state embeds the original signatures so
digest mutation cannot create a deny decision. `advance-policy-deployment`
accepts repeatable `--suspension-state` evidence and rejects an exact suspended
candidate digest before writing deployment state. Suspension is never
automatic. MCP exposes signing and application tools; the Action accepts
`policy-suspension-*` inputs and enforces the same promotion deny gate.

Release one exact successor remediation after independent review:

```sh
pcbex sign-policy-remediation-approval policy-suspension.json \
  candidate-policy.json candidate-policy-trust-state.json \
  policy-rollout.json canary-monitoring.json \
  --approved-at-unix 1785301000 \
  --private-key remediator-a.key \
  --signer-id remediator-a \
  --reason "Successor passed complete clean canary verification" \
  --ticket HW-422 \
  --output remediation-a.json

pcbex apply-policy-remediation policy-suspension.json \
  --policy-pack active-policy.json \
  --candidate-policy-pack candidate-policy.json \
  --candidate-policy-trust-state candidate-policy-trust-state.json \
  --rollout policy-rollout.json \
  --monitoring canary-monitoring.json \
  --approval remediation-a.json \
  --approval remediation-b.json \
  --recorded-at-unix 1785301060 \
  --output policy-remediation.json \
  --require-verified
```

The successor must have a higher revision and different digest, an accepted
policy trust state, unchanged human trust roots, and complete regression-free
canary evidence. At least two remediation approvers must be distinct from every
suspension approver and from each other. Their signatures bind the suspension,
successor digest, accepted trust state, rollout, monitoring, reason, ticket,
and time. A suspended policy identity blocks later promotion until
`advance-policy-deployment` receives a matching `--remediation-state`; the
release applies only to that exact successor digest and never lifts suspension
automatically. CLI, MCP, and the composite Action enforce the same boundary.

Retain every suspension and remediation as one append-only lifecycle:

```sh
pcbex append-policy-lifecycle-event \
  --suspension policy-suspension.json \
  --output policy-lifecycle.json \
  --summary-output policy-lifecycle.md

pcbex append-policy-lifecycle-event \
  --baseline-ledger policy-lifecycle.json \
  --remediation policy-remediation.json \
  --output policy-lifecycle.next.json \
  --summary-output policy-lifecycle.next.md \
  --require-no-pending-suspensions

pcbex snapshot-policy-lifecycle policy-lifecycle.next.json \
  --generation 1 \
  --output policy-lifecycle.generation-1.json
```

Every entry binds its sequence, previous entry, event type, complete embedded
state digest, policy identity, and time. Parsing recomputes the complete chain,
revalidates every embedded signed state, and derives which decisions are
`awaiting_remediation`, `released`, `superseded`, or
`continued_under_review`. A remediation must resolve one exact active
suspension and cannot be replayed. Historical snapshots embed the complete
source ledger and its digest, then recompute the requested generation rather
than trusting copied counters. `advance-policy-deployment` accepts repeatable
`--policy-lifecycle-ledger` inputs and reuses their fully verified evidence.
MCP exposes append and snapshot tools; the Action can append one selected
event, publish its generation and pending count, and consume retained lifecycle
ledgers at the deployment gate.

Authenticate the latest lifecycle generation before CI adopts it:

```sh
pcbex sign-policy-lifecycle-checkpoint policy-lifecycle.next.json \
  --issued-at-unix 1785301100 \
  --private-key lifecycle-root.key \
  --signer-id lifecycle-root \
  --output policy-lifecycle.checkpoint.json

pcbex verify-policy-lifecycle-checkpoint \
  policy-lifecycle.next.json policy-lifecycle.checkpoint.json \
  --public-key lifecycle-root.pub \
  --baseline-state policy-lifecycle.previous.trust.json \
  --accepted-at-unix 1785301101 \
  --output policy-lifecycle.trust.json \
  --require-accepted
```

The Ed25519 signature binds the policy identity, generation, entry count,
normalized ledger digest, hash-chain head, signer, and issue time. Verification
requires a separately trusted public key and a checkpoint no older than 24
hours. A retained trust state makes exact replay idempotent while rejecting
generation rollback, same-generation equivocation, signer or key substitution,
backward time, and higher-generation ledgers that do not retain the previously
trusted head. Closed checkpoint and trust-state schemas are available from
`signed-policy-lifecycle-checkpoint-schema` and
`policy-lifecycle-trust-state-schema`. MCP exposes signing as a
task-forbidden destructive tool and verification as an optional task. The
Action accepts `policy-lifecycle-checkpoint-*`, publishes the newly accepted
trust state, and can fail closed with
`fail-on-policy-lifecycle-checkpoint: "true"`.

Rotate a lifecycle signing root without resetting trusted history:

```sh
pcbex sign-policy-lifecycle-key-rotation \
  policy-lifecycle.previous.trust.json \
  --old-private-key lifecycle-root.key \
  --new-private-key lifecycle-root.next.key \
  --rotated-at-unix 1785301200 \
  --output policy-lifecycle.key-rotation.json

pcbex verify-policy-lifecycle-checkpoint \
  policy-lifecycle.next.json policy-lifecycle.next.checkpoint.json \
  --public-key lifecycle-root.next.pub \
  --baseline-state policy-lifecycle.previous.trust.json \
  --key-rotation policy-lifecycle.key-rotation.json \
  --accepted-at-unix 1785301201 \
  --output policy-lifecycle.next.trust.json \
  --require-accepted
```

The rotation advances exactly one key generation and binds the policy,
signer, previously accepted checkpoint, prior rotation digest, old and new
public keys, and rotation time. Both private keys must sign the same payload.
The verifier rejects missing, replayed, skipped, reordered, future-dated, or
single-key transitions and carries the rotation digest into the next trust
state. The closed contract is emitted by
`signed-policy-lifecycle-key-rotation-schema`; MCP exposes signing as
task-forbidden, and the Action accepts
`policy-lifecycle-checkpoint-key-rotation`.

Require independent observers before adopting an accepted checkpoint:

```sh
pcbex witness-policy-lifecycle-checkpoint policy-lifecycle.trust.json \
  --private-key witness-a.key \
  --witness-id witness-a \
  --observed-at-unix 1785301300 \
  --output witness-a.json

pcbex verify-policy-lifecycle-checkpoint-witnesses \
  policy-lifecycle.trust.json \
  --witness witness-a.json --public-key witness-a.pub \
  --witness witness-b.json --public-key witness-b.pub \
  --minimum-witnesses 2 \
  --evaluated-at-unix 1785301301 \
  --output policy-lifecycle.witness-quorum.json \
  --require-quorum
```

Each witness signature binds the exact accepted checkpoint digest, policy,
generation, hash-chain head, witness identity, and observation time.
Verification pairs every witness with a separately trusted public-key file,
requires distinct identities and keys, and rejects stale observations after 24
hours. Insufficient but otherwise valid evidence is retained as a structured
non-passing report; malformed, untrusted, duplicate, cross-checkpoint, or
tampered evidence fails before output. Closed contracts are available from
`signed-policy-lifecycle-checkpoint-witness-schema` and
`policy-lifecycle-witness-quorum-schema`. MCP exposes signing as
task-forbidden and quorum verification as an optional task. The Action accepts
`policy-lifecycle-witness-*`, publishes the report and quorum result, and can
fail closed with `fail-on-policy-lifecycle-witness-quorum: "true"`.

Remote security domains can produce those observations without placing witness
private keys on CI runners:

```sh
pcbex request-policy-lifecycle-checkpoint-witness \
  policy-lifecycle.trust.json \
  --endpoint https://witness-a.example/v1/lifecycle \
  --public-key witness-a.pub \
  --bearer-token-env PCBEX_LIFECYCLE_WITNESS_TOKEN \
  --timeout-seconds 30 \
  --evaluated-at-unix 1785301301 \
  --output witness-a.json \
  --receipt-output witness-a.receipt.json
```

The request includes the complete accepted trust state, including its signed
checkpoint, so the remote service can independently validate the lifecycle
root instead of trusting client-supplied digest fields. The client permits
HTTPS only, refuses redirects, URL credentials, and query strings, applies a
1–600 second end-to-end timeout, and limits the response to 1 MiB of
`application/json`. The Bearer token is read from the named environment
variable and is excluded from arguments and receipts. Before either output is
created, the response must strictly deserialize, match the exact accepted
checkpoint, use the separately trusted key, have a fresh observation time, and
pass Ed25519 verification. The closed receipt binds the
endpoint, checkpoint, request and response digests, response size, evaluation
time, witness identity, key, and observation time; emit its schema with
`remote-policy-lifecycle-witness-receipt-schema`.

MCP exposes the same operation as the open-world, task-forbidden
`request_remote_policy_lifecycle_checkpoint_witness` tool. The Action accepts
up to ten paired endpoints and trusted keys through
`policy-lifecycle-remote-witness-endpoints` and
`policy-lifecycle-remote-witness-public-key-files`, retains every verified
response and receipt, then includes all remote results in the existing quorum
gate. An optional `policy-lifecycle-remote-witness-bearer-token` remains an
environment-only secret.

Rotate a lifecycle witness service key without silently replacing its identity:

```sh
pcbex init-policy-lifecycle-witness-trust \
  --witness-id witness-a \
  --public-key witness-a.pub \
  --output witness-a.trust.0.json

pcbex sign-policy-lifecycle-witness-key-rotation \
  witness-a.trust.0.json \
  --old-private-key witness-a.key \
  --new-private-key witness-a.next.key \
  --rotated-at-unix 1785301400 \
  --output witness-a.rotation.1.json

pcbex apply-policy-lifecycle-witness-key-rotation \
  witness-a.trust.0.json witness-a.rotation.1.json \
  --output witness-a.trust.1.json \
  --public-key-output witness-a.trust.1.pub
```

The immutable trust state pins the witness identity, key generation, current
Ed25519 key, previous rotation digest, and monotonic rotation time. Each
domain-separated transition advances exactly one generation and requires both
old-key authorization and new-key possession over the same payload. Replay,
rollback, skipped generations, forked rotation history, same-key transitions,
identity substitution, invalid signatures, and backward time are rejected
before new files are created. The verifier and remote client accept
`--witness-key-trust-state` as an identity-bound alternative to a raw
`--public-key`.

Closed contracts are emitted by
`policy-lifecycle-witness-trust-state-schema` and
`signed-policy-lifecycle-witness-key-rotation-schema`. MCP exposes
initialize, sign, apply, and export tools; signing and trust mutation are
task-forbidden. The Action accepts newline-separated
`policy-lifecycle-witness-key-trust-state-files` and
`policy-lifecycle-remote-witness-key-trust-state-files`, each mutually
exclusive with its legacy public-key input. Remote receipts additionally bind
the exact trust-state SHA-256 and key generation when this mode is used; both
fields are `null` for the legacy raw-key path.

Anchor an accepted lifecycle checkpoint in a separately operated public
Merkle log:

```sh
pcbex create-policy-lifecycle-log-anchor \
  policy-lifecycle.checkpoint.json \
  --log-checkpoint policy-lifecycle.previous.checkpoint.json \
  --log-checkpoint policy-lifecycle.checkpoint.json \
  --leaf-index 1 \
  --log-id organization-lifecycle-log \
  --private-key lifecycle-public-log.key \
  --observed-at-unix 1785301500 \
  --output policy-lifecycle.anchor.json

pcbex verify-policy-lifecycle-log-anchor \
  policy-lifecycle.checkpoint.json \
  --proof policy-lifecycle.anchor.json \
  --log-id organization-lifecycle-log \
  --public-key lifecycle-public-log.pub \
  --output policy-lifecycle.anchor-verification.json
```

Checkpoint digests are domain-separated leaves in an RFC 6962-style tree.
The signed tree head binds the public-log identity, exact tree size, root
digest, and observation time under a key that is independent from both the
lifecycle signer and its witnesses. Verification reconstructs the exact root
from a bounded audit path and rejects a different checkpoint, leaf index,
sibling, root, signature, trusted key, malformed proof, oversized tree, or
trusted log identity, or tree head that predates the checkpoint.

Closed contracts are available from
`policy-lifecycle-log-anchor-proof-schema` and
`policy-lifecycle-log-anchor-verification-report-schema`. MCP exposes
`create_policy_lifecycle_public_anchor` and
`verify_policy_lifecycle_public_anchor`. The Action accepts
`policy-lifecycle-log-anchor-proof` with
`policy-lifecycle-log-anchor-id` and
`policy-lifecycle-log-anchor-public-key`, publishes the verification report
and boolean result, and can fail closed with
`fail-on-policy-lifecycle-log-anchor: "true"`.

Retain the last accepted anchor and require an append-only transition before
accepting the next signed tree head:

```sh
pcbex create-policy-lifecycle-log-consistency \
  --previous-anchor policy-lifecycle.anchor.previous.json \
  --current-anchor policy-lifecycle.anchor.json \
  --log-checkpoint policy-lifecycle.previous.checkpoint.json \
  --log-checkpoint policy-lifecycle.checkpoint.json \
  --output policy-lifecycle.consistency.json

pcbex verify-policy-lifecycle-log-consistency \
  --previous-anchor policy-lifecycle.anchor.previous.json \
  --current-anchor policy-lifecycle.anchor.json \
  --proof policy-lifecycle.consistency.json \
  --log-id organization-lifecycle-log \
  --public-key lifecycle-public-log.pub \
  --output policy-lifecycle.consistency-verification.json
```

The bounded RFC 6962-style consistency path reconstructs both signed roots
without retaining every checkpoint in the consumer. Verification requires the
proof's old tree head to equal the explicitly retained anchor and its new tree
head to equal the current anchor. It verifies both signatures under one
separately trusted log identity and key, and rejects size rollback,
same-size root equivocation, observation-time rollback, path mutation,
incomplete or extra nodes, non-prefix history, key substitution, and log
substitution. Generation requires the complete current checkpoint snapshot,
checks both signed roots before writing, and emits only a logarithmic proof.

Closed contracts are available from
`policy-lifecycle-log-consistency-proof-schema` and
`policy-lifecycle-log-consistency-verification-report-schema`. MCP exposes
`create_policy_lifecycle_public_log_consistency` and
`verify_policy_lifecycle_public_log_consistency`. The Action accepts
`policy-lifecycle-log-previous-anchor-proof` and
`policy-lifecycle-log-consistency-proof` alongside the current anchor,
publishes the verification report and boolean result, and can fail closed with
`fail-on-policy-lifecycle-log-consistency: "true"`.

Exchange a trusted tree-head observation with an independently operated CI
consumer:

```sh
pcbex sign-policy-lifecycle-log-gossip-receipt \
  --anchor policy-lifecycle.anchor.previous.json \
  --log-id organization-lifecycle-log \
  --log-public-key lifecycle-public-log.pub \
  --observer-id independent-ci \
  --private-key independent-ci-gossip.key \
  --received-at-unix 1785301600 \
  --expires-at-unix 1785906400 \
  --output policy-lifecycle.gossip.json

pcbex verify-policy-lifecycle-log-gossip-receipt \
  --local-anchor policy-lifecycle.anchor.json \
  --receipt policy-lifecycle.gossip.json \
  --consistency-proof policy-lifecycle.consistency.json \
  --log-id organization-lifecycle-log \
  --log-public-key lifecycle-public-log.pub \
  --observer-id independent-ci \
  --observer-public-key independent-ci-gossip.pub \
  --evaluated-at-unix 1785301700 \
  --output policy-lifecycle.gossip-verification.json
```

The observer first verifies the original log signature, then domain-separates
and signs the exact tree-head digest, log identity, tree size, root, log key,
receipt time, and expiry. Observer and log keys must be independent. Receipts
are valid for at most seven days and fail before their receipt time or after
expiry. Verification pins the observer identity and key separately from the
log identity and key. Equal-size trees must have the same root; different-size
trees require an exact v1.356.0 consistency proof in either direction. This
rejects observer, key, tree-head, timestamp, signature, log, root, and
consistency-proof substitution, including same-size split views.

Closed contracts are available from
`signed-policy-lifecycle-log-gossip-receipt-schema` and
`policy-lifecycle-log-gossip-verification-report-schema`. MCP exposes
`sign_policy_lifecycle_public_log_gossip_receipt` and
`verify_policy_lifecycle_public_log_gossip_receipt`; signing is task-forbidden.
The Action accepts `policy-lifecycle-log-gossip-receipt`, separately trusted
observer identity and key, evaluation time, and an optional consistency proof.
It publishes the verification report and boolean result and can fail closed
with `fail-on-policy-lifecycle-log-gossip: "true"`.

Require a fresh view shared by distinct organizations, including observations
acquired directly from bounded remote services:

```sh
pcbex request-policy-lifecycle-log-gossip-observation \
  --local-anchor policy-lifecycle.anchor.json \
  --endpoint https://observer-a.example/v1/gossip \
  --log-id organization-lifecycle-log \
  --log-public-key lifecycle-public-log.pub \
  --organization-id independent-lab \
  --observer-id independent-lab-ci \
  --observer-public-key independent-lab-gossip.pub \
  --evaluated-at-unix 1785301700 \
  --output independent-lab.observation.json \
  --receipt-output independent-lab.transport.json

pcbex verify-policy-lifecycle-log-gossip-quorum \
  --local-anchor policy-lifecycle.anchor.json \
  --observation independent-lab.observation.json \
  --observation security-partner.observation.json \
  --organization-id independent-lab \
  --organization-id security-partner \
  --observer-id independent-lab-ci \
  --observer-id security-partner-ci \
  --observer-public-key independent-lab-gossip.pub \
  --observer-public-key security-partner-gossip.pub \
  --minimum-organizations 2 \
  --log-id organization-lifecycle-log \
  --log-public-key lifecycle-public-log.pub \
  --evaluated-at-unix 1785301700 \
  --output policy-lifecycle.gossip-quorum.json \
  --require-quorum
```

Each observation envelope pairs one signed receipt with its optional exact
consistency proof, preventing proof/receipt re-pairing between observers.
Quorum verification freshly checks every log signature, observer signature,
validity window, and prefix proof, then rejects duplicate organizations,
observer identities, keys, or receipts. Members are canonically ordered and a
below-threshold report is retained before the optional gate fails. Even when a
receipt has a longer valid lifetime, quorum membership additionally requires
receipt acquisition within the preceding 24 hours.

Remote acquisition accepts HTTPS only, follows no redirects, limits the
end-to-end request to 1–600 seconds and the response to 1 MiB, keeps an
optional Bearer secret out of argv and retained evidence, and writes the
observation plus a request/response-hash-bound transport receipt atomically
only after full cryptographic verification. Loopback HTTP exists solely as a
hidden test escape hatch.

Closed contracts are emitted by
`policy-lifecycle-log-gossip-observation-schema`,
`policy-lifecycle-log-gossip-quorum-schema`, and
`remote-policy-lifecycle-log-gossip-receipt-schema`. MCP exposes
`verify_policy_lifecycle_public_log_gossip_quorum` and
`request_remote_policy_lifecycle_public_log_gossip`. The Action accepts local
observation tuples and/or up to ten remote observer tuples, publishes quorum
and remote transport evidence, and can fail closed with
`fail-on-policy-lifecycle-log-gossip-quorum: "true"`.

Retain each organization's observer identity across controlled key changes:

```sh
pcbex init-policy-lifecycle-log-gossip-observer-trust \
  --organization-id independent-lab \
  --observer-id independent-lab-ci \
  --public-key independent-lab-gossip.pub \
  --output independent-lab-gossip.trust.json

pcbex sign-policy-lifecycle-log-gossip-observer-key-rotation \
  independent-lab-gossip.trust.json \
  --old-private-key independent-lab-gossip.key \
  --new-private-key independent-lab-gossip.next.key \
  --rotated-at-unix 1785301800 \
  --output independent-lab-gossip.rotation.json

pcbex apply-policy-lifecycle-log-gossip-observer-key-rotation \
  independent-lab-gossip.trust.json \
  independent-lab-gossip.rotation.json \
  --output independent-lab-gossip.next.trust.json \
  --public-key-output independent-lab-gossip.next.pub
```

The immutable trust state binds organization ID, observer ID, exact key
generation, current Ed25519 key, previous rotation digest, and monotonic
rotation time. A one-generation transition is domain-separated and requires
both old-key authorization and proof of possession of the new key. Replay,
fork, skipped generation, same-key replacement, identity substitution,
wrong-old-key use, signature mutation, and time reversal fail before any
output is written.

Pass repeated `--observer-trust-state` values instead of the direct
organization/observer/key tuples to
`verify-policy-lifecycle-log-gossip-quorum` or pass one
`--observer-trust-state` to remote acquisition. The resulting trust-bound
quorum nests the complete v1.358.0 quorum and canonically records every
observer trust-state digest, generation, identity, and current key. Remote
transport receipts likewise bind the accepted trust-state digest and
generation.

Closed contracts are emitted by
`policy-lifecycle-log-gossip-observer-trust-state-schema`,
`signed-policy-lifecycle-log-gossip-observer-key-rotation-schema`, and
`policy-lifecycle-log-gossip-trust-bound-quorum-schema`. MCP exposes
initialize, sign, apply, and export operations as task-forbidden tools, while
quorum verification accepts trust-state arrays. The Action accepts local and
remote `*-gossip-*-trust-state-files` as a mutually exclusive replacement for
direct identity/key tuples.

Govern organization membership separately from each observer's rotatable key:

```sh
pcbex init-policy-lifecycle-log-gossip-organization-registry \
  --registry-id production-gossip \
  --authority-public-key gossip-registry-authority.pub \
  --output gossip-registry.0.json

pcbex sign-policy-lifecycle-log-gossip-organization-registry-transition \
  gossip-registry.0.json \
  --authority-private-key gossip-registry-authority.key \
  --action admit-observer \
  --organization-id independent-lab \
  --observer-trust-state independent-lab-gossip.trust.json \
  --reason-sha256 "$ADMISSION_RECORD_SHA256" \
  --effective-at-unix 1785301900 \
  --output gossip-registry.admit.json

pcbex apply-policy-lifecycle-log-gossip-organization-registry-transition \
  gossip-registry.0.json gossip-registry.admit.json \
  --output gossip-registry.1.json
```

The registry authority signs every exact one-generation transition under a
separate domain. Transitions chain the previous digest and monotonic time.
`admit-observer` binds the exact observer trust-state digest and can update
that digest after an authorized observer-key rotation. `suspend-organization`
immediately removes all of the organization's observers from quorum
eligibility; `revoke-organization` is permanent. Replay, fork, skipped
generation, wrong authority, signature mutation, duplicate admission,
unknown-organization status changes, and attempts to admit into a non-active
organization fail closed.

Pass `--organization-trust-registry gossip-registry.json` together with
`--observer-trust-state` values during quorum verification. The registry-bound
report nests the complete trust-bound quorum and records the exact registry
identity, generation, and SHA-256. Closed schemas cover the registry, signed
transition, and registry-bound quorum. MCP exposes initialization, signing,
and application as task-forbidden tools. The Action accepts
`policy-lifecycle-log-gossip-organization-trust-registry` only with
trust-state mode.

Rotate the registry authority without resetting its organization history:

```sh
pcbex sign-policy-lifecycle-log-gossip-organization-registry-authority-key-rotation \
  gossip-registry.json \
  --old-private-key gossip-registry-authority.key \
  --new-private-key gossip-registry-authority.next.key \
  --rotated-at-unix 1785302000 \
  --output gossip-registry-authority.rotation.json

pcbex apply-policy-lifecycle-log-gossip-organization-registry-authority-key-rotation \
  gossip-registry.json gossip-registry-authority.rotation.json \
  --output gossip-registry.next.json \
  --public-key-output gossip-registry-authority.next.pub
```

The rotation occupies the next generation in the same registry transition
chain and binds the registry identity, prior transition digest, old/new keys,
and monotonic rotation time. Both old-key authorization and new-key possession
must verify. All admitted observers and suspension/revocation decisions remain
unchanged. Replay, fork, skipped generation, registry substitution, wrong-old
key, same-key replacement, signature mutation, and time reversal fail before
either output is written. The next ordinary registry transition must be signed
by the new authority and extend the rotation digest.

The closed rotation contract is emitted by
`signed-policy-lifecycle-log-gossip-organization-registry-authority-key-rotation-schema`.
MCP exposes sign/apply operations as task-forbidden tools. The Action can apply
one retained rotation with
`policy-lifecycle-log-gossip-organization-registry-authority-key-rotation`
before registry-bound quorum verification.

Require a quorum of distinct authority identities for registry decisions:

```sh
pcbex sign-policy-lifecycle-log-gossip-organization-registry-governance \
  gossip-registry.json \
  --registry-authority-private-key gossip-registry-authority.key \
  --minimum-approvals 2 \
  --authority-id security --authority-public-key security.pub \
  --authority-id hardware --authority-public-key hardware.pub \
  --authority-id compliance --authority-public-key compliance.pub \
  --issued-at-unix 1785302100 \
  --output gossip-registry.governance.json

pcbex sign-policy-lifecycle-log-gossip-organization-registry-threshold-transition \
  gossip-registry.json gossip-registry.governance.json \
  --authority-id security --authority-private-key security.key \
  --authority-id hardware --authority-private-key hardware.key \
  --action suspend-organization \
  --organization-id compromised-lab \
  --reason-sha256 "$INCIDENT_SHA256" \
  --effective-at-unix 1785302200 \
  --output gossip-registry.suspend.json

pcbex apply-policy-lifecycle-log-gossip-organization-registry-threshold-transition \
  gossip-registry.json gossip-registry.governance.json \
  gossip-registry.suspend.json \
  --output gossip-registry.next.json
```

The retained registry root signs the governance policy, which fixes a
configurable threshold and an ordered set of distinct authority identities and
keys. Every admission, suspension, or revocation then binds that exact policy
digest, registry identity, prior transition digest, next generation, action,
reason, and monotonic time under a separate domain. Duplicate identities or
keys, untrusted signers, insufficient quorum, policy/root substitution,
signature mutation, replay, and forks fail before output is written.

The first threshold transition also retains its governance SHA-256 directly in
the registry. Every later threshold transition must use that exact digest, and
an approved governance rotation atomically replaces it with the successor
digest. Consumers therefore reject a different or stale policy even when it
has a valid registry-root signature, without carrying a separate trust
pointer. Once governance is active, root-only organization transitions and
root-only authority-key rotations are locked out instead of bypassing the
threshold.

Closed schemas cover both root-signed governance and threshold transitions.
MCP exposes sign/apply operations as task-forbidden tools. The Action accepts
the governance and threshold transition together, applies them atomically
after any authority-key rotation, and uses only the resulting registry for
quorum verification.

Governance itself rotates through the same registry chain. Create a successor
root-signed policy, then run
`sign-policy-lifecycle-log-gossip-organization-registry-governance-rotation`
with repeated old and new authority identity/private-key pairs. Apply it with
the retained registry, both policies, and the rotation artifact. The transition
binds both policy digests, the prior registry digest, the next generation, and
monotonic time under a dedicated domain. Both configured quorums must verify;
missing members, key or policy substitution, signature mutation, replay, fork,
and stale successor policies fail before the registry is written.

The closed contract is emitted by
`signed-policy-lifecycle-log-gossip-organization-registry-governance-rotation-schema`.
MCP exposes sign/apply as task-forbidden tools. The Action accepts old policy,
new policy, and rotation together, applies the change atomically, and uses the
successor policy for any following threshold transition. The registry schema
exposes the nullable `active_governance_sha256` field; initialization leaves it
unset, threshold bootstrap sets it, ordinary governed changes preserve it, and
only governance or governed-root rotation may replace it.

After governance activation, rotate a lost or expiring registry root without
dropping the retained threshold:

```sh
pcbex sign-policy-lifecycle-log-gossip-organization-registry-successor-governance \
  gossip-registry.json \
  --successor-registry-authority-private-key gossip-registry-root.next.key \
  --minimum-approvals 2 \
  --authority-id next-security --authority-public-key next-security.pub \
  --authority-id next-hardware --authority-public-key next-hardware.pub \
  --issued-at-unix 1785302300 \
  --output gossip-registry.governance.next-root.json

pcbex sign-policy-lifecycle-log-gossip-organization-registry-governed-authority-key-rotation \
  gossip-registry.json \
  gossip-registry.governance.json \
  gossip-registry.governance.next-root.json \
  --old-authority-id security --old-authority-private-key security.key \
  --old-authority-id hardware --old-authority-private-key hardware.key \
  --new-authority-id next-security --new-authority-private-key next-security.key \
  --new-authority-id next-hardware --new-authority-private-key next-hardware.key \
  --rotated-at-unix 1785302400 \
  --output gossip-registry.root.rotation.json

pcbex apply-policy-lifecycle-log-gossip-organization-registry-governed-authority-key-rotation \
  gossip-registry.json \
  gossip-registry.governance.json \
  gossip-registry.governance.next-root.json \
  gossip-registry.root.rotation.json \
  --output gossip-registry.next-root.json \
  --public-key-output gossip-registry-root.next.pub
```

The successor policy's root signature proves possession of the prospective
root private key. Both the retained active governance quorum and the successor
quorum independently approve one domain-separated payload binding the old/new
root keys, old/new policy digests, exact next generation, prior transition
digest, and monotonic time. Applying it replaces the root and active governance
digest atomically while preserving every organization decision. Missing
quorum, stale or forged successor policy, root/policy/key substitution,
signature mutation, replay, fork, and time rollback fail before either output
is written. The Action reuses its old/new governance inputs with
`policy-lifecycle-log-gossip-organization-registry-governed-authority-key-rotation`;
ordinary governance rotation and root-only rotation are mutually exclusive.
MCP exposes successor-policy creation and sign/apply rotation as task-forbidden
tools, and the closed artifact contract is available from
`signed-policy-lifecycle-log-gossip-organization-registry-governed-authority-key-rotation-schema`.

Audit an entire mixed registry history without accepting intermediate registry
snapshots as trust anchors:

```sh
pcbex audit-policy-lifecycle-log-gossip-organization-registry-history \
  gossip-registry.history.json \
  --output gossip-registry.history.audit.json \
  --final-registry-output gossip-registry.verified.json
```

The closed history contains only an empty generation-zero registry and an
ordered typed event stream. Events may be legacy root-signed transitions,
dual-signed legacy root rotations, threshold transitions with their exact
root-signed governance, dual-quorum governance rotations, or dual-quorum
governed root rotations. `pcbex` replays every event through the same
production verifier used by the individual apply commands and emits an entry
for each exact event digest, computed registry digest, retained root, and
active governance digest. The audit rejects non-genesis starts, more than
10,000 events, reordering, chain-breaking omissions, replay, forks, generation gaps, stale
time, policy substitution, invalid signatures, and insufficient quorums before
either output is written. Its schemas are available from
`policy-lifecycle-log-gossip-organization-registry-history-schema` and
`policy-lifecycle-log-gossip-organization-registry-history-audit-schema`.
GitHub Actions accepts
`policy-lifecycle-log-gossip-organization-registry-history`, exports the audit
and computed final registry, and forbids pairing the history with a copied
retained registry. MCP exposes the same atomic audit as a task-forbidden tool.
The audit proves internal completeness and authenticity of the supplied chain;
it does not by itself prove that a valid prefix is the globally latest head.

Publish and independently witness the exact audited head:

```sh
pcbex sign-policy-lifecycle-log-gossip-organization-registry-history-checkpoint \
  gossip-registry.history.json \
  --authority-private-key gossip-registry-root.key \
  --issued-at-unix 1785302500 \
  --output gossip-registry.history.checkpoint.json

pcbex accept-policy-lifecycle-log-gossip-organization-registry-history-checkpoint \
  gossip-registry.history.json gossip-registry.history.checkpoint.json \
  --baseline gossip-registry.history.checkpoint.previous.trust.json \
  --accepted-at-unix 1785302600 \
  --output gossip-registry.history.checkpoint.trust.json

pcbex verify-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witnesses \
  gossip-registry.history.json gossip-registry.history.checkpoint.json \
  --witness witness-a.json --witness witness-b.json \
  --trusted-witness-id independent-a \
  --trusted-witness-id independent-b \
  --trusted-witness-public-key independent-a.pub \
  --trusted-witness-public-key independent-b.pub \
  --minimum-witnesses 2 --evaluated-at-unix 1785302700 \
  --require-quorum --output gossip-registry.history.checkpoint.quorum.json
```

The root signature binds the complete audit digest, computed registry digest,
last transition, active governance, retained root, and exact generation.
Acceptance pins that checkpoint and rejects rollback, history truncation, or a
different valid checkpoint at the same generation. A higher generation must
contain the pinned state at its exact prior position. Each witness independently
replays the entire history before signing, and quorum verification requires
fresh signatures from distinct trusted identities and keys over the same
checkpoint. This detects split views once conflicting artifacts reach a common
consumer; it does not claim network-wide latest-head discovery.

Closed schemas cover checkpoints, trust states, witnesses, and quorum reports.
MCP exposes all four operations as task-forbidden tools. GitHub Actions accepts
the signed checkpoint and optional baseline trust state, then can require a
fresh witness quorum using paired witness artifacts, trusted IDs, and trusted
public-key files.

Long-lived checkpoint witnesses can rotate keys without resetting identity
trust. Initialize a witness trust state, create a rotation signed by both the
retained and successor private keys, and apply it:

```sh
pcbex init-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witness-trust \
  --witness-id independent-a --public-key independent-a.pub \
  --output independent-a.trust.json
pcbex sign-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witness-key-rotation \
  independent-a.trust.json --old-private-key independent-a.key \
  --new-private-key independent-a.next.key --rotated-at-unix 1785302800 \
  --output independent-a.rotation.json
pcbex apply-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witness-key-rotation \
  independent-a.trust.json independent-a.rotation.json \
  --output independent-a.next.trust.json \
  --public-key-output independent-a.next.pub
```

The transition advances exactly one generation and binds the previous rotation
digest, both public keys, witness identity, and monotonic time under a dedicated
domain. Replay, forks, identity/key substitution, same-key rotation, and either
missing signature fail before outputs are written. Quorum verification accepts
repeated `--witness-trust-state` values as an exclusive alternative to direct
ID/key pairs. The Action exposes the same alternative through
`policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witness-trust-state-files`,
and MCP exposes initialize/sign/apply/export operations as task-forbidden tools.

Independent witnesses no longer need to be pre-staged. A consumer can send the
accepted checkpoint trust state to a bounded HTTPS service and immediately
verify the returned signature against either a direct key or the rotatable
identity-bound trust state:

```sh
pcbex request-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witness \
  gossip-registry.history.checkpoint.trust.json \
  --endpoint https://witness.example/v1/registry-history-checkpoint \
  --witness-key-trust-state independent-a.next.trust.json \
  --evaluated-at-unix 1785302900 \
  --output independent-a.remote-witness.json \
  --receipt-output independent-a.remote-receipt.json
```

The client permits HTTPS only, follows no redirects, bounds the complete
request to 600 seconds and the JSON response to 1 MiB, and keeps optional
Bearer credentials in an environment variable. Both output files are written
atomically only after the closed response is checkpoint-bound, fresh,
identity/key-bound, and cryptographically valid. The receipt binds the endpoint,
accepted checkpoint and trust-state digests, exact request and response hashes,
response length, evaluation time, and witness-key generation. GitHub Actions
accepts paired remote endpoints with either identities/public keys or witness
trust states, retains every response and receipt, and composes them with local
artifacts in the same fail-closed quorum. MCP exposes the same HTTPS-only
operation as an open-world, task-forbidden tool.

Verified remote registry-history witness receipts can also become first-class
append-only transparency events. This reuses the existing signed approval-log
checkpoint, public-anchor, independent-witness, remote-witness, and witness-key
rotation machinery:

```sh
pcbex init-approval-log --log-id registry-witness-receipts \
  --output receipt-log.0.json
pcbex append-approval-log receipt-log.0.json \
  --artifact independent-a.remote-receipt.json \
  --kind remote-registry-history-checkpoint-witness-receipt \
  --recorded-at-unix 1785303000 --output receipt-log.1.json
pcbex sign-approval-log receipt-log.1.json \
  --private-key receipt-log.key --signer-id registry-receipt-log \
  --output receipt-log.checkpoint.json
```

Append structurally validates the closed receipt, transport adapter,
HTTPS-or-test-loopback policy, response bound, true verification decision,
checkpoint/trust-state hashes, request/response hashes, witness key, identity,
and optional key-generation binding before creating a new immutable log
snapshot. Its normalized event retains the receipt digest, exact checkpoint
digest, request/response digests, and witness identity. Mutation after append,
replay that breaks sequence, truncation, reordering, or a false verification
decision fails before output. The log signer remains responsible for admitting
receipts produced by its trusted acquisition boundary. The existing MCP append
tool accepts this artifact kind, and the Action's signed transparency-log
verification, public anchor, and witness-quorum gates apply without a separate
trust mechanism.

### GitHub Actions hardware CI

The repository is also a composite GitHub Action. It builds the engine from the
selected pcbex tag, analyzes the current board, adds Markdown to the Job
Summary, and uploads the complete bundle. An optional baseline board enables
the structured regression comparison. The public action keeps its direct
`pr-comment` input as a backwards-compatible opt-in for trusted callers; the
example below is therefore only appropriate when the caller deliberately
grants comment-write access and does not execute unreviewed pull-request code:

```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write

steps:
  - uses: actions/checkout@v7
  - uses: actions/checkout@v7
    with:
      ref: ${{ github.event.pull_request.base.sha }}
      path: .pcbex-baseline
  - name: Install trusted pcbex policy root
    env:
      PCBEX_POLICY_PUBLIC_KEY: ${{ vars.PCBEX_POLICY_PUBLIC_KEY }}
    run: |
      umask 077
      printf '%s\n' "$PCBEX_POLICY_PUBLIC_KEY" \
        > "$RUNNER_TEMP/pcbex-policy-root.pub"
  - id: hardware
    uses: penguin425/pcbex@v1.424.0
    with:
      board: hardware/controller.kicad_pcb
      baseline-board: .pcbex-baseline/hardware/controller.kicad_pcb
      schematic: hardware/controller.kicad_sch
      baseline-schematic: .pcbex-baseline/hardware/controller.kicad_sch
      schematic-reviewer-routing-policy: hardware/reviewer-routing-policy.json
      fail-on-unrouted-schematic-review: "true"
      signed-policy-pack: hardware/organization-policy-pack.signed.json
      policy-public-key: ${{ runner.temp }}/pcbex-policy-root.pub
      policy-trust-state: .pcbex-baseline/hardware/organization-policy-pack.trust.json
      ai-review-request: hardware/review-request.json
      ai-review-generated-schematic: hardware/controller.kicad_sch
      ai-review-session: hardware/review-session.json
      ai-approval-files: |
        hardware/reviewer-a.approval.json
        hardware/reviewer-b.approval.json
      ai-response-files: |
        hardware/reviewer-a.response.json
        hardware/reviewer-b.response.json
      deterministic-pipeline-plan: hardware/pipeline-plan.json
      fail-on-ai-quorum: "true"
      manufacturing-feedback-declaration: manufacturing/fab-feedback.json
      manufacturing-feedback-artifacts: |
        manufacturing/inspection.csv
        manufacturing/fab-report.pdf
      fail-on-manufacturing-feedback: "true"
      fail-on-regressions: "true"
      upload-sarif: "true"
      pr-comment: ${{ github.event.pull_request.head.repo.full_name == github.repository }}
      github-token: ${{ github.token }}
      comment-id: controller-layout
```

The action outputs the artifact directory, current and comparison SARIF paths,
violation count, regression result, and optional PR comment URL.
`upload-sarif` is opt-in because the calling job must grant
`security-events: write`; artifact upload defaults to on.

Version 1.423 adds opt-in circuit-spec writer parity. Supplying
`circuit-spec` first retains the immutable ERC report at the fixed
`${output-dir}/circuit-spec-check.json` path. A rejected design exposes
`circuit-spec-check` and `circuit-spec-approved: "false"` before the Action
fails, and no schematic is created. An approved design additionally emits
`${output-dir}/circuit-spec.kicad_sch` and exposes its fixed path, byte count,
and SHA-256:

```yaml
- id: generated-schematic
  uses: penguin425/pcbex@v1.424.0
  with:
    board: hardware/controller.kicad_pcb
    circuit-spec: build/circuit-spec-v2.json
```

The output names are `circuit-spec-schematic`,
`circuit-spec-schematic-bytes`, and `circuit-spec-schematic-sha256`. The
Action does not replace its `schematic` input with this artifact or inject it
into either pipeline; callers must make that later trust decision explicitly.
Writer generation adds no network access.

Version 1.414.0 adds opt-in hardware-pipeline parity. Set
`pipeline-verify: "true"` and provide the existing `board`/`schematic` plus
the closed electrical review, final manufacturing ZIP, and firmware manifest;
`pipeline-electrical-policy`, `pipeline-factory-receipt`, and
`pipeline-require-factory` are optional. The Action forwards the generated
analysis manifests, any automatically discovered sibling `.kicad_pro` and
`.kicad_dru` inputs, the effective physical profile/policy, and these inputs
to `pipeline-verify`, then exposes `pipeline-report` and `pipeline-passed`:

```yaml
# Add these fields to a `penguin425/pcbex@v1.424.0` step:
with:
  board: hardware/controller.kicad_pcb
  schematic: hardware/controller.kicad_sch
  pipeline-verify: "true"
  pipeline-electrical-review: build/electrical-review.json
  pipeline-manufacturing-package: build/manufacturing/manufacturing.zip
  pipeline-firmware-manifest: build/firmware/manifest.json
```

The gate writes its JSON report, Job Summary, comment content, and retained
artifact evidence even when a phase rejects an input. The final Action
enforcement step fails afterward when `pipeline-passed` is not `true`, so a
failed check remains available for diagnosis. Keep the opt-in disabled for
analysis-only workflows. The Action requires `output-dir` to be absent or an
empty real directory when the step starts; a symlink or any pre-existing entry
is rejected before analysis so stale or attacker-controlled files cannot be
published as evidence.

Toolchain installation, compilation, and hardware analysis run through a
process-tree supervisor with fixed deadlines and output ceilings. Artifact,
SARIF, and trusted direct-comment publication additionally require a
regular-file-only analysis tree within 4,096 entries, depth 16, 128 MiB per
file, and 512 MiB total. Repository workflows also enforce explicit job
timeouts and two-run matrix parallelism; the complete contract is documented
in [bounded release and CI execution](docs/CI_EXECUTION_LIMITS.md).

`pr-comment` remains opt-in and requires both `pull-requests: write` and an
explicit `github-token`. A stable `comment-id` creates a hidden marker; later
runs update the newest editable matching comment instead of appending another.
The comment body is read from the generated `pr-comment.md` artifact and is
never expanded as shell source. Invalid identities, blank or oversized bodies,
unexpected API shapes, and missing event context fail closed. The example
disables comments for fork PRs, whose default `GITHUB_TOKEN` is read-only,
while still producing their Job Summary and evidence artifact.

This repository uses a stricter split for its own pull-request workflow. The
job that checks out and executes pull-request code has only `contents: read`;
checkout does not persist credentials, the local action receives no token
input, and the job has no comment-write permission. It emits only a small,
hash-bound publisher artifact containing the
minimum run, attempt, PR, head/base, and comment-body provenance needed by the
publisher. A default-branch `workflow_run` publisher is the only comment writer
and has `actions: read` plus `pull-requests: write`. Before posting, it
revalidates repository names and immutable IDs, the event, exact run and
attempt, exact artifact and digest, current PR head/base, and that the run is
the newest eligible run for the PR. Closed or stale PRs are skipped; malformed
or invalid bindings fail closed. The artifact's `pr-comment.md` is untrusted
data, so the publisher adds a provenance banner, escapes raw HTML, suppresses
mentions, and never treats its contents as instructions or shell source. It
updates only marker comments owned by `github-actions[bot]`, and never forwards
the API bearer token across an artifact-download redirect. This separation
reduces token exposure; it is not a general sandbox for arbitrary action code
or the hosted runner.

Every external GitHub Action used by this repository is pinned to a reviewed
40-character commit SHA, with the corresponding release version retained as a
comment for auditability. A repository test rejects mutable tags, branches,
short SHAs, expressions, and Docker `uses:` references across workflows and
composite actions. Dependabot proposes weekly GitHub Actions updates, while the
repository setting rejects any workflow that introduces a non-SHA external
reference. The release audit's `--check-protection` mode verifies that this
enforcement remains enabled; the full update procedure and reviewed commit map
are documented in
[`docs/GITHUB_ACTIONS_SUPPLY_CHAIN.md`](docs/GITHUB_ACTIONS_SUPPLY_CHAIN.md).
The semver references in the caller-facing example above prioritize a stable
public integration contract; production callers may pin those references to
reviewed commit SHAs under their own supply-chain policy.

Callers select exactly one of `fab`, `fab-profile`, `policy-pack`, or
`signed-policy-pack`. A signed pack additionally requires
`policy-public-key`; `policy-trust-state` optionally pins the accepted state
from the protected base revision. The same authenticated physical policy is
applied to current and baseline analysis, and the exact verified source digest
is retained in each run manifest. The Action also outputs and uploads
`verified-policy-trust-state.json` for review and later adoption.
When a manufacturing declaration is supplied, the Action publishes its bound
JSON, Markdown, and SARIF, appends the result to the Job Summary and PR comment,
and exposes `manufacturing-feedback` plus `manufacturing-feedback-passed`.
Artifact paths are supplied one per line; the manufacturing gate is opt-in so
design-only workflows remain backward compatible.
Supplying both `schematic` and `baseline-schematic` adds semantic JSON,
Markdown, and SARIF to the same evidence bundle and exposes
`schematic-diff` plus `schematic-review-required`. The optional schematic gate
therefore blocks electrical-intent changes while allowing drawing-only edits.
Supplying `schematic-reviewer-routing-policy` additionally recomputes that
semantic diff and assigns every change to one or more specialist AI reviewer
profiles. Changes not claimed by a specialist are assigned to the mandatory
fallback profile. The Action publishes `schematic-reviewer-routing` and
`schematic-review-all-routed`; the opt-in unrouted-review gate runs only after
the plan and Markdown summary have been retained.
Supplying one digest-bound `ai-review-request`, paired newline-separated
`ai-approval-files` and `ai-response-files`, and an organization policy pack
adds a verified multi-reviewer quorum report. The Action exposes
`ai-approval-quorum` and `ai-approval-quorum-met`; its opt-in gate runs only
after the JSON, Markdown, Job Summary, PR comment, and workflow artifact are
retained. Approval, provider, and model thresholds default to two and remain
independently configurable. Supplying `ai-review-session` additionally requires
every approval to carry the active session challenge and rejects expired or
legacy envelopes.

Version 1.424 additionally accepts `ai-review-generated-schematic` together
with `deterministic-pipeline-plan`. This opts the quorum into request-schema-v2
artifact binding. Version 1.425 additionally accepts
`ai-review-native-kicad-erc-report` (and `ai-review-kicad-cli`) to opt into
request-schema-v3 native KiCad ERC evidence. Version 1.426 adds
`ai-review-native-kicad-erc-warning-policy`, which opts a report-v2 flow into
request schema v4 and publishes its warning budget result and policy identity.
The Action runs the plan and,
when enabled, reads the retained native report before quorum verification;
the CLI live-verification gate independently reruns the fixed error-only
native ERC check and the deterministic plan before accepting signatures. See
[`docs/AI_REVIEW_ARTIFACT_BINDING.md`](docs/AI_REVIEW_ARTIFACT_BINDING.md) and
[`docs/NATIVE_KICAD_ERC.md`](docs/NATIVE_KICAD_ERC.md).
Only after that gate succeeds, the Action exposes
`ai-review-artifacts-verified`, generated-schematic byte/SHA outputs, raw plan
source byte/SHA outputs, normalized `ai-review-pipeline-plan-sha256`, retained
report byte/SHA outputs, and `ai-review-pipeline-run-sha256`. Omitting the
generated schematic preserves request-schema-v1 behavior.

Violation and regression gates run only after uploads and comment updates, so
a failed PR check still retains the JSON, SVG, SARIF, summaries, and provenance
manifests. Baseline checkout is intentionally caller-controlled, allowing a PR
workflow to compare against its exact base SHA without using
`pull_request_target`.

### MCP server

Start the built-in Model Context Protocol server over stdio:

```sh
pcbex mcp-server
```

Configure an MCP host to launch the binary directly:

```json
{
  "mcpServers": {
    "pcbex": {
      "command": "/absolute/path/to/pcbex",
      "args": ["mcp-server"]
    }
  }
}
```

The server implements the 2025-11-25 MCP lifecycle and negotiates compatible
2025-06-18, 2025-03-26, and 2024-11-05 clients. It exposes
`list_dfm_profiles`, policy verification, board analysis and routing,
manufacturing-feedback recording/comparison, schematic semantic comparison,
and signed schematic-review tools.
Every tool has a closed input schema, an output schema, safety annotations, a
human-readable text result, and matching `structuredContent`. Tool processes
capture stdout and stderr so the stdio transport emits only newline-delimited
JSON-RPC messages. Expected analysis or regression gate failures use
`isError: true` while retaining structured manifests and artifact paths;
malformed requests remain JSON-RPC errors so an agent can correct its call.
Each request and serialized response is capped at 16 MiB. Tool subprocesses
have a 600-second deadline, 16 MiB stdout ceiling, and 1 MiB stderr ceiling;
expired tasks actively cancel their running child.

For 2025-11-25 clients, the server also implements the experimental MCP Tasks
API. Board analysis/comparison/routing, manufacturing-feedback tools, and
schematic semantic comparison declare `execution.taskSupport: "optional"` and
accept task-augmented calls:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "analyze_kicad",
    "arguments": {
      "input": "board.kicad_pcb",
      "output_dir": "pcbex-analysis"
    },
    "task": {"ttl": 600000}
  }
}
```

Use `tasks/get` to poll, `tasks/result` to retrieve the original tool result,
`tasks/list` to inspect retained jobs, and `tasks/cancel` to terminate work.
Tasks are process-local, default to a 10-minute lifetime, and permit a requested
TTL up to 24 hours. The server retains at most 32 tasks and executes at most
four concurrently. A task watchdog actively cancels bounded child work at TTL
expiry. Older negotiated protocol versions continue to execute calls
synchronously and ignore task augmentation as required by their capability
model.

Version 1.414.0 carries the complete hardware pipeline boundary into MCP. The
server adds `check_schematic` (with optional explanation, JUnit, SARIF, and
policy inputs), `check_circuit_spec` (circuit-spec v2 plus the immutable ERC
floor), and `pipeline_verify` (the same required evidence and optional factory
arguments as the CLI). When Tasks are negotiated, each tool advertises
`execution.taskSupport: "optional"`; otherwise the call is synchronous. A
rejected check still returns its retained JSON report in structured content
with an error result, rather than dropping evidence.

Minimal schematic-check call:

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "tools/call",
  "params": {
    "name": "check_schematic",
    "arguments": {
      "input": "hardware/controller.kicad_sch",
      "output": "build/electrical-review.json"
    }
  }
}
```

For the complete gate, call `pipeline_verify` with `schematic`,
`electrical_review`, `board`, `analysis_manifest`, `analysis_checks`, `quality`,
`manufacturing_package`, `firmware_manifest`, and `output`; add
`analysis_physical_profile`, `factory_receipt`, or `require_factory` when those
bindings are selected. A caller that supports Tasks may add
`"task": {"ttl": 600000}` to the request and retrieve the retained result with
`tasks/get` and `tasks/result`.

Version 1.415.0 adds `verify_circuit_kicad_handoff`, a task-compatible
digest-bound verifier for an existing flat/single-unit KiCad schematic and a
circuit-spec v2. It returns source/canonical identities, native circuit and
schematic check/review evidence, findings, counts, and `approved`; a failed
`require_approved` call retains that report for the caller. Geometry/UUIDs,
hierarchy, buses, power-symbol extras, multi-unit symbols, unresolved
libraries, live suppliers, placement, routing, and fabrication remain outside
this closed verifier.

Version 1.416.0 adds the standalone `verify_circuit_kicad_board_binding`
operation.  It recalculates the v1.415 handoff from the raw circuit-spec v2 and
KiCad schematic, then binds the exact references, footprint metadata, pin/pad
numbers, nets, no-connect states, and assembly metadata to the actual
`.kicad_pcb`.  Board-net matching uses canonical net names from the imported
schematic; KiCad net 0 is a reserved no-net identifier, not a circuit terminal,
and remains validated.  The operation returns source, canonical, and binding
digests plus deterministically ordered findings for semantic mismatches;
ambiguous duplicate net declarations are malformed input.  Declared
no-connect pins map to same-numbered unconnected pads (`net 0` and an absent
net field are equivalent); only an empty, unconnected NPTH mechanical pad may
appear as an extra unnumbered pad, and a numbered NPTH pad cannot satisfy a
circuit pin.  Binding-relevant pad size, copper-layer membership, drill, and
supported custom-polygon structure fail closed.  It is task-compatible,
retains rejected reports before a required-approval failure, and rejects
bounded-input violations atomically.
Geometry, routing, DRC/DFM, hierarchy, buses, and multi-unit/nested handoffs
remain outside this strict closed subset.  Emit its schema with
`circuit-kicad-board-binding-schema` and see
[`docs/CIRCUIT_KICAD_BOARD_BINDING.md`](docs/CIRCUIT_KICAD_BOARD_BINDING.md)
for the CLI, MCP, and retained-report contract.  This operation is not a new
`pipeline-verify` phase; v1.417 composes it into the deterministic runner.

Version 1.418.0 adds the task-compatible `run_deterministic_pipeline` tool.
It accepts only `plan`, `output`, and optional `require_approved` arguments:

```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "method": "tools/call",
  "params": {
    "name": "run_deterministic_pipeline",
    "arguments": {
      "plan": "pipeline-plan.json",
      "output": "build/deterministic-pipeline-report.json",
      "require_approved": true
    },
    "task": {"ttl": 600000}
  }
}
```

The complete report remains at `output`. Because that report may approach
128 MiB while an MCP frame is limited to 16 MiB, structured content returns a
compact `report_summary` instead of duplicating the report. The bridge verifies
the retained file's exact byte count and SHA-256 plus its approval, failure
count, and plan/run identities before trusting the summary. A required-approval
rejection therefore returns `isError: true` with verified retained evidence;
it never truncates a valid report to fit the protocol frame.

Version 1.423 adds the task-compatible
`write_circuit_spec_kicad_schematic` tool. It accepts only `input` and
`output`, preflights an absent destination, invokes the same CLI writer, and
revalidates the retained regular file under the writer's 64 MiB ceiling. The
MCP result never embeds schematic text; `structuredContent.schematic` contains
only `path`, `bytes`, and `sha256`, keeping every response within the 16 MiB
frame boundary:

```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "method": "tools/call",
  "params": {
    "name": "write_circuit_spec_kicad_schematic",
    "arguments": {
      "input": "circuit-spec-v2.json",
      "output": "build/generated.kicad_sch"
    },
    "task": {"ttl": 600000}
  }
}
```

The tool is closed-world and performs no network call. Existing destinations,
aliases, links, writer rejection, cancellation, or retained-file identity
changes fail without attributing stale bytes to the call.

Analysis and routing tools require explicit output paths and may overwrite
files there. MCP hosts should retain their normal user-approval prompt for
these non-read-only tools.

Length groups may also set `tuning_amplitude_nm`, `tuning_pitch_nm`, and
`max_tuning_sections`. The tuner distributes the required delay across multiple
legal straight sections, checking the whole board after every section, while
the existing defaults retain single-section behavior.

## BGA escape routing

Escape groups require unique non-empty names, declared unique net IDs, and
exclusive membership so a net cannot be assigned to multiple escape groups.
Fanout distance and optional via grid must be positive, ring count must be
between 1 and 8, and the target must be a declared non-front copper layer.
Each unrouted group is preflighted to ensure its nets begin at front-layer
terminals. Router construction also rejects assigned nets that already have
routes.
`escape_groups` assigns dense package nets a fanout distance and target copper
layer. Four-way, radial, row, and column strategies classify package pads from
their group centroid. Via locations may snap to an absolute grid and search up
to eight outward rings; blocked candidates rotate through the remaining
directions. Before global routing, pcbex creates checked dog-bone tracks and
stackup-aware vias from each first terminal, routes from the escaped inner-layer
locations, then restores the original pad terminals. The completed board,
including every fanout stub, must pass the normal full-board checker.

## Return-path stitching

Return-path rules require unique non-empty names, one declared reference net,
and a non-empty set of unique declared signal nets distinct from the reference.
Maximum stitching-via distance and optional plane-sampling interval must both
be positive.

`return_path_rules` associates high-speed signal nets with a reference net and
a maximum signal-to-reference via distance. The board checker reports every
layer transition without a nearby reference via that spans the same layers.
With `auto_stitch: true`, routing adds a checked reference via and short
connection to existing reference copper when a legal site is available. A via
inside an owned reference Zone connects directly to that plane without an
artificial track.

With `require_continuous_plane: true`, each signal segment is sampled against
the stackup-selected reference layer. Missing fills and split-plane/slot
crossings produce `return_path_plane` violations; the optional
`plane_sample_spacing_nm` controls resolution.

## Rounded routing

New routes automatically replace legal orthogonal corners with tangent
quarter-circle arcs using the routing grid as the preferred radius. Each
replacement is kept only when the complete board passes connectivity,
clearance, edge, length, and manufacturing checks.

## Stackup impedance checks

KiCad `(setup (stackup ...))` data is imported automatically, including copper
thickness, adjacent dielectric height/permittivity, and reference planes on
both sides. Inner layers therefore retain symmetric stripline or asymmetric
embedded-microstrip geometry. JSON entries can define the second side with
`secondary_reference_layer`, `secondary_dielectric_height_nm`, and
`secondary_dielectric_constant`.
Net classes may set
`target_impedance_ohms` and `impedance_tolerance_ohms`; the normal checker uses
the copper-thickness-aware microstrip or embedded estimate for every routed
segment and reports missing stackup data or out-of-range geometry. Differential
pairs use the same stackup geometry. This is an early
layout constraint, not a replacement for a field solver or fabrication-house
stackup validation.
Every net-class name assigned to a net must exist in `net_classes`; both the
normal checker and Router reject unresolved names instead of silently applying
the base routing rules.
Net-class track widths and via drills must be positive, clearances must be
non-negative, and via diameters must be larger than their drills. These
dimensions are validated even when no net currently uses the class.
When a net class restricts routing layers, its `layers` value must be a
non-empty, duplicate-free subset of the board copper stackup. Omitting
`layers` keeps the class unrestricted.
Optional `minimum_length_nm` and `maximum_length_nm` values must be positive,
and a bounded range must place the minimum at or below the maximum.
Impedance targets and tolerances must be provided together as finite values;
targets must be positive, while tolerances and maximum impedance steps must be
non-negative.
Optional differential widths must be positive and differential gaps must be
non-negative; both normal DRC and Router construction enforce these dimensions.
Net-class table keys must contain at least one non-whitespace character.
Differential-pair definitions require unique non-empty names and two distinct,
declared member nets; a net may belong to at most one pair.

Set `maximum_impedance_step_ohms` on a net class to limit discontinuity where
connected segments change layers through a via. This check is independent of
the absolute target, so it also catches large layer-to-layer steps when both
segments would individually fit a broad target tolerance.

Use `pcbex impedance-width board.json --layer F.Cu --target-ohms 50` to
reverse-solve a trace width from the imported stackup. Add
`--differential-gap-mm 0.15` for a differential target. The command searches
the configured width range and emits the selected width and estimated impedance
as JSON, using the same microstrip or embedded model as DRC.

`pcbex impedance-report board.json [--output impedance.json]` audits every
routed segment and differential-pair member. Its JSON includes layer, width,
estimate, target deviation/pass state, allowed and observed via-transition
steps, and a total count of segments whose stackup geometry could not be
evaluated. Add `--fail-on-violations` for CI: the report is still written, then
the command exits unsuccessfully if geometry is missing, a segment misses its
target, or a via step exceeds its configured limit.
Use `--baseline previous-impedance.json` to reject regressions against an
earlier report. Besides increases in the three summary counters, this compares
the absolute target deviation of stable net/segment indexes and observed
transition steps for single-ended nets and both differential members.

## Manufacturing checks

Boards may define `manufacturing_rules` for minimum track width, copper
clearance, drill, annular ring, copper-to-edge distance, board thickness, and
maximum via aspect ratio. These checks are included in the normal board checker.

Built-in fabrication profiles make those rules explicit, revisioned, and
reproducible:

```sh
pcbex dfm-profiles
pcbex analyze-kicad board.kicad_pcb --output-dir build/analysis \
  --fab jlcpcb-2layer
pcbex route-kicad board.kicad_pcb --output routed.kicad_pcb \
  --fab pcbway-2layer
pcbex dfm board.json --fab jlcpcb-standard-2layer-1oz-v1
```

The stable aliases `jlcpcb-2layer` and `pcbway-2layer` currently resolve to the
immutable `jlcpcb-standard-2layer-1oz-v1` and
`pcbway-standard-2layer-1oz-v1` profiles. Each listing includes its revision,
verification date, official capability URLs, and exact nanometre rules.
`analyze-kicad` records the resolved profile and effective routing rules in
`run.json`. Profile application raises base and net-class track width,
clearance, drill, and annular-ring-derived via diameter where required; it
never lowers a stricter project rule. Both initial profiles model routed-edge
clearance and a 1.6 mm board. They use a conservative 10:1 via aspect-ratio
limit where the standard capability pages do not publish a tighter limit.

Organizations can distribute the same contract as a strict external JSON file:

```sh
pcbex dfm-profile-schema --output dfm-profile.schema.json
pcbex validate-dfm-profile hardware/acme-dfm.json \
  --output build/acme-dfm.normalized.json
pcbex analyze-kicad board.kicad_pcb --output-dir build/analysis \
  --fab-profile hardware/acme-dfm.json
```

External profiles use `schema_version: 1`, a stable lowercase ID, optional
aliases, a positive revision, a real `YYYY-MM-DD` verification date, at least
one HTTPS source, and a complete manufacturing-rules object. Unknown fields,
invalid dimensions, duplicate names or sources, and collisions with built-in
IDs or aliases fail closed. `--fab-profile` is supported by KiCad analysis,
routing, route-candidate generation, board DFM checks, the composite Action,
and the corresponding MCP analysis and routing tools. Analysis manifests bind
both the normalized resolved profile and the source file's path, byte length,
and SHA-256 digest.

### Physical constraint profiles

Use one closed physical profile when automation must also bind board geometry,
fixed connector/component coordinates, keepouts, and manufacturing minima:

```sh
pcbex physical-profile-schema --output physical-profile.schema.json
pcbex validate-physical-profile examples/nes-60pin-physical-profile.json
pcbex analyze-kicad board.kicad_pcb --output-dir build/analysis \
  --physical-profile examples/nes-60pin-physical-profile.json
pcbex fabricate board.kicad_pcb --output-dir build/manufacturing \
  --physical-profile examples/nes-60pin-physical-profile.json
```

The profile is applied by JSON/KiCad placement and routing as well as analysis
and fabrication. Profile-aware analysis and manufacturing manifests use schema
v2 and carry the same raw-source and domain-separated canonical SHA-256
binding; `pipeline-verify --analysis-physical-profile` recomputes and compares
that binding across both phases. Existing no-profile schema-v1 artifacts remain
valid. See [the physical-profile contract](docs/PHYSICAL_CONSTRAINT_PROFILE.md)
for limits, fail-closed behavior, GitHub Action/MCP usage, and the complete
pipeline example.

### Organization policy packs

An organization can bind its complete approval contract in one distributable
JSON file:

```sh
pcbex policy-pack-schema --output organization-policy-pack.schema.json
pcbex validate-policy-pack examples/acme-policy-pack.json \
  --output build/acme-policy-pack.normalized.json

pcbex analyze-kicad board.kicad_pcb --output-dir build/analysis \
  --policy-pack examples/acme-policy-pack.json
pcbex check-schematic design.kicad_sch \
  --policy-pack examples/acme-policy-pack.json \
  --output electrical-review.json --require-approved
```

The closed `schema_version: 1` contract combines one DFM profile, one
electrical policy, explicit AI-review requirements, whether simulation
evidence is mandatory, and an allowlist of signer IDs with Ed25519 public
keys. IDs, dates, dimensions, rule settings, requirements, and keys are
strictly validated; unknown fields, duplicates, and altered profiles that
impersonate built-in DFM identities fail closed. Private keys are never part
of a policy pack.

`--policy-pack` applies to KiCad analysis, routing, route-candidate generation,
board DFM checking, schematic checking, AI-review preparation, approval
verification, the composite Action, and the corresponding MCP analysis,
routing, preparation, and verification tools. It is mutually exclusive with
ad-hoc policy/profile overrides. Analysis manifests bind the pack ID, resolved
DFM rules, source path, byte length, and SHA-256 digest.

Authenticate packs before distributing them to CI:

```sh
# Run once and keep the private key outside the repository.
pcbex policy-keygen \
  --private-key .secrets/policy-signing.key \
  --public-key policy-root.pub

pcbex sign-policy-pack organization-policy-pack.json \
  --private-key .secrets/policy-signing.key \
  --signer-id hardware-security \
  --output organization-policy-pack.signed.json

pcbex signed-policy-pack-schema \
  --output signed-policy-pack.schema.json
pcbex verify-policy-pack organization-policy-pack.signed.json \
  --public-key policy-root.pub \
  --baseline-state accepted-policy.trust.json \
  --output build/verified-policy-pack.json \
  --state-output build/candidate-policy.trust.json
pcbex policy-trust-state-schema \
  --output policy-trust-state.schema.json
```

The signed envelope embeds the normalized pack and authenticates its SHA-256,
ID, revision, and signer under a domain-separated Ed25519 signature. Unknown
fields, digest mismatch, altered content, unsupported algorithms, invalid
signatures, and a key other than the separately trusted public key fail
closed. Key generation, signing, and verified extraction refuse to overwrite
existing files.

The optional baseline trust state records the accepted pack ID, highest
revision, exact canonical digest, signer ID, and signing public key. An
identical replay remains valid and a higher revision advances the candidate
state. A lower revision, different content under the same revision, or a
changed ID, signer, or key fails before extraction. The candidate state is
written separately and never mutates the accepted baseline; promote it through
the normal protected-branch review process.
The MCP server exposes the same authenticated extraction boundary as
`verify_policy_pack`, including `baseline_state` and `state_output`; it never
receives or exposes the signing private key.

CI can retrieve the signed envelope directly from an organization registry:

```sh
pcbex fetch-policy-pack \
  --endpoint https://policies.example/v1/current \
  --public-key policy-root.pub \
  --baseline-state accepted-policy.trust.json \
  --bearer-token-env PCBEX_POLICY_TOKEN \
  --signed-output build/policy.signed.json \
  --output build/policy.json \
  --state-output build/policy.trust.json \
  --receipt-output build/policy.fetch-receipt.json
```

Retrieval requires HTTPS, follows no redirects, accepts no URL query or
userinfo, bounds the total timeout and response to 4 MiB, and reads an optional
Bearer value only from the named environment variable. The response is
strictly parsed, signature-verified, and checked against the monotonic baseline
before any output is created. The four outputs are recovered together on a
write failure. The receipt binds the endpoint, raw response digest and size,
pack identity/revision/digest, signer key, and exact baseline without retaining
the token. `remote-policy-pack-receipt-schema` publishes its closed contract.
MCP exposes the same HTTPS-only `fetch_policy_pack` operation. The Action uses
`policy-pack-url`, `policy-public-key`, optional `policy-trust-state`, and
optional `policy-pack-bearer-token`, and retains both the signed response and
receipt as analysis artifacts.

For the composite Action, write the trusted public key from a protected
repository variable or secret into a runner-temporary file before invoking
the Action; do not derive trust from the public key embedded in the signed
envelope. The Action verifies and retains the extracted pack before current
or baseline analysis starts.

Invalid physical limits are reported individually as `dfm_rule_dimensions`;
track width, drill size, and board thickness must be positive, while clearance
and spacing limits may be zero but not negative.
The maximum via aspect ratio must be positive, and the minimum trace angle must
be at most 180 degrees; invalid values use `dfm_rule_aspect_ratio` and
`dfm_rule_trace_angle`, respectively.
Aspect-ratio comparisons use overflow-safe widened arithmetic for both routed
vias and plated component holes.
Annular-ring comparisons likewise use widened arithmetic, including exact
boundary handling for routed vias and circular or slotted plated holes.
Drill-to-drill spacing thresholds use widened, saturating arithmetic so extreme
input dimensions cannot wrap before geometric comparison.
Copper-to-edge envelopes use the same overflow-safe approach for tracks, vias,
and component holes.
PDN resistance estimation widens endpoint coordinate differences before
computing segment lengths, preventing wraparound on extreme board coordinates.
Acute trace-angle analysis reuses the widened coordinate-difference path for
both vectors at each junction.
Rotated component-hole offsets and slot endpoints use saturating coordinate
arithmetic at the signed board-coordinate boundaries.
PDN resistance estimation skips invalid or non-finite conductor cross sections
instead of propagating infinite or NaN voltage-drop results.
Track-angle classification widens and safely takes the absolute value of
endpoint coordinate differences before checking horizontal, vertical, or
45-degree geometry.
The normal DRC track-angle check shares that full-range-safe classification,
so extreme signed coordinates cannot panic or be misclassified.
Route-length measurement widens endpoint differences and saturates accumulated
segment and arc lengths, preserving deterministic results for extreme routes.
Routing-quality bend classification also widens endpoint differences before
deriving segment direction at the signed coordinate limits.
Differential-pair coupled-length measurement uses the same widened geometry and
saturating accumulation for full-range and multi-segment routes.
Differential coupling-distance thresholds combine both widths, gap, and
tolerance with widened saturating arithmetic.
Rule-area segment midpoints use widened interpolation, including segments that
span the complete signed coordinate range.
Track-to-edge, rectangular, polygon, and keepout clearance envelopes combine
track width and both clearance sides with widened saturating arithmetic.
Round and capsule obstacle clearance envelopes additionally combine obstacle
diameters without overflowing extreme manufacturing dimensions.
Cross-net track-to-track clearance thresholds combine both widths and bilateral
clearance with widened saturating arithmetic.
Cross-net track-to-via checks use the same overflow-safe envelope in both route
directions, combining track width, via diameter, and bilateral clearance.
Cross-net via-to-via checks likewise combine both diameters and bilateral
clearance with widened saturating arithmetic.
Manufacturing track-to-track clearance uses the same overflow-safe envelope,
including extreme imported widths and clearance limits.
Manufacturing track-to-via clearance applies widened saturating arithmetic in
both route-order directions.
Manufacturing via-to-via clearance also combines both diameters and bilateral
clearance without signed overflow.
Within-route via connectivity combines both via diameters with widened
saturating arithmetic before evaluating the connectivity graph.
Within-route track connectivity combines both track widths with widened
saturating arithmetic before testing segment contact.
Within-route track-to-via connectivity safely combines track width and via
diameter before testing layer-spanning contact.
Via-to-edge, rectangular, polygon, and keepout clearance checks reuse a widened
saturating diameter-plus-bilateral-clearance envelope.
Via-to-round and via-to-capsule obstacle checks additionally combine obstacle
diameters through a widened saturating envelope.
Return-path plane sampling uses overflow-safe ceiling division and widened
endpoint interpolation, including segments spanning the full coordinate range.
Return-path via proximity checks widen coordinate differences before subtraction
and bound each axis before squaring, including full-range coordinates.
Pad containment widens point-to-pad coordinate differences before rotation so
full-range board coordinates cannot wrap into a false electrical connection.
`pcbex dfm board.json [--output report.json]` emits a machine-readable report
and exits unsuccessfully when manufacturing violations are present.
Optional rules also detect drill-to-drill spacing, prohibited Via-in-pad, and
acute trace junctions. Use `--format sarif` to emit SARIF 2.1.0 suitable for
GitHub Code Scanning; JSON remains the default.
KiCad PTH and NPTH pad drill dimensions are retained, including rotated oval
holes. Component and mounting holes participate in minimum-drill, aspect-ratio,
board-edge, and exact hole-to-hole spacing checks alongside vias. Plated holes
also enforce the minimum annular ring, while NPTH mounting holes do not.
The normal board checker rejects incomplete or non-positive component drills
even without manufacturing rules, and requires every plated drill to fit
strictly inside its pad.
KiCad `(drill ... (offset x y))` values are retained in pad-local coordinates.
The rotated offset is applied to exact hole capsules for board-edge and
hole-spacing DFM, and plated-hole validation includes the offset displacement.
For circular and oval pads, plated-hole containment follows the actual curved
boundary rather than its bounding box, catching diagonal offset holes that
leave insufficient copper while retaining valid offset slots.
KiCad roundrect corner ratios are retained as physical radii. Plated-hole
containment erodes the rounded rectangle by the drill radius, so holes entering
a curved corner are rejected even when their bounding boxes still fit.
KiCad trapezoid `rect_delta` values are also retained. Plated-hole containment
requires the complete hole capsule to remain at least its radius inside every
sloped edge of the resulting convex pad polygon.
Custom plated pads use their imported polygon directly: both hole-capsule
endpoints must be inside, and the centerline must remain more than the drill
radius from every boundary edge, including concave boundaries.
The normal board checker also rejects custom pad polygons with fewer than three
vertices, degenerate edges or area, or non-adjacent self-intersections before
routing and hole checks consume their geometry.
All pad shapes require positive dimensions and a finite rotation. Roundrect
radii must fit the source pad, and trapezoid deltas must leave a non-degenerate
shape.
Pads must also name at least one unique layer present in the board copper
stackup; invalid or duplicate layer memberships are rejected by normal DRC.
When a pad carries a net identifier, its `net` field must contain exactly one
identifier and name, and that identifier must exist in the board net table;
normal DRC reports malformed or undeclared pad-net references explicitly.
Imported KiCad track segments, route arcs, vias, and copper zones with non-zero
net identifiers must likewise reference entries declared in that table.
When any of those copper primitives supplies a `net` field, its identifier must
be a non-negative integer rather than malformed data that loses net ownership.
Each primitive may supply at most one such field, preventing duplicate or
conflicting declarations from being silently resolved by source order. The
field must contain exactly one identifier, so trailing values cannot be
silently ignored.
Copper zones with a net field must also provide a scalar `net_name`; the empty
name remains valid for unconnected net 0 zones, while every other name must
match the net table declaration for its identifier. At most one `net_name`
field is permitted, and that field must contain exactly one name, so duplicate,
conflicting, or trailing values cannot be hidden.
Each net-table declaration must contain exactly one identifier and one name.
The table requires unique non-zero identifiers and unique non-empty names,
preventing trailing metadata, ambiguous routing, rule lookup, and pad ownership.
Every route must likewise reference a declared net; normal DRC reports unknown
route ownership before applying connectivity, width, or clearance rules.
Normal DRC also permits at most one route record per net, preventing map
construction from silently hiding copper in duplicate records.
Track segments require distinct endpoints, a positive width, and a layer from
the declared copper stackup before angle, boundary, or clearance evaluation.
Route arcs similarly require positive width, a declared copper layer, and three
points defining a curve; malformed arcs are rejected before DRC linearization.
Vias require a positive drill diameter and a larger outer diameter before
layer-range, board-edge, minimum-size, or copper-clearance evaluation.
Via endpoints must also belong to distinct declared copper layers, and
microvias may span only adjacent layers, before further physical checks.
Teardrops must form simple, non-degenerate polygons on declared copper layers
before normal DRC converts them into net-owned copper obstacles.
Filled zone contours have the same topology and layer requirements before
their copper participates in clearance and return-plane calculations.
Zone source outlines must also be simple, non-degenerate polygons on declared
copper layers so refilling and plane checks never consume malformed inputs.
Zone clearance and thermal gaps must be non-negative, minimum copper thickness
must be positive, and enabled thermal relief requires a positive spoke width.

## Planning and repair agent

The dependency-free Python agent converts bounded natural-language requirements
to an auditable JSON plan. It does not choose coordinates: only the
deterministic Rust engines may change physical design state.
Agent inputs must be regular non-symlink files and generated outputs are
size-checked, synchronized, and atomically replaced. Generic files are capped
at 32 MiB; exact limits and platform containment behavior are documented in
[`docs/PYTHON_AGENT_LIMITS.md`](docs/PYTHON_AGENT_LIMITS.md).

```sh
PYTHONPATH=agent/src python -m pcbex_agent plan examples/requirements.txt \
  --output plan.json
PYTHONPATH=agent/src python -m pcbex_agent apply-constraints \
  examples/placement.json plan.json --output planned-placement.json
```

The agent also normalizes KiCad DRC reports, maps violations to repair actions,
limits repair iterations and changed components, and accepts a candidate only
when its score does not regress. Unrecognized prose is surfaced explicitly
instead of being guessed. Optional adapters accept an injected LLM transport,
convert a built SKiDL circuit into the placement graph, and search an injected
component catalog. None of these adapters can write coordinates directly.
With `pcbex-agent[kicad]` installed and KiCad's IPC API enabled, routed JSON can
also be applied to the open editor as one undoable transaction:

```sh
pcbex-agent apply-ipc simple.ipc-routes.json
```

For a headless repair run, the agent generates bounded routing candidates,
executes KiCad DRC after each one, rejects repeated or unsupported repairs, and
atomically publishes only a DRC-clean board:

```sh
pcbex-agent repair-kicad input.kicad_pcb \
  --output repaired.kicad_pcb --report repair.json \
  --pcbex target/release/pcbex --max-iterations 4
```

The JSON report records every iteration, remaining errors and warnings, repair
actions, the stop reason, and the best observed error count.

## Rust-gated circuit generation

The agent can turn bounded natural-language requirements into a closed
`circuit-spec-v2` candidate without allowing the model to emit Python or edit
KiCad files. Every raw candidate is normalized by the Rust engine, converted
to the canonical schematic IR, and checked by the same immutable ERC safety
floor used for imported schematics. Repeated or non-improving candidates stop
the correction loop, and only a native zero-error review publishes the
digest-bound JSON bundle and namespace-isolated SKiDL source.

```sh
pcbex check-circuit-spec examples/circuit-spec-v2.json \
  --output circuit-check.json --require-approved

PYTHONPATH=agent/src python3 -m pcbex_agent generate-circuit \
  examples/circuit-requirements.txt \
  --output circuit-generation.json \
  --skidl-output circuit.py \
  --pcbex target/release/pcbex \
  --catalog-snapshot examples/catalog-snapshot-v1.json \
  --provider-command ./structured-circuit-provider
```

The provider command is shell-free and must be the final option. Schema
loading, provider calls, and native checks share one monotonic deadline and
bounded process-tree/output policy. With `--catalog-snapshot`, pcbex first
requires a zero-error native Rust review, then resolves MPNs from the closed
snapshot and runs a second Rust review on the resolved specification. The
generation bundle is `schema_version: 2` and carries the digest-bound catalog
receipt when selection is enabled. See
[`docs/CIRCUIT_GENERATION.md`](docs/CIRCUIT_GENERATION.md) for the v2 contract,
correction rules, evidence digests, and remaining trust boundaries. The
snapshot and receipt contracts can be emitted independently:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent catalog-snapshot-schema
PYTHONPATH=agent/src python3 -m pcbex_agent catalog-selection-receipt-schema
PYTHONPATH=agent/src python3 -m pcbex_agent catalog-fetch-receipt-schema
PYTHONPATH=agent/src python3 -m pcbex_agent catalog-generation-provenance-schema
```

Version 1.420 added acquisition of that same closed snapshot through one
explicit, bounded HTTPS pre-step:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent fetch-catalog-snapshot \
  --endpoint https://inventory.example.test/catalog/v1 \
  --provider jlcpcb \
  --output build/catalog-snapshot.json \
  --receipt build/catalog-fetch-receipt.json \
  --bearer-token-environment PCBEX_CATALOG_TOKEN
```

The endpoint must already return `catalog-snapshot-v1`; provider-native field
mapping remains a separate adapter boundary. The fetcher rejects redirects,
credentials/query/fragment in URLs, non-JSON responses, stale or malformed
snapshots, links, overwrites, and responses beyond its deadline or 4 MiB cap.
It normalizes the snapshot and retains a secret-free receipt binding the exact
response, normalized output, provider, endpoint identity, timestamps, and
catalog digest. Endpoints are capped at 4 KiB; bearer tokens are capped at 8
KiB, read only from a named environment variable, and excluded from the
bounded resolver process.
Selection and circuit generation never fetch implicitly and remain offline and
replayable. Supplier search, substitution, reservation, purchasing, datasheet
truth, and qualification are not performed.

Version 1.421 can bind that retained fetch evidence to the exact offline
selection and generation artifacts without changing generation bundle v2:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent generate-circuit \
  examples/circuit-requirements.txt \
  --pcbex target/release/pcbex \
  --catalog-snapshot build/catalog-snapshot.json \
  --catalog-fetch-receipt build/catalog-fetch-receipt.json \
  --catalog-provenance-output build/catalog-generation-provenance.json \
  --output build/circuit-generation.json \
  --skidl-output build/circuit.py \
  --provider-command ./structured-circuit-provider
```

The receipt/provenance flags are an all-or-nothing pair. Before the provider
starts, pcbex revalidates the normalized snapshot against the fetch receipt and
fixes catalog evaluation to its fetch timestamp. The closed sidecar then
recomputes the embedded selection receipt and binds the exact bundle and SKiDL
bytes. It contains no token or local path, performs no network request, and is
published last after all distinct no-clobber destinations are preflighted.
One-byte changes in any retained input fail replay validation.

`--allow-out-of-stock`, `--require-basic`, and
`--allow-footprint-fallback` are explicit snapshot policies; footprint-only
fallback is disabled by default and is recorded in the receipt when enabled.
See [`docs/CATALOG_SELECTION.md`](docs/CATALOG_SELECTION.md) and the example
[`examples/catalog-snapshot-v1.json`](examples/catalog-snapshot-v1.json) for
the closed fields and selection semantics. Generated SKiDL keeps the selected
MPNs in `_PCBEX_MPN_BY_REFERENCE` and, for snapshot selection, records
`_PCBEX_CATALOG_RECEIPT_SHA256`; it does not pass an unsupported `mpn=`
keyword to `Part`.

## Deterministic circuit-spec v2 to KiCad schematic writer

Version 1.422 can materialize an immutable-ERC-approved circuit-spec as a
self-contained flat, single-unit KiCad schematic:

```sh
pcbex write-circuit-spec-kicad-schematic circuit-spec-v2.json \
  --output hardware/generated.kicad_sch
```

The writer normalizes source ordering, uses fixed-grid geometry and stable
domain-separated UUIDs, embeds synthetic symbol definitions, and preserves
reference/value/footprint/MPN and `pcbex:*` power metadata. It emits explicit
net labels and no-connect markers, re-imports the exact generated bytes, and
runs the existing semantic handoff verifier before returning them. An ERC,
coverage, import, or handoff failure produces no output. The CLI atomically
publishes one new file and refuses aliases, overwrites, and symlink paths.

Version 1.423 exposes this writer as the metadata-only MCP tool
`write_circuit_spec_kicad_schematic` and as the root Action's optional
`circuit-spec` input. MCP returns only the retained path, bytes, and SHA-256;
the Action first retains the immutable ERC report and uses the fixed
`output-dir/circuit-spec.kicad_sch` destination. Neither integration silently
replaces a caller's schematic or changes a pipeline plan.

This is a logical handoff writer rather than an autorouter or symbol-library
resolver. Hierarchy, buses, multi-unit symbols, external library lookup,
existing-schematic mutation, placement/routing, DRC/DFM, and pipeline
orchestration beyond the explicit writer call remain outside the v1 boundary.
See [`docs/CIRCUIT_KICAD_SCHEMATIC_WRITER.md`](docs/CIRCUIT_KICAD_SCHEMATIC_WRITER.md)
for the exact contract.

## Circuit-spec v2 to KiCad handoff verification

When a KiCad schematic is authored separately, pcbex can verify it against an
exact circuit-spec v2 without generating or modifying either file. Emit the
closed native contract and run the digest-bound semantic gate:

```sh
pcbex circuit-kicad-handoff-schema \
  --output circuit-kicad-handoff.schema.json

pcbex verify-circuit-kicad-handoff \
  circuit-spec-v2.json hardware/controller.kicad_sch \
  --policy electrical-policy.json \
  --output build/circuit-kicad-handoff.json \
  --require-approved
```

The report binds source byte counts and SHA-256 identities, canonical circuit
and schematic identities, the effective policy identity, native circuit and
schematic ERC/check results, findings, counts, and the final `approved`
decision. `--require-approved` fails after writing the report, so rejected
comparisons retain machine-readable evidence for CI and review. The MCP
server exposes the same contract as `verify_circuit_kicad_handoff`.

The v1 comparison is intentionally closed: flat, single-unit symbols with
exact symbol/reference/value, pin/electrical type, explicit net-label and
canonical voltage-label sets, net membership, footprint, and pcbex metadata.
Geometry, drawing style, and UUIDs are ignored. Hierarchy,
buses, power-symbol extras, multi-unit symbols, unresolved libraries, live
supplier checks, and every placement/routing/DRC/fabrication decision remain
outside this verifier. See
[`docs/CIRCUIT_KICAD_HANDOFF.md`](docs/CIRCUIT_KICAD_HANDOFF.md) for the
schema boundary and retained rejection behavior.

## Circuit-spec v2 to KiCad schematic and board binding

Bind the same closed circuit intent to both an authored schematic and the
actual board with the standalone v1.416 gate:

```sh
pcbex circuit-kicad-board-binding-schema \
  --output circuit-kicad-board-binding.schema.json

pcbex verify-circuit-kicad-board-binding \
  circuit-spec-v2.json hardware/controller.kicad_sch \
  hardware/controller.kicad_pcb \
  --policy electrical-policy.json \
  --output build/circuit-kicad-board-binding.json \
  --require-approved
```

The gate recomputes the v1.415 handoff from raw inputs, then compares exact
references, footprint identifiers/values/MPNs/assembly metadata, pin-to-pad
number/net/no-connect state, and complete net/footprint/pad coverage.  It
uses canonical net names from the imported schematic rather than inventing
board labels from the circuit JSON.  It retains terminal-less raw nets and
validates net 0 as a reserved no-net identifier.  Declared no-connect pins use
same-numbered unconnected pads; only an empty, unconnected NPTH mechanical pad
may be added without a pin number.  Source, canonical, and binding SHA-256
identities and deterministic findings are retained in the
closed report; malformed or oversized inputs and output collisions fail within
the bounded atomic contract.  Hierarchy, buses, multi-unit/nested handoffs,
geometry, routing, DRC, and DFM are rejected or out of scope.  The MCP tool is
`verify_circuit_kicad_board_binding` with the same raw input and output
arguments.  This is not a new `pipeline-verify` phase; v1/v2 pipeline reports
remain unchanged.

## Bounded-input deterministic pipeline runner

Version 1.417 composes the raw circuit/schematic/board binding and the existing
hardware pipeline gate through one closed, digest-bound plan. Version 1.418
exposes the same runner through MCP:

```sh
pcbex deterministic-pipeline-plan-schema \
  --output deterministic-pipeline-plan.schema.json
pcbex deterministic-pipeline-report-schema \
  --output deterministic-pipeline-report.schema.json
pcbex run-deterministic-pipeline pipeline-plan.json \
  --output build/deterministic-pipeline-report.json \
  --require-approved
```

Every required or optional input is explicitly a relative-path, byte-count,
and SHA-256 descriptor (optional roles use an explicit `null`). The runner
stable-reads and privately stages the authorized bytes, enforces the exact
firmware-directory contract, preserves identity-sensitive basenames, runs both
gates in process, and cross-binds their canonical schematic and raw board
identities. A valid plan retains one deterministic rejected report before a required-approval
failure. It performs no design mutation, child-process execution, network/AI
call, factory submission, or order. Existing `pipeline-verify` v1/v2 schemas
are unchanged. See
[`docs/DETERMINISTIC_PIPELINE_RUNNER.md`](docs/DETERMINISTIC_PIPELINE_RUNNER.md)
for the complete plan, report, resource, and failure contract.

Version 1.419 adds root composite-Action parity. Set
`deterministic-pipeline-plan` to opt in and optionally set
`deterministic-pipeline-require-approved: "true"` for a final fail gate. The
Action retains the complete report at the fixed path
`${output-dir}/deterministic-pipeline-report.json` and exposes the report path
plus seven revalidated outputs: `deterministic-pipeline-schema-version`,
`deterministic-pipeline-approved`, `deterministic-pipeline-plan-sha256`,
`deterministic-pipeline-run-sha256`, `deterministic-pipeline-failure-count`,
`deterministic-pipeline-report-bytes`, and
`deterministic-pipeline-report-sha256`. With approval enforcement disabled, a
valid rejected report succeeds and remains available; with it enabled, the
same evidence is published before the Action fails. Empty plans preserve
analysis-only behavior. Stale, aliased, symlinked, malformed, or digest-
mismatched reports are rejected before attribution. The v1.419 runner path by
itself adds no file discovery, design mutation, repair, AI/network/factory
call, submission, or ordering behavior.

Version 1.424 can cryptographically join that deterministic evidence to an AI
schematic approval. `prepare-ai-review` request schema v2 records the exact
generated schematic, raw/normalized plan, retained report, and run identities.
Version 1.425 can additionally bind the normalized native KiCad ERC report as
request schema v3/artifact binding v2. Version 1.426 can instead bind the
warning-policy native ERC report as request schema v4/artifact binding
v3/native identity v2. The signing and verification commands
rerun every enabled gate and require retained reports to match fresh compact
JSON plus final newline exactly; a stored digest or self-consistent report
alone is never trusted. See
[`docs/AI_REVIEW_ARTIFACT_BINDING.md`](docs/AI_REVIEW_ARTIFACT_BINDING.md).

Minimal Action opt-in:

```yaml
- id: deterministic-pipeline
  uses: penguin425/pcbex@v1.424.0
  with:
    board: hardware/controller.kicad_pcb
    deterministic-pipeline-plan: hardware/pipeline-plan.json
    deterministic-pipeline-require-approved: "true"
```

## Schematic electrical IR

Normalize a KiCad 6–10 `.kicad_sch` file before deterministic electrical
checking or AI review:

```sh
pcbex import-schematic design.kicad_sch \
  --output design.schematic.json --require-complete
pcbex schematic-schema --output schematic-ir-v1.schema.json
```

The schema-versioned IR retains source-format identity, symbols, all
properties, unit/convert selection, pin UUIDs and electrical types, transformed
pin coordinates, wires, junctions, local/global/power labels, explicit
no-connect markers, KiCad 10 local/global power scope, and deterministic
electrical nets. Connectivity joins wire endpoints and T-junctions, splits
unmarked crossings, and unifies repeated labels. Net members retain both
reference designators and symbol UUIDs so unannotated or multi-unit parts
remain unambiguous.

The importer rejects unknown future formats, malformed coordinates, duplicate
UUIDs/properties/pins, missing embedded symbols, unsupported pin types, and
bounded-resource overflows. Buses, bus entries, net-class directives, extended
library symbols, and hierarchical sheets/labels are retained as explicit
coverage gaps rather than silently approved. `--require-complete` writes the
inspectable IR first and then fails if any such gap exists. The included
example is also parsed by KiCad 10 in CI-facing verification.

PCB, schematic, manufacturing, placement, and custom-rule paths share a typed,
iterative KiCad S-expression parser. It rejects documents larger than 128 MiB,
more than 4,000,000 lexical tokens, atoms larger than 4 MiB, nesting deeper than
128 lists, and lists with more than 1,000,000 direct elements before the AST can
grow without bound. Quoted parentheses remain data rather than syntax, and
custom rules are parsed as a no-copy sequence instead of wrapping the input in
an additional allocation. Exact limits, error behavior, and the remaining CLI
read boundary are documented in
[`docs/KICAD_SEXP_LIMITS.md`](docs/KICAD_SEXP_LIMITS.md).

After syntax parsing, physical values and statically derivable geometry work
pass a second fail-closed boundary. It checks finite nanometre conversion,
board/grid/layer products, polygon and checker pair work, raster edge visits,
segment/via clearance scans, and atomic copper-zone work. The exact production
ceilings and remaining dynamic scope are documented in
[`docs/NUMERIC_RASTER_LIMITS.md`](docs/NUMERIC_RASTER_LIMITS.md).

Compare two schematic revisions by electrical intent rather than KiCad
s-expression or drawing coordinates:

```sh
pcbex compare-schematics accepted.kicad_sch current.kicad_sch \
  --output schematic-diff.json \
  --summary-output schematic-diff.md \
  --sarif-output schematic-diff.sarif \
  --require-no-review
pcbex schematic-diff-schema --output schematic-diff-v1.schema.json
```

The closed diff binds canonical SHA-256 identities for both normalized
schematics and compares symbols by UUID, pins by UUID or stable number, named
nets by label, and unnamed nets by their sorted pin-set digest. It reports
added, removed, and modified symbols, pins, labels, and connectivity together
with the complete affected reference and net sets. Value, footprint,
annotation, DNP/BOM, custom property, pin-type, no-connect, and connectivity
changes require review. Pure drawing movement, rotation, wire ordering, and
coordinate-preserving presentation edits do not. Incomplete importer coverage
always requires review; `--require-no-review` writes every requested artifact
before failing.

## Deterministic schematic approval gate

Run policy-controlled electrical checks before asking an AI reviewer to assess
intent:

```sh
pcbex check-schematic design.kicad_sch \
  --output electrical-review.json \
  --explain electrical-explanations.json \
  --junit-output electrical-review.xml \
  --sarif-output electrical-review.sarif \
  --require-approved
pcbex electrical-policy --output electrical-policy.json
pcbex check-schematic design.kicad_sch \
  --policy electrical-policy.json \
  --output electrical-review.json --require-approved
```

The default policy checks importer coverage, annotation and footprint
completeness, duplicate reference units, connected no-connect pins, unmarked
unconnected pins, conflicting signal and power drivers, undriven signal and
power inputs, nets with multiple names, invalid power metadata, conflicting
rail-voltage declarations, power-input over-voltage, and explicitly required
decoupling. DNP symbols are excluded. Every finding has a stable identity and
structured symbol/pin references. Power-safety metadata and inference rules are
documented in
[`docs/ELECTRICAL_POWER_SAFETY.md`](docs/ELECTRICAL_POWER_SAFETY.md).
The 12 rules whose release default is `error` form an immutable safety floor:
policy files and signed packs cannot disable or demote them. The exact floor,
waiver behavior, and baseline semantics are documented in
[`docs/ERC_SAFETY_FLOOR.md`](docs/ERC_SAFETY_FLOOR.md).

`--explain` writes a separate policy-bound report covering all 16 rules,
including each rule's purpose, exact trigger, remediation guidance, effective
severity and enablement, and the stable IDs of findings it produced. This keeps
the signed electrical-review contract unchanged while making CI failures and
AI hand-offs directly explainable.

`--junit-output` emits one testcase for each built-in electrical rule. Enabled
rules with error findings produce failures, warning and informational findings
remain visible in `system-out`, and policy-disabled advisory rules are
explicitly skipped. Suite properties retain the schematic and policy SHA-256
identities, so Jenkins, GitLab, Buildkite, and other JUnit-aware CI systems can
display the same approval evidence without changing the canonical JSON review.

`--sarif-output` emits SARIF 2.1.0 for GitHub Code Scanning and other
SARIF-aware review tools. Every finding carries its severity, source schematic,
stable partial fingerprint, net/symbol/pin context, and the canonical
schematic/policy identities. The SARIF driver also embeds the title, purpose,
trigger, remediation, default level, and enablement of all 16 rules.

Adopt an existing review as a CI baseline without allowing new electrical
errors:

```sh
pcbex compare-electrical-reviews accepted-review.json electrical-review.json \
  --output electrical-comparison.json \
  --require-no-new-errors
pcbex electrical-review-comparison-schema \
  --output electrical-review-comparison-v1.schema.json
```

The comparison uses stable finding IDs instead of aggregate counts. Existing
non-floor baseline errors do not fail the regression gate, while a current
immutable-floor error, a new error, or a warning/info finding escalated to
error returns nonzero after writing the report. New, resolved, unchanged, and
severity-changed findings are counted separately; actionable summaries and
canonical SHA-256 identities for both reviews are retained. Duplicate or
malformed finding IDs, inconsistent counts or approval flags, blank policy
identities, and future schema versions fail closed. A comparison does not
recompute the schematic and must not replace the absolute
`check-schematic --require-approved` gate.

Temporary exceptions are represented separately from the immutable electrical
review. Every waiver targets one stable finding ID and requires a non-empty
reason, approver identity, and expiration date:

```json
{
  "schema_version": 1,
  "id": "prototype-v1",
  "waivers": [{
    "id": "temporary-footprint-metadata",
    "finding_id": "pcbex-er-0123456789abcdef",
    "reason": "Prototype footprint metadata is tracked for the next revision",
    "approved_by": "hardware-lead",
    "expires_on": "2026-08-31"
  }]
}
```

Apply waivers with an explicit date so the same invocation remains
reproducible:

```sh
pcbex apply-electrical-waivers \
  electrical-review.json electrical-waivers.json \
  --as-of 2026-08-01 \
  --output electrical-waiver-report.json \
  --require-approved
```

Unknown findings, duplicate waiver IDs or targets, invalid dates, blank audit
fields, expired waivers, and attempts to waive an immutable-floor finding fail
closed. The result binds canonical SHA-256 identities for the source review and
waiver set. Closed contracts are emitted by `electrical-waiver-set-schema` and
`electrical-waiver-report-schema`. The waiver command does not recompute the
schematic or policy, so supply only a review produced by a trusted
`check-schematic`, pipeline, or AI-review gate and retain its digest.

Reports are deterministic and contain canonical SHA-256 identities for both
the normalized schematic and effective policy. An approval is granted only
when no enabled error-severity finding remains. A policy may explicitly
disable or change the severity of advisory rules, but every built-in
error-severity rule must remain enabled at error severity. Unknown rules,
unsafe floor overrides, fields, and schema versions fail closed.
`--require-approved` writes the review before returning nonzero for findings;
an invalid policy is rejected before a review can be produced.

Closed Draft 2020-12 contracts are available through
`electrical-policy-schema`, `electrical-review-schema`, and
`electrical-explanation-schema`.

## Bound simulation evidence

Simulator-independent declarations turn measured results into an auditable
approval gate. Each assertion declares a measurement, unit, and inclusive
minimum and/or maximum:

```json
{
  "schema_version": 1,
  "id": "power-rail-dc",
  "analysis": "dc_operating_point",
  "simulator": {"name": "ngspice", "version": "42"},
  "schematic_sha256": "<electrical-review schematic_sha256>",
  "assertions": [{
    "id": "vout",
    "description": "regulated output",
    "measured": 3.3,
    "unit": "V",
    "minimum": 3.2,
    "maximum": 3.4
  }]
}
```

Bind that declaration and the raw simulator output to an approved electrical
review:

```sh
pcbex record-simulation-evidence simulation.json \
  --electrical-review electrical-review.json \
  --artifact ngspice.raw --artifact measurements.csv \
  --output simulation-evidence.json --require-passed
```

Artifacts are streamed through SHA-256 rather than loaded into memory. The
deterministic evidence report records their basename, media type, byte count,
and digest together with the exact electrical-review and normalized schematic
identities. It passes only when the electrical review is approved and every
bounded assertion passes. Empty artifacts, duplicate basenames/assertions,
non-finite values, reversed bounds, mismatched schematics, unknown fields, and
future schema versions fail closed. The report is still written before a
failed assertion gate.

Supported analysis categories are DC operating point, AC sweep, transient,
signal integrity, power integrity, thermal, and custom. The engine does not
trust a specific simulator; CI supplies raw results from ngspice, SPICE,
IBIS/SI, PDN, or thermal tooling. Closed contracts are emitted by
`simulation-declaration-schema` and `simulation-evidence-schema`.

## AI schematic review and signed approval

### Risk-based reviewer routing

Select reviewers from the actual electrical-intent delta before asking any
model to approve it:

```sh
pcbex route-schematic-review \
  accepted.kicad_sch proposed.kicad_sch \
  --routing-policy examples/reviewer-routing-policy.json \
  --output reviewer-routing.json \
  --summary-output reviewer-routing.md \
  --require-routed
```

The strict policy declares named reviewer profiles, exact provider/model
candidates, minimum reviewer counts, review instructions, and selectors for
change kinds, reference prefixes, library prefixes, net-name prefixes, and
changed fields. Values within one selector field are alternatives; populated
fields are combined, so all of them must match. Multiple profiles may claim
the same high-risk change. Every otherwise unmatched change is assigned to the
required selector-free fallback profile, including importer-coverage changes.

pcbex imports both schematics and recomputes the semantic diff instead of
trusting caller-supplied impact JSON. The deterministic plan binds the exact
baseline/current schematic digests and normalized policy digest, lists every
matched or fallback change, and reports the sum of minimum review assignments.
Unknown fields, duplicate profile identities, impossible reviewer counts,
missing fallbacks, selecting fallbacks, blank values, and future schema
versions fail closed. Closed contracts are emitted by
`schematic-reviewer-routing-policy-schema` and
`schematic-reviewer-routing-plan-schema`.

The AI reviews intent, while pcbex retains authority over deterministic gates
and the cryptographic approval:

```sh
# Run once; existing key files are never overwritten.
pcbex approval-keygen \
  --private-key .secrets/schematic-approval.key \
  --public-key schematic-approval.pub

# Recomputes the embedded electrical review and validates every simulation
# binding. Simulation evidence is required unless explicitly waived.
pcbex prepare-ai-review design.kicad_sch \
  --electrical-review electrical-review.json \
  --policy electrical-policy.json \
  --simulation-evidence power-rail.evidence.json \
  --requirement 'power=All IC supply pins have a valid source and decoupling' \
  --requirement 'reset=Reset defaults to a defined safe state' \
  --output ai-review-request.json \
  --session-output ai-review-session.json

# Give ai-review-request.json to the model and require the closed response
# contract emitted by `ai-review-response-schema`.

pcbex sign-ai-review ai-review-request.json ai-review-response.json \
  --private-key .secrets/schematic-approval.key \
  --signer-id production-ci \
  --session ai-review-session.json \
  --output signed-approval.json --require-approved

pcbex verify-ai-approval \
  signed-approval.json ai-review-request.json ai-review-response.json \
  --public-key schematic-approval.pub \
  --session ai-review-session.json \
  --require-approved
```

Version 1.424 adds opt-in request schema v2 for production pipelines. It binds
the signature to the exact generated schematic bytes, raw and normalized
deterministic plan identities, and the exact approved runner report and run
identity. Version 1.425 adds optional native KiCad ERC evidence as request
schema v3/artifact binding v2. Version 1.426 adds the mutually exclusive
warning-policy path as request schema v4/artifact binding v3/native identity
v2. First retain the approved reports, then pass
the same plan/report paths (and `--native-kicad-erc-report` for v3 or v4) while
preparing the request:

```sh
pcbex run-deterministic-pipeline pipeline-plan.json \
  --output deterministic-pipeline-report.json \
  --require-approved

pcbex run-native-kicad-erc generated.kicad_sch \
  --output native-kicad-erc.json --require-approved

# To bind warnings too, add:
#   --warning-policy examples/native-kicad-warning-policy.json

pcbex prepare-ai-review generated.kicad_sch \
  --electrical-review electrical-review.json \
  --policy-pack organization-policy-pack.json \
  --deterministic-pipeline-plan pipeline-plan.json \
  --deterministic-pipeline-report deterministic-pipeline-report.json \
  --native-kicad-erc-report native-kicad-erc.json \
  --output ai-review-request.json

pcbex sign-ai-review ai-review-request.json ai-review-response.json \
  --generated-schematic generated.kicad_sch \
  --deterministic-pipeline-plan pipeline-plan.json \
  --deterministic-pipeline-report deterministic-pipeline-report.json \
  --native-kicad-erc-report native-kicad-erc.json \
  --private-key .secrets/schematic-approval.key \
  --signer-id production-ci \
  --output signed-approval.json --require-approved

pcbex verify-ai-approval \
  signed-approval.json ai-review-request.json ai-review-response.json \
  --generated-schematic generated.kicad_sch \
  --deterministic-pipeline-plan pipeline-plan.json \
  --deterministic-pipeline-report deterministic-pipeline-report.json \
  --native-kicad-erc-report native-kicad-erc.json \
  --public-key schematic-approval.pub --require-approved
```

For request schema v4, generate the native report with
`--warning-policy examples/native-kicad-warning-policy.json` and append
`--native-kicad-erc-warning-policy examples/native-kicad-warning-policy.json`
to prepare, sign, approval verification, and quorum verification. The trusted
policy is stable-read and the native warning report is freshly reproduced at
each boundary; schema v3 rejects this option and schema v4 requires it.

Prepare, sign, approval verification, and quorum verification each stable-read
the four artifacts, rerun the closed pipeline and native KiCad ERC, require
both reports to be approved, and compare the freshly rendered reports
byte-for-byte. The request's raw electrical-review digest and recomputed
electrical result must also match the plan and circuit handoff. This rejects
stale, changed, or independently valid but mixed artifacts; a byte-identical
copy at another path remains valid.
Schema-v1 requests remain supported without these flags and reject them when
supplied. Request schema v2 is distinct from the existing session-bound signed
approval envelope schema v2. See
[`docs/AI_REVIEW_ARTIFACT_BINDING.md`](docs/AI_REVIEW_ARTIFACT_BINDING.md).

With an organization policy pack, review requirements and the simulation gate
are supplied by policy, and approval verification selects the trusted key by
the signed envelope's `signer_id`. Verification also requires the request's
electrical policy, complete requirement set, and simulation gate to match the
pack exactly:

```sh
pcbex prepare-ai-review design.kicad_sch \
  --electrical-review electrical-review.json \
  --policy-pack examples/acme-policy-pack.json \
  --simulation-evidence power-rail.evidence.json \
  --output ai-review-request.json

pcbex verify-ai-approval \
  signed-approval.json ai-review-request.json ai-review-response.json \
  --policy-pack examples/acme-policy-pack.json --require-approved
```

For production review, verify multiple independently signed responses against
the same request and organization trust root:

```sh
pcbex verify-ai-quorum ai-review-request.json \
  --generated-schematic generated.kicad_sch \
  --deterministic-pipeline-plan pipeline-plan.json \
  --deterministic-pipeline-report deterministic-pipeline-report.json \
  --approval reviewer-a.approval.json \
  --approval reviewer-b.approval.json \
  --response reviewer-a.response.json \
  --response reviewer-b.response.json \
  --policy-pack organization-policy-pack.json \
  --minimum-approvals 2 \
  --minimum-distinct-providers 2 \
  --minimum-distinct-models 2 \
  --session ai-review-session.json \
  --output approval-quorum.json \
  --summary-output approval-quorum.md \
  --require-quorum
```

`prepare-ai-review --session-output` creates a cryptographically random
256-bit challenge bound to the exact request digest. Sessions expire after one hour by
default and cannot exceed seven days. A session-bound signature uses envelope
schema v2 and covers the session digest as well as the request, response, gate
result, and signer. Verification checks the session self-digest and evaluates
its issuance/expiration window before accepting any signature, so an approval
cannot be replayed in a later CI run even when the schematic has not changed.
The Rust verification API accepts an explicit evaluation timestamp for
reproducible tests; CLI, MCP, and Action verification use the current system
clock. Legacy v1 envelopes remain verifiable only when no session is
requested, preventing a downgrade from the time-bound path. The Rust API
exposes closed schemas for the session and both time-bound quorum report forms.

When reviewer routing is configured, the same command freshly recomputes the
semantic diff and additionally enforces every active reviewer profile:

```sh
pcbex verify-ai-quorum ai-review-request.json \
  --approval reviewer-a.approval.json \
  --response reviewer-a.response.json \
  --policy-pack organization-policy-pack.json \
  --minimum-approvals 1 \
  --minimum-distinct-providers 1 \
  --minimum-distinct-models 1 \
  --baseline-schematic accepted.kicad_sch \
  --current-schematic proposed.kicad_sch \
  --reviewer-routing-policy reviewer-routing-policy.json \
  --output routed-quorum.json \
  --summary-output routed-quorum.md \
  --require-quorum
```

The proposed schematic must have the exact normalized digest embedded in the
AI review request. Only freshly verified signed approvals whose complete
provider/model/version identity appears in a routed profile count toward that
profile. A valid global quorum therefore cannot substitute unrelated models
for a required power, safety, or specialist reviewer. Profile shortages write
the nested global quorum and deterministic per-profile evidence before the
optional gate fails. The Action enables this stronger gate automatically when
schematics, reviewer routing, and AI quorum inputs are supplied together.
The closed contract is emitted by `routed-ai-approval-quorum-schema`.

Every envelope is freshly verified against the exact request, response, and
trusted signer key. Signer IDs, public keys, and response digests must be
unique, preventing one model response or signing identity from being counted
twice. Provider and full provider/model/version identities are normalized
case-insensitively before diversity counting. Valid signed rejections remain
visible in the report but never count as approvals. A threshold failure writes
deterministic JSON and Markdown before the optional gate exits unsuccessfully;
signature tampering or an untrusted signer fails closed without producing a
misleading report. The closed report schema is emitted by
`ai-approval-quorum-schema`.

An AI `needs_human` result can enter a governed dual-control path without
turning human review into an unrestricted safety override. Add dedicated
`trusted_human_escalation_keys` to the organization policy pack, using signer
IDs and public keys that do not appear in `trusted_approval_keys`. Each human
decision is signed over the exact request, active session, normalized AI quorum
evidence, reason, and ticket:

```sh
pcbex sign-human-escalation ai-review-request.json \
  --session ai-review-session.json \
  --ai-quorum approval-quorum.json \
  --private-key .secrets/engineer-a.key \
  --signer-id engineer-a \
  --decision approve \
  --reason 'Independent review confirmed the intended power-up behavior.' \
  --ticket HW-42 \
  --output engineer-a.escalation.json

pcbex verify-human-escalation ai-review-request.json \
  --session ai-review-session.json \
  --ai-quorum approval-quorum.json \
  --escalation engineer-a.escalation.json \
  --escalation engineer-b.escalation.json \
  --policy-pack organization-policy-pack.json \
  --minimum-approvals 2 \
  --output human-escalation.json \
  --summary-output human-escalation.md \
  --require-approved
```

The verifier requires at least two distinct trusted human keys, rejects any
human rejection, and rechecks session expiration and all evidence digests.
Escalation is eligible only when at least one verified AI member explicitly
returned `needs_human`. AI rejection, ERC or simulation failure, unknown/failed
requirements, and error/critical risks remain non-overridable. The closed
contracts are emitted by `signed-human-escalation-schema` and
`human-escalation-report-schema`.

Approval evidence can be retained in an append-only, hash-chained transparency
log and sealed with a trusted Ed25519 checkpoint:

```sh
pcbex init-approval-log \
  --log-id production-schematic-approvals \
  --output approvals.0.json

pcbex append-approval-log approvals.0.json \
  --artifact signed-approval.json \
  --kind signed-ai-approval \
  --output approvals.1.json

pcbex append-approval-log approvals.1.json \
  --artifact human-escalation.json \
  --kind human-escalation-report \
  --output approvals.2.json

pcbex sign-approval-log approvals.2.json \
  --private-key .secrets/transparency-log.key \
  --signer-id release-control \
  --output approvals.checkpoint.json

pcbex verify-approval-log approvals.2.json \
  --checkpoint approvals.checkpoint.json \
  --public-key transparency-log.pub \
  --output approvals.verification.json
```

Each append command requires different input and output paths, preserving the
previous immutable snapshot. Artifacts are strictly parsed by their closed
contract and hashed as normalized typed JSON. Entry sequence numbers,
timestamps, previous-entry hashes, and self-hashes detect mutation,
reordering, insertion, and deletion. The signed checkpoint binds the complete
log digest, head, and entry count, so truncation, rollback to an older snapshot,
and stale checkpoints also fail closed. Supported evidence includes signed AI
approvals, global or routed AI quorum reports, signed human escalations, human
escalation reports, and signed organization policy packs. The log proves
retention integrity; each artifact should still pass its normal signature and
policy verification before being appended.

The composite Action accepts `approval-transparency-log`,
`approval-log-checkpoint`, and `approval-log-public-key`, publishes
`approval-log-verification` and `approval-log-verified`, and can enforce the
result with `fail-on-approval-log`. Closed contracts are emitted by
`approval-transparency-log-schema`,
`signed-approval-log-checkpoint-schema`, and
`approval-log-verification-report-schema`.

Independent services or security domains can witness that exact checkpoint
before it is accepted:

```sh
pcbex witness-approval-log approvals.checkpoint.json \
  --private-key .secrets/witness-a.key \
  --witness-id witness-a \
  --output witness-a.json

pcbex verify-approval-log-witnesses approvals.checkpoint.json \
  --witness witness-a.json --public-key witness-a.pub \
  --witness witness-b.json --public-key witness-b.pub \
  --minimum-witnesses 2 \
  --output witness-quorum.json \
  --require-quorum
```

Every witness signature binds the normalized checkpoint digest, log identity,
head, entry count, witness identity, and observation time. Verification
requires at least two distinct trusted witness IDs and keys, rejects signatures
replayed against a newer checkpoint, and retains a report even when a valid
set is below threshold. Callers first verify the log and origin checkpoint,
then verify its witnesses. The Action accepts paired
`approval-log-witness-files` and `approval-log-witness-public-keys`, and can
enforce them with `fail-on-approval-log-witnesses`.

Witnesses can also run as independent HTTPS services. pcbex sends one closed,
versioned request and accepts only a response that verifies against the
separately configured Ed25519 trust root:

```sh
export PCBEX_WITNESS_TOKEN='short-lived service credential'
pcbex request-approval-log-witness approvals.checkpoint.json \
  --endpoint https://witness-a.example/v1/witness \
  --public-key witness-a.pub \
  --bearer-token-env PCBEX_WITNESS_TOKEN \
  --timeout-seconds 30 \
  --output witness-a.json \
  --receipt-output witness-a.receipt.json
```

Remote endpoints must use HTTPS, cannot contain query parameters, never follow
redirects, and have a 600-second absolute timeout ceiling plus a 1 MiB response
limit. Bearer values are read from an environment variable and are never
placed in process arguments or receipts. The response must be
`application/json`, strictly deserialize as a signed witness, match the exact
checkpoint, use the configured public key, and pass Ed25519 verification
before either output is written. The hash-bound transport receipt records the
endpoint, request/response digests and size, and verified witness identity.
The Action can request one remote witness with `remote-witness-endpoint` and
`remote-witness-public-key`; it automatically includes that result in the
configured witness quorum. MCP exposes the same bounded operation without the
test-only loopback escape hatch.

Long-lived witness identities can rotate keys without replacing an unaudited
configuration value:

```sh
pcbex init-approval-log-witness-trust \
  --witness-id witness-a \
  --public-key witness-a.pub \
  --output witness-a.trust.0.json

pcbex sign-approval-log-witness-key-rotation witness-a.trust.0.json \
  --old-private-key .secrets/witness-a.key \
  --new-private-key .secrets/witness-a-next.key \
  --rotated-at-unix 1785283200 \
  --output witness-a.rotation.1.json

pcbex apply-approval-log-witness-key-rotation \
  witness-a.trust.0.json witness-a.rotation.1.json \
  --output witness-a.trust.1.json \
  --public-key-output witness-a.current.pub
```

Each rotation is domain-separated and signed by both the currently trusted
key and the new key. The proof binds witness identity, exact consecutive
generations, the previous rotation digest, both public keys, and a monotonic
rotation timestamp. Applying a proof therefore rejects rollback, replay, forks,
key substitution, and registration of a new key whose private half is not
controlled. Input snapshots are never overwritten. The exported key can be
used with the existing witness verifier; the Action also accepts
`remote-witness-trust-state` instead of `remote-witness-public-key` and
validates/exports its current key before making the HTTPS request. Closed
contracts are available from `approval-log-witness-trust-state-schema` and
`signed-approval-log-witness-key-rotation-schema`. MCP exposes initialize,
sign, apply, and validated-export operations with destructive-action
annotations.

For public, append-only retention, an operator can publish checkpoint digests
as leaves of an RFC 6962-style Merkle tree and sign its exact tree head:

```sh
pcbex create-approval-log-anchor approvals.checkpoint.json \
  --log-checkpoint earlier.checkpoint.json \
  --log-checkpoint approvals.checkpoint.json \
  --leaf-index 1 \
  --log-id organization-public-approvals \
  --private-key .secrets/public-log.key \
  --output approvals.anchor.json

pcbex verify-approval-log-anchor approvals.checkpoint.json \
  --proof approvals.anchor.json \
  --public-key public-log.pub \
  --output approvals.anchor-verification.json
```

The inclusion verifier recomputes the domain-separated checkpoint leaf, walks
the bounded audit path with RFC 6962 tree splitting, requires the exact leaf
index and tree size, and verifies the reconstructed root against a separately
trusted Ed25519-signed tree head. A proof for another checkpoint, index, tree,
log key, or mutated sibling fails before output. The Action accepts
`approval-log-anchor-proof` with `approval-log-anchor-public-key`, publishes
the verification report, and can enforce it with
`fail-on-approval-log-anchor`. MCP exposes both operator-side proof creation
and verifier-side inclusion checking. Closed proof and report contracts are
available from `approval-log-anchor-proof-schema` and
`approval-log-anchor-verification-report-schema`.

Separate CI consumers can retain only an earlier accepted anchor and verify
that a newer signed tree is its exact append-only extension:

```sh
pcbex create-approval-log-consistency \
  --old-anchor approvals.previous-anchor.json \
  --new-anchor approvals.anchor.json \
  --log-checkpoint earlier.checkpoint.json \
  --log-checkpoint approvals.checkpoint.json \
  --output approvals.consistency.json

pcbex verify-approval-log-consistency \
  --old-anchor approvals.previous-anchor.json \
  --new-anchor approvals.anchor.json \
  --proof approvals.consistency.json \
  --public-key public-log.pub \
  --output approvals.consistency-verification.json
```

Generation uses the complete newer checkpoint snapshot, but verification needs
only both accepted anchors, the logarithmic consistency path, and the trusted
tree-head key. It verifies both signatures and rejects log/key substitution,
tree-size or observation-time rollback, equal-size equivocation, incomplete or
redundant paths, and roots that do not prove prefix extension. The Action
accepts `approval-log-previous-anchor-proof` and
`approval-log-consistency-proof` alongside the current anchor inputs,
publishes `approval-log-consistent`, and can enforce
`fail-on-approval-log-consistency`. MCP exposes create/verify tools; closed
contracts are emitted by `approval-log-consistency-proof-schema` and
`approval-log-consistency-verification-report-schema`.

Independent observers can gossip the exact trusted tree head without sharing
their retained baseline:

```sh
pcbex sign-approval-log-gossip-receipt \
  --anchor approvals.anchor.json \
  --log-public-key public-log.pub \
  --observer-id independent-observer \
  --observer-private-key .secrets/observer.key \
  --received-at-unix 1770000000 \
  --expires-at-unix 1770086400 \
  --output approvals.gossip.json

pcbex verify-approval-log-gossip-receipt \
  --local-anchor approvals.previous-anchor.json \
  --receipt approvals.gossip.json \
  --consistency-proof approvals.consistency.json \
  --log-public-key public-log.pub \
  --observer-id independent-observer \
  --observer-public-key observer.pub \
  --evaluated-at-unix 1770000100 \
  --output approvals.gossip-verification.json
```

The observer first verifies the log-operator signature, then signs the exact
tree-head digest under a separate Ed25519 key. Receipts bind the log identity,
tree size, root, log key, observer identity, and a lifetime of at most seven
days. Verification accepts identical trees without a proof and either prefix
direction with the exact consistency proof. It rejects equal-size different
roots as a split view, as well as stale/future receipts, redundant or missing
proofs, and observer/log key substitution. The Action accepts
`approval-log-gossip-receipt`, trusted observer identity/key, evaluation time,
and an optional gossip consistency proof; it publishes
`approval-log-gossip-verified` and supports `fail-on-approval-log-gossip`.
MCP exposes task-forbidden signing and verification tools. Closed contracts
come from `signed-approval-log-gossip-receipt-schema` and
`approval-log-gossip-verification-report-schema`.

Require fresh consistent observations from multiple independent organizations:

```sh
pcbex verify-approval-log-gossip-quorum \
  --local-anchor approvals.previous-anchor.json \
  --observation independent-lab.observation.json \
  --observation security-partner.observation.json \
  --organization-id independent-lab \
  --organization-id security-partner \
  --observer-id lab-observer \
  --observer-id partner-observer \
  --observer-public-key lab-observer.pub \
  --observer-public-key partner-observer.pub \
  --minimum-organizations 2 \
  --log-public-key public-log.pub \
  --evaluated-at-unix 1770000100 \
  --output approvals.gossip-quorum.json \
  --require-quorum

pcbex request-approval-log-gossip-observation \
  --local-anchor approvals.previous-anchor.json \
  --endpoint https://observer.example/v1/gossip \
  --log-public-key public-log.pub \
  --organization-id independent-lab \
  --observer-id lab-observer \
  --observer-public-key lab-observer.pub \
  --evaluated-at-unix 1770000100 \
  --output independent-lab.observation.json \
  --receipt-output independent-lab.transport.json
```

Each quorum member is independently reverified against the trusted log key and
must be no more than 24 hours old. Organizations, observer identities, keys,
and receipt digests must all be distinct, preventing one operator from
inflating the threshold. The HTTPS adapter follows no redirects, limits the
response to 1 MiB and the timeout to 600 seconds, and binds the endpoint,
request, response, byte count, identities, and verified gossip receipt into a
transport receipt. Bearer credentials are read only from an environment
variable.

The Action combines local observations with up to ten bounded remote
endpoints, publishes the quorum and every remote response/transport receipt,
and can enforce `fail-on-approval-log-gossip-quorum`. MCP exposes quorum
verification as an optional task and remote acquisition as open-world and
task-forbidden. Closed contracts come from
`approval-log-gossip-observation-schema`,
`approval-log-gossip-quorum-report-schema`, and
`remote-approval-log-gossip-receipt-schema`.

Rotate an organization-bound observer without replacing its long-lived
identity:

```sh
pcbex init-approval-log-gossip-observer-trust \
  --organization-id independent-lab \
  --observer-id lab-observer \
  --public-key lab-observer.pub \
  --output lab-observer.trust.json

pcbex sign-approval-log-gossip-observer-key-rotation \
  lab-observer.trust.json \
  --old-private-key .secrets/lab-observer.key \
  --new-private-key .secrets/lab-observer.next.key \
  --rotated-at-unix 1770000200 \
  --output lab-observer.rotation.json

pcbex apply-approval-log-gossip-observer-key-rotation \
  lab-observer.trust.json lab-observer.rotation.json \
  --output lab-observer.next.trust.json \
  --public-key-output lab-observer.next.pub
```

Every transition advances exactly one generation, incorporates the previous
rotation digest, and requires both old-key authorization and new-key possession
over one domain-separated payload. Identity changes, same-key transitions,
timestamp rollback, replay, forks, missing signatures, or overwrite of either
output fail closed.

Pass `--observer-trust-state` values instead of direct organization, observer,
and key arrays to `verify-approval-log-gossip-quorum`. The resulting
trust-bound report records the canonical digest and key generation of every
observer. Remote acquisition accepts one trust state and binds its digest and
generation into the transport receipt. The Action accepts local and remote
`*-observer-trust-state-files` as a mutually exclusive replacement for direct
trust. MCP exposes initialization, signing, application, key export, and
trust-bound quorum verification. Closed contracts come from
`approval-log-gossip-observer-trust-state-schema`,
`signed-approval-log-gossip-observer-key-rotation-schema`, and
`approval-log-gossip-trust-bound-quorum-report-schema`.

Govern which organization-bound observers are eligible for that quorum:

```sh
pcbex init-approval-log-gossip-organization-registry \
  --registry-id production-approvals \
  --authority-public-key gossip-registry.pub \
  --output gossip-registry.0.json

pcbex sign-approval-log-gossip-organization-registry-transition \
  gossip-registry.0.json \
  --authority-private-key .secrets/gossip-registry.key \
  --action admit-observer \
  --organization-id independent-lab \
  --observer-trust-state lab-observer.trust.json \
  --reason-sha256 "$ADMISSION_EVIDENCE_SHA256" \
  --effective-at-unix 1770000300 \
  --output gossip-registry.admit-lab.json

pcbex apply-approval-log-gossip-organization-registry-transition \
  gossip-registry.0.json gossip-registry.admit-lab.json \
  --output gossip-registry.1.json

pcbex verify-approval-log-gossip-quorum \
  --local-anchor approvals.previous-anchor.json \
  --observation independent-lab.observation.json \
  --observation security-partner.observation.json \
  --observer-trust-state lab-observer.trust.json \
  --observer-trust-state partner-observer.trust.json \
  --organization-registry gossip-registry.json \
  --minimum-organizations 2 \
  --log-public-key public-log.pub \
  --evaluated-at-unix 1770000400 \
  --output approvals.registry-bound-quorum.json \
  --require-quorum
```

Every authority signature binds the registry identity, consecutive generation,
previous transition digest, exact action, reason evidence, effective time, and
observer trust-state digest. An admitted organization starts active. A
suspension immediately removes all of its observers from quorum eligibility,
and revocation is permanent. Re-admitting a rotated observer replaces only
that observer's pinned trust-state digest and is forbidden while its
organization is suspended or revoked. Replay, forks, skipped generations,
wrong-authority signatures, stale trust states, and direct-key mode with a
registry all fail closed.

The registry-bound report retains the registry ID, generation, and normalized
digest around the complete trust-bound quorum. The Action accepts
`approval-log-gossip-organization-registry` only with trust-state mode. MCP
exposes registry initialization, signed transition creation/application, and
registry-bound quorum verification. Closed contracts come from
`approval-log-gossip-organization-registry-schema`,
`signed-approval-log-gossip-organization-registry-transition-schema`, and
`approval-log-gossip-registry-bound-quorum-report-schema`.

Rotate the retained registry authority without discarding any organization
decision:

```sh
pcbex sign-approval-log-gossip-organization-registry-authority-key-rotation \
  gossip-registry.json \
  --old-private-key .secrets/gossip-registry.key \
  --new-private-key .secrets/gossip-registry.next.key \
  --rotated-at-unix 1770000500 \
  --output gossip-registry-authority.rotation.json

pcbex apply-approval-log-gossip-organization-registry-authority-key-rotation \
  gossip-registry.json gossip-registry-authority.rotation.json \
  --output gossip-registry.next.json \
  --public-key-output gossip-registry.next.pub
```

The rotation occupies the next generation in the same digest chain and binds
the registry identity, prior transition, old and new keys, and monotonic
rotation time. The retained key must authorize the change and the successor
must prove possession. Applying it atomically preserves every observer
admission, suspension, and revocation. Replay, forks, skipped generations,
same-key replacement, key substitution, either invalid signature, and time
rollback fail before either output is written. The Action optionally applies
`approval-log-gossip-organization-registry-authority-key-rotation` before
quorum verification; MCP exposes matching sign/apply tools. The closed
rotation contract comes from
`signed-approval-log-gossip-organization-registry-authority-key-rotation-schema`.

Require multiple independent authorities for every registry decision:

```sh
pcbex sign-approval-log-gossip-organization-registry-governance \
  gossip-registry.json \
  --registry-authority-private-key .secrets/gossip-registry.key \
  --minimum-approvals 2 \
  --authority-id security \
  --authority-public-key security.pub \
  --authority-id hardware \
  --authority-public-key hardware.pub \
  --issued-at-unix 1770000600 \
  --output gossip-registry.governance.json

pcbex sign-approval-log-gossip-organization-registry-threshold-transition \
  gossip-registry.json gossip-registry.governance.json \
  --authority-id security \
  --authority-private-key .secrets/security.key \
  --authority-id hardware \
  --authority-private-key .secrets/hardware.key \
  --action suspend-organization \
  --organization-id compromised-lab \
  --reason-sha256 "$INCIDENT_SHA256" \
  --effective-at-unix 1770000700 \
  --output gossip-registry.suspend.json

pcbex apply-approval-log-gossip-organization-registry-threshold-transition \
  gossip-registry.json gossip-registry.governance.json \
  gossip-registry.suspend.json \
  --output gossip-registry.next.json
```

The retained root signs the exact threshold, ordered authority identities,
and distinct Ed25519 keys. Each admission, suspension, or revocation then
binds that governance digest into the existing generation and transition
chain. Duplicate identities or keys, insufficient or untrusted signers,
policy/key substitution, signature mutation, replay, forks, and timestamp
rollback fail closed. The first successful quorum transition retains its
governance digest; root-only registry operations and root-only key rotation
are locked out afterward. The Action accepts paired
`approval-log-gossip-organization-registry-governance` and
`approval-log-gossip-organization-registry-threshold-transition` inputs. MCP
exposes governance signing and threshold sign/apply tools. Closed contracts
are emitted by
`signed-approval-log-gossip-organization-registry-governance-schema` and
`signed-approval-log-gossip-organization-registry-threshold-transition-schema`.

Replace an active governance policy only after both authority sets approve:

```sh
pcbex sign-approval-log-gossip-organization-registry-governance-rotation \
  gossip-registry.json \
  gossip-registry.governance.json \
  gossip-registry.governance.next.json \
  --old-authority-id security \
  --old-authority-private-key .secrets/security.key \
  --old-authority-id hardware \
  --old-authority-private-key .secrets/hardware.key \
  --new-authority-id hardware \
  --new-authority-private-key .secrets/hardware.key \
  --new-authority-id compliance \
  --new-authority-private-key .secrets/compliance.key \
  --rotated-at-unix 1770000800 \
  --output gossip-registry.governance.rotation.json

pcbex apply-approval-log-gossip-organization-registry-governance-rotation \
  gossip-registry.json \
  gossip-registry.governance.json \
  gossip-registry.governance.next.json \
  gossip-registry.governance.rotation.json \
  --output gossip-registry.next.json
```

The retained and successor root-signed policies must describe the same
registry and root key, while changing the governance digest. Each policy
independently enforces its own threshold over distinct authority identities
and keys. Applying the rotation advances exactly one generation, retains all
organization decisions, and atomically replaces the active governance digest;
the old policy cannot authorize later changes. Replay, forks, stale policies,
signature or key substitution, missing either quorum, and time rollback fail
closed. The Action applies the optional paired governance-rotation inputs
after threshold activation, and MCP exposes matching sign/apply tools. The
closed transition contract is emitted by
`signed-approval-log-gossip-organization-registry-governance-rotation-schema`.

Rotate an active registry root without reopening a root-only bypass:

```sh
pcbex sign-approval-log-gossip-organization-registry-successor-governance \
  gossip-registry.json \
  --successor-registry-authority-private-key .secrets/registry.next.key \
  --minimum-approvals 2 \
  --authority-id hardware \
  --authority-public-key hardware.pub \
  --authority-id compliance \
  --authority-public-key compliance.pub \
  --issued-at-unix 1770000900 \
  --output gossip-registry.governance.next-root.json

pcbex sign-approval-log-gossip-organization-registry-governed-authority-key-rotation \
  gossip-registry.json \
  gossip-registry.governance.json \
  gossip-registry.governance.next-root.json \
  --old-authority-id security \
  --old-authority-private-key .secrets/security.key \
  --old-authority-id hardware \
  --old-authority-private-key .secrets/hardware.key \
  --new-authority-id hardware \
  --new-authority-private-key .secrets/hardware.key \
  --new-authority-id compliance \
  --new-authority-private-key .secrets/compliance.key \
  --rotated-at-unix 1770001000 \
  --output gossip-registry.root.rotation.json

pcbex apply-approval-log-gossip-organization-registry-governed-authority-key-rotation \
  gossip-registry.json \
  gossip-registry.governance.json \
  gossip-registry.governance.next-root.json \
  gossip-registry.root.rotation.json \
  --output gossip-registry.next.json \
  --public-key-output gossip-registry.next.pub
```

The prospective root proves private-key possession by signing the complete
successor governance policy. Retained and successor authority quorums then
approve one payload binding both root keys, both governance digests, the exact
next generation, prior transition digest, and monotonic time. Applying it
atomically replaces the root and active governance while preserving every
organization decision. Missing either quorum, root/policy/key substitution,
same-root rotation, stale policy, replay, forks, and signature mutation fail
closed. Root-only and governed root rotations are mutually exclusive in the
Action; MCP exposes successor-policy and governed sign/apply tools. The closed
transition contract is emitted by
`signed-approval-log-gossip-organization-registry-governed-authority-key-rotation-schema`.

Audit the complete approval gossip registry history instead of trusting a
copied head snapshot:

```sh
pcbex validate-approval-log-gossip-organization-registry-history \
  gossip-registry.history.json \
  --output gossip-registry.history.normalized.json

pcbex audit-approval-log-gossip-organization-registry-history \
  gossip-registry.history.normalized.json \
  --output gossip-registry.history-audit.json \
  --registry-output gossip-registry.computed.json
```

The bounded history begins with a generation-zero empty registry and contains
typed root transitions, dual-signed root rotations, threshold transitions,
governance rotations, and governed root rotations. Every event is replayed
through its production verifier; generations, prior digests, timestamps,
signatures, root keys, governance digests, and distinct-key quorums must form
one exact chain. The audit binds each event and resulting state digest and
emits the only registry eligible for downstream quorum verification.
Reordering, replay, omission, forks, non-genesis starts, stale governance,
signature mutation, and copied-registry substitution fail closed without
partial outputs. This proves genesis-to-supplied-head integrity.

Pin that supplied head with the retained root, advance local trust
monotonically, and require independent witnesses:

```sh
pcbex sign-approval-log-gossip-organization-registry-history-checkpoint \
  gossip-registry.history.normalized.json \
  --authority-private-key gossip-registry.root.key \
  --issued-at-unix 1785400000 \
  --output gossip-registry.history.checkpoint.json

pcbex accept-approval-log-gossip-organization-registry-history-checkpoint \
  gossip-registry.history.normalized.json \
  gossip-registry.history.checkpoint.json \
  --accepted-at-unix 1785400001 \
  --output gossip-registry.history.trust.json

pcbex verify-approval-log-gossip-organization-registry-history-checkpoint-witnesses \
  gossip-registry.history.normalized.json \
  gossip-registry.history.checkpoint.json \
  --witness witness-a.json --witness witness-b.json \
  --trusted-witness-id witness-a --trusted-witness-public-key witness-a.pub \
  --trusted-witness-id witness-b --trusted-witness-public-key witness-b.pub \
  --evaluated-at-unix 1785400002 --require-quorum \
  --output gossip-registry.history.witness-quorum.json
```

The checkpoint binds the exact audit, computed final registry, retained root,
last transition, active governance, generation, and issuance time. A prior
trust state rejects rollback, truncation, time reversal, and same-generation
equivocation. Witness verification requires fresh, distinct identities and
keys over that exact checkpoint. Long-lived witness trust can rotate without
silent key replacement:

```sh
pcbex init-approval-log-gossip-organization-registry-history-checkpoint-witness-trust \
  --witness-id witness-a --public-key witness-a.pub \
  --output witness-a.trust.json

pcbex sign-approval-log-gossip-organization-registry-history-checkpoint-witness-key-rotation \
  witness-a.trust.json \
  --old-private-key witness-a.key --new-private-key witness-a.next.key \
  --rotated-at-unix 1785400010 --output witness-a.rotation.json

pcbex apply-approval-log-gossip-organization-registry-history-checkpoint-witness-key-rotation \
  witness-a.trust.json witness-a.rotation.json \
  --output witness-a.next.trust.json \
  --public-key-output witness-a.next.pub
```

Each exact one-generation transition is signed by both old and new keys and
binds the witness identity, previous rotation digest, keys, and monotonic
time. Replay, forks, key substitution, same-key rotation, and time reversal
fail closed. Quorum verification accepts either direct identity/key pairs or
rotatable trust states, never both.

Accepted checkpoint trust can also be sent to independently operated witness
services and combined with local evidence:

```sh
export PCBEX_APPROVAL_HISTORY_WITNESS_TOKEN='...'
pcbex request-approval-log-gossip-organization-registry-history-checkpoint-witness \
  gossip-registry.history.trust.json \
  --endpoint https://witness.example/v1/approval-registry-history-checkpoint \
  --witness-key-trust-state witness-a.next.trust.json \
  --bearer-token-env PCBEX_APPROVAL_HISTORY_WITNESS_TOKEN \
  --timeout-seconds 30 \
  --evaluated-at-unix 1785400020 \
  --output witness-a.remote.json \
  --receipt-output witness-a.remote.receipt.json
```

The client sends one closed request, forbids redirects, userinfo, and query
credentials, accepts at most 1 MiB of JSON, and verifies freshness, registry,
generation, checkpoint, identity, trusted key, and Ed25519 signature before
atomically retaining either artifact. The receipt binds the accepted
checkpoint trust-state digest, request and response digests, endpoint,
evaluation time, and—when used—the witness trust-state digest and generation.
Bearer values are read only from the named environment variable and are never
written to argv or evidence. Production endpoints require HTTPS; loopback HTTP
exists only behind the hidden test flag.

The Action accepts newline-aligned
`approval-log-gossip-organization-registry-history-checkpoint-remote-witness-*`
inputs, permits at most ten endpoints, requires local and remote evidence to
use the same direct-key or trust-state mode, and folds every verified response
into the same quorum. It publishes separate witness and receipt directories.
MCP exposes one open-world, task-forbidden request tool. Receipt schema and
normalization are available through
`remote-approval-log-gossip-organization-registry-history-checkpoint-witness-receipt-schema`
and
`validate-remote-approval-log-gossip-organization-registry-history-checkpoint-witness-receipt`.
The remaining closed contracts are emitted by
`approval-log-gossip-organization-registry-history-schema` and
`approval-log-gossip-organization-registry-history-audit-schema`, plus the
checkpoint, trust-state, witness-trust, rotation, and quorum schema commands.
The Action accepts only pre-signed trust and witness evidence, never private
keys.

Verified remote approval registry-history witness receipts can be admitted to
the signed approval transparency chain:

```sh
pcbex init-approval-log \
  --log-id approval-registry-history-witness-receipts \
  --output receipt-log.0.json
pcbex append-verified-remote-approval-registry-history-checkpoint-witness-receipt \
  receipt-log.0.json \
  --receipt witness-a.remote.receipt.json \
  --checkpoint-trust-state registry-history.checkpoint.trust.json \
  --response witness-a.remote.json \
  --witness-key-trust-state witness-a.trust.json \
  --evaluated-at-unix 1785400030 \
  --recorded-at-unix 1785400030 \
  --output receipt-log.1.json
pcbex sign-approval-log receipt-log.1.json \
  --private-key receipt-log.key \
  --signer-id approval-registry-receipt-log \
  --output receipt-log.checkpoint.json
```

Admission reconstructs the exact HTTPS request from the retained checkpoint
trust state, hashes the exact retained response bytes, and checks every receipt
binding. It then parses the response witness, rebinds its registry, generation,
checkpoint, identity, time, public key, witness trust-state digest and
generation, independently rechecks witness freshness at admission time, and
verifies the Ed25519 signature before appending anything. A
direct trusted public key may be supplied instead of a witness trust state, but
the two trust modes are mutually exclusive and must exactly match how the
receipt was acquired. The request command now preserves the exact response
document so offline admission can reproduce its byte digest.

The normalized event retains the exact receipt digest, checkpoint digest,
request digest, response digest, and witness identity. The existing
approval-log signature, public anchor, consistency proof, gossip, remote
witness, witness quorum, and witness key-rotation controls then protect the
receipt history. Receipt, trust-state, response-byte, witness-time, identity,
key, or signature substitution fails before the new log snapshot is written.
MCP exposes the same dedicated verifier-bound append tool; the generic append
tool remains available for already trusted artifacts.

For a multi-witness admission boundary, verify every independently retained
receipt and response in one transaction:

```sh
pcbex append-verified-remote-approval-registry-history-checkpoint-witness-receipt-quorum \
  receipt-log.0.json \
  --receipt witness-b.remote.receipt.json \
  --receipt witness-a.remote.receipt.json \
  --checkpoint-trust-state registry-history.checkpoint.trust.json \
  --response witness-b.remote.json \
  --response witness-a.remote.json \
  --witness-key-trust-state witness-a.trust.json \
  --witness-key-trust-state witness-b.trust.json \
  --minimum-witnesses 2 \
  --evaluated-at-unix 1785400030 \
  --recorded-at-unix 1785400030 \
  --output receipt-log.quorum.json \
  --report-output receipt-log.quorum-report.json
```

Receipts and responses remain positional pairs, while witness trust states are
matched by identity and may be supplied in any order. The verifier rejects
duplicate witness identities, public keys, receipt digests, or response
digests, then orders admitted members by witness identity. A threshold miss
writes neither output. On success, the updated log and closed quorum report are
created atomically. Paired `--trusted-witness-id` and
`--trusted-witness-public-key` values provide the mutually exclusive direct-key
mode. The report contract is available from
`remote-approval-log-gossip-organization-registry-history-checkpoint-witness-receipt-quorum-report-schema`
and its matching `validate-...` command. MCP exposes the same verifier-bound
quorum transaction.

The successful report also binds the exact resulting log identity, entry
count, head, complete digest, and each admitted request/response/receipt
member. Use the quorum-gated checkpoint signer to prevent a partial, extended,
or unrelated log from being signed:

```sh
pcbex sign-approval-log-with-remote-approval-registry-history-checkpoint-witness-receipt-quorum \
  receipt-log.quorum.json \
  --quorum-report receipt-log.quorum-report.json \
  --private-key receipt-log.key \
  --signer-id approval-registry-receipt-log \
  --output receipt-log.checkpoint.json
```

MCP exposes the same gate as
`sign_quorum_bound_approval_transparency_log`. The generic signer remains
available for approval logs whose artifacts do not use this receipt-quorum
policy.

For a checkpoint that is cryptographically distinct from the generic approval
checkpoint, sign the exact quorum report and log under the dedicated domain:

```sh
pcbex sign-remote-approval-registry-history-receipt-quorum-log-checkpoint \
  receipt-log.quorum.json \
  --quorum-report receipt-log.quorum-report.json \
  --private-key receipt-log.key \
  --signer-id approval-registry-receipt-log \
  --output receipt-log.quorum-checkpoint.json
pcbex verify-remote-approval-registry-history-receipt-quorum-log-checkpoint \
  receipt-log.quorum.json \
  --quorum-report receipt-log.quorum-report.json \
  --checkpoint receipt-log.quorum-checkpoint.json \
  --public-key receipt-log.pub \
  --output receipt-log.quorum-checkpoint.verification.json
```

The signature covers the normalized report digest, registry identity,
generation and checkpoint, full approval-log state, threshold and valid member
count, and signer identity. Generic approval checkpoints cannot substitute for
this closed contract. MCP exposes matching
`sign_remote_approval_registry_history_receipt_quorum_log_checkpoint` and
`verify_remote_approval_registry_history_receipt_quorum_log_checkpoint` tools.

The request embeds the normalized schematic, effective electrical policy,
freshly recomputed electrical review, bound simulation evidence, explicit
requirements, and the complete set of evidence IDs the model may cite. Its
self-identity excludes only the identity field itself, so any mutation is
detected. Every requirement must be assessed exactly once and cite at least
one known evidence ID. Unknown requirements, missing evidence, failed
simulations, ERC rejection, an AI reject/needs-human decision, or error/critical
AI risks prevent approval.

The model response is never allowed to change those gates. pcbex reevaluates
the full request immediately before signing and produces a deterministic
Ed25519 approval or rejection envelope. Verification requires the separately
trusted public-key file; trusting only the public key embedded in the envelope
would not establish signer identity. The private key is created with mode
`0600` on Unix and must never be supplied to the model.

AI integration is provider-neutral. `pcbex_agent.review_schematic_with_llm`
accepts an injected transport, rejects non-JSON or invented evidence before
Rust validation, accepts request schemas v1 through v4, and treats every
artifact identity as evidence rather than instructions. Schema v3 is confined
to error-only native ERC identity v1, while schema v4 requires warning-policy
native ERC identity v2. It tells the model
to use `unknown`/`needs_human` instead of guessing, while the response schema
remains v1. The MCP server exposes `route_schematic_reviewers`,
`prepare_schematic_review`,
`sign_schematic_approval`, `verify_schematic_approval`, and
`verify_schematic_approval_quorum`, plus signed human escalation and approval
transparency-log tools; signing, appending, and report writes are marked as
destructive actions so MCP hosts can retain their user-approval boundary. The
GitHub Action accepts `ai-review-session`
alongside its quorum inputs, optionally verifies `human-escalation-files`, and
publishes `schematic-approval-met` as the AI-or-governed-human result. The
human path also requires `human-escalation-ai-quorum`, the exact retained
report the humans signed; the Action freshly verifies the AI inputs and
requires their stable quorum content to match that retained report. Closed
request, response, and signature contracts are emitted by
`ai-review-request-schema`, `ai-review-response-schema`,
and `signed-ai-approval-schema`; the Rust API exposes the session contract.

For OpenAI, Anthropic, or Gemini, the managed adapter calls the provider's
official structured-output API directly and normalizes its response into the
same closed pcbex contract:

```sh
export OPENAI_API_KEY='...'
pcbex-agent review-managed ai-review-request.json \
  --output ai-review-response.json \
  --receipt ai-provider-receipt.json \
  --provider openai \
  --model YOUR_MODEL_ID \
  --model-version YOUR_IMMUTABLE_DEPLOYMENT_REVISION

pcbex-agent managed-provider-receipt-schema \
  --output managed-provider-receipt.schema.json
```

The default credential environments are `OPENAI_API_KEY`,
`ANTHROPIC_API_KEY`, and `GEMINI_API_KEY`; `--api-key-environment` selects a
different environment variable by name. Credentials never enter argv,
normalized responses, receipts, or error bodies. Default endpoints use HTTPS;
custom endpoints must also use HTTPS and cannot contain credentials, a query,
or a fragment. Redirects, incomplete/refused outputs, multiple structured
outputs, non-JSON content, timeouts, and oversized responses fail before any
artifact is written. The response model identity is fixed from the trusted CLI
arguments instead of accepting the model's self-identification.

A dedicated composite Action exposes only the normalized response and
secret-free receipt. Pass the key from GitHub Secrets:

```yaml
- id: ai-review
  uses: penguin425/pcbex/.github/actions/managed-ai-review@v1.424.0
  with:
    request: hardware/ai-review-request.json
    provider: openai
    model: YOUR_MODEL_ID
    model-version: YOUR_IMMUTABLE_DEPLOYMENT_REVISION
    api-key: ${{ secrets.OPENAI_API_KEY }}
```

Its `response` output can enter the existing `sign-ai-review` and quorum flow;
the receipt is retained alongside the signed approval evidence. Provider API
access alone never grants approval authority.

For another provider or an organization-specific gateway, wrap its SDK or HTTP
API in an executable that reads the review prompt from stdin and writes only
the response JSON to stdout. The agent runs that adapter without a shell:

```sh
pcbex-agent review-schematic ai-review-request.json \
  --output ai-review-response.json \
  --receipt ai-provider-receipt.json \
  --timeout-seconds 120 \
  --maximum-output-bytes 1048576 \
  --provider-command ./review-adapter --model production-reviewer

pcbex-agent provider-receipt-schema \
  --output provider-receipt.schema.json
```

`--provider-command` must be last so every following token is passed as one
exact argument. pcbex-agent does not interpret a command string, expand shell
syntax, or accept or persist a provider credential. Credentials remain an
adapter concern, typically supplied through its environment. pcbex-agent
bounds stdout and stderr while the process runs, kills the provider process
tree on timeout or overflow, validates the closed response before writing
anything, and refuses to overwrite an existing response or receipt. The generated prompt labels
every schematic and requirement field as untrusted evidence rather than model
instructions, reducing prompt-injection authority at the review boundary.

The versioned receipt records SHA-256 and byte length for the request and
normalized response, the provider executable basename, a SHA-256 commitment to
the exact argument vector, and the applied runtime limits. The receipt does not
contain the prompt, command arguments, environment, or credentials. A valid
provider response still has no approval authority until `sign-ai-review`
recomputes every deterministic gate and signs it with the separately held
Ed25519 key.

## Releases

Diagnose the local CLI and its optional KiCad, Git, and Python integrations
before adding it to CI:

```sh
pcbex capabilities
pcbex doctor
pcbex doctor --require-kicad --output doctor.json
```

`capabilities` emits a versioned JSON inventory of every CLI command, supported
board schema, fabrication profile, external integration, and output contract.
Agents and CI wrappers can use it for feature discovery without parsing help
text or assuming compatibility from the executable version alone.

The command always emits a versioned JSON report. Optional integrations are
reported without failing the command; `--require-kicad` promotes KiCad CLI
availability to a required readiness check.
Each version check has a 10-second deadline and captures at most 64 KiB from
each output stream, so a missing, hung, or noisy executable cannot block the
readiness report indefinitely.

Pushing a semantic-version tag from `main` creates a GitHub Release:

```sh
git switch main
git pull --ff-only
git tag -a v0.1.0 -m "pcbex v0.1.0"
git push origin v0.1.0
```

The tag must match both the workspace version in `Cargo.toml` and the agent
version in `agent/pyproject.toml`. The release workflow runs all Rust and Python
checks, then publishes CLI archives for Linux x64, macOS Intel and Apple
Silicon, and Windows x64. Each archive includes a SHA-256 checksum and an SPDX
SBOM, and has signed GitHub build-provenance and SBOM attestations. Verify a
downloaded archive with:

```sh
gh attestation verify pcbex-v0.1.2-x86_64-unknown-linux-gnu.tar.gz \
  --repo penguin425/pcbex
```

If a build fails, the release remains a draft and the workflow can be rerun
safely.

Before publication, the workflow runs `scripts/release-audit.py` against the
machine-readable [product roadmap](docs/ROADMAP.md). It requires the exact 12
release assets, downloads them, verifies every archive checksum and SPDX
document, and confirms the tag commit. Audit subprocesses share one aggregate
deadline, while local roadmap and asset work checks that deadline between
bounded items. It also bounds command output, rejects links and special files,
and caps archives, checksums, SBOMs, and their aggregate downloaded size.
Repository administrators can also
audit the live `main` protection:

```sh
python3 scripts/release-audit.py \
  --repository penguin425/pcbex \
  --check-protection
```

The protection audit requires pull-request flow, strict Rust/Python/KiCad
checks, administrator enforcement, linear history, conversation resolution,
and disabled force-pushes and deletions.

## Scope

pcbex is a deterministic physical-design engine for placed signal boards with
a versioned KiCad schematic electrical IR. It supports polygonal multilayer
boards, differential pairs, length tuning, copper zones, partial-span vias,
exact KiCad pad geometry, placement optimization, DFM reporting, and headless
or IPC-assisted KiCad workflows. The companion agent can render a validated,
closed circuit specification as executable SKiDL, resolve MPNs from a
digest-bound local catalog snapshot, and run bounded natural-language
candidate correction against the native immutable ERC floor. It can explicitly
acquire the closed snapshot from a bounded HTTPS feed before selection, but
does not translate arbitrary supplier-native APIs. Declared power metadata and
catalog inventory remain input evidence rather than verified datasheet or
supplier truth. pcbex does not yet replace complete electrical design, live
supplier qualification, analog or signal-integrity simulation, final KiCad
ERC/DRC, or fabrication review.
