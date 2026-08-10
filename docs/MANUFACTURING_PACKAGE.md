# Manufacturing package

`pcbex fabricate <board.kicad_pcb> --output-dir <directory>` is the headless
manufacturing gate. It first runs KiCad DRC and stops on any DRC violation;
only then are manufacturing artifacts published. With
`--physical-profile <profile.json>`, pcbex also performs its internal profile
check before creating the staging directory and binds that profile into the
resulting package.

`--kicad-cli <executable-or-path>` selects the directly invoked KiCad command
without a shell and defaults to `kicad-cli`. `--timeout-seconds <seconds>`
accepts a finite, positive value through 600 only when Rust can represent it as
a positive `Duration`; fractional seconds are accepted, but a value that
converts to zero at nanosecond resolution is rejected. It defaults to 600.
One absolute monotonic deadline covers input/profile validation, DRC, Gerber
and drill export, KiCad build-identity capture, intervening quota/source checks,
normalization, package validation, and publication. Each of the four KiCad
children receives the earlier of the shared time remaining and its existing
per-child cap. A direct `fabricate` invocation gives each child an isolated
process group on Unix or Job on Windows.

Publication checks the deadline during preflight, before every staged-artifact
copy and synchronization, and immediately before every visible atomic persist.
It commits ordinary sibling files first, then `manifest.json`, and commits the
canonical `manufacturing.zip` last. A deadline failure can therefore leave
some new sibling files or the new manifest visible, but without a newly
committed canonical archive they are not evidence of a complete new package.
There is intentionally no deadline check after the archive commit: synchronous
metadata and diagnostic work already in progress is not preempted, so a direct
`fabricate` success can cross the nominal deadline after committing the
complete archive.

The board and adjacent same-stem `.kicad_pro`/`.kicad_dru` inputs are copied to
a private staging directory before KiCad is started. This preserves project
DRC context without writing `.kicad_prl` or DRC sidecars beside the source.
Gerber layers are derived from the validated KiCad layer table: every declared
copper layer, front/back paste, mask and silkscreen, plus `Edge.Cuts`. Four-layer
and larger boards therefore retain every inner copper plane. KiCad may omit an
empty optional layer (for example `F.Paste`/`B.Paste`) from its export; such an
omission is not an error, while a declared copper layer and `Edge.Cuts` remain
mandatory.

The command emits the KiCad Gerber and Excellon files plus:

- `bom.csv`: grouped, deterministic BOM rows (`Comment`, `Designator`,
  `Footprint`, `Quantity`, `MPN`, `Layer`, and `Type`);
- `cpl.csv`: surface-mount pick-and-place rows with absolute board coordinates
  in millimetres and milli-degree precision rendered as decimal degrees;
- `drc.rpt`: the KiCad DRC report; this artifact is mandatory even when the
  report contains zero violations;
- `manifest.json`: schema version, pcbex/KiCad versions, board and project-input
  digests, component counts, and SHA-256 digests for every exported artifact;
  and
- `manufacturing.zip`: a sorted archive containing the generated directory
  files (the archive itself is intentionally excluded to avoid a hash cycle).

KiCad embeds wall-clock creation times in DRC, Gerber, Gerber-job, and drill
files. pcbex replaces only those volatile timestamp fields with a fixed epoch;
the exact KiCad CLI build version and a SHA-256 fingerprint of its `about`
report remain in the manifest. With identical input bytes, filenames, pcbex
version, and KiCad build, `manufacturing.zip` is byte-for-byte reproducible.
The ZIP uses sorted names, fixed entry metadata, and contains `manifest.json`;
the manifest's artifact array intentionally omits itself and the archive.

No-profile packages retain manifest schema v1. A physical-profile package keeps
schema v2 and its existing physical binding unchanged. A DFM-profile package
uses schema v3 and includes the DFM profile ID/revision, the
domain-separated canonical SHA-256, and an explicit origin: an external origin
contains one portable basename/byte-count/raw-SHA-256 source descriptor, while
a built-in origin contains only the closed built-in ID (no fabricated raw
source). Physical and DFM selections remain mutually exclusive, so this
release intentionally has no schema v4. The factory validator accepts v1,
v2, and v3, rejects profile fields in the wrong version, and factory feedback
repair cannot add, drop, or substitute the complete binding.

Generation occurs entirely in the private stage. Contents of files already
present in the requested output directory are never read or added to the
manifest/ZIP, and unrelated files are left untouched. A destination path or
any parent component that is a symlink is rejected before KiCad or private
staging is started. A generated manufacturing filename left by a previous run
but absent from the current staged set (for
example an obsolete inner-copper Gerber) is treated as stale and causes the
command to fail; use a fresh, dedicated output directory. Current generated
filenames are replaced only after every destination is preflighted and copied
to a temporary regular file.

## Resource quotas

One production quota contract covers the complete private manufacturing
workspace, artifact collection, timestamp normalization, ZIP creation, and
publication:

| Resource | Limit |
|---|---:|
| Descendant workspace entries / ZIP entries | 4,096 |
| Workspace traversal depth | 16 |
| One regular file or final ZIP | 128 MiB |
| Expanded artifact payload accepted from a ZIP | 512 MiB |
| `manifest.json` or one Gerber job | 1 MiB |
| Complete private workspace | 1 GiB |
| Manufacturing footprints / BOM-CPL source parts | 100,000 |
| One portable UTF-8 basename | 255 bytes |
| One line normalized from a KiCad artifact | 1 MiB |

Entry names may not be empty, dot or dot-dot, contain a path separator, any
Windows-forbidden character (`<`, `>`, `:`, `"`, `/`, `\\`, `|`, `?`, `*`),
NUL, another control character, a trailing dot/space, or a reserved Windows
device name. Names which collide under case-insensitive filesystems are also
rejected within each directory and archive. Walkers use non-following metadata
checkpoints, charge an entry before queueing it, and reject every observed
link, socket, or other non-regular entry. Exact limits are accepted; the next
entry, byte, depth, or name byte fails closed.

BOM and CPL sizes are calculated before either destination is replaced. Rows
are then emitted directly through an 8 KiB buffered, byte-counted temporary
writer; the implementation never builds the complete CSV or a joined
designator field in memory. Minimal CSV quoting, doubled embedded quotes, raw
UTF-8 bytes, LF terminators, and deterministic reference ordering remain part
of the byte-level reproducibility contract. Existing files which are not part
of the archive are still charged to the private package-directory quota, and
bytes/entries used by the sibling source and KiCad-environment stages are
reserved before package creation.

Before a ZIP is published, pcbex applies one semantic BOM/CPL validator to
the generated files. The validator uses a bounded RFC 4180 record reader:
quoted fields may contain commas, doubled quotes, and embedded CR/LF records,
but malformed quoting, unterminated records, oversized fields/records, and
aggregate CSV input beyond the manufacturing quotas fail closed. The first
record must match the exact byte-level headers (with no aliases, reordered
columns, extra columns, or leading BOM):

```text
Comment,Designator,Footprint,Quantity,MPN,Layer,Type
Designator,Mid X (mm),Mid Y (mm),Rotation,Layer
```

Every BOM row must have exactly seven fields. Its non-empty `Comment`,
`Designator`, and `Footprint` fields, positive checked base-10 integer
`Quantity`, `SMD`/`THT` `Type`, and `F`/`B` `Layer` are validated. The checked
aggregate quantity must match the manifest, and both quantity and logical
record counts stay within the bounded manufacturing-part contract. Every CPL row must have exactly
five fields, a non-empty unique designator, finite checked-decimal X/Y and
rotation values (no NaN, infinity, exponent, overflow, or unchecked float
conversion), an `F`/`B` layer, and a bounded placement-row count. The validator
does not require CPL designators to be a subset of BOM designators and does
not impose a BOM/CPL canonical ordering; uniqueness is enforced only within
the CPL. This is a semantic CSV gate, not a vendor coordinate transform: CPL
coordinates retain the vendor-neutral board-origin convention below and must
be transformed by a factory profile when a vendor requires another origin,
axis, or rotation convention.

The same validator is authoritative for the generated package, `factory-submit`
before network access, every candidate in `factory-feedback-loop`, and the
manufacturing phase of `pipeline-verify` (including deterministic-pipeline
verification). This milestone changes no manifest/receipt/plan/report schema
version and adds no Gerber semantic parser; Gerber-job structure remains the
existing structural validator boundary.

The archive is written through a size-limited temporary regular file with
sorted unique names, flushed and synchronized, then atomically replaces the
private staged archive. A normalization, source-change, archive, or publication
quota error leaves an existing archive and every public destination unchanged.
Opened source identities are checked around hashing, normalization, and copy,
and each source is read twice through the same opened descriptor with digest or
byte-for-byte comparison so an in-place same-inode/same-size rewrite is not
accepted merely because metadata stayed constant. On Unix, manufacturing
temporary files and replacements are created, removed, and renamed relative to
a pinned directory descriptor. Windows uses a retained directory handle with
guarded identity checks around its path-based atomic replacement.
The generated canonical ZIP is passed through the same complete validator
used by `factory-submit` before any public file is replaced. The staged board
and adjacent project/rule bytes are compared with their original snapshots
after every KiCad subprocess phase, so an export cannot silently rebind the
manifest to mutated design inputs.
Each public file is replaced atomically, but the set of sibling files is not a
cross-file transaction: an operating-system failure during the final sequence
of renames can leave earlier destinations updated. Consumers which require one
atomic hand-off should use the validated `manufacturing.zip` boundary.
A directory-synchronization error is reported even when the immediately
preceding atomic rename already committed; failure-preservation guarantees
therefore apply to validation and pre-commit errors, not to a durability error
reported after the filesystem accepted a rename.
The complete private workspace is rescanned after project staging, DRC, each
KiCad export, normalization, KiCad identity discovery, and package creation.
These are deterministic post-process checkpoints: an external KiCad process
can still consume disk between checkpoints. Use an operating-system filesystem
quota or sandbox when live enforcement or race-free traversal against a hostile
concurrent writer is required.

For manufacturing upload, treat `manufacturing.zip` as the canonical package
boundary. The sibling files are useful for inspection and review, but the ZIP
is the reproducible, hash-bound artifact to submit to a fabrication service.

## Fresh exact replay

Version 1.455 adds a standalone consumer which freshly regenerates that
canonical ZIP and accepts it only when all bytes match the retained package:

```sh
pcbex-agent replay-manufacturing-package \
  board.kicad_pcb manufacturing/manufacturing.zip \
  --pcbex pcbex \
  --kicad-cli kicad-cli \
  --kicad-project board.kicad_pro \
  --kicad-rules board.kicad_dru \
  --fab-profile profiles/acme-dfm.json \
  --timeout-seconds 120 \
  > manufacturing-replay.json

pcbex-agent manufacturing-package-replay-result-schema \
  --output manufacturing-package-replay.schema.json
```

The equivalent Python API is `replay_manufacturing_package`. Project and rules
paths are optional explicit inputs; when present their exact captured bytes are
staged under the board-derived same-stem `.kicad_pro` and `.kicad_dru` names.
They must be omitted when those companions were not part of the retained
package. Built-in fabrication IDs match `[a-z0-9][a-z0-9.-]{0,127}`. An
external DFM or physical profile is staged under its validated
portable caller basename because that name is retained in the manufacturing
manifest. A built-in `--fab`, file-backed `--fab-profile`, and
`--physical-profile` remain mutually exclusive.

Before native execution, the adapter stable-reads every caller source as a
nonempty regular non-link file. Board, project, rules, retained package, and
fresh package reads are each limited to 128 MiB; an external profile is limited
to 4 MiB; and all caller inputs together may not exceed 512 MiB. The board must
have one portable `.kicad_pcb` basename. Each caller `PathLike` is converted to
immutable path text exactly once; the identity computed at the first stable
read is retained for the result rather than recomputed from a later path. The
caller-selected sources are then written to a private temporary workspace, and
the selected pcbex command is invoked without a shell as `fabricate` with the
private board/output, explicit KiCad executable, profile selection, and a
shorter inner timeout. Child stdout and stderr are independently limited to
1 MiB. Both the caller command and final injected argv are capped at 256
arguments and 32,768 aggregate UTF-8 bytes; the rendered Windows command line,
including its terminator, is capped at 32,767 UTF-16 code units.

The Python aggregate deadline accepts finite `0 < seconds <= 600` and defaults
to 120 seconds. Immediately before invoking `fabricate`, the adapter reserves
the smaller of 15 seconds or half the remaining budget for Python cleanup and
post-child reads. Rust therefore receives a strictly shorter aggregate timeout;
that inner value must also be representable as a positive Rust `Duration`.
The adapter also activates a hidden internal outer-supervision mode. Instead of
creating nested isolated groups/Jobs, DRC, Gerber, drill, and identity children
inherit the Python-owned pcbex process group on Unix or outer Job on Windows.
Rust can terminate and reap a direct KiCad child at its earlier deadline, while
the later Python timeout still owns pcbex and every ordinary descendant if a
wrapper or pre-exec delay prevents orderly inner cleanup. Direct standalone
`fabricate` retains its isolated child mode. Synchronous file reads cannot be
interrupted in the middle of a stalled filesystem operation, but Python checks
the deadline after temporary cleanup and again immediately before returning,
so replay never reports success after observing expiry.

After `fabricate` has generated and internally validated the fresh package, the
adapter requires the fresh and retained ZIP bodies to be byte-for-byte equal.
It then rereads every private staged source, the fresh package, and every
caller-visible input. Any observed mutation, missing/extra profile selection,
different sidecar bytes, producer-version/KiCad-output change, timeout, child
failure, output overflow, or package mismatch fails closed. Regenerated Gerber,
drill, BOM, CPL, DRC, manifest, and ZIP files remain private and are removed
with the temporary workspace.

Success returns the closed path-free result schema v1 with verification scope
`manufacturing-package-fresh-replay-v1`. It contains only the portable board
name; byte/SHA-256 identities for the board, optional project/rules,
file-backed profile, and retained/fresh packages; a built-in profile ID when
selected; an explicit `identical: true`; and completed input, reproduction,
staged-source, and caller-source validation flags. It contains no caller or
temporary paths, command output, credentials, or manufacturing payloads.

The supplied pcbex and KiCad commands remain unauthenticated, unsandboxed trust
boundaries. Process-tree supervision covers ordinary descendants, not a tool
that intentionally escapes with `setsid` or an equivalent Job-breakaway
mechanism. Exact package equality establishes deterministic reproduction under
those selected tools, not their provenance, signer, operating-system isolation,
or absence of network/filesystem access. This command does not change the
deterministic pipeline or its schemas, expose MCP or Action integration, submit
to a factory, authenticate a factory receipt, authorize procurement/fabrication,
or place an order.

## Circuit-handoff composition (v1.457)

Version 1.457 composes that standalone replay with exact circuit-handoff and
board-binding evidence through the existing `replay-circuit-handoff-bundle`
command:

```sh
pcbex-agent replay-circuit-handoff-bundle circuit-handoff.zip \
  --pcbex pcbex \
  --kicad-board board.kicad_pcb \
  --board-binding-report circuit-kicad-board-binding.json \
  --require-board-binding-approved \
  --manufacturing-package manufacturing/manufacturing.zip \
  --manufacturing-kicad-cli kicad-cli \
  --manufacturing-kicad-project board.kicad_pro \
  --manufacturing-kicad-rules board.kicad_dru \
  --manufacturing-fab-profile profiles/acme-dfm.json \
  --timeout-seconds 120 \
  > circuit-manufacturing-replay.json

pcbex-agent circuit-handoff-bundle-manufacturing-replay-result-schema \
  --output circuit-manufacturing-replay.schema.json
```

Manufacturing replay is legal only with the complete v5 board-binding pair,
`--kicad-board` and `--board-binding-report`, plus the retained package. There
is intentionally no second manufacturing board argument. The adapter captures
one raw board and uses those exact bytes for both the existing geometry-free
electrical binding and the package producer. The board byte count and SHA-256
in the nested standalone replay must equal the v5 board identity, so even a
geometry-only raw-board change fails the composition when its electrical
digest happens to remain equal.

The unchanged handoff ZIP first reproduces exactly, followed by any requested
native ERC, AI quorum, or catalog assertions and the exact board-binding
report. If `--require-board-binding-approved` is set, an exact rejected report
stops before manufacturing; otherwise the rejected decision remains visible
evidence. The existing manufacturing producer then runs privately with the
same captured board, explicit project/rules inputs, and one mutually exclusive
profile at most: a built-in DFM profile, external DFM profile, or physical
profile. A profile is optional. Its fresh ZIP must equal the retained ZIP
byte-for-byte.

One outer monotonic deadline governs every capture, native child, cross-binding
check, reread, result construction, and cleanup. The nested manufacturing
replay receives a strictly shorter remaining deadline. Before success, the
composition completes the package replay's staged-source checks and one final
union reread of the caller-visible handoff, optional assertion, binding, and
manufacturing sources. Any source mutation or timeout fails without a partial
v6 result.

The closed path-free result has schema version 6 and exact verification scope
`deterministic-electrical-handoff-chain-manufacturing-package-replay-v6`. It
retains the complete closed `manufacturing-package-fresh-replay-v1` result and
states that package replay and shared-board identity matching completed.
Omitting every manufacturing option preserves exact handoff replay v1–v5
serialization and the unchanged six-entry archive. The standalone
`replay-manufacturing-package` API, CLI, and schema v1 are unchanged.

The v6 result proves exact reproduction under caller-selected, unauthenticated
pcbex and KiCad executables. It does not authenticate toolchain provenance,
supplier or factory acceptance, a network request or receipt; publish or submit
the regenerated package; establish current inventory, pricing, reservation, or
fabrication availability; independently approve a PCB layout; authorize
procurement, manufacturing, fabrication, deployment, or ordering; add
MCP/Action/pipeline schema parity; or generate/build firmware.

Component metadata is read from KiCad `property` fields and legacy `fp_text`
fields. `Reference` and `Value` are required for a manufacturing row. `MPN`,
`LCSC`, `JLCPCB`, `DigiKey`, and equivalent normalized property names are
accepted as manufacturer-part-number aliases. KiCad
`exclude_from_bom`/`exclude_from_pos_files`, `DNP`, and `Do Not Populate`
markers are honored deterministically. Duplicate aliases are rejected rather
than resolved by order. A footprint identifier and reference are mandatory,
and populated BOM rows must also have a non-empty value. Common fields such as
`LCSC Part #` and `JLCPCB Part #` are normalized as MPN aliases.

Coordinates in `cpl.csv` are the original KiCad board coordinates, rather than
the normalized coordinates used internally by the router. The contract uses
the board origin, does not negate bottom-side X, preserves the footprint's
stored rotation, and writes `F`/`B` as the side. Factory-specific origin,
bottom-rotation, and axis transformations must be applied by a DFM/factory
profile before upload; the vendor-neutral CPL must not be assumed to match
every assembler's convention.
