# Bounded Python agent I/O and subprocess execution

The `pcbex-agent` treats caller-selected paths and external executables as
untrusted boundaries. All production file-content reads and writes now use one
stdlib-only facade, and every local child process uses one shell-free bounded
runner.

## File boundaries

Generic agent JSON, text, schema, catalog, route, and generated-source files
are limited to 33,554,432 bytes (32 MiB). AI review requests use the same
32 MiB limit. The repair loop permits KiCad board candidates up to 134,217,728
bytes (128 MiB) and DRC reports up to 32 MiB. The final allowed byte is valid;
the next byte is rejected before its contents reach a parser or output path.
Request schema v2 artifact descriptors are also closed and bounded before the
request enters an LLM prompt: generated schematic identities allow at most
64 MiB, plan-source identities 4 MiB, and retained-report identities 128 MiB.
These are descriptor checks; the adapter never loads those artifacts itself,
and Rust remains the authority that live-reruns and verifies them.

The circuit handoff ZIP has a separate 234,881,024-byte (224 MiB) outer and
aggregate ceiling because it carries a generated schematic plus retained
evidence. Its six stored entries also retain their individual generation,
specification, check, schematic, handoff-report, and manifest limits. The
offline verifier preflights the exact six-record central directory before ZIP
allocation, streams each payload under its role limit, and rejects compression
and noncanonical framing. Extraction reserves one new private directory,
writes only fixed regular-file names, and writes `manifest.json` last as the
commit marker. A caught failure rolls back only identities proven to be owned
by that run; if initial identity inspection fails, the reservation is left
untouched rather than risking deletion of a concurrent replacement. An abrupt
crash may also leave an incomplete reserved directory that must be reverified
rather than trusted by existence. Rollback is live-state cleanup;
directory-entry deletion is not claimed crash-durable on filesystems that do
not support directory `fsync`.

The optional v1.451 handoff native-ERC replay keeps its evidence outside that
ZIP. A retained normalized report is limited to 32 MiB and its optional exact
warning-policy source to 1 MiB. Both are stable-read before the expensive
handoff-chain replay, staged as exact bytes only in private temporary storage,
and reread from the caller-visible paths after KiCad exits. A mutation, alias,
non-regular file, linked path, empty input, or over-limit input fails closed.

The optional v1.452 handoff AI-quorum replay likewise keeps every sidecar
outside the ZIP. Its retained quorum report and freshly generated comparison
report are each limited to 16 MiB. The schema-v1 review request, organization
policy pack, every signed approval, and every paired response are each limited
to 32 MiB and to 128 MiB in aggregate, excluding the retained/fresh report.
One to 100 approval/response pairs are accepted. The complete set is
stable-read before producer replay. The exact schematic, request, policy pack,
approvals, and responses are staged under fixed private names only after the
six-entry archive reproduces exactly (and after optional native ERC); the fresh
private report is compared with the retained bytes in memory. Every
caller-visible sidecar is reread before success. When both assertions are
enabled, the native report and policy are reread again after the AI verifier.

The optional v1.453 catalog-provenance replay keeps its complete evidence set
outside the same unchanged ZIP. Catalog-generation provenance and its retained
fetch receipt are limited to 1 MiB each; the exact normalized snapshot is
limited to 4 MiB; and the three captured sources are limited to 6 MiB in
aggregate. All three paths are required together, must be nonempty stable
regular files, and are accepted only for a catalog-backed archive. They are
captured before a producer child, reread before offline provenance validation,
and reread again afterward. A file-origin snapshot is staged under its exact
bound basename only in a private temporary directory. No catalog source is
published, embedded in the archive, or returned by path.

The optional v1.454 retained-board replay keeps the board and board-binding
report outside the same unchanged ZIP and emits scope
`deterministic-electrical-handoff-chain-board-binding-replay-v5` with a
path-free `board_binding` result object. `--kicad-board` and
`--board-binding-report` are required together; the board is limited to 128 MiB
and the compact report to 12 MiB canonical JSON plus one trailing newline
byte. An optional `--board-binding-policy` is
limited to 4 MiB (all three sources are 144 MiB plus one byte in aggregate)
and is the exact custom policy source for the fresh replay; omission selects the existing built-in
policy. All
supplied sources are nonempty stable regular files, captured before a producer
child, staged only in a private temporary workspace, and reread byte-for-byte
after the board verifier. The fresh report is read from its private output
file and compared including its trailing newline; the hidden
`--mcp-echo-report-summary` bridge sends only its closed numeric/digest summary
through Python stdout, never the full report. No board/report/policy source is
embedded in the archive or returned by path.

The standalone v1.455 manufacturing replay is separate from the electrical
handoff archive. It captures a portable-basename board and retained package,
plus optional explicit KiCad project/rules and one optional profile selection,
before starting `pcbex fabricate`. Board, project, rules, and retained/fresh
package reads are each limited to 128 MiB; external DFM and physical profiles
are each limited to 4 MiB; and all caller inputs together are limited to
512 MiB. Project and rules bytes are staged under names derived from the board
stem. An external profile retains its validated portable caller basename
because the manufacturing manifest binds that name. Every staged input, the
fresh ZIP, and every caller-visible input is reread before success. Fresh and
retained `manufacturing.zip` bodies must be byte-for-byte equal; regenerated
manufacturing outputs never leave the private temporary workspace.
Built-in fabrication IDs are limited to 128 lowercase ASCII letters, digits,
dots, or hyphens, beginning with a letter or digit.
Every caller `PathLike` is frozen to built-in immutable text with one
`os.fspath` conversion before validation or reading, and the first stable-read
byte/SHA-256 identity is retained for the final result. The caller pcbex
command and the complete injected argv are each limited to 256 arguments and
32,768 aggregate UTF-8 bytes. The rendered Windows command line, including its
terminating null, is additionally limited to 32,767 UTF-16 code units.

Inputs must be regular files. Direct symbolic links, symbolic links in any
lexical ancestor, and Windows reparse points are rejected; lexical `..` parent
traversal is not accepted. The reader checks the advertised path identity and size, opens
without following the final symlink where the platform permits,
checks the descriptor, reads at most the limit plus one byte, and rechecks both
the descriptor and path before returning. Text is decoded as strict UTF-8.

Private workspaces used by the repair loop, circuit generation, and circuit
handoff builder canonicalize only the trusted temporary root selected for the
process before creating their directories. Caller-provided paths remain
lexical and therefore still reject every direct or ancestor symlink. This
distinction is required on macOS, where the standard temporary area is normally
exposed through the system-managed `/var` symlink.

Outputs are size-checked in memory, written to a private sibling file, flushed
and synchronized, and then atomically replaced. Existing Unix mode bits are
preserved; new Unix outputs use mode `0644`. Provider responses and receipts
retain their no-clobber contract and use an atomic hard-link publication so a
concurrent destination creation cannot be overwritten. Parent directories are
created component by component and rechecked without following symlinks.
Provider target paths are preflighted before a subprocess or network request,
and the race-safe publication checks are repeated afterward. Response and
receipt files are each atomic but are not a multi-file transaction: if receipt
publication fails, a response already published by that invocation is retained.

No-clobber publication requires a filesystem that supports hard links within
the destination directory. Filesystems that do not provide that primitive fail
closed instead of falling back to a racy existence-check-and-rename sequence.
The staged file is always synchronized before publication. Parent-directory
sync is also attempted on Unix; Windows and filesystems that explicitly report
directory `fsync` as unsupported retain atomic replacement without promising
crash-durable directory metadata.

Atomic replacement creates a new filesystem object. Inode identity, ownership,
ACLs, extended attributes, and hard-link relationships are not preserved. The
pre/post checks reduce path-replacement races but are not a filesystem sandbox
against a hostile local administrator. That threat model requires an isolated
filesystem namespace or container.

## Subprocess boundaries

The runner never invokes a shell. Standard output and error are drained
concurrently under independent limits. Standard input is closed immediately
when absent; provider prompt delivery runs concurrently and is covered by the
same monotonic deadline as execution. Supplied standard input is checked before
it is copied and is limited to 32 MiB by default. Provider prompts use a fixed
32 MiB UTF-8 limit; managed-provider JSON request bodies use a separate 64 MiB
limit before network access.

| Invocation | Deadline | stdin | stdout | stderr |
|---|---:|---:|---:|---:|
| External AI provider adapter | configurable 1–600 seconds; default 120 | 32 MiB | configurable 1 byte–16 MiB; default 1 MiB | same as stdout |
| Generic agent `pcbex` invocation | default 300 seconds | closed | 8 MiB | 1 MiB |
| Circuit handoff chain/native ERC/AI quorum/catalog-provenance replay (`replay-circuit-handoff-bundle`) | one aggregate `--timeout-seconds`, 1–600 seconds; default 120 | closed | 1 MiB per child | 1 MiB per child |
| Circuit handoff retained-board binding replay | same aggregate `--timeout-seconds`, 1–600 seconds; default 120 | closed | 1 MiB per child | 1 MiB per child |
| Fresh manufacturing-package replay (`replay-manufacturing-package`) | one aggregate `--timeout-seconds`, finite `0 < seconds <= 600`; default 120; inner Rust deadline reserves up to 15 seconds or half of remaining time and must convert to a positive Rust `Duration` | closed | 1 MiB | 1 MiB |
| Repair-loop `pcbex route-kicad` | 300 seconds | closed | 8 MiB | 1 MiB |
| Repair-loop `kicad-cli pcb drc` | 300 seconds | closed | 8 MiB | 1 MiB |

The circuit handoff replay is the only handoff consumer in this table that
starts native children. Its one monotonic deadline begins before the archive
read and is shared by canonical archive validation, every `pcbex` child,
bounded temporary artifact reads, deterministic ZIP reconstruction, and the
final byte-for-byte comparison. When a retained native report is supplied, the
same deadline also covers its optional policy, private staging, fresh native
KiCad verification, post-run stable rereads, and cleanup. Each producer child
receives only the remaining time; the deadline is not reset for the
catalog-input ERC, resolved ERC, schematic writer, or semantic handoff stages.
The nested Rust native verifier receives a shorter internal duration that
reserves outer cleanup time and applies it directly to the KiCad process tree.
A requested AI assertion uses the same deadline for all AI sidecar reads,
private staging, the existing `verify-ai-quorum --schematic` child, exact
retained/fresh report comparison, closed report validation, final source
rereads, and cleanup. The verifier child receives the remaining duration minus
an outer cleanup reserve. `--require-ai-quorum` is evaluated only after the
complete evidence replay and rereads, so a valid below-threshold report remains
inspectable when the final gate is not requested.
A requested catalog-provenance assertion uses that same deadline for its
1/1/4 MiB source reads, complete producer replay, optional independent native
and AI assertions, pre-validation rereads, private snapshot staging when
required by its retained source descriptor, the offline v1.421 validation,
post-validation rereads, and cleanup. The replay does not use a fresh current
time or make a supplier/network request.
A requested retained-board assertion uses that same deadline for its 128 MiB
board, 12 MiB canonical report (+1 newline byte), and optional 4 MiB policy
reads, complete producer replay, optional independent native/AI/catalog assertions,
private staging,
the existing geometry-free `verify-circuit-kicad-board-binding` child, fresh
report validation, final source rereads, and cleanup. The standalone Rust
board-binding command has no timeout flag; the Python supervisor passes only
the remaining aggregate budget to the child. A retained but rejected report
remains inspectable unless `--require-board-binding-approved` is requested,
and that final gate is evaluated only after exact report comparison and all
rereads.

The manufacturing replay starts one independent monotonic deadline before any
input read. It covers the bounded board/package/sidecar/profile captures,
private staging, one shell-free `pcbex fabricate` child, fresh-package read and
exact comparison, staged-source checks, caller-source rereads, result creation,
and cleanup checkpoints. Immediately before the child starts, Python reserves
the smaller of 15 seconds or half the remaining budget and passes the rest as
Rust `fabricate --timeout-seconds`. Rust applies that strictly shorter deadline
to its synchronous phase checkpoints and to DRC, Gerber, drill, and identity
children, each with the earlier of the shared remaining time and its own cap.
The inner timeout must be finite, positive, no greater than 600, and
representable as a positive Rust `Duration`; a value that converts to zero at
nanosecond resolution fails closed.

The replay passes a hidden internal outer-supervision marker. Python's bounded
runner makes pcbex the supervised process-group leader on Unix or places it in
an outer Job on Windows; all four KiCad children inherit that tree instead of
creating nested groups/Jobs. Rust terminates and reaps a direct child when its
shorter deadline expires, and the outer supervisor can still collect pcbex and
ordinary descendants across wrapper or pre-exec delays. A direct standalone
Rust `fabricate` call does not use this marker and retains isolated KiCad child
groups/Jobs. Intentional `setsid` or equivalent Job escape by an unauthenticated
supplied tool is outside the containment guarantee. The caller-selected
`--kicad-cli` is passed as a direct argument, not resolved or invoked by
Python.

Rust publication preflights, copies, synchronizes, and checks immediately
before each visible persist; it commits ordinary siblings, `manifest.json`,
then canonical `manufacturing.zip`. An inner failure may leave intermediate
siblings or a manifest in the private output, but no newly committed canonical
archive evidences a complete fresh package. Rust performs no deadline check
after that final archive commit, so direct `fabricate` can cross its nominal
deadline during non-preemptible post-commit work. The Python consumer accepts
only a successful child, exact fresh archive bytes, all final rereads, and a
deadline check after temporary cleanup and immediately before return, so it
cannot report replay success after expiry.

A monotonic deadline is checked after every bounded input read and no success
is returned after it expires. Ordinary synchronous filesystem reads cannot be
preempted in the middle of a kernel/FUSE/network-filesystem operation, so a
stalled special backing filesystem can delay the error beyond the configured
wall-clock duration; native child execution and cleanup remain actively
bounded by the process supervisor.
A catalog receipt makes the catalog-input ERC stage required. The replay writes
only private temporary files and publishes no archive or extraction directory.

`--pcbex` is a caller-supplied executable/argument boundary, invoked without a
shell. The process runner bounds its output and process-tree lifetime, but it
is not a CPU, memory, filesystem, network, syscall, or privilege sandbox.
The supplied binary and its reported version are not authenticated. Exact
archive reproduction normally implies a matching retained `engine_version`,
but that is an output equality check rather than binary provenance. The default
replay uses pcbex's semantic `verify-circuit-kicad-handoff` gate without real
KiCad schematic ERC. v1.451 runs real `kicad-cli sch erc` only when the caller
explicitly supplies `--native-kicad-erc-report`; both `--pcbex` and
`--kicad-cli` are unauthenticated, unsandboxed caller-selected executables. The
v1.452 AI option set makes no provider or network call: it passes the exact
privately staged schema-v1 request, policy pack, approval/response pairs, and
reproduced schematic to the existing Rust quorum verifier. That verifier's
live schematic boundary compares imported semantic IR, not irrelevant raw
source formatting. Session-bound and routed quorums, artifact-bound request
schemas, and tool provenance remain outside this replay contract. The
v1.453 catalog option set similarly makes no supplier or network call. It
revalidates a retained historical digest graph from the exact provenance,
fetch-receipt, snapshot, and archived generation bytes, but does not
authenticate a supplier, TLS session, or raw HTTP response; establish current
inventory, price, or reservation; authorize procurement or fabrication; prove
toolchain provenance; or approve a board, layout, or manufacturing operation.
The v1.454 board option set similarly makes no layout or manufacturing
decision: it revalidates only the retained raw board and compact report against
the geometry-free electrical subset. It does not approve placement/footprint
geometry, copper/routing/zones, PCB DRC/DFM, Gerber/BOM/CPL, manufacturing or
fabrication, procurement, supplier facts, or pcbex/KiCad/toolchain provenance.
The v1.455 manufacturing replay starts no supplier/provider request and makes
no fabrication decision. Its exact package equality binds fresh output to the
captured board, optional sidecars/profile, and selected commands, but does not
authenticate those pcbex/KiCad executables or provide a CPU, memory, filesystem,
network, syscall, or privilege sandbox. It neither updates nor replaces a
deterministic-pipeline report, factory receipt, AI approval, fabrication
authorization, procurement authorization, or order record. MCP and GitHub
Action exposure are not part of this standalone boundary.
The offline `verify-circuit-handoff-bundle` and
`extract-circuit-handoff-bundle`
paths remain native-child-free and retain their existing no-execution boundary.

Exactly the configured input or output limit is accepted. The next byte, deadline,
pipe failure, or cleanup failure terminates the process tree and reaps the
direct child before an error is returned. A cleanup failure takes precedence
while retaining the original timeout, overflow, or other failure as its cause.
A nonzero exit remains available to
the owning integration: provider adapters report a bounded diagnostic,
`run_pcbex` preserves its check-true failure contract, and KiCad DRC may retain
its report when actual parsed violations intentionally produce a nonzero exit.
An empty, truncated, or malformed KiCad report, and a nonzero exit without a
parsed violation, fail closed and cannot publish a repaired board.

POSIX children start in a new session and are killed by process group. Windows
children are attached to a kill-on-close Job Object immediately after spawn.
On Darwin only, an initial process-group `EPERM` is treated as an exited-group
race when `poll()` has reaped the direct child and a signal-zero group probe
returns `ESRCH`. A live child, an existing group, an unauthorized probe, or any
other probe result remains a cleanup failure. Windows necessarily has a small
post-spawn assignment race, and a POSIX descendant that deliberately creates
another session can escape the group.
The runner is not a CPU, memory, filesystem, network, syscall, or privilege
sandbox.

External tools still create candidate boards and DRC reports by pathname. The
agent validates those private-workspace files through the bounded facade before
hashing, parsing, or publishing them, but it cannot cap filesystem growth while
the external process is running.

## Scope

Managed HTTPS AI providers already have their own response byte and end-to-end
time limits; their local request and evidence files use the shared Python
facade. Rust firmware and factory-repair subprocesses now use the Rust process
supervisor documented in [`CLI_IO_LIMITS.md`](CLI_IO_LIMITS.md). Rust
manufacturing ZIP, artifact, and repair-workspace walkers now share a finite
quota contract. Release helpers, GitHub Actions jobs, and composite-action
output trees now have the outer execution limits documented in
[`CI_EXECUTION_LIMITS.md`](CI_EXECUTION_LIMITS.md). Live filesystem growth by
an external child remains a runner/sandbox responsibility.
