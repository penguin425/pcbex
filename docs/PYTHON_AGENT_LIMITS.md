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
| Circuit handoff chain/native ERC replay (`replay-circuit-handoff-bundle`) | one aggregate `--timeout-seconds`, 1–600 seconds; default 120 | closed | 1 MiB per child | 1 MiB per child |
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
offline `verify-circuit-handoff-bundle` and `extract-circuit-handoff-bundle`
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
