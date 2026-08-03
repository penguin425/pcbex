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

Inputs must be regular files. Direct symbolic links, symbolic links in any
lexical ancestor, and Windows reparse points are rejected; lexical `..` parent
traversal is not accepted. The reader checks the advertised path identity and size, opens
without following the final symlink where the platform permits,
checks the descriptor, reads at most the limit plus one byte, and rechecks both
the descriptor and path before returning. Text is decoded as strict UTF-8.

The repair loop canonicalizes only the trusted temporary root selected for the
process before creating its private workspace. Caller-provided paths
remain lexical and therefore still reject every direct or ancestor symlink.
This distinction is required on macOS, where the standard temporary area is
normally exposed through the system-managed `/var` symlink.

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
| Repair-loop `pcbex route-kicad` | 300 seconds | closed | 8 MiB | 1 MiB |
| Repair-loop `kicad-cli pcb drc` | 300 seconds | closed | 8 MiB | 1 MiB |

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
Windows necessarily has a small post-spawn assignment race, and a POSIX
descendant that deliberately creates another session can escape the group.
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
supervisor documented in [`CLI_IO_LIMITS.md`](CLI_IO_LIMITS.md). Manufacturing
ZIP and artifact walkers, release helpers, and CI shell/background processes
remain separate follow-up boundaries.
