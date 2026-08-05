# Bounded release and CI execution

pcbex places explicit time, output, parallelism, and retained-artifact ceilings
around its repository automation. These limits complement the command-specific
Rust and Python boundaries; they do not replace the electrical, routing, DRC,
or manufacturing gates.

## Workflow policy

Every GitHub Actions job has a reviewed `timeout-minutes` value. Repeated runs
share a concurrency group, while release runs deliberately remain serialized
and are never cancelled during publication.

| Workflow job | Timeout |
|---|---:|
| CI hardware action | 45 minutes |
| CI Rust | 45 minutes |
| CI Python | 20 minutes |
| CI Python boundary matrix | 20 minutes |
| CodeQL language matrix | 30 minutes |
| Fuzz target matrix | 30 minutes |
| KiCad end-to-end | 45 minutes |
| Release verify | 45 minutes |
| Release draft preparation | 10 minutes |
| Release target build | 45 minutes |
| Release audit | 15 minutes |
| Release publication | 10 minutes |
| Trusted PR comment publisher | 10 minutes |

Every matrix uses `fail-fast: false` and runs at most two variants at once.
The scheduled fuzz workflow additionally gives each libFuzzer process a
60-second campaign, 10-second per-input timeout, 2,048 MiB RSS limit, and
1 MiB input limit. Before upload, each target's failure tree is limited to 16
regular files at depth one, 1 MiB per file, and 16 MiB total. Accepted crash
artifacts are retained for seven days.

`scripts/tests/test_ci_execution_policy.py` is a dependency-free, fail-closed
check of the workflow inventory, exact job timeouts, concurrency, matrix
parallelism, fuzz flags, serialized release policy, fixture-server cleanup,
and composite-action publication gate. Adding a workflow or job therefore
requires an explicit policy decision in the same change.
The shared runtime boundary suite is also repeated on macOS and Windows.

## Shared script runtime

`scripts/ci_runtime.py` delegates to the same stdlib-only bounded I/O and
process-tree supervisor used by `pcbex-agent`. It provides:

- shell-free child execution with independent stdout and stderr ceilings;
- a monotonic deadline that can be shared across sequential commands;
- POSIX process-group and Windows Job Object descendant cleanup;
- strict UTF-8 decoding and bounded HTTP response reads;
- workspace-relative output-path validation; and
- a regular-file-only output-tree scan with descriptor/path identity checks.

The public composite action runs toolchain installation, compilation, and the
complete hardware-analysis script through this supervisor. Analysis has a
40-minute command deadline and 8 MiB for each output stream. Before artifact,
SARIF, or direct trusted-comment publication, its output tree must contain no
links or special files and stay within 4,096 entries, depth 16, 128 MiB per
file, and 512 MiB total. The three loopback fixture servers used by repository
CI have recorded PIDs and an unconditional cleanup step.

The deterministic pipeline runner is an explicit root-Action opt-in through
`deterministic-pipeline-plan`; an empty value leaves analysis-only behavior.
When enabled, the same supervised command retains exactly
`output-dir/deterministic-pipeline-report.json` and publishes its seven
authenticated metadata outputs only after rechecking the retained report's
size, digest, identities, counts, schema version, and decision. A valid
rejected report is published before `deterministic-pipeline-require-approved`
causes the final Action step to fail. No implicit input discovery or alternate
report destination is allowed, and stale, linked, malformed, or substituted
reports fail closed.

The root Action also supports the closed compiler through the paired
`deterministic-pipeline-intent` and `deterministic-pipeline-plan-output`
inputs. Both are workspace-relative and must be supplied together. They are
mutually exclusive with `deterministic-pipeline-plan`; a partial pair or mixed
legacy/new selection fails before analysis. The compiler runs before analysis
under the same bounded shell-free process policy, publishes only through a
new-file/no-clobber destination, and passes its effective plan to the
unchanged deterministic runner. The plan-output parent is the canonical base
for every explicit role path in the intent, even when the intent file lives in
another directory. Only descendants of that parent are allowed; absolute,
traversal, linked, aliased, special, duplicate, stale, or concurrently changed
sources fail closed.

The compiler bridge authenticates exactly five bounded scalar values before
the runner starts: schema version, intent source bytes, intent source
SHA-256, plan source bytes, and plan source SHA-256. Plan source bytes include
the canonical JSON final newline. After runner EOF, the bridge stable-reads
the current intent and effective plan again and requires the report's raw plan
source identity to match the compiler metadata, so a post-compilation
substitution fails closed before attribution. It exposes only
`deterministic-pipeline-effective-plan`,
`deterministic-pipeline-intent-source-bytes`,
`deterministic-pipeline-intent-source-sha256`,
`deterministic-pipeline-plan-source-bytes`, and
`deterministic-pipeline-plan-source-sha256`; plan and role bodies never enter
Action metadata. The four source-identity values are empty outside compiler
mode; `deterministic-pipeline-effective-plan` is the legacy plan path in
legacy plan mode and is empty only in analysis-only mode. Existing runner
outputs remain unchanged. The compiler adds no LLM, network,
discovery, gate, approval, design mutation, or manufacturing operation.

Version 1.436.0 also preflights the explicit firmware role before the plan is
published. Its path must be `manifest.json`; the parent is an exact eight-entry
directory containing that manifest and the seven fixed v2 source artifacts.
The bounded compiler read rejects symbolic links, special files, unsafe names, missing
or extra entries, malformed or duplicate manifest fields, and every
manifest-to-source byte-count or lowercase SHA-256 mismatch. A second
directory scan follows each source snapshot, and a final complete snapshot is
compared after every explicit role is confirmed; any observed replacement,
removal, or addition fails closed. The plan remains schema v1 with only the `firmware_manifest`
descriptor; no source descriptors or artifact hashes are emitted into it.
This is not a build or approval step: the compiler does not run firmware
commands, evaluate build evidence, bind the canonical schematic, or call an
LLM/network. The runner and pipeline gate repeat the exact-eight checks and
remain final authority.

A composite action cannot set `timeout-minutes` on its caller's job. Its three
supervised commands remain individually finite (10, 30, and 40 minutes), but
artifact and SARIF service actions are governed by the calling job. Public
consumers that need a tighter aggregate must set a job timeout; the repository
smoke job uses 45 minutes.

## Release audit

Release-audit subprocesses share one eight-minute aggregate deadline, and local
roadmap/asset work checks that deadline between bounded items. Git commands
have a 30-second per-call cap; GitHub metadata calls have a 60-second cap;
asset download has a 240-second cap. Captured stdout is at most 16 MiB by
default (1 MiB for download diagnostics) and stderr is at most 1 MiB.

The roadmap and version files are limited to 1 MiB, with at most 1,024 roadmap
milestones. GitHub release enumeration is limited to 100 pages of 100 entries
and the bounded command output. The exact 12 downloaded files must be regular,
non-link files and obey these limits:

| Asset | Per-file limit |
|---|---:|
| Platform archive | 128 MiB |
| SHA-256 file | 4 KiB |
| SPDX JSON | 16 MiB |
| All 12 assets | 640 MiB aggregate |

Advertised GitHub sizes and identity-checked local reads are both checked.
Checksums and SPDX structure are then validated from those bounded bytes.

The completion-audit generator runs `cargo test --list` for at most ten
minutes with 32 MiB stdout and 4 MiB stderr. Its TOML inputs are capped at
1 MiB, and the 2 MiB completion document is updated with synchronized atomic
replacement. The trusted direct PR-comment helper accepts at most 256 KiB of
Markdown, 1 MiB per GitHub API response, 8 MiB across the invocation, and a
1 MiB GitHub output file.

## Residual boundary

These controls are deterministic application and workflow boundaries, not an
OS resource sandbox. A third-party action or external tool can consume CPU,
memory, network, or filesystem space until its job or process deadline, and an
external writer can race between output-tree scans. POSIX descendants that
deliberately create a new session are outside process-group cleanup; Windows
has a small post-spawn Job Object assignment race. Deployments requiring live
CPU, memory, disk, syscall, or network enforcement must add runner-level
cgroups, quotas, containers, or equivalent isolation.
