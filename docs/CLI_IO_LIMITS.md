# Bounded CLI I/O and subprocess execution

pcbex applies one shared boundary to the generic file operations used by the
Rust CLI. A single input or generated output is limited to 134,217,728 bytes
(128 MiB). This outer limit is aligned with the KiCad S-expression input limit
and is enforced before parsers or downstream command handlers receive bytes.

## File inputs

Generic `pcbex` command inputs must be regular files. Direct symbolic links and
symbolic links in ancestor path components are rejected. The reader:

1. checks the path type and advertised size;
2. opens the file and verifies that its identity and size still match;
3. reads at most the limit plus one byte;
4. rewinds the same opened descriptor and compares a second fixed-buffer pass
   byte-for-byte with the first; and
5. rechecks the opened file and path identity before returning data.

Text inputs are decoded as strict UTF-8 after the bounded read. Empty files are
permitted by the I/O layer so the owning parser can report its format-specific
error. Command-specific limits that are smaller than 128 MiB remain in force;
the shared boundary never relaxes them.

## File outputs

Generic outputs are size-checked in memory, written to a private temporary file
beside the destination, flushed and synchronized, then atomically renamed.
Existing regular outputs retain the historical overwrite behavior and their
Unix mode bits. New Unix files use mode `0644`. Atomic replacement creates a
new filesystem object, so inode identity, ownership, ACLs, extended attributes,
and hard-link relationships are not a preservation contract. A direct or
ancestor symbolic link and a non-regular destination are rejected.

Outputs whose existing contract is no-clobber, including AI review approvals,
signing keys, and factory or pipeline evidence, use the same staged and
synchronized publication but fail if the destination already exists.
`sign-ai-review` performs its response, signer, optional-session, evidence,
and destination preflight before opening the private key. Multi-file commands
publish each file atomically; the set is not one transaction.
Output-directory creation is also outside the per-file transaction. A command may
therefore retain already completed evidence files when a later publication or
quality gate fails, as documented by that command.

Fabrication authorization uses the same no-clobber boundary. The deterministic
plan is limited to 4 MiB, the retained report and manufacturing ZIP to 128 MiB,
the factory receipt and organization policy pack to 64 MiB each, and each
signed fabrication approval to 1 MiB. Signing reserves its destination and
freshly validates the approved factory-bound pipeline, exact ZIP/receipt/pack,
scope, and dedicated trusted signer before reading the private key. Verification
limits the approval set to 100. The runner snapshots the plan-selected inputs
during its fresh replay; the authorization layer then final-rereads the plan,
retained report, ZIP, receipt, pack, and submitted approvals, rechecks the
output against the same replayed plan, captures the current time, and publishes
a closed report within the generic 128 MiB output limit. A valid policy-level
`not_authorized` decision is retained before `--require-authorized` fails;
malformed, untrusted, mismatched, or mutated evidence produces no report.

For signing, a valid response that fails an approval gate is still a legitimate
signed rejection: the no-clobber approval is published before
`--require-approved` returns failure. Any existing regular file, symbolic link,
or other non-regular destination remains untouched on preflight, signing, or
publication failure. The destination-file boundary is atomic, but input
verification, private-key access, and publication are not one atomic filesystem
transaction.

The checks before and after opening reduce path-replacement races but are not an
OS filesystem sandbox. Callers that require protection from a hostile local
administrator must run pcbex in an isolated filesystem namespace.

Manufacturing publication additionally pins each validated destination
directory. On Unix, temporary creation, cleanup, and atomic replacement are
directory-descriptor-relative (`openat`/`unlinkat`/`renameat`), so renaming and
replacing an ancestor cannot redirect a commit. Windows retains a real
directory handle and performs identity checks immediately around its guarded
path-based replacement. Protection against a process that can write arbitrary
entries inside the already-pinned directory still requires an OS sandbox or
private directory permissions.

## Subprocess limits

Rust CLI integrations use a shared shell-free runner. Standard input is closed
unless an integration supplies an already bounded, file-backed input; standard
output and error are drained concurrently in fixed chunks, and every invocation
has a hard deadline.

| Invocation | Deadline | stdout | stderr |
|---|---:|---:|---:|
| `pcbex doctor` version check | 10 seconds | 64 KiB | 64 KiB |
| KiCad DRC and manufacturing export | 600 seconds | 8 MiB | 1 MiB |
| KiCad build identity | 600 seconds | 128 KiB | 1 MiB |
| MCP child `pcbex` command | 600 seconds | 16 MiB | 1 MiB |
| Firmware compiler, smoke test, or Python check | configurable 1–3600 seconds; default 120 | 1 MiB | 1 MiB |
| Factory repair wrapper | remaining portion of its 600-second repair limit | 1 MiB | 1 MiB |

The final allowed byte is valid. The next byte, timeout, cancellation, read
failure, or wait failure terminates and reaps the child before returning. Unix
children run in a new process group; Windows children are assigned to a
kill-on-close Job Object, so ordinary descendants created after assignment are
terminated with the child. Windows assignment necessarily occurs just after
`std::process` starts the child. An assignment error is accepted only when
`try_wait` proves that the direct child already exited; otherwise it fails
closed and cleans up. The already-exited fallback cannot guarantee descendant
cleanup. This is not a CPU, memory, filesystem, network, syscall, or privilege
sandbox, and a Unix descendant that deliberately creates a new session is
outside the process-group guarantee.

KiCad DRC writes to a private staged report. pcbex publishes the report through
the atomic file boundary only after the process succeeds and the staged report
passes regular-file and size validation. A timeout, output overflow, or nonzero
exit therefore leaves an existing public report unchanged.
KiCad manufacturing exports remain inside their purpose-specific private stage
until validation and promotion. The stage is checked after every external
phase under the manufacturing quota contract: 4,096 entries, depth 16, 128 MiB
per file and final ZIP, 1 GiB aggregate workspace bytes, 255-byte portable
basenames, and 1 MiB normalization lines, manifests, and Gerber jobs. ZIP
expanded artifact payload is separately limited to 512 MiB. Archive creation
and public copies are bounded and staged before atomic replacement. BOM/CPL
rows are size-preflighted and streamed through a bounded writer, manufacturing
metadata is capped at 100,000 parts, and the package generator reserves bytes
and entries already consumed elsewhere in the private workspace. The
generated ZIP is revalidated through the factory acceptance boundary. The
external tool's filesystem writes are not live-capped while that process is
running.

Firmware validation discards captured diagnostics after recording the process
status, so its closed manifest schema and deterministic evidence remain
unchanged. Factory repair passes the normalized receipt through a seek-rewound
temporary file instead of a pipe, which cannot deadlock when a wrapper exits
without reading stdin. A repair timeout, output overflow, nonzero exit, input
mutation, or invalid candidate retains the last fully validated manufacturing
package.

## MCP framing

Each newline-delimited MCP request and serialized response is limited to 16
MiB. An oversized request is drained through its newline before a bounded
JSON-RPC error is returned, preserving the next frame boundary. If a response
would exceed the limit, pcbex emits a small internal-error response instead of
writing a partial JSON document. Child-process diagnostics exposed in a tool
result are trimmed to 4 KiB. A per-task watchdog sets the cancellation flag at
TTL expiry so a running bounded child is stopped rather than merely being
forgotten.

## Scope

The hardware pipeline, factory HTTPS connector, and remote adapters retain
their existing narrower, purpose-specific limits. The Python agent has an
equivalent stdlib-only boundary documented in
[`PYTHON_AGENT_LIMITS.md`](PYTHON_AGENT_LIMITS.md). Rust manufacturing ZIP,
artifact, workspace, and repair walkers use the production contract documented
in [`MANUFACTURING_PACKAGE.md`](MANUFACTURING_PACKAGE.md). Release workflows,
CI jobs, composite-action output trees, and their Python helper scripts use the
outer limits documented in [`CI_EXECUTION_LIMITS.md`](CI_EXECUTION_LIMITS.md).
Core A*, zone fill, placement, and raster budgets are unchanged.
