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

The v1.474 routing-convergence report is an explicit no-clobber output. Its
destination rejects symbolic-link components and lexical/canonical aliasing
with the board input, routed board output, applied profiles/rules, and optional
SVG or JSON adapter outputs. pcbex reserves a sibling temporary file before
routing, renders the bounded closed report in memory, synchronizes it, and
publishes without replacement. The routed board keeps its historical output
semantics; board and report publication are not one transaction. A valid
partial/no-candidate board and report are both retained before the unrouted
gate fails. The report binds canonical internal Board identities rather than
raw source-file bytes; see [Routing Convergence](ROUTING_CONVERGENCE.md).

The v1.475 fresh verifier adds a distinct 32 MiB no-clobber report. Board JSON
verification captures the input Board, exact routed Board, 16 MiB retained
convergence report, and optional 4 MiB physical profile under a 276 MiB
aggregate. KiCad verification additionally captures optional project/custom
rules at 128 MiB each and exactly one external DFM (4 MiB), policy pack
(64 MiB), or physical profile (4 MiB) under a 592 MiB aggregate. Input roles
must not alias, JSON inputs reject duplicate keys, and the retained report must
be canonical with one trailing LF. After fresh replay and exact routed-output
regeneration, every source is reread before synchronized no-replace
publication. These sequential checks are not an atomic multi-file snapshot.
A truthful partial result is retained before `--require-complete` fails;
malformed, substituted, changed, unsafe, or cross-bound input produces no
verification report. See
[Fresh Routing Convergence Verification](ROUTING_CONVERGENCE_VERIFICATION.md).

The v1.476 Python-agent handoff publishes a separate 4 MiB no-clobber report.
CLI preflight rejects an occupied destination and destination overlap with the
original board, routed board, retained convergence/verification reports,
manufacturing ZIP, and explicit sidecars. The Python core then rejects aliases
among all source roles, freshly invokes the existing Rust routing verifier and
manufacturing producer in private stages, and rereads the union before
publication. `--require-ready` runs only after a truthful incomplete result is
retained. This composition does not change either Rust child schema or output
contract. See
[Fresh Routing-to-Manufacturing Handoff](ROUTING_MANUFACTURING_HANDOFF.md).

The v1.477 Python-agent handoff publishes a separate 1 MiB no-clobber report.
CLI preflight adds the retained v1.476 handoff and 32 MiB normalized native DRC
report to the complete source/output alias set. The Python core rejects aliases
among all eleven file roles, caps their direct union at 724 MiB, freshly
reproduces the retained v1.476 bytes, and only then invokes the read-only Rust
native DRC verifier against the same routed board and explicit companions. A
valid routing-incomplete or DRC-rejected decision is retained before
`--require-ready` fails. Invalid bindings, source substitutions, mutations, or
child-summary mismatches produce no outer report. See
[Fresh Routing, Native DRC, and Manufacturing Handoff](ROUTING_DRC_MANUFACTURING_HANDOFF.md).

The v1.478 Python-agent boundary publishes a separate 4 MiB no-clobber release
report. CLI preflight covers every direct routing report, plan, retained
pipeline report, approval, sidecar, and destination. The Python core additionally
captures the complete plan-selected closure, enforces a 1,469 MiB union and a
100-file/100 MiB approval aggregate, requires the same manufacturing package
on both sides, and invokes the trusted Rust fabrication verifier only from a
private stage. Valid independent routing or fabrication negatives are retained
before `--require-authorized`; invalid pin, signature, binding, alias, mutation,
or child-summary evidence produces no outer report. See
[Policy-pinned Routing, DRC, and Fabrication Release](ROUTING_DRC_FABRICATION_RELEASE.md).

The v1.479 `replay-executable-pinned-fabrication-release` command adds one
8 MiB no-clobber report, one retained 4 MiB v1.478 report, and three selected
native entrypoint reads capped at 128 MiB each and 384 MiB in aggregate. Bare
names resolve through `PATH`; relative paths resolve from the initial caller
directory; resolved targets must be executable regular PE, Mach-O, or ELF
files. Routing and authorization commands accept no wrapper arguments. Exact
entrypoint bytes must match three independently supplied SHA-256 pins and pass
post-replay rereads. The result remains an observation snapshot rather than a
binary-origin, library/plugin, loader/OS, sandbox, or same-principal race
guarantee. See
[Executable-pinned Fabrication Release](EXECUTABLE_PINNED_FABRICATION_RELEASE.md).

The v1.480 Rust receipt boundary reads one 128 MiB manufacturing ZIP, one 64
MiB normalized receipt, one 64 MiB organization policy pack, and one 1 MiB
signed attestation. Signing publishes at most 1 MiB; verification publishes at
most 4 MiB. Every JSON input rejects duplicate and unknown keys, every source
is reread before publication, destinations never overwrite, and the expected
canonical policy digest must come from outside the submitted evidence.

The signer validates all public evidence, selected factory identity, output
aliases, and policy bounds before opening the private key. On Unix that key
must belong to the effective UID and have mode exactly `0400` or `0600`; all
platforms use the hardened no-follow/reparse, stable-handle, and alias checks.
An inactive or policy-overlong attestation is retained as `not_authenticated`
before `--require-authenticated` fails. See
[Signed Factory-receipt Release](SIGNED_FACTORY_RECEIPT_RELEASE.md).

The v1.463 `generate-circuit-kicad-board` producer uses a stricter directory
contract. Circuit-spec input remains capped at 16 MiB, schematic input at
64 MiB, footprint-closure JSON at 96 MiB with at most 256 embedded sources,
4 MiB per footprint and 64 MiB decoded aggregate, the construction profile at
1 MiB, and the physical profile at 4 MiB. It captures those five regular UTF-8 sources before
generation and rereads them before publication. The requested output directory
must be new and must not alias an input. A private sibling stage is checked for
the exact three regular files `board.kicad_pcb`, `board-binding.json`, and
`manifest.json`, then renamed without replacing the destination. The generated
board remains under the generic 128 MiB ceiling; the binding report keeps its
existing 12 MiB-plus-LF bound. Publication is one directory rename, not a
transaction with any later routing, DRC, or manufacturing command. Unix also
requires the canonical output parent to be owned by the effective user and not
group- or other-writable, and rechecks that policy and the pinned parent around
the rename. Windows retains real directory handles and performs corresponding
identity checks. Mutation by another process under the same OS identity remains
outside this boundary. A failure after the rename can leave the directory in
place; such an ambiguously finalized directory must not be consumed.

The v1.464 `verify-final-bom` boundary stable-reads one nonempty board and one
nonempty manufacturing ZIP at up to 128 MiB each. The ZIP then passes the full
manufacturing validator, including its 4,096-entry, 512 MiB expanded-payload,
1 MiB manifest, and 100,000-part limits. The board may contain at most 256
populated BOM references. The actual package BOM and freshly regenerated
canonical BOM are each bounded by 128 MiB; the closed report is bounded by
16 MiB. Present reference, value, footprint, and MPN fields accept one to 4,096
UTF-8 bytes and reject NUL. Both inputs are reread against their initially
captured identities before the optional report is atomically published to a
new file. A valid source or canonical-BOM mismatch is retained before
`--require-approved` fails. Invalid package/board content, an input mutation,
an alias, an unsafe destination, or an over-limit value produces no report.
Omitting `--output` writes the same bounded bytes to standard output.

The final-BOM JSON Schema is a closed structural contract. Its `maxLength`
keywords count Unicode code points, while the runtime limits above count UTF-8
bytes. Runtime validation is authoritative for byte and aggregate ceilings,
package semantics, exact source identities, canonical BOM bytes, sorting, and
cross-field approval invariants; schema validation alone is not approval.

The v1.465 `verify-final-cpl` boundary uses the same input, package, output,
and no-clobber limits. The board may contain at most 256 in-position references;
the actual and freshly regenerated canonical CPL are each bounded by 128 MiB,
and the closed report is bounded by 16 MiB. Each emitted placement reference is
one to 4,096 UTF-8 bytes without NUL; X/Y and rotation are checked signed
integer nanometre/milli-degree values and the side is `F` or `B`. The complete
package validator's independent part, archive, expanded-payload, manifest, CSV,
and portable-name ceilings remain authoritative.

A valid board-source or canonical-CPL mismatch is retained before the optional
gate fails. Invalid board/package content, a link, alias, mutation observed at
the checkpoints, unsafe destination, or over-limit report produces no output.
The initial capture and final stable reread are sequential observations, not an
atomic snapshot against a same-principal writer which changes and restores the
bytes between them. The final-CPL schema is likewise structural; runtime checks
remain authoritative for byte/aggregate ceilings, exact identities, canonical
rendering, ordering, and approval invariants.

The v1.466 `verify-firmware-build` boundary accepts only a file named
`manifest.json` in an exact-eight directory containing the seven fixed
manifest-v2 artifacts. The manifest is capped at 4 MiB; every nonempty source
is capped at 16 MiB. The directory and entries must be regular and symlink-free
when inspected, and source bytes must match the exact ordered manifest
descriptors. Historical manifest build argv are validated but never executed.
The seven captured sources are recreated in a private workspace for six fixed
fresh C, C++, and Python compile/smoke checks. Ordinary regular hardlinks remain
allowed and content-bound; inode uniqueness and link count are not enforced,
and a write through an outside hardlink is rejected only when a checkpoint
observes changed bytes.

Each child has a caller-selected 1–3600 second timeout (120 seconds by default)
and independent 1 MiB stdout and stderr ceilings. A C, C++, or Python compile
failure skips only its dependent smoke/self-test check; unrelated families
continue so an ordinary build rejection retains all meaningful outcomes. The
closed path-free report is capped at 1 MiB. It is written with a final LF to
stdout or atomically to a new no-clobber file outside the bundle directory. A
valid rejected report is published before `--require-approved` fails.
Malformed, symbolic-link or junction/name-surrogate-reparse-point, special,
missing, extra, empty, oversized, descriptor-mismatched, or observed-mutated
input, unsafe/aliased/existing output, report overflow, and cancellation are
hard failures with no report.
Post-spawn setup or pipe-read failure is retained as `supervision_failure` only
after successful cleanup/reaping or observed child completion; an invalid core
timeout or wait/cleanup/reap failure remains a no-report hard error.

Capture and the final exact-eight reread immediately before publication are
sequential checks, not an input/output transaction or an atomic snapshot.
They reject mutation or special-file replacement that they observe, but do not
prevent every change-and-restore race by another process with the same OS
principal. Unix opens fixed entries relative to a pinned directory with
no-follow/nonblocking flags and performs regular-file identity plus two-pass
content checks, so an observed leaf symlink/FIFO race fails promptly. Non-Unix
uses the shared path reader and retains the adversarial leaf link/special-file
race and blocking-open denial-of-service nonclaim. Either platform permits
mutation after the last checkpoint. Use a private isolated trusted bundle
directory.

This verifier starts selected PATH compilers/interpreter, the C/C++ smoke
programs they build, and supplied `host.py`. Shell-free argv, private staging,
deadlines, stream ceilings, and ordinary managed-descendant cleanup are process
bounds, not a sandbox; accessible filesystem, network, credentials, syscalls,
privileges, CPU/memory, process count, and deliberate process escape remain
outside the contract. Compiler outputs, Python bytecode, arbitrary stage files,
and aggregate disk/storage consumption have no quota. Use trusted
bundle/toolchain inputs or an independent OS sandbox.
The report is not toolchain/producer provenance, reproducibility,
cross-compilation, target-MCU, hardware-safety, pipeline, fabrication, MCP,
Action, procurement, or order evidence. See
[`FIRMWARE_BUILD_VERIFICATION.md`](FIRMWARE_BUILD_VERIFICATION.md).

The v1.467 Python `build-assembly-evidence` CLI composes existing bounded
children and requires an explicit no-clobber `--output`. Its direct handoff
archive, board, manufacturing ZIP, board-binding report, retained procurement
intent, catalog snapshot, retained final-CPL report, and optional replay
sidecars retain their original role ceilings under one 768 MiB caller-input
aggregate. The final closed report is capped at 32 MiB. The selected pcbex
command and complete child argv retain the 256-argument/32,768-UTF-8-byte
limits; child stdout and stderr are capped independently at 1 MiB. The finite
outer timeout is 1–600 seconds and defaults to 120.

Every nested report is validated through its runtime contract. The retained
final-CPL bytes, including the final LF, must equal the fresh verifier output
exactly;
the procurement object is semantically and fully replayed from the exact
handoff generation entry rather than accepted by digest alone. A valid
incomplete decision is published before `--require-complete` fails. Malformed,
forged, cross-boundary-inconsistent, aliased, unsafe, over-limit, or observed-
mutated input produces no report. The outer capture and final union reread are
sequential checks, not an atomic multi-input snapshot. See
[`ASSEMBLY_EVIDENCE.md`](ASSEMBLY_EVIDENCE.md) and
[`PYTHON_AGENT_LIMITS.md`](PYTHON_AGENT_LIMITS.md).

The v1.468 Python `build-supplier-offer-coverage` CLI requires an explicit
no-clobber `--output` and preflights it before fresh replay. Its board,
manufacturing ZIP, generation bundle, historical catalog snapshot, retained
procurement intent, and normalized offer are capped at 128 MiB, 128 MiB,
32 MiB, 4 MiB, 16 MiB, and 4 MiB under a 384 MiB aggregate. The result is at
most 16 MiB. At most 256 offer lines are accepted; requested boards,
quantities, and fixed-scale monetary integers use the stricter bounds in
[`SUPPLIER_OFFER_COVERAGE.md`](SUPPLIER_OFFER_COVERAGE.md). The selected pcbex
command, child streams, and Windows command rendering retain the
procurement-intent limits. The v1.468 outer deadline is finite and restricted
to 1–600 seconds.

A valid `not_covered` result is atomically published before
`--require-covered` fails. Exact intent-byte misbinding, malformed/unsafe/
aliased/oversized input, replay or cleanup failure, and mutation observed by
the staged or caller-visible rereads produce no report. The output gate and
input observations are sequential rather than an atomic multi-input snapshot.
The schema commands write canonical one-LF JSON to standard output or a new
no-clobber path. Runtime replay and validation, not schema validation alone,
remain authoritative.

The v1.469 Python `fetch-supplier-offer` CLI requires two distinct explicit
new destinations: a normalized offer up to 4 MiB and a receipt up to 1 MiB.
Both are frozen and preflighted before environment lookup or network access.
The response ceiling is an exact integer from 1 through 4 MiB; the network
timeout is an exact integer from 1 through 60 seconds and covers bounded DNS,
TCP, platform-default TLS, headers, and entity-body reads. Endpoint and header
bounds, exact framing rules, token limits, and canonical output details are in
[`SUPPLIER_OFFER_ACQUISITION.md`](SUPPLIER_OFFER_ACQUISITION.md).

The canonical offer is published first and the receipt second with the shared
atomic no-clobber writer. This is not a two-file transaction: a valid offer is
retained if receipt publication later loses a race. The schema command writes
canonical one-LF JSON to stdout or one new no-clobber path. The offline receipt
validator caps offer plus receipt inputs at 5 MiB, stable-reads path sources,
and performs no network or output write. The network deadline does not cover
earlier output preflight/token lookup or later normalization, hashing, fsync,
and publication.

The v1.470 Python `build-assembly-supplier-offer-evidence` CLI is a separate
offline consumer. It requires explicit retained assembly, normalized-offer,
fetch-receipt, and coverage paths in addition to the original v1.467 source
closure and an explicit requested-board count and evaluation timestamp. It
accepts no independent generation path and no endpoint, token, or network
option; coverage uses the exact generation entry extracted from the validated
handoff. The output is one explicit new no-clobber path and is capped at
128 MiB.

The complete captured v1.467 validation union plus the 4 MiB offer, 16 MiB
coverage result, and 1 MiB receipt is capped at 789 MiB. Validation of a
retained outer result additionally includes that result under a 917 MiB total.
The selected commands, profile exclusion, argv, child-stream, and Windows
rendering limits are unchanged. One 1–600 second outer timeout defaults to
300 and reserves bounded time across both complete fresh child validations,
cleanup, composition, and final staged/caller union rereads.

A valid incomplete assembly child or `not_covered` coverage child is fully
retained before `--require-complete` fails. Malformed/misbound receipt or
offer evidence, fresh replay mismatch, cross-boundary inconsistency, unsafe/
aliased/oversized input, deadline/cleanup failure, or observed mutation
produces no report. Schema output is canonical one-LF JSON to stdout or a new
no-clobber path. See
[`ASSEMBLY_SUPPLIER_OFFER_EVIDENCE.md`](ASSEMBLY_SUPPLIER_OFFER_EVIDENCE.md).

Procurement authorization uses a separate Python orchestration boundary around
the full v1.470 replay and a dedicated trusted Rust cryptographic helper. The
policy pack is limited to 64 MiB; the private derived request and each signed
approval to 1 MiB; verification accepts 1–100 approvals under a 32 MiB
aggregate; the helper's cryptographic assessment and the final public report
remain under the generic 128 MiB ceiling. The complete Python caller-source
aggregate, including the retained v1.470 result, policy, and approvals, is
1,013 MiB for the public sign/verify CLI boundary (signing has no approval
aggregate and accepts less). The Python API that freshly validates a retained
authorization additionally accepts that outer report under its 128 MiB
ceiling, for a separate 1,141 MiB union. See
[`PYTHON_AGENT_LIMITS.md`](PYTHON_AGENT_LIMITS.md) for the complete
original-closure accounting.

Python invokes `--pcbex` only for the existing unauthenticated v1.470 replay
and invokes the distinct `--authorization-pcbex` as a deployment-trusted
component for strict request/policy/signature operations. The private request
is closed and path-free. Both internal Rust commands require the expected
canonical policy digest and independently validate the typed policy, request,
output, signer material, and role disjointness. The signing helper performs
all public preflight before opening the private-key path. Python itself never
opens or copies that key. On Unix the helper requires that file to be owned by
the effective UID with exact mode `0400` or `0600`; `approval-keygen` creates
the compatible `0600` mode.

The CLI's early lexical preflight rejects only output aliases with its built-in
path inputs (including the private-key path) and whole command tokens already
recognized as paths. It does not yet compare the private key with sources or
with `@path`, a path suffix after `=`, or a compact option's path substring. At
the underlying API boundary, Python deliberately does not convert or stat an
arbitrary private-key PathLike until the first fresh replay and the
complete-and-covered `approve` gate succeed; it then freezes the pathname once
and checks it against all public paths plus direct whole-token, `@`, `=`, and
compact command path candidates before the trusted child. Neither boundary
isolates the key from the caller-selected unsandboxed replay executable or
KiCad process, which can access arbitrary filesystem paths including a known
key path. Thus `@file`, `--name=/path`, and `-I/path` are checked, but encoded
paths, environment, configuration, and other indirect access remain outside
this best-effort syntax check. It prevents accidental forwarding and path-role
overlap only, not key disclosure.

The core first makes one byte/count/aggregate-bounded immutable baseline of
all public caller sources, before consulting its injected monotonic clock or
normalizing command hooks. Arbitrary in-process capture hooks are not
preemptively timed. A single finite, non-rollback 1–600 second deadline then
covers the remaining normalization, replay, helper, cleanup, finalization, and
reread work.

The Rust verification helper emits only a closed internal cryptographic/policy
assessment. It does not validate the original v1.470 closure and does not emit
the public `procurement_authorized` claim. Python freshly validates the exact
retained v1.470 result before and after that child and alone publishes the
public report following final rereads. Direct hidden-helper use is
non-authoritative without that surrounding fresh replay. The trusted helper
can read the key and is part of the authorization TCB; this separation is not
key isolation, executable provenance, or a CPU/memory/filesystem/network/
syscall/credential/privilege sandbox.

For its private output, the Rust helper pins and revalidates the no-clobber
parent, installs relative to its directory descriptor on Unix, and uses a
guarded path-based installation on non-Unix systems. A hostile same-principal
rename after the final guard can still leave a committed-but-uncertain helper
artifact in a moved or replacement private staging directory. Python treats
the child error as hard and publishes no public approval or report; complete
private cleanup, rollback, and an atomic filesystem snapshot are not claimed.
The later public atomic no-clobber publication is a distinct boundary.

After the first replay, Python stages and verifies the exact request, policy,
and approval bytes, rereads the caller-source union, and samples one local
assessment instant. A bounded post-hook path-stability reread follows before
Python constructs and runs the trusted verifier command. That child validates
and evaluates at the supplied integer. Retained validation reuses the report's
historical instant without resampling.
The required second v1.470 replay is an unchanged-evidence guard, not a second
time decision. The public report can therefore claim policy satisfaction only
at its retained assessment instant, not at publication or later consumption.

A valid policy-level negative is retained before the public final gate;
malformed/mixed/unpinned/invalidly signed input, an unsafe output, child or
cleanup failure, or observed mutation produces no public report. The mandatory
digest pin prevents a different unsigned pack from being self-selected
relative to the supplied expected value but does not authenticate the pack or
pin. A deployment must establish that trust separately. See
[`PROCUREMENT_AUTHORIZATION.md`](PROCUREMENT_AUTHORIZATION.md).

The v1.472 procurement reservation helper accepts one canonical marker up to
16 KiB, one absolute pre-existing ledger, one expected 64-hex ledger ID, and
at most 128 protected input paths. The ledger manifest is limited to 4 KiB.
The public Python command freshly validates the retained v1.471 report and its
complete original closure before this hidden Rust helper is invoked.

On Linux and macOS the helper pins the ledger directory, requires effective-UID
ownership and exact mode `0700`, and rejects unknown, network, clustered, or
FUSE filesystems. Linux admits only reviewed local filesystem
types through the pinned descriptor;
macOS additionally requires the kernel `MNT_LOCAL` flag. Windows and other
unreviewed Unix targets fail closed.

The marker is installed through the pinned descriptor without replacement,
with file and directory synchronization. The helper revalidates the manifest,
protected-path separation, staged marker identity, approval window, half-open
offer window, and receipt-observation age before and after installation. Any
existing final leaf burns the challenge without parsing that leaf. After a
successful install, a later validation, cleanup, clock, or durability error
never removes the marker and reports committed uncertainty.

This internal helper cannot validate the original v1.470 closure and is not a
standalone authorization boundary. The marker proves admission only inside one
selected ledger; same-UID mutation, another host or ledger, trusted time,
supplier inventory, order execution, payment, and global one-time use remain
outside the contract. See
[`PROCUREMENT_AUTHORIZATION_RESERVATION.md`](PROCUREMENT_AUTHORIZATION_RESERVATION.md).

The v1.481 signed-release reservation reuses the same descriptor-pinned Unix
ledger boundary with a distinct manifest, scope, and challenge-derived name.
Its canonical marker and fixed manifest remain capped at 16 KiB and 4 KiB;
the helper accepts at most 128 protected replay paths. It requires the signed
receipt attestation and underlying fabrication authorization to remain active
before, around, and after durable no-replace installation.

The marker binds the retained and fresh v1.480 report identities, stable
release subject, package, receipt, policy, signed attestation, verifier, signer,
and both windows. It keeps network, global one-time use, submission, capacity,
order, and payment false. See
[Signed Release Reservation](SIGNED_FACTORY_RECEIPT_RELEASE_RESERVATION.md).

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
The v1.460 MCP verifier invokes this same bounded CLI path, then stable-reads
the retained report within the same 128 MiB limit and compares its exact byte
count, SHA-256, decision, scope, counts, plan/run digests, and raw manufacturing
ZIP, factory-receipt source, and policy-pack source SHA-256 values with a closed
23-field child snapshot. That snapshot does not expose the receipt provider,
endpoint, or quote SHA-256, nor the policy canonical SHA-256, ID, or revision.
The complete policy and approval envelopes are present in the retained output
but never enter the MCP response. Real-stdio E2E asserts that representative
responses stay below the 16 MiB frame ceiling; it does not synthesize a
near-limit 128 MiB authorization report, so the two independently enforced
ceilings should not be read as one adversarial cross-boundary test claim.
Cancellation or TTL expiry never produces a successful authenticated-summary
Task result. If the child completed atomic publication just before cancellation
was observed, the no-clobber report may remain; the cancelled Task does not
authenticate it, and a consumer must rerun verification into a new path.

The v1.461 focused Action accepts the same direct source ceilings and 1–100
approval files. Its locked release build is bounded to 30 minutes, the wrapper
to 15 minutes, and the inner verifier child to 10 minutes. After authentication
it scans exactly one depth-one regular report with 128 MiB per-file and
aggregate ceilings, then repeats direct-input snapshot and report-summary
authentication at the publication boundary. The full report remains on disk
or in the optional artifact; only the fixed report path and 23 bounded scalar
fields become Action outputs.

The v1.462 `reserve-fabrication-authorization` command reuses the verifier's
direct-source and 1–100 approval bounds, but publishes no full authorization
report and writes nothing to standard output. Its complete in-memory report
remains under the generic 128 MiB ceiling; only its closed 23-field compact
summary enters a fixed challenge-keyed reservation marker no larger than 16
KiB. The fixed ledger manifest is limited to 4,096 bytes. Both JSON objects are
duplicate-free, closed, and path-free.

Reservation is available only on Unix. The caller supplies an absolute,
already existing, non-symlink ledger directory owned by the effective UID with
mode exactly `0700`, its fixed manifest, and the expected ledger ID. The
directory is pinned by descriptor before the complete private temporary marker
is written and synchronized. It must not overlap a direct authorization input,
plan-selected input, or the exact firmware bundle directory. Publication uses
a descriptor-relative no-replace operation and synchronizes that same
directory before returning success. Local validity-window checks run before
and after the installation and once more after durability; expiry after the
final name appears returns an error but never removes that marker. Any existing
marker-name entry blocks the operation regardless of its type or contents.
Once final installation succeeds, a later validation, cleanup, directory-sync,
path-identity, process, or reporting failure never removes the marker
automatically; an ambiguous attempt is burned rather than retried.

These mechanics provide cooperative at-most-once admission only within the
same trusted, non-replaced, non-rollback local ledger. They do not protect
against the same UID or an administrator, span another root/host/runner, cover
Windows or network/distributed/overlay/ephemeral filesystems, or make a factory
submission, order, payment, or other external side effect exactly once. The
nested verifier summary therefore continues to state
`challenge_one_time_use_enforced: false`.

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
| Python procurement replay or trusted authorization child | one aggregate 1–600 second Python deadline; default 300 | 1 MiB | 1 MiB |
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
