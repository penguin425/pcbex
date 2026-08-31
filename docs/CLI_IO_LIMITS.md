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

The v1.482 signed-release adapter keeps its durable intent, original result,
and reconciliation observations in that same pinned v1.481 ledger. Intent and
receipt files are capped at 16 KiB and 32 KiB; response entities are capped at
64 KiB. The selected manufacturing ZIP retains the existing 128 MiB archive
ceiling. Output paths must be new and remain outside the ledger.

Submit validates and snapshots the exact package and reservation marker,
commits one deterministic intent without replacement, then issues one bounded
POST. It never retransmits when that intent already exists. Reconciliation
uses a bounded GET, never includes ZIP bytes, and retains one deterministic
observation per idempotency-key/reconciliation-ID pair. The HTTP timeout is
1–600 seconds, redirects are disabled, and production endpoints require HTTPS.
The idempotency key is stable for one ledger reservation and package; changing
the intent-bound nonce or endpoint cannot create a second submit key.
Each receipt records a local pre-call `attempted_at_unix`; it always keeps
`trusted_time_verified` false and does not claim a remote processing time.

Durable records survive output-publication and final-gate failures. A transport
failure becomes an `outcome_unknown` receipt rather than an unbounded error;
the next action is reconciliation, not another POST. The Bearer token is loaded
from the named environment variable only after public preflight, is never
written to a durable record, and reflected credentials are reduced to a stable
failure code. See [Durable Signed Factory-release Submission](SIGNED_FACTORY_RELEASE_SUBMISSION.md).

The v1.483 authenticated commands retain the same intent and compatible receipt
limits, then add one closed outer response-authentication report capped at 64
KiB. They exact-read an organization policy pack under the existing 64 MiB
policy ceiling, require it to stay outside the ledger, and recheck its observed
identity around intent and result commits.

Each response admits exactly one `Content-Type`, `Content-Digest`,
`Signature-Input`, and `Signature` header, with each captured value capped at 8
KiB and restricted to visible ASCII plus spaces. The bounded 64 KiB entity is
consumed once by the unchanged receipt parser; authentication retains only its
digest and closed acknowledgement projection, never the raw body or Bearer
credential.

The authentication report commits before the compatible v1.482 receipt. A
later invocation can restore a missing compatible receipt from the exact outer
report without network I/O, while an old unsigned reconciliation observation
forces a fresh ID instead of repeating the same GET. See
[Authenticated Factory-release Adapter Responses](AUTHENTICATED_FACTORY_RELEASE_ADAPTER_RESPONSES.md).

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

## Factory-state external-anchor limits

The v1.488 external-anchor verifier accepts a 64 KiB canonical policy and one
64 KiB canonical inclusion proof. A policy contains 1–100 canonically ordered
external logs and a local checkpoint-age bound of 1–604,800 seconds. The signed
tree is limited to 100,000 leaves and the supplied audit path to 64 nodes. The
self-contained verification report, including the complete v1.487 report,
policy, and proof, is capped at 4 MiB.

The durable command is Unix-only and reuses the existing absolute, pinned,
effective-UID-owned `0700` release ledger. Direct policies and proof inputs must
be bounded stable regular files outside that ledger and must not alias the new
output. Before and around descriptor-relative no-replace publication, the
verifier reloads the current monotonic head, complete transparency consistency
chain, and exact latest witness-quorum record, then rereads every direct input.

Exact retry returns the retained report bytes even after its original local
freshness window. Another proof under the same release generation, witness
policy, external log, and anchor policy conflicts instead of replacing the
record. These mechanics do not protect the selected ledger from rollback or
prove that one external tree head extends another; both claim flags remain
false.

## Factory-state external consistency limits

The v1.489 verifier accepts one 64 KiB canonical consistency proof containing
two complete v1.488-format signed tree heads and at most 64 RFC 6962-shaped
nodes. Both tree sizes remain capped at 100,000. The recursively closed report
embeds the exact v1.488 anchor, proof, identities, claims, and nonclaims under an
8 MiB ceiling. One selected release/log/policy context admits at most 10,000
durable consistency generations.

The Unix-only command reuses the same absolute pinned `0700` ledger. It reloads
the complete v1.484–v1.488 chain, authenticates both external heads before
interpreting their relationship, requires a strict extension, verifies the
current head against the v1.488 local age bound, and reloads the complete
v1.489 predecessor chain around descriptor-relative no-replace publication.

Generation 1 must name the retained v1.488 checkpoint generation. Later
generations start from the exact latest retained v1.489 head. Exact proof retry
returns retained bytes after expiry; an alternate branch cannot overwrite the
winner. These mechanics prove selected-view prefix consistency only. Global
non-equivocation, selected-ledger rollback resistance, and trusted time remain
false.

## Factory-state external gossip limits

The v1.490 verifier accepts one canonical observer receipt up to 64 KiB. The
receipt embeds one complete external signed tree head and a separate Ed25519
observer signature, names an independently pinned observer ID and key, and has
a positive lifetime no longer than 604,800 seconds.

The verifier always selects the exact latest complete v1.489 report. Identical
tree size and root need no proof; unequal sizes require one canonical 64 KiB
v1.489 consistency proof with at most 64 nodes; equal sizes with different roots
fail as a split view. Both trees remain capped at 100,000 leaves.

The recursively closed self-contained report embeds the exact v1.489 report,
receipt, optional proof, identities, claims, and nonclaims under a 16 MiB
ceiling. Its deterministic filename binds the local generation and one observer
ID/key pair, so separately pinned observers do not collide.

The Unix-only command reloads the complete v1.484–v1.489 chain and rereads every
direct input around descriptor-relative no-replace publication. Exact evidence
retry returns retained bytes after receipt expiry; different receipt or proof
bytes for the same local generation and observer pin conflict. Global
non-equivocation, observer quorum, real organizational independence,
selected-ledger rollback resistance, and trusted time remain false.

## Factory-state external gossip quorum limits

The v1.491 acquisition command sends one canonical request to a query-free,
userinfo-free HTTPS endpoint, follows no redirects, and accepts only HTTP 200
`application/json` responses up to 1 MiB. Its aggregate timeout is configurable
from 1 to 600 seconds. A hidden loopback-only HTTP escape exists for the real
transport regression and is not exposed by the public CLI.

Each response must be one canonical observation envelope no larger than 256
KiB. The envelope carries one unchanged v1.490 observer receipt and an optional
unchanged v1.489 consistency proof. The create-new 64 KiB transport receipt
binds request and response identities, byte counts, exact local head, policy,
organization, observer, key, and local evaluation window. Optional Bearer
credentials are read only from the selected environment variable and are never
retained.

The static canonical quorum policy is capped at 64 KiB and 100 distinct,
sorted organization/observer/key tuples. Its threshold is 2–100 organizations,
and its additional receipt-age ceiling is 1–86,400 seconds. The Unix-only
verifier reloads the complete v1.484–v1.489 chain, replays the v1.490 verifier
for every selected observation, rejects duplicate roles or evidence, and
requires all selected observers to name the same exact signed head before
counting organizations.

The recursively closed report is capped at 32 MiB. Below-threshold evidence is
written only to the requested create-new output; a met quorum is also retained
through the existing descriptor-pinned no-replace ledger boundary. Exact retry
may reorder paired observations and returns retained bytes after expiry.
Alternate evidence for the same local generation and policy digest conflicts.
Global non-equivocation, real organizational independence or key custody,
endpoint authenticity, selected-ledger rollback resistance, trusted time,
server idempotency, and exactly-once execution remain false.

## Factory-state external gossip observer-rotation limits

The v1.492 trust state and each canonical dual-signed rotation are capped at 16
KiB. One observer may advance through generations 1–4,096, while one trust-bound
evaluation accepts at most 4,096 aggregate retained rotations across the base
policy's existing maximum of 100 observers.

Every transition advances exactly one generation and binds the immutable base
v1.491 policy digest, policy ID, organization, observer, preceding rotation
digest, old and new non-weak Ed25519 keys, explicit time, and algorithm. Both
keys sign the same payload. Time may remain equal but cannot decrease, and no
historical key may become current again.

Rotation filenames use a domain-separated digest of the base-policy/member
context plus the exact generation, keeping maximum-length IDs below filesystem
component limits. The Unix apply command reloads the complete selected history
around descriptor-relative no-replace publication. Identical concurrent writers
converge; fork, gap, replay, mutation, and historical-key reuse fail closed.

Effective-policy derivation emits one canonical unchanged-v1.491 policy plus
its normalized semantic SHA-256. The 64 MiB recursively closed trust report
embeds exact base/effective policies, every rotation and current trust state,
and one complete v1.491 quorum report. A met quorum is retained; a
below-threshold report remains output-only. Host-ledger rollback resistance,
global non-equivocation, trusted time, real organizational independence,
endpoint/legal identity, ordering, payment, and exactly-once execution remain
false.

## Factory-state external gossip organization-registry limits

The v1.493 generation-zero registry is capped at 256 KiB. Each canonical
authority-signed transition is capped at 16 KiB, and one registry may advance
through generations 1–4,096 while retaining no more than 100 organizations and
100 observer admissions under the unchanged v1.491 policy bound.

Every transition advances exactly one generation and binds the immutable base
policy digest, policy ID, registry ID, prior transition digest, action,
organization, optional exact v1.492 trust-state digest, reason digest,
nondecreasing explicit time, authority key, and algorithm. Admission requires
the latest selected-ledger observer trust state. Suspension and permanent
revocation carry no observer state.

Transition filenames use a domain-separated digest of the registry genesis,
base policy, and registry ID plus the exact generation. Unix export, apply, and
verification reload the complete registry and observer histories around
descriptor-relative no-replace publication. Exact concurrent writers converge;
fork, gap, stale trust, signature mutation, role reuse, and input races fail
closed.

The 128 MiB recursively closed report embeds the exact genesis, every
transition, current registry, and exact self-contained v1.492 trust report. A
met quorum is retained; below-threshold evidence remains output-only. The
registry timestamp is ordered but not trusted, and host-ledger rollback
resistance, global non-equivocation, real organizational independence, legal
identity, ordering, payment, and exactly-once execution remain false.

## Factory-state external gossip registry authority-rotation limits

The v1.494 dual-signed authority rotation is capped at 16 KiB. It shares the
v1.493 registry's 4,096-generation and 128 MiB report ceilings; organization
transitions and authority rotations together consume that history bound.

Each rotation binds the base-policy digest, policy ID, registry ID, exact next
generation, preceding history-event digest, old and new non-weak Ed25519 keys,
nondecreasing explicit time, and algorithm. Both keys sign the same payload.
The successor must never appear in earlier authority history and every
historical authority key remains disjoint from all observer keys.

Unix transition and rotation apply commands serialize on the descriptor-pinned
ledger manifest before reloading history and publishing one no-replace event.
Identical retries converge; a transition/rotation race selects one generation
winner. The legacy v1.493 verifier rejects any rotation, while the v1.494
verifier embeds typed mixed-history evidence and the exact v1.492 trust report.

Authority threshold governance, host-ledger rollback resistance, global
non-equivocation, trusted time, real organizational independence, legal
identity, ordering, payment, and exactly-once execution remain false.

## Factory-state external gossip registry threshold-governance limits

The v1.495 root-signed governance document is capped at 32 KiB. It contains
2–100 ordered, distinct authority identities and non-weak Ed25519 public keys;
`minimum_approvals` is bounded from 2 through the authority count.

Each self-contained threshold transition is capped at 128 KiB. It embeds the
exact governance document, one admission/suspension/revocation payload, and an
ordered set of distinct approvals. The event shares the existing 4,096-event
registry history ceiling. The threshold-aware report remains capped at
128 MiB.

Governance binds the exact pre-activation registry generation and semantic
state digest. Its first accepted transition stores the governance digest in
registry state; later root-only transitions and authority rotations fail
closed. Governance, registry-root, and every initial, historical, and current
observer key must remain role-disjoint at the selected-ledger boundary.

Legacy, authority-rotation, and threshold apply commands serialize on the same
descriptor-pinned ledger manifest. Identical retries converge, while competing
event types select one no-replace generation winner. The v1.493 and v1.494
verifiers reject threshold-governed history.

The report proves cryptographic threshold satisfaction, not independent
control of the configured keys. Host-ledger rollback resistance, global
non-equivocation, trusted time, legal identity, ordering, payment, and
exactly-once execution remain false.

## Factory-state external gossip registry governance-rotation limits

The v1.496 governance rotation is capped at 256 KiB. It embeds both 32 KiB
governance documents plus ordered old and new approval sets of at most 100
members each. The four-event history remains bounded to 4,096 generations, and
the self-contained governance-rotation report remains capped at 128 MiB.

Successor governance must bind the exact current registry generation and
semantic state digest under the retained root signature. Its threshold remains
2–100, its authority list remains ordered and distinct, and it must change at
least one threshold, identity, or key. Issue and rotation times are bounded by
`999999999999999` and must not precede retained state.

The rotation advances exactly one shared registry generation and prior-event
digest. Both old and new approval sets must satisfy their own governance,
contain ordered unique identities and distinct policy-matched keys, and verify
over one domain-separated payload. Organizations, admissions, and registry root
remain unchanged; only the active governance digest advances.

All four mutation filenames occupy the same generation namespace under one
descriptor-pinned manifest lock. Exact retry converges, while cross-type
competition, stale replay, gaps, signature substitution, and observer-role key
reuse fail closed. The v1.495 verifier rejects a governance-rotation event.

Two valid quorum sets do not prove independent governance control and may
overlap. Governed registry-root rotation, host-ledger rollback resistance,
global non-equivocation, trusted time, legal identity, ordering, payment, and
exactly-once execution remain false.

## Factory-state external gossip governed registry-root rotation limits

The v1.497 governed root rotation is capped at 256 KiB. It embeds retained and
successor governance documents plus ordered old/new approval sets of at most
100 members each. The five-event history remains bounded to 4,096 generations,
and the self-contained verification report remains capped at 128 MiB.

Successor governance must bind the exact current registry generation and
semantic digest under a distinct prospective-root Ed25519 signature. Governance
thresholds remain 2–100. Issue and rotation times are bounded by
`999999999999999` and may not precede retained state.

One payload binds the exact next generation, prior event digest, old/new root
keys, old/new governance digests, and rotation time. Both approval sets must
satisfy their own governance. Applying it changes the root and active
governance together while preserving organizations and observer admissions.

All five mutation filenames share one descriptor-pinned manifest lock and
generation namespace. Exact retry converges; cross-type conflict, gap, fork,
stale state, signature substitution, historical root reuse, observer-role or
governance-role collision, and time rollback fail closed. The v1.496 verifier
rejects the fifth event.

Quorum satisfaction and prospective-root possession do not prove independent
people, organizations, or key custody. Host-ledger rollback resistance, global
non-equivocation, trusted time, legal identity, ordering, payment, and
exactly-once execution remain false.

## Factory-state external gossip registry history-audit limits

The v1.498 portable history and its audit report are each capped at 128 MiB and
4,096 events. The history starts with one exact canonical registry artifact of
at most 256 KiB and permits only the five existing event types, each under its
original 16 KiB, 128 KiB, or 256 KiB bound.

Export is a Unix selected-ledger operation. It pins the manifest identity,
immutable base-policy semantic digest, and generation-zero registry semantic
digest; loads the selected history; confirms replay reaches the selected final
registry; then reloads all sources before guarded no-replace publication.

Audit is cross-platform. It requires canonical pretty JSON plus LF, rejects
duplicate or unknown keys, verifies every declared byte count and SHA-256,
starts only from exact empty generation zero, and applies every event through
the production verifier. The audit report and computed final registry publish
as one alias-free no-clobber set after exact input revalidation.

This proves only the supplied chain. It does not prove the selected latest head,
host-ledger rollback resistance, global non-equivocation, trusted time,
independent organization or key control, legal identity, ordering, payment, or
exactly-once execution.

## Factory-state external gossip registry history-checkpoint limits

The unchanged v1.499 signed checkpoint and signed witness are each capped at
32 KiB. The accepted checkpoint trust state is capped at 64 KiB, and the
witness-quorum report is capped at 128 KiB. Every checkpoint command replays
the canonical v1.498 history, which retains its 128 MiB and 4,096-event bounds.

Acceptance must occur no earlier than checkpoint issuance and no more than
86,400 seconds later. A supplied baseline requires the same registry identity,
forbids generation rollback and same-generation equivocation, preserves
nondecreasing issue/acceptance times, and requires the new audit to contain the
exact accepted state at its historical generation.

Witness thresholds are 2–100, with at most 100 supplied witness artifacts and
trusted identity/key pairs. Witnesses must be no older than 86,400 seconds at
evaluation, cannot be future-dated, and must use distinct non-weak Ed25519 keys
that do not reuse any registry root or embedded governance authority key.

The v1.500 witness trust state and dual-signed rotation are each capped at
32 KiB. Trust generations range from 0 to 4,096. Each successor advances by
exactly one, binds the previous rotation digest, uses a distinct non-weak key,
and carries a nondecreasing time no greater than `999999999999999`.

The v1.501 remote witness adapter keeps the complete canonical history local,
posts only the accepted checkpoint trust state, and caps the HTTP response at
1 MiB under one 1–600 second deadline. Redirects are disabled. Production URLs
must use HTTPS and cannot contain userinfo or a query; an optional Bearer token
is read from a validated environment-variable name and never enters either
output. The returned document must also satisfy the unchanged 32 KiB canonical
signed-witness limit.

The hash-bound remote transport receipt is capped at 64 KiB. It records the
exact history, checkpoint trust state, request, response, and normalized witness
SHA-256 values plus response bytes, endpoint, evaluation time, witness identity
and key, and optional trust-state digest/generation. Witness and receipt outputs
are retained as one alias-free no-clobber set only after complete-history
verification and exact input revalidation.

The v1.502 receipt-transparency append accepts that canonical 64 KiB receipt as
one new approval-event kind. It reuses the approval log's 100,000-entry bound
and the generic 128 MiB file ceiling, validates the receipt before producing a
new no-clobber snapshot, and binds its compact digest plus checkpoint, request,
response, and witness identities. Append is structural admission: it does not
reload the complete registry history, checkpoint trust state, response bytes,
or witness trust evidence.

The v1.503 verifier-bound append additionally requires the canonical complete
history, checkpoint trust state, exact signed-witness response, and either a
65-byte direct public-key file or a 32 KiB witness trust state. It applies the
existing 128 MiB history/log, 64 KiB checkpoint-trust/receipt, and 32 KiB
response/trust-state ceilings, replays every verifier before append, and
re-reads all six inputs by byte count and SHA-256 before publishing one
alias-free no-clobber log snapshot. Final reread detects sequential changes; it
does not create an atomic filesystem snapshot across same-principal inputs.

The v1.504 quorum append accepts 1–100 receipt/response pairs and requires a
2–100 witness threshold. It applies the same per-file limits, accepts either
paired direct identity/key files or witness trust-state files for the whole
invocation, and caps its canonical report at 128 KiB. The complete history and
checkpoint context are reconstructed once; every member is then reverified
before the production quorum verifier rejects repeated identities or keys. The
report additionally rejects repeated receipt, response, or witness digests.
All inputs are re-read before the log and exact-log-bound report are published
as one alias-free no-clobber output set. Threshold failure creates neither
output.

The v1.505 signing gate accepts one approval transparency log under the generic
128 MiB ceiling, one canonical v1.504 quorum report under 128 KiB, and one
private-key file under 1 KiB. It validates the complete log chain, exact
ID/count/head/digest, met quorum, and every ordered factory-receipt suffix event
before reading private signing material. The log, report, and key are re-read by
byte count and SHA-256 before one alias-free no-clobber generic checkpoint is
published. The existing checkpoint schema and verification limits do not
change.

The v1.506 dedicated checkpoint keeps the same 128 MiB log, 128 KiB quorum
report, 100-member, and 1 KiB key-file bounds. Its canonical checkpoint and
verification documents are each capped at 64 KiB, require closed
duplicate-key-free pretty JSON plus LF, and bind the normalized report digest,
registry checkpoint, threshold/result, complete log state, and signer beneath
the factory receipt-quorum signature domain. Signing validates public evidence
before key access; signing and verification re-read every input before one
alias-free no-clobber output is published.

The v1.507 checkpoint-witness command keeps the 128 MiB log, 128 KiB receipt
quorum report, 64 KiB dedicated checkpoint, and 1 KiB key-file limits. Each
canonical signed witness is capped at 64 KiB. Quorum verification accepts 1–100
paired witness/key inputs, requires a 2–100 threshold, and caps its canonical
report at 128 KiB. Witnessing re-verifies public evidence before private-key
access; both operational commands re-read every input before alias-free,
no-clobber publication. A valid below-threshold report is retained before the
verification command returns nonzero.

The v1.508 trust state and signed witness-key rotation are each capped at 32
KiB. Initialization and signing accept 64 lowercase hexadecimal key digits
with an optional LF, capped at 65 bytes.
Rotation advances one generation from 0 through 4096, binds the preceding
rotation SHA-256, and caps timestamps at `999999999999999`. Quorum verification
accepts either 1–100 paired direct public keys or 1–100 paired trust states,
never both. Every input is re-read before alias-free no-clobber publication.

The v1.509 remote dedicated-checkpoint witness request keeps the 128 MiB log,
128 KiB receipt-quorum report, 64 KiB checkpoint, 65-byte key, and 32 KiB trust
state limits. The compact request is capped at 129 MiB. Transport accepts at
most 1 MiB, then canonical witness parsing tightens a successful response to 64
KiB. The canonical receipt is capped at 64 KiB; the timeout is 1–600 seconds
with a 30-second default. Both outputs are alias-free and no-clobber, and every
local input is re-read before publication.

The v1.510 transparency append keeps the generic 128 MiB input-log and artifact
read boundary, then tightens the selected v1.509 receipt to its canonical 64
KiB contract before mutation. The existing log permits at most 100,000 entries
and 256-byte event text fields. Append validates the complete input chain and
receipt before publishing one new no-clobber snapshot; signing, anchoring,
consistency, gossip, and witness limits remain unchanged.

The v1.511 verifier-bound append additionally accepts the canonical 128 KiB
quorum report, 128 MiB complete factory receipt log, 64 KiB dedicated
checkpoint, 65-byte checkpoint key, exact 64 KiB witness response, and either
a 65-byte direct witness key or 32 KiB current witness trust state. It
reconstructs the compact request, replays the production checkpoint and witness
verifiers, then re-reads all eight inputs by identity, byte count, and SHA-256
before one alias-free no-clobber snapshot is published. Final reread detects
sequential changes; it does not create an atomic filesystem snapshot across
same-principal inputs.

The v1.512 quorum append accepts 1–100 canonical 64 KiB v1.509 receipts and
paired 64 KiB exact responses, plus the same shared 128 KiB report, 128 MiB
complete log, 64 KiB checkpoint, and 65-byte checkpoint key. Witness trust is
either 1–100 paired 65-byte direct key files or 1–100 canonical 32 KiB trust
states for the entire invocation; the threshold is 2–100 and the canonical
bound report is capped at 128 KiB. Both output paths and every input path must
be distinct, both outputs are no-clobber, and every input is re-read before
publication; this still does not create an atomic same-principal snapshot or a
globally atomic two-file commit.

The v1.513 signing gate accepts the exact 128 MiB admission log and canonical
128 KiB v1.512 quorum report plus one 1 KiB private-key file. It validates the
complete log and sorted final suffix before key access, then re-reads all three
inputs before one alias-free no-clobber generic approval checkpoint is
published. It adds no wire format or larger I/O boundary.

The v1.514 dedicated checkpoint keeps the same 128 MiB admission-log, 128 KiB
quorum-report, 100-member, and 1 KiB key-file bounds. Its closed canonical
checkpoint and verification documents are each capped at 64 KiB. Signing
validates all public evidence before key access, then re-reads every input
before one alias-free no-clobber publication.

The v1.515 witness boundary keeps those public-evidence limits, accepts 1–100
paired 64 KiB witness documents and 1 KiB direct public-key files, and requires
a 2–100 threshold. Each closed canonical witness is capped at 64 KiB; the
quorum report is capped at 128 KiB. Witness signing validates the v1.512 report,
complete admission log, v1.514 checkpoint, and checkpoint key before private-key
access. Both commands re-read every input before one alias-free no-clobber
publication, while a valid below-threshold report is retained before nonzero
exit.

The v1.516 final-witness trust state and signed key rotation are each capped at
32 KiB. Initialization, rotation signing, and key export tighten key sources to
64 lowercase hexadecimal digits plus an optional LF, capped at 65 bytes. Each
rotation advances exactly one generation from 0 through 4096, binds the prior
canonical rotation SHA-256, and caps timestamps at `999999999999999`. The
unchanged v1.515 verifier accepts either 1–100 paired direct public keys or
1–100 paired current trust states, never both. Every input is re-read before
one alias-free no-clobber output is published.

The v1.517 remote final-witness request keeps the 128 MiB admission-log, 128
KiB v1.512 report, 64 KiB v1.514 checkpoint, 65-byte key, and 32 KiB v1.516
trust-state limits. Its compact public request is capped at 129 MiB, its
end-to-end deadline at 1–600 seconds, and its `application/json` response at 1
MiB before canonical v1.515 parsing tightens the witness to 64 KiB. The closed
receipt is capped at 64 KiB. Acquisition verifies public evidence before
credential or network access, then re-reads every input before publishing the
unchanged witness and receipt as one alias-free no-clobber set. Offline receipt
validation repeats the full evidence, signature, freshness, and trust replay
and emits at most one 64 KiB normalized receipt.

All seven v1.499–v1.501 registry artifacts require canonical pretty JSON plus LF
and reject duplicate or unknown keys. Rotation apply publishes the next trust
state and exported public key as one alias-free no-clobber set after exact
input revalidation. Quorum verification accepts direct identity/key pairs or
trust-state files, never both. A valid below-threshold report is retained before
`--require-quorum` returns nonzero.

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
