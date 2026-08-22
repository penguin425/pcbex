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

The v1.464 offline procurement-intent adapter captures four distinct inputs:
a board and manufacturing ZIP at up to 128 MiB each, a retained catalog-backed
circuit-generation bundle at up to 32 MiB, and its retained catalog snapshot
at up to 4 MiB. Their combined source bytes may not exceed 384 MiB. The private
Rust final-BOM report and final procurement-intent report are each limited to
16 MiB. The final result retains the complete validated Rust report and the
raw report's separate byte/SHA-256 identity. The adapter accepts at most 256
populated BOM references. It preserves
the Rust report's deliberately broad nonempty reference, value, footprint, and
optional MPN fields through 4,096 UTF-8 bytes each and rejects NUL. Every caller
`PathLike` is frozen once; inputs must be distinct, nonempty stable regular
non-link files with portable board/snapshot basenames. Staged artifacts, the
child report, and caller-visible inputs are reread before success. The CLI
publishes one atomic no-clobber result; a valid semantic rejection is retained
before `--require-approved` fails, while malformed, forged, changed, aliased,
or over-limit evidence produces no output.

The closed procurement-intent schema is structural. JSON Schema string
`maxLength` counts Unicode code points rather than UTF-8 bytes, so the runtime
byte, duplicate-key, basename, aggregate, exact-replay, digest, ordering, and
cross-field checks remain authoritative. A schema-valid document alone is not
an approved final BOM or procurement intent.

The v1.467 assembly-evidence composer captures the 224 MiB handoff archive,
128 MiB board, 128 MiB manufacturing ZIP, 12 MiB-plus-LF board-binding report,
16 MiB procurement-intent report, 4 MiB catalog snapshot, 16 MiB final-CPL
report, and optional existing board/manufacturing replay sidecars under their
role-specific ceilings and one 768 MiB caller-source aggregate. Its result is
limited to 32 MiB. At most 256 populated BOM references are construction-time
validated; the outer result retains them only in membership arrays and approved
procurement line references, because its compact final-BOM projection omits
`in_bom_parts` and its compact procurement projection omits nested final BOM.
The procurement projection also omits the original procurement binding digest,
which covered that omitted nested object; the raw source identity, full replay,
and outer binding remain.
At most 256 in-position CPL references remain in the exact retained final-CPL
evidence and membership partition. Every caller `PathLike` is frozen before
capture, and the direct sources must be distinct, nonempty stable regular files
accepted by the shared link/reparse-aware reader.

The composer privately invokes only existing local replay/verifier paths. It
requires a closed schema-v6 handoff/manufacturing replay, semantically reruns
the complete procurement intent from the exact handoff
`generation-bundle.json` bytes and supplied snapshot, and requires the fresh
final-CPL report bytes plus final LF to equal the retained source exactly. One
outer finite 1–600 second deadline (default 120) covers all captures, nested
deadlines, child cleanup, comparisons, cross-bindings, final union rereads, and
result construction. The pcbex command and injected argv are limited to 256
arguments and 32,768 UTF-8 bytes; stdout and stderr are each capped at 1 MiB,
and the existing Windows UTF-16 rendered-command ceiling still applies.

An exact negative board-binding, procurement, or final-CPL decision produces a
truthful incomplete result before the optional final gate. Hard input, replay,
identity, mutation, deadline, cleanup, output, or validation failure produces
no result. Publication requires an explicit new output path. The membership
partition is informational and non-gating; completion does not require the CPL
reference set to be a BOM subset. The schema is structural, while runtime
validation remains authoritative for exact child contracts, bytes, sorting,
identity equivalences, decision invariants, and the binding digest. See
[`ASSEMBLY_EVIDENCE.md`](ASSEMBLY_EVIDENCE.md).

The v1.468 supplier-offer coverage boundary captures the same 128 MiB board,
128 MiB manufacturing ZIP, 32 MiB generation bundle, 4 MiB historical catalog
snapshot, and 16 MiB retained procurement intent, plus one normalized offer up
to 4 MiB. Those six direct sources, and the optional retained coverage result
during fresh validation, remain under a 384 MiB aggregate ceiling. The closed
coverage result is at most 16 MiB. Offers contain at most 256 strictly
supplier-part-number-sorted lines. Requested boards are limited to
1..1,000,000, required and quoted quantities to 1..2,147,483,647, and
fixed-scale monetary integers and checked sums to 9,007,199,254,740,991.

One finite 1–600 second monotonic deadline covers capture, private staging,
the complete public procurement-intent replay, comparison, rendering, cleanup,
and staged and caller-visible final rereads. The existing 256-argument,
32,768-byte argv, 1 MiB child-stream, and Windows 32,767 UTF-16-unit command
ceilings still apply. Every caller path is frozen once before a stateful
command iterable is consumed. Sources must be distinct stable regular
link/reparse-safe files. Exact intent-byte misbinding, unsafe input, observed
mutation, timeout, cleanup failure, or malformed evidence produces no result.

A valid supplier, offer-line set/identity, quantity, window, or upstream
approval mismatch produces a closed `not_covered` result before the optional
gate. The normalized-offer and coverage schemas are structural; runtime
validation remains authoritative for UTF-8 byte bounds, strict types,
duplicate keys, sorting, exact source digests, checked multiplication and
summation, finding/decision equivalences, canonical bytes, and fresh replay.
See [`SUPPLIER_OFFER_COVERAGE.md`](SUPPLIER_OFFER_COVERAGE.md).

The v1.469 supplier-offer acquisition boundary accepts one exact normalized
JSON response and publishes an offer up to 4 MiB followed by a receipt up to
1 MiB. Its response ceiling is an exact integer from 1 through 4 MiB. At most
64 response header fields and 64 KiB of combined header name/value bytes are
accepted. Endpoint and bearer-token values are capped at 4 KiB and 8 KiB;
tokens are environment-only and are not retained. Case-insensitive
`SystemRoot` is reserved as a bearer environment name because it is the only
runtime variable forwarded to the isolated Windows resolver. For hostname
endpoints on Windows, an exact bearer-token byte sequence occurring anywhere
in that bounded forwarded value also fails before DNS; literal-IP endpoints do
not invoke the resolver helper. The offline receipt validator limits receipt
plus offer input to 5 MiB.

One exact-integer 1–60 second monotonic deadline covers bounded resolver
execution and cleanup, TCP, platform-default TLS, request, response headers,
and entity-body reads. A one-slot transaction gate prevents another
acquisition from reaching DNS/connect while a prior request/response worker is
active; a separate one-slot connect-worker gate caps late connects. Both are
independent of the v1.420 catalog-fetch boundary. Earlier destination preflight
and token lookup plus later normalization, hashing, fsync, and sequential
offer/receipt publication are outside that network deadline. The adapter
accepts no redirect, retry, response-body spill, or raw-response output.

The test-only insecure transport accepts only literal loopback and is not a
CLI option. Production HTTPS has no private-address denylist and must not be
exposed to untrusted MCP or Action inputs. The schema and offline validator can
recompute canonical offer and request identities but, without the raw response
or transport evidence, cannot authenticate the recorded network/status/time/
response observations. See
[`SUPPLIER_OFFER_ACQUISITION.md`](SUPPLIER_OFFER_ACQUISITION.md).

The v1.470 assembly/supplier-offer composer captures the complete v1.467
validation union, including the retained assembly report, then adds the 4 MiB
canonical offer, 16 MiB retained coverage report, and 1 MiB acquisition
receipt. The direct caller-source aggregate is capped at 789 MiB. Fresh
validation of a retained outer result additionally admits that result under
its 128 MiB ceiling, for a 917 MiB aggregate. The exact handoff
`generation-bundle.json` entry is bounded at 32 MiB and staged as a derived
source rather than accepted or counted as a second caller path. Every
role-specific v1.467–v1.469 source ceiling remains unchanged.

One finite 1–600 second monotonic deadline, defaulting to 300, covers source
capture, strict preparse, archive validation and generation extraction,
private staging, offline receipt validation, both complete child validations,
cross-binding, cleanup, result construction, and final staged/caller union
rereads. After staging, the assembly child receives at most half the remaining
budget. The coverage child then receives the remainder minus the smaller of
15 seconds or half that remainder, reserving time for final composition and
rereads. Both children share the outer clock and cannot extend its absolute
deadline. The existing 256-argument, 32,768-byte argv, 1 MiB per-child-stream,
and Windows 32,767-UTF-16-unit command ceilings remain in force.

All path-backed sources must be distinct stable regular link/reparse-safe
files. Retained child and outer reports may instead be copied from bounded
canonical bytes or one-pass Mapping snapshots; the raw offer and original
replay closure remain path inputs. The inherited v1.467 path union is captured
first, the raw offer PathLike is frozen and read next, and each path-backed
child is then frozen and read immediately in positional order rather than
through a freeze-all/read-all child pass. The first alias check precedes child
bytes and then Mapping snapshots. The validator intentionally captures its
retained outer artifact wholly last regardless of representation and applies a
second alias check if it is path-backed; that outer artifact is excluded from
the earlier path-before-child-Mapping rule. The composer stages one captured
union, rereads that entire union after each fresh child validation, validates
and renders one bounded outer snapshot, then rereads both the staged and
caller-visible path unions. These observations detect changes but are not an
atomic snapshot against a same-principal change-and-restore race. A valid
incomplete assembly or not-covered offer is retained; a malformed receipt,
replay or identity mismatch, unsafe/aliased/oversized source,
deadline/cleanup failure, or observed mutation produces no outer result. See
[`ASSEMBLY_SUPPLIER_OFFER_EVIDENCE.md`](ASSEMBLY_SUPPLIER_OFFER_EVIDENCE.md).

The v1.471 procurement-authorization boundary captures the complete v1.470
validation union, including the retained v1.470 outer report under its 128 MiB
ceiling, plus one organization policy pack up to 64 MiB. Verification accepts
1–100 signed approvals at 1 MiB each and no more than 32 MiB in aggregate. The
complete caller-source aggregate is capped at 1,013 MiB: the existing 917 MiB
v1.470 retained-validation union, policy pack, and approval aggregate. The
derived closed cryptographic request is capped at 1 MiB and is staged
privately rather than accepted or counted as another caller source. The
canonical public authorization report is capped at 128 MiB. Fresh validation
of a retained authorization prepends that report, so its complete caller
union is capped independently at 1,141 MiB. Signing has no submitted-approval
aggregate and therefore accepts less than the shared 1,013 MiB direct ceiling.

The CLI requires its original v1.470 artifacts, policy pack, submitted
approvals, and output to satisfy their mutually distinct stable regular
link/reparse-safe path contracts. At the API, the retained outer v1.470
evidence, policy pack, individual approvals, and retained authorization also
accept bounded copied bytes or one-pass Mapping snapshots; the three inherited
v1.470 retained child roles preserve their existing bytes/Mapping parity, while
the remaining original closure stays path-backed. Every path-backed public
input remains mutually distinct. Signing also accepts one private-key path,
but Python does not convert, freeze, or stat an arbitrary private-key PathLike
until the first fresh replay and the complete-and-covered pre-key gate for an
`approve` decision have succeeded. It then freezes that pathname exactly once
for direct forwarding and rejects aliases with every data path and
normalized replay, KiCad, or authorization command path candidate before
starting the trusted child. Candidate syntax is a direct whole-token path, the
path after `@`, the suffix after the first `=`, or a compact option substring
beginning at its first path separator, covering forms such as `@file`,
`--name=/path`, and `-I/path`. Python never opens, reads, parses, copies,
hashes, or stages private-key bytes. Encoded paths and environment,
configuration, or other indirect path access are not resolved by that
best-effort syntax check. The authorization child validates
the complete public request, policy raw/canonical identity, mandatory expected
canonical digest pin, output, signer role, and decision material before it
reads the key. An approval over incomplete or uncovered upstream evidence is
rejected before private-key access; a deliberate signed rejection remains
available.

One byte/count/aggregate-bounded immutable baseline of caller sources is
captured before the first injected monotonic-clock observation. The exact
order is original and optional v1.470 paths, raw offer, retained v1.470
path/bytes/Mapping values, v1.471 evidence and policy path/bytes/Mapping
values, retained authorization outer value when present, then the approval
iterator and items. The retained outer deliberately precedes approvals so the
iterator cannot mutate it. Previously captured mutable buffers and Mappings
cannot change the baseline; later observed path mutation is rejected.

Arbitrary in-process PathLike, iterator, and Mapping hooks in that initial
phase are not preemptively time-bounded. After the baseline, one finite 1–600
second monotonic deadline, defaulting to 300, covers subsequent normalization
and strict preparse, complete v1.470 validation, private staging,
trusted-child execution and cleanup, its bounded artifact validation, a
second complete v1.470 validation from the same captured closure, exact
pre/post comparison, public report construction, and final staged and
caller-visible union rereads. Every injected monotonic observation must be
finite and nondecreasing. The existing 256-argument, 32,768-UTF-8-byte argv,
1 MiB child stdout/stderr, and Windows 32,767-UTF-16-unit rendered-command
ceilings apply independently to both child roles.

`--pcbex` remains the unauthenticated and unsandboxed v1.470 replay child.
`--authorization-pcbex` is a distinct deployment-trusted Rust binary used only
for strict Ed25519 signing or cryptographic/policy assessment. The hidden
verification output is not a public authorization report. Python requires its
bounded assessment to bind the exact request and policy, repeats the entire
v1.470 validation afterward, and alone emits the public decision. A direct
hidden-helper invocation is therefore non-authoritative without Python's
fresh pre/post replay and source checks. The trusted process can access the
signing key, and neither process runner provides executable provenance, key
isolation, or a CPU, memory, filesystem, network, syscall, credential, or
privilege sandbox.

In particular, the caller-selected unsandboxed replay executable and KiCad
process may access arbitrary filesystem paths through argv, environment,
configuration, or their own logic, so Python makes no claim that they are
isolated from a known private-key path; deployments must provide that isolation
externally. Alias rejection prevents accidental forwarding and path-role
overlap only, not key disclosure.

The Rust helper pins and revalidates its private no-clobber output parent,
installs descriptor-relatively on Unix, and uses guarded path-based
installation elsewhere. This is sequential race detection, not an atomic
filesystem snapshot. A hostile same-principal parent rename after the final
guard can leave a committed-but-uncertain, non-authoritative helper artifact
in a moved or replacement private staging directory. Python turns any such
child error into a hard failure and publishes no approval or public report,
but does not promise that every private temporary artifact was rolled back or
removed. Successful public publication remains a separate atomic no-clobber
operation.

After its first replay, Python stages and verifies the exact request, policy,
and approval bytes, rereads the caller-source union, and samples one local
`evaluated_at_unix`. A bounded post-hook path-stability reread follows before
Python constructs and runs the trusted verification command. The child
validates and retains that integer before the required second v1.470 replay.
Retained-report validation reuses its historical T without resampling. The
second replay proves unchanged exact evidence rather than reassessing the wall
clock. A positive outer decision is therefore policy satisfaction at the
retained assessment instant, never a claim that the interval remains active at
final publication or later use.

A valid incomplete/uncovered, quorum, submitted-rejection, local-window,
offer-window, receipt-observation-age, or component-subtotal/policy-limit
failure is retained before the optional `--require-authorized` gate. Malformed
or mixed evidence, a missing/wrong digest pin, signature failure, unsafe alias,
limit failure, child/cleanup failure, or observed mutation produces no public
report. Local clock and receipt age are only untrusted correlation. The
mandatory policy digest match prevents a different unsigned
pack from being selected relative to that expected value, but authenticating
the expected digest remains a deployment responsibility. See
[`PROCUREMENT_AUTHORIZATION.md`](PROCUREMENT_AUTHORIZATION.md).

The composed v1.457 handoff-to-manufacturing replay requires the complete v5
board-binding inputs and one retained package. It keeps the existing 224 MiB
handoff-archive ceiling, the 128 MiB board / 12 MiB canonical report plus one
newline / 4 MiB policy ceilings and 144 MiB plus one byte board-binding
aggregate, and the v1.455 manufacturing per-file and 512 MiB aggregate bounds.
The board PathLike is frozen before its first read and the raw bytes are
captured only once; the manufacturing capture reuses them but still counts
their size in its aggregate input budget. Newly supplied manufacturing
PathLikes are likewise frozen exactly once. Project/rules and profile/package
sources are captured before the handoff producer child, and all regenerated
files stay within private temporary workspaces. The v6 result contains only
bounded identities and closed nested evidence under scope
`deterministic-electrical-handoff-chain-manufacturing-package-replay-v6`,
never paths or payloads.

The standalone v1.456 deterministic-pipeline replay captures one plan up to
4 MiB and one retained report up to 128 MiB before native execution. It parses
the plan's closed 16-role shape itself, captures every present descriptor under
the same role-specific 4–128 MiB limits enforced by Rust, and captures all seven
fixed firmware siblings at up to 16 MiB each. Present role inputs and firmware
siblings share one 512 MiB aggregate ceiling; the plan and retained/fresh
reports are checked separately, and no more than 64 role/artifact evidence
entries or 128 report failures are accepted. The original relative role tree
is reproduced under a private input root without rewriting the plan. The
firmware directory must contain exactly `manifest.json`, `pinout.h`,
`firmware.h`, `firmware.c`, `firmware_smoke_test.c`, `firmware.cpp`,
`firmware_cpp_smoke_test.cpp`, and `host.py`, both before and after execution
and in the private stage.

Every captured role and firmware source must match the descriptor or fixed
source identity and is reread from both the stage and caller-visible path
before and after the child where applicable. The plan, retained report, staged
plan, and fresh private report receive their own final rereads. The fresh
report must equal the retained bytes exactly, including its single final LF.
The complete nested Rust report-v1 contract is then checked with closed object
shapes, strict integer (not Boolean or floating-point) bounds, fixed pipeline
phases, and binding/pipeline decision invariants.
Only the plan/report and aggregate input identities plus bounded decisions are
returned; paths, input bodies, report bodies, failures, and command output are
excluded from the result.

This descriptor-exact, nonempty regular-file and exact-eight firmware
precondition means the adapter can reproduce approved reports and downstream
binding/pipeline-gate rejections. It does not reproduce a Rust report whose
rejection was itself caused by a missing, linked, empty, oversized,
digest-mismatched, or inexact firmware source.

The composed v1.458 replay reuses those exact v1.456 capture and size limits
inside the handoff command. A plan/report pair is accepted only with the full
v6 board-binding/manufacturing input set, and all pipeline sources are captured
before the first producer child. Circuit, schematic, board, and package bytes
are matched to the earlier archive/v5/v6 captures without a second caller read;
the effective policy digest and canonical nested board-binding report are also
matched. The final caller-source union includes the plan, retained report,
every selected role, and every firmware file. After the fixed-file rereads it
rescans the firmware directory and still requires exactly the eight names, so
a late extra file cannot evade the closure check. Returned v7 evidence remains
path-free and contains neither role bodies nor the retained report body.

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
| Fresh routing-to-manufacturing handoff (`replay-routing-manufacturing-handoff`) | one aggregate `--timeout-seconds`, finite `0 < seconds <= 600`; default 300; routing receives half of the remaining budget, then manufacturing preserves its existing cleanup/final-reread reserve | closed | 64 KiB for routing; 1 MiB for manufacturing | 1 MiB per child |
| Fresh routing/native-DRC/manufacturing handoff (`replay-routing-drc-manufacturing-handoff`) | one aggregate `--timeout-seconds`, finite `0 < seconds <= 600`; default 300; v1.476 replay receives half of the remaining budget, then native DRC preserves up to 15 seconds or half of its remaining interval | closed | 64 KiB for routing/native DRC; 1 MiB for manufacturing | 1 MiB per child |
| Policy-pinned routing/DRC fabrication release (`replay-routing-drc-fabrication-release`) | one aggregate `--timeout-seconds`, finite `0 < seconds <= 600`; default 300; v1.477 replay receives half of the remaining budget, then fabrication authorization reserves up to 30 seconds or half of its remaining interval | closed | 64 KiB fabrication summary; nested routing/manufacturing limits remain unchanged | 1 MiB for fabrication; nested child limits remain unchanged |
| Executable-pinned fabrication release (`replay-executable-pinned-fabrication-release`) | reuses the complete v1.478 aggregate deadline, finite `0 < seconds <= 600`; default 300; entrypoint capture occurs after the evidence closure and before its first selected child | closed | unchanged nested v1.478 stdout limits | unchanged nested v1.478 stderr limits |
| Offline final-BOM/catalog intent (`build-procurement-intent`) | one aggregate `--timeout-seconds`, finite `0 < seconds <= 600`; default 120; the child reserves up to 15 seconds or half of the remaining time for process cleanup and outer rereads | closed | 1 MiB | 1 MiB |
| Exact per-board assembly composition (`build-assembly-evidence`) | one aggregate `--timeout-seconds`, finite `1 <= seconds <= 600`; default 120; every handoff/manufacturing, procurement, final-CPL, cleanup, cross-binding, and reread reserve remains nested inside it | closed | 1 MiB per child | 1 MiB per child |
| Dual-control procurement signing/verification (`sign-procurement-approval`, `verify-procurement-authorization`) | one aggregate `--timeout-seconds`, finite `1 <= seconds <= 600`; default 300; both complete v1.470 replays, trusted authorization child, cleanup, comparison, rendering, and final rereads remain nested inside it | closed | 1 MiB per child | 1 MiB per child |
| Fresh deterministic-pipeline report replay (`replay-deterministic-pipeline`) | one aggregate `--timeout-seconds`, finite `0 < seconds <= 600`; default 120; child execution reserves up to 30 seconds or half of the remaining time, split between bounded process cleanup and outer rereads/cleanup | closed | 64 KiB | 1 MiB |
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

The v1.476 routing-to-manufacturing handoff first creates a bounded immutable
baseline before invoking the injected clock or command hooks. This initial
capture is not wall-clock timed. The source union is capped at 688 MiB: the
original KiCad board at 128 MiB, retained convergence report at 16 MiB,
retained v1.475 verification at 32 MiB, and the existing manufacturing replay
closure at its 512 MiB aggregate. The latter includes the routed board,
retained ZIP, optional project/rules sidecars, and one external DFM or physical
profile. Cross-role aliases fail before either child runs.

After that baseline, command hooks run under working-directory guards and are
followed by source rereads. One aggregate monotonic deadline then covers both
children, subsequent comparisons, rereads, and cleanup. Hook-driven
working-directory changes and backwards or non-finite clock samples are
restored and rejected; source rereads prevent later hooks from replacing the
captured baseline.

Python stages the exact captured routing closure, gives the v1.475 verifier half
of the remaining budget, limits its stdout to 64 KiB and stderr to 1 MiB, and
requires exact retained verification bytes. It validates the nested binding and
source projection before invoking manufacturing. An incomplete fresh routing
decision skips `fabricate` and becomes a retained `not_ready` result. A complete
decision passes the same captured routed board and sidecars to the existing
v1.455 replay, which keeps its own 1 MiB stream ceilings and inner reserve.
Every caller source is reread before the 4 MiB outer result returns. See
[Fresh Routing-to-Manufacturing Handoff](ROUTING_MANUFACTURING_HANDOFF.md).

The v1.477 routing/native-DRC/manufacturing handoff extends that immutable
baseline with the 4 MiB retained v1.476 report and 32 MiB retained normalized
DRC report. The complete direct union is capped at 724 MiB. Both reports are
strictly decoded and binding-checked before any child starts; every source role
must remain distinct.

The first private stage gives the complete v1.476 replay half of the remaining
outer budget and requires its pretty JSON bytes to equal the retained report.
When that result is incomplete, native DRC is skipped and a bounded negative is
returned. Otherwise Python invokes `verify-native-kicad-drc-report` against the
same staged routed board, project, and rules. The child emits only its 17-field
digest summary; Python matches it to the already captured compact report,
rechecks the native run binding and counts, rereads the staged closure after the
last clock hook, then cross-binds all shared identities. Output is capped at
1 MiB. See
[Fresh Routing, Native DRC, and Manufacturing Handoff](ROUTING_DRC_MANUFACTURING_HANDOFF.md).

The v1.478 release composer adds the factory-required deterministic plan,
retained pipeline report, complete plan-selected closure, and 1–100 signed
fabrication approvals. It captures that closure before consuming the approval
sequence, caps the complete union at 1,469 MiB and approvals at 100 MiB, and
requires the plan's exact package bytes to equal the v1.477 package before any
selected tool or clock hook runs.

After an exact private v1.477 replay, Python runs the explicit trusted Rust
fabrication verifier without a shell. A no-hook final staged reread immediately
precedes spawn. The returned canonical report and compact summary must bind the
captured plan, pipeline report, package, receipt, policy, expected canonical
policy digest, and complete signer-sorted approval envelopes. Final staged and
caller rereads precede the 4 MiB outer result. This sequential snapshot does
not authenticate the selected tools, policy distributor, receipt, signer
custody, or local clock. See
[Policy-pinned Routing, DRC, and Fabrication Release](ROUTING_DRC_FABRICATION_RELEASE.md).

The v1.479 consumer additionally requires three one-token native commands.
Each resolved entrypoint is a stable regular executable capped at 128 MiB;
their aggregate is 384 MiB, the outer report is 8 MiB, and the derived complete
input ceiling is 1,857 MiB. Expected digests are exact built-in lowercase-hex
strings and must come from an independent protected source. The default clock
uses pre/post replay byte observations; every injected clock callback return
also triggers an exact entrypoint reread before execution continues. This is
callback-driven mutation detection, not an atomic observation-to-exec lock or
full toolchain provenance. See
[Executable-pinned Fabrication Release](EXECUTABLE_PINNED_FABRICATION_RELEASE.md).

The composed v1.457 replay uses the handoff command's single outer monotonic
deadline rather than starting a second independent authority. It covers all
handoff, optional native/AI/catalog, board-binding, and manufacturing captures;
every child and cleanup boundary; exact report/archive/ZIP comparisons;
shared raw-board identity checks; result construction; and the final success
check. Immediately before package replay, Python reserves the smaller of 15
seconds or half the outer remaining budget for the composed final rereads and
cleanup, then passes a strictly earlier deadline into the captured v1.455
replay. The latter retains its own bounded `fabricate` process-tree cleanup
reserve within that subdeadline. After it verifies staged inputs and exact ZIP
bytes, the outer replay performs one final union reread of all caller-visible
handoff, optional assertion, board-binding, and manufacturing sources. No
later child starts after an earlier assertion or required board-approval gate
fails, and no v6 success is returned after either deadline expires.

When v1.458 pipeline composition is selected, the outer replay reserves half
of the remaining time before manufacturing for the downstream pipeline rather
than using the v1.457 final-reread reserve. After manufacturing completes, the
pipeline stage receives a deadline earlier than the outer authority by up to
30 seconds or half of its remaining budget. That reserve covers canonical
cross-binding, the complete final union reread, firmware-directory closure,
result construction, and cleanup. The pipeline helper does not start a new
deadline; it consumes the supplied absolute subdeadline while retaining its
own process cleanup reserve. No v7 success is returned after any of the three
ordered deadline boundaries expires.

The deterministic-pipeline replay starts its own monotonic deadline before
reading the plan. That deadline covers the plan and retained-report captures,
closed plan validation, every role and fixed firmware read, private staging,
pre-child rereads, one shell-free `run-deterministic-pipeline` child, its
bounded summary, the private fresh-report read and exact comparison, every
post-child staged/caller reread, temporary cleanup, result construction, and
the final pre-success check. The selected pcbex command and complete injected
argv are limited to 256 arguments and 32,768 UTF-8 bytes; the rendered Windows
command line including its terminator is limited to 32,767 UTF-16 units.

The child receives the remaining aggregate time minus a cleanup/reread reserve
of up to 30 seconds, or half the remaining time when smaller. Half of that
reserve is an explicit process-tree termination/reap/worker-join deadline; the
other half remains for fresh-report validation, final rereads, and temporary
cleanup. The child writes its full report solely to a private no-clobber
destination. Its hidden summary is
limited to 64 KiB and is accepted only when its schema, approval decision,
failure count, plan/run identities, and fresh report byte/SHA-256 identity all
match the independently parsed file. A successful child does not imply an
approved report: exact reproduction may return `verified: true` and
`approved: false`. The replay operation returns the truthful reproduced
decision in either case. The Python API leaves approval policy to its caller;
the CLI's optional `--require-approved` gate is applied only after the exact
result has been printed. Before returning, the adapter also recomputes the
plan-v1 and run-v1 domain hashes, checks bounded sorted failure evidence and
the top-level approval relationship, and restricts the returned engine version
to a bounded SemVer string.

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
The v1.464 procurement-intent adapter also performs no network operation. It
replays one historical catalog selection and compares only final-BOM
reference/value/footprint/MPN metadata. It does not establish an electrical
circuit/schematic/board binding, bind the package manifest's input basename,
verify current stock, price, lifecycle, authenticity, or reservation, multiply
an assembly quantity, authorize procurement, or place an order. Its quantities
are per-board populated-reference counts only, and a rejected result contains
no partial line items. The selected pcbex command remains unauthenticated.
The v1.468 supplier-offer boundary likewise performs no adapter network call.
Its caller-normalized offer, explicit untrusted evaluation instant, fixed-scale
component-line subtotals, and checked requested-board multiplication prove no
supplier or offer authenticity, current stock, unit-price or rounding truth,
shipping/tax/duty/fee/discount/landed cost, MOQ/order multiple, reservation,
authorization, order readiness, ordering, payment, or spend. It does not use
the v1.467 composition as authority and changes none of the v1.464/v1.467
schema or serialized-byte contracts.
The v1.469 supplier-offer acquisition adapter performs one explicit bounded
network GET and records that local observation separately. It does not retain
or authenticate the raw response or TLS session and proves no supplier,
endpoint, transport, offer, price, currentness, trusted time, reservation,
authorization, order readiness, ordering, payment, or spend. v1.468 remains
offline even when its input file came from this adapter.
The v1.470 assembly/supplier-offer composer is offline. It validates the
unsigned receipt against the exact offer and freshly validates the full
assembly and coverage children, but cannot authenticate the receipt's
historical response/network/TLS/time observations. Timestamp equality is only
an untrusted cross-binding. The requested-board multiplier applies only to
commercial coverage and creates no batch/panel/assembly evidence. The outer
result proves no current stock, supplier/offer/price authenticity, landed
cost, reservation, readiness, authorization, ordering, payment, or spend and
changes none of the v1.467–v1.469 schemas or bytes.
The v1.471 procurement authorization boundary likewise performs no intended
network request. Its local evaluation instant and receipt-observation-age gate
do not authenticate time. Even when the exact complete
and covered v1.470 projection and distinct trusted signature quorum authorize
the component-line release scope, the result proves no current stock,
supplier/offer/price/receipt/policy authenticity, landed or invoice total,
shipping, tax, MOQ, tiers, reservation, assembly/fabrication/order readiness,
order placement, payment, spend, machine execution, or challenge one-time use.
The authorization report is a point-in-time audit snapshot; current authority
requires rerunning the public verifier from the entire original closure.

The v1.472 `reserve-procurement-authorization` command takes the same retained
v1.471 report and complete original validation union. It uses one 3–600 second
whole-operation deadline: the fresh retained-report audit receives the main
budget while a final slice remains for the durable ledger helper. A negative,
malformed, changed, or mismatched retained report stops before the ledger
helper and creates no marker.

After successful replay, Python renders the exact canonical v1.471 report,
builds a closed path-free marker no larger than 16 KiB, and stages it under the
trusted temporary root. It stable-reads the staged marker before and after the
shell-free hidden Rust child. Child stdout and stderr are each capped at 64
KiB; only fixed already-reserved and committed-uncertainty outcomes are mapped
to public path-free errors. Other child diagnostics, filesystem paths, and
provider text are not relayed.

The helper receives at most 128 absolute protected paths derived from the CLI
closure, approvals, retained report, optional profiles, and path-looking
commands. Those paths prevent ledger/input containment and aliasing; they are
not a filesystem sandbox. The caller-selected replay and KiCad executables can
still access arbitrary known paths, and a same-UID concurrent writer remains
outside Python's sequential mutation checks.

Windows fails before fresh replay. On supported Unix hosts the Rust helper
owns ledger pinning, exact `0700`/effective-UID enforcement, local-filesystem
classification, fixed-manifest validation, descriptor-relative no-replace
installation, time rechecks, and file/directory synchronization. Python does
not implement or emulate those durability rules. See
[`PROCUREMENT_AUTHORIZATION_RESERVATION.md`](PROCUREMENT_AUTHORIZATION_RESERVATION.md).
The v1.456 deterministic-pipeline replay likewise makes no producer or network
call beyond its caller-selected local pcbex process. The child runs only the
existing runner against the privately staged closure; the adapter does not run
KiCad or `fabricate`, generate or repair a circuit/board/package, rebuild
firmware, contact an AI/supplier/factory, or authenticate the supplied binary.
Exact equality may require the producer-compatible pcbex version because the
report retains its engine version and run identity. Replay verification is not
pipeline approval, deployment approval, procurement/fabrication authorization,
or an order, and this release adds no MCP or GitHub Action surface.
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
race only after the direct-child kill fallback, a bounded poll has reaped that
child, and a signal-zero group probe returns `ESRCH`. The proof window is at
most one second and is clipped to the active execution or cleanup deadline;
only `poll()` and an ambiguous Darwin `EPERM` probe are retried, never the
group-termination signal. A live child, an existing group, an unauthorized
probe that remains ambiguous at the deadline, or any other probe result remains
a cleanup failure. Windows necessarily has a small post-spawn assignment race,
and a POSIX descendant that deliberately creates another session can escape the
group.
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
