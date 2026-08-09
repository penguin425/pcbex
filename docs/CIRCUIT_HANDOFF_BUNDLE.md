# Atomic circuit-generation to KiCad handoff bundle

`pcbex-agent handoff-circuit` turns one already-retained
`generate-circuit` schema-v2 result into a self-contained, deterministic KiCad
handoff archive:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent handoff-circuit \
  build/circuit-generation.json \
  --pcbex target/release/pcbex \
  --output build/circuit-handoff.zip \
  --timeout-seconds 120

PYTHONPATH=agent/src python3 -m pcbex_agent \
  circuit-handoff-bundle-schema \
  --output build/circuit-handoff-manifest.schema.json

PYTHONPATH=agent/src python3 -m pcbex_agent \
  verify-circuit-handoff-bundle build/circuit-handoff.zip \
  --expected-archive-sha256 "$ARCHIVE_SHA256" \
  --expected-bundle-sha256 "$BUNDLE_SHA256"

PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-circuit-handoff-bundle build/circuit-handoff.zip \
  --pcbex target/release/pcbex \
  --timeout-seconds 120 \
  --expected-archive-sha256 "$ARCHIVE_SHA256" \
  --expected-bundle-sha256 "$BUNDLE_SHA256"

PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-circuit-handoff-bundle build/circuit-handoff.zip \
  --pcbex target/release/pcbex \
  --native-kicad-erc-report build/native-kicad-erc.json \
  --kicad-cli kicad-cli \
  --require-native-kicad-erc-approved \
  --timeout-seconds 120

PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-circuit-handoff-bundle build/circuit-handoff.zip \
  --pcbex target/release/pcbex \
  --ai-quorum-report build/ai-quorum.json \
  --ai-review-request build/ai-review-request.json \
  --ai-policy-pack hardware/organization-policy-pack.json \
  --ai-approval build/reviewer-a.approval.json \
  --ai-response build/reviewer-a.response.json \
  --ai-approval build/reviewer-b.approval.json \
  --ai-response build/reviewer-b.response.json \
  --minimum-ai-approvals 2 \
  --minimum-distinct-ai-providers 2 \
  --minimum-distinct-ai-models 2 \
  --require-ai-quorum \
  --timeout-seconds 120

PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-circuit-handoff-bundle build/circuit-handoff.zip \
  --pcbex target/release/pcbex \
  --catalog-generation-provenance build/catalog-generation-provenance.json \
  --catalog-fetch-receipt build/catalog-fetch-receipt.json \
  --catalog-snapshot build/catalog-snapshot.json \
  --timeout-seconds 120

PYTHONPATH=agent/src python3 -m pcbex_agent \
  replay-circuit-handoff-bundle build/circuit-handoff.zip \
  --pcbex target/release/pcbex \
  --kicad-board hardware/controller.kicad_pcb \
  --board-binding-report build/circuit-kicad-board-binding.json \
  --board-binding-policy electrical-policy.json \
  --require-board-binding-approved \
  --timeout-seconds 120

PYTHONPATH=agent/src python3 -m pcbex_agent \
  extract-circuit-handoff-bundle build/circuit-handoff.zip \
  --output-dir build/verified-circuit-handoff

PYTHONPATH=agent/src python3 -m pcbex_agent \
  circuit-handoff-bundle-result-schema

PYTHONPATH=agent/src python3 -m pcbex_agent \
  circuit-handoff-bundle-replay-result-schema

PYTHONPATH=agent/src python3 -m pcbex_agent \
  circuit-handoff-bundle-native-erc-replay-result-schema

PYTHONPATH=agent/src python3 -m pcbex_agent \
  circuit-handoff-bundle-ai-quorum-replay-result-schema

PYTHONPATH=agent/src python3 -m pcbex_agent \
  circuit-handoff-bundle-catalog-provenance-replay-result-schema

PYTHONPATH=agent/src python3 -m pcbex_agent \
  circuit-handoff-bundle-board-binding-replay-result-schema
```

The `verify-circuit-handoff-bundle` and `extract-circuit-handoff-bundle`
commands consume a saved bundle without calling an LLM, supplier API, SKiDL,
KiCad GUI, native `pcbex`, or a shell. The bundle's SKiDL text and provider
metadata are validated as inert evidence and are never executed. The explicit
`replay-circuit-handoff-bundle` command is the exception: it invokes the
caller-supplied `pcbex` executable through the bounded, shell-free process
runner and requires the complete native chain to reproduce the archive.

## Gates

Before starting a native child, the command stable-reads the input once and
validates its closed shape and every retained or reconstructable generation
relationship. This includes normalized spec/check equality, top-level
digests, per-attempt digest types, unique final approval, zero immutable ERC
errors, optional catalog receipt circuit/selection relationships, and exact
deterministic SKiDL rendering. Duplicate keys, non-finite JSON, unknown fields,
invalid UTF-8, broken evidence relationships, and unsupported schema versions
fail closed.

For a catalog-resolved bundle, schema v2 does not retain the initial
pre-selection spec/check bytes. The initial circuit semantics are reconstructed
and bound through the catalog receipt, then freshly replayed through Rust ERC;
that native result must match all four retained initial spec/check/review
history digests. The resolved final spec/check digests are also bound exactly.

The accepted normalized circuit is then staged privately and passed through
the following native operations using one monotonic deadline:

1. For catalog-resolved input only, `check-circuit-spec --require-approved`
   checks the reconstructed pre-selection circuit and authenticates its four
   retained history digests.
2. `check-circuit-spec --require-approved` recomputes the immutable Rust ERC
   result. The complete output must equal the check retained by generation.
3. `write-circuit-spec-kicad-schematic` generates a deterministic flat,
   single-unit schematic. The writer itself re-imports and self-checks its
   result before returning bytes.
4. `verify-circuit-kicad-handoff --require-approved` recomputes the semantic
   handoff and binds the exact staged spec/check/schematic bytes.

The deadline begins before output preflight and input reading. Every native
process receives only the remaining duration, and expiry before a stage or
the final commit prevents that stage from starting. The final bounded local
atomic write and filesystem synchronization are not asynchronously cancelled
after commit begins.

## Exact handoff-chain replay (v1.450)

`replay-circuit-handoff-bundle` is an explicit fresh handoff-chain replay gate. It
first performs the identical canonical six-entry archive verification used by
`verify-circuit-handoff-bundle`, then rebuilds the handoff from the retained
`generation-bundle.json` using the supplied `--pcbex` command. It publishes no
archive or extracted directory; all intermediate files are private temporary
files.

For a catalog-resolved generation bundle, the receipt reconstructs the
pre-selection circuit and the replay runs its `check-circuit-spec
--require-approved` gate. The result must match the four retained
pre-selection history digests. The replay then runs the resolved-circuit ERC,
the deterministic schematic writer, and the semantic
`verify-circuit-kicad-handoff --require-approved` gate. The newly generated
ZIP bytes and manifest must equal the retained archive byte-for-byte. Thus a
catalog-input ERC is replayed when, and only when, the retained generation
bundle contains a catalog receipt; no live catalog request is made.

`--timeout-seconds` is one aggregate monotonic deadline for archive input,
canonical validation, every native child, temporary artifact reads, archive
reconstruction, and the final byte comparison (default 120 seconds, maximum
600 seconds). Each child receives only the remaining time. A timeout, child
failure, digest mismatch, engine-version mismatch, or any byte difference
fails closed and returns no replay success.

The replay result is emitted as the closed
`circuit-generation-kicad-handoff-bundle-replay-result-v1` contract. It reports
`archive_reproduced: true`, `native_handoff_replayed: true`, and whether
`catalog_input_erc_required` and `catalog_input_erc_replayed` were true. It
also reports `native_kicad_erc_replayed: false`: the semantic pcbex handoff
gate is not the real KiCad `kicad-cli sch erc` command.

## Native KiCad ERC assertion (v1.451)

Supplying `--native-kicad-erc-report` extends the exact replay with one retained,
read-only native KiCad ERC assertion. Expected archive/bundle identities and the
canonical archive graph are checked first. The report is then stable-read under
a 32 MiB ceiling, and an optional
`--native-kicad-erc-warning-policy` is stable-read under a 1 MiB ceiling. The
complete six-entry producer chain must still reproduce the archive and manifest
byte-for-byte before KiCad is allowed to start.

After reproduction, the command stages the exact verified schematic, retained
report, and optional policy bytes in a private temporary directory. It invokes
the supplied pcbex command's `verify-native-kicad-erc-report` boundary with the
caller-selected `--kicad-cli`. The Rust verifier privately restages the
schematic, reruns `kicad-cli sch erc`, normalizes the result, and requires an
exact retained-report match. The caller-visible report and policy are reread
after the child exits and must still equal their initial stable reads.

Omitting the warning policy selects the error-only native report schema v1;
supplying the exact original policy selects schema v2. There is no report
autodetection or policy fallback. An exact but rejected report is a successful
replay by default and remains visibly `approved: false` in the result. Add
`--require-native-kicad-erc-approved` when rejection must fail the command.
That option, a warning policy, or a custom `--kicad-cli` is invalid without a
retained report.

The native-enabled command emits the closed
`circuit-generation-kicad-handoff-bundle-native-erc-replay-result-v2`
contract. Its path-free `native_kicad_erc` object binds the native schema,
decision, approval requirement, error/warning/policy-failure counts, run
identity, exact report byte/SHA-256 identity, and the optional canonical plus
source-byte policy identities. The existing v1 result remains byte-for-byte
compatible when no report is supplied: `native_kicad_erc_replayed` remains
false and no `native_kicad_erc` object is added.

The aggregate Python deadline covers archive input, expected identities,
sidecar reads, complete producer replay, staging, native verification, caller
source rereads, and cleanup. The nested Rust verifier receives the remaining
budget minus a cleanup reserve and applies that finite timeout directly to the
KiCad process tree, so the inner verifier can terminate and reap KiCad before
the outer process guard expires. The selected pcbex must therefore support the
v1.451 `verify-native-kicad-erc-report --timeout-seconds` contract. The standalone
Rust verifier defaults to 600 seconds when that option is omitted and accepts
only finite positive values no greater than 600 seconds.

CI exercises the Python argument/deadline boundary on macOS and Windows and the
complete real pcbex/KiCad flow on Linux. Deployments using another native KiCad
platform should additionally qualify that exact KiCad build and its process-tree
cleanup behavior in their protected runner environment.

This addition does not change the ZIP or manifest schema: native ERC evidence
and its warning policy remain sidecars and are never embedded in the canonical
six-entry archive. Consequently the archive alone still makes no native-KiCad
claim. The native result authenticates exact replay under the supplied tools,
not the provenance of those tools or the authority of the caller.

## Exact AI schematic quorum assertion (v1.452)

Supplying any AI replay option selects a complete, non-session schema-v1 AI
schematic quorum assertion. These inputs are all required together:

- `--ai-quorum-report` for the exact retained closed quorum report;
- `--ai-review-request` for its schema-v1 request without an artifact binding;
- `--ai-policy-pack` for the organization policy and trusted approval keys;
- one to 100 `--ai-approval` values and the same number of `--ai-response`
  values, paired by their occurrence order.

The three verification thresholds are caller-visible inputs:
`--minimum-ai-approvals`, `--minimum-distinct-ai-providers`, and
`--minimum-distinct-ai-models`. Each defaults to 2, must be between 1 and 100,
and neither diversity threshold may exceed the approval threshold. A threshold
override, `--require-ai-quorum`, or any other AI option without the complete
sidecar set is rejected rather than silently falling back to a different
verification mode.

The retained quorum report is stable-read under a 16 MiB ceiling. The request,
policy pack, each signed approval, and each response are individually limited
to 32 MiB; together those non-report sidecars may occupy at most 128 MiB. Empty,
non-regular, direct/ancestor symlink or reparse, changed, or over-limit inputs
fail through the same caller-file boundary as the archive and native sidecars.

The AI verifier child begins only after canonical offline verification and a
complete byte-for-byte producer replay of the unchanged six-entry ZIP and
manifest. If a native ERC report was also supplied, the v1.451 native replay
runs next.
The command then copies the exact reproduced `circuit-spec.kicad_sch` and the
stable-read AI request, policy pack, approvals, and responses to fixed names in
a private temporary directory. It invokes the existing Rust
`verify-ai-quorum --schematic` command with the three exact thresholds and a
fresh private report destination. No provider is called and no signing key is
accepted.

The Rust quorum verifier freshly checks every signed approval/response pair against
the supplied organization policy and verifies that the schema-v1 request still
matches the imported semantics of the reproduced schematic. Its stdout must be
empty, its new report must fit the 16 MiB report ceiling, and its bytes must
equal the retained quorum report exactly. The replay independently validates
the closed report shape, sorted unique members, counts, threshold failures, and
decision before exposing a result. Every caller-visible AI sidecar is then
reread and must equal its initial stable read. When native ERC and AI replay are
combined, the earlier native report and warning policy are reread again after
the AI child so the combined result cannot retain stale native evidence.

An exact report with `quorum_met: false` is useful retained evidence and is
accepted by default. `--require-ai-quorum` applies the final fail gate only
after the complete report reproduction, report validation, and all final
rereads. It neither modifies nor deletes the caller's retained evidence.
`--require-native-kicad-erc-approved` remains an independent gate for the
optional native assertion.

Success emits the closed, path-free
`circuit-generation-kicad-handoff-bundle-ai-quorum-replay-result-v3`
contract. Its `ai_schematic_quorum` object records the request identity carried
by the report, explicit policy thresholds, verified counts and decision,
whether quorum was required, exact report bytes/SHA-256, and exact byte/SHA-256
identities for the request, policy pack, and each order-paired approval/
response source. `validation.ai_schematic_quorum_replayed` is true;
`native_kicad_erc_replayed` states whether the optional v2 native evidence is
also present. The `native_kicad_erc` object is absent for AI-only v3 and is the
unchanged v2 evidence object when the assertions are combined. Host paths and
sidecar contents are not returned.

Omitting every AI option preserves the earlier result contracts exactly: an
ordinary exact producer replay returns v1, while a native-enabled replay
returns v2. The archive, manifest, offline verify/extract commands, and their
result bytes are unchanged. AI sidecars remain external and are never added to
the canonical ZIP.

This mode deliberately accepts only the existing live-schematic schema-v1
request. That request is bound to pcbex's imported semantic schematic IR, not
to irrelevant raw-source formatting; the preceding archive reproduction is
the separate check that fixes the exact archived schematic bytes. Session
binding, reviewer routing, schema-v2 through v4 artifact bindings, provider
execution, signing, and toolchain provenance are outside this v3 assertion. AI
quorum does not imply native KiCad approval; that evidence is present only when
the independent optional v1.451 assertion is also requested. PCB binding, PCB
DRC/DFM, and manufacturing authorization likewise require their existing
explicit gates.

## Catalog-provenance-bound exact replay (v1.453)

Supplying any catalog replay input selects one complete retained evidence set:

- `--catalog-generation-provenance` for the exact v1.421 provenance sidecar;
- `--catalog-fetch-receipt` for the exact v1.420 fetch receipt named by that
  provenance; and
- `--catalog-snapshot` for the exact normalized snapshot bound by both.

All three inputs are required together. A partial set fails instead of falling
back to an earlier replay mode, and the complete set is accepted only when the
archive generation bundle is catalog-backed. The provenance and fetch receipt
are each limited to 1 MiB, the snapshot is limited to 4 MiB, and their combined
captured size is limited to 6 MiB. Empty, non-regular, linked, changed, or
over-limit sources fail through the same bounded caller-file boundary as the
archive and other optional sidecars.

Execution stays within the one aggregate monotonic replay deadline. Canonical
archive verification and optional expected-identity checks complete first, and
the generation bundle must prove that catalog input ERC is required. The three
catalog sources are then captured before any producer child. The unchanged
six-entry archive must reproduce byte-for-byte. Optional native KiCad ERC runs
next when independently requested, followed by optional AI quorum when its own
complete input set is requested. The three catalog sources are reread before
provenance validation;
the existing `validate_catalog_generation_provenance` contract then
revalidates the retained provenance, fetch receipt, normalized snapshot,
embedded catalog-selection receipt, reconstructed pre-selection and resolved
circuit specs, generation history/check, exact generation-bundle bytes, and
generated SKiDL digest. File-origin snapshots are privately staged under the
exact bound source basename; injected snapshots are validated directly from
the captured bytes. The caller-visible sources are reread again after
validation.

This final validation is offline and historical. It performs no supplier or
network request and evaluates the catalog graph at the fetch time retained in
the receipt, rather than at the current clock. Success emits the closed schema
identified by
`circuit-generation-kicad-handoff-bundle-catalog-provenance-replay-result-v4.json`
with `schema_version: 4` and exact scope
`deterministic-electrical-handoff-chain-catalog-provenance-replay-v4`.
`validation.catalog_generation_provenance_replayed` is true, catalog input ERC
is required and replayed, and the `catalog_generation_provenance` object
directly contains the 13 validated provenance-v1 fields plus `sources`; there
is no intermediate `binding` key. The closed `sources.provenance`,
`sources.fetch_receipt`, and `sources.snapshot` objects each contain only
`bytes` and `sha256`. The result contains no caller path, raw provenance
encoding, raw fetch-receipt body, or raw snapshot body.

Native and AI assertions remain independent optional evidence. Their existing
objects appear only when the corresponding assertion was requested, and the
v4 validation booleans state whether each was replayed. Omitting all three
catalog inputs returns the exact existing v1 result for producer replay alone,
v2 with native ERC, or v3 with AI quorum (with or without native ERC). The
archive and manifest remain the unchanged canonical six-entry v1 format;
catalog evidence is never embedded in them.

The v4 result proves exact offline linkage to retained historical evidence. It
does **not** authenticate a supplier, TLS connection, endpoint, or raw HTTP
response; prove current inventory, price, or reservation; authorize procurement
or fabrication; authenticate pcbex, KiCad, or any other toolchain; or approve a
board, placement, layout, routing, PCB DRC/DFM, manufacturing package, or
manufacturing operation.

## Exact retained-board binding replay (v1.454)

Version 1.454.0 extends the same replay with one optional retained KiCad board
and its retained board-binding report. `--kicad-board` and
`--board-binding-report` are an all-or-nothing pair. The optional
`--board-binding-policy` supplies the exact custom electrical-policy source
used by the fresh replay; omitting it selects the board verifier's built-in
default. `--require-board-binding-approved` is valid only with the pair and
is applied after all evidence has been reproduced and reread. A partial pair,
an approval requirement, or a policy by itself fails closed; there is no
report or policy autodetection.

The board is stable-read as caller evidence before a producer child starts,
with a 128 MiB ceiling. The compact retained board-binding report is bounded
at 12 MiB for canonical JSON (12 MiB plus one byte for its required trailing
newline), and an optional policy is bounded at 4 MiB. The complete board,
rendered-report, and policy capture is capped at 144 MiB plus one byte in
aggregate. Each source must be a
nonempty regular file with no direct or ancestor symlink/reparse component;
size growth, replacement, aliasing, and any mutation fail closed. Python treats
the retained report as opaque evidence and compares it byte-for-byte, including
its canonical
trailing newline, with a fresh report written to a private output destination
by the existing `verify-circuit-kicad-board-binding` gate. The replay requests
the hidden `--mcp-echo-report-summary` bridge, while the full report remains in
its private output file; it is never echoed through the Python child stdout
path. Only bounded parsing and the compact numeric/digest summary cross that
boundary, and the summary cannot substitute for exact retained-report byte
comparison.
With the trusted pcbex verifier used by the release workflow, malformed board
or policy inputs and noncanonical report output also fail closed. A
caller-supplied `--pcbex` executable is an unauthenticated execution boundary,
however, so Python does not independently claim to parse or authenticate that
executable's retained report semantics.
The report binds the normalized effective policy, not the historical raw JSON
serialization. The v5 evidence therefore records both the effective
`policy_sha256` and, when supplied, the exact raw policy source used for this
fresh replay; it does not claim that an equivalent retained report was
originally produced from byte-identical policy JSON.

The v1.454 order is deterministic and remains within the one aggregate
`--timeout-seconds` deadline (default 120 seconds, finite range 1–600):

1. verify the canonical six-entry archive and any expected archive/bundle
   identities;
2. capture the board, retained report, and optional policy;
3. reproduce the unchanged archive and manifest byte-for-byte;
4. run any independently requested native KiCad ERC, AI quorum, and catalog
   provenance assertions in their existing v1.451–v1.453 order;
5. run the existing geometry-free board-binding verifier against the exact
   reproduced circuit specification and schematic, the retained board, and
   the optional policy; and
6. reread every caller-visible source (including the board, report, and policy)
   and then apply the optional approval gate.

Every child receives only the remaining monotonic budget; the board verifier
has no separate timeout flag. Its compact summary and child stdout/stderr each
remain within the existing 1 MiB Python child-stream ceilings, while the
12 MiB canonical report (+1 newline byte) is read from the private output file.
A timeout,
child failure, report-shape/hash mismatch, byte difference, source reread
change, or cleanup failure returns no v5 success. No archive or extraction
directory is published, and board evidence remains a sidecar rather than a
seventh ZIP entry.

Success emits the closed, path-free
`circuit-generation-kicad-handoff-bundle-board-binding-replay-result-v5.json`
contract with scope
`deterministic-electrical-handoff-chain-board-binding-replay-v5`. Its
`board_binding` summary contains only the retained-report schema and
engine, decision/approval requirement, compact finding counts, exact board
source and retained/fresh report byte/SHA-256 identities, and the
board-electrical, circuit-handoff, binding, and effective-policy identities.
The object is closed schema-v1: `counts`, `board`, `report`, optional raw
replay-source `policy` (`null` when the built-in policy is used),
`policy_sha256`, and the three electrical/handoff/binding SHA-256 identities
are the only evidence fields.
`validation.board_binding_replayed` is true. It contains no caller paths or raw
board/report/policy bodies. An exact but
rejected report is successful evidence by default; the optional
`--require-board-binding-approved` flag turns that decision into a final
failure only after replay and rereads.

Omitting all v1.454 board options preserves v1, v2, v3, and v4 result bytes,
schemas, archive bytes, and six-entry ZIP membership exactly, including when
the earlier native, AI, or catalog options are used. The board replay binds
only the electrical subset already defined by the standalone gate: reference,
footprint, pad, net, no-connect, and related handoff identity. It does not
approve placement or footprint geometry, copper geometry, routing, zones,
PCB DRC or DFM, Gerber/BOM/CPL, manufacturing or fabrication data, supplier
or procurement state, or toolchain provenance/authentication. In particular,
an unchanged board-electrical digest after a geometry-only source edit does
not make that edit layout-approved; the raw board and binding identities still
change and must match the retained report exactly.

## Exact archive

Success publishes exactly one no-clobber ZIP file with these ordered entries:

```text
generation-bundle.json
circuit-spec-v2.json
circuit-spec-check.json
circuit-spec.kicad_sch
circuit-kicad-handoff.json
manifest.json
```

Entries are stored without compression, with fixed timestamps, fixed regular
file modes, no comments, and deterministic ordering. `generation-bundle.json`
contains the exact source bytes rather than a reserialization. The normalized
spec and all native outputs contain the exact bytes checked during the run.
The closed schema-v1 manifest binds every fixed entry by name, byte count, and
SHA-256, plus the native engine version, canonical circuit and electrical
review identities, effective handoff policy, approval decision, and a
domain-separated aggregate bundle identity.

Changing only whitespace in the source generation bundle intentionally
changes the raw source descriptor and aggregate identity, even when the
normalized circuit remains equal. Repeating the command with identical input
bytes and the same pcbex engine produces identical archive bytes.

The destination is preflighted before any child starts. Existing files,
directories, symbolic links, ancestor links/reparse points, and concurrent
no-clobber races are rejected. All intermediate files remain in a private
temporary directory; an invalid generation result, failed ERC, writer error,
handoff rejection, timeout, malformed native output, or output collision
publishes no archive.

## Offline verification and extraction

Version 1.449.0 adds a consumer for the exact v1.448 archive. The verify-only
command stable-reads the ZIP once under the 224 MiB archive ceiling and writes
nothing. Before `zipfile` parses the central directory, pcbex requires one
single-disk, comment-free end record describing exactly six entries and the
canonical fixed-size central directory. It then requires the exact entry order
shown above, stored/no-compression payloads, equal compressed and expanded
sizes, fixed timestamps, regular `0644` Unix metadata, empty entry comments
and extras, zero flags, supported version fields, and every role-specific byte
limit. CRC failures, truncation, prefix/trailing data, ZIP64 framing, data
descriptors, encryption, links, special files, alternate names, duplicates,
missing/extra entries, and any noncanonical local/central framing are rejected.
The verifier never calls `extract()` or `extractall()`; it streams only the six
fixed records into bounded memory and requires the complete input bytes to
equal a reconstruction by the deterministic v1 writer.

All JSON evidence is parsed as strict UTF-8 with duplicate keys, non-finite or
oversized numbers, invalid Unicode, excessive depth, and excessive node counts
rejected. The consumer manually revalidates the closed manifest, every raw
byte-count/SHA-256 descriptor, the domain-separated aggregate identity, the
generation history/SKiDL/catalog relationships retained by schema v2, the
normalized specification and immutable ERC check, and the exact schematic and
handoff report bindings. A manifest whose hashes have merely been recomputed
over semantically inconsistent files therefore still fails.

The v1.449 offline `verify` and `extract` behavior is unchanged by v1.450:
they still start no native child and still report both replay flags as false.
Both commands emit the same closed result-schema-v1 JSON. It contains no host
paths and deliberately uses `verified`, not a production `approved` decision.
It records the outer archive bytes/SHA-256, raw manifest identity, five
artifact descriptors, logical bundle identity, engine claim, operation, and
whether extraction completed. Its closed `validation` object states that
internal consistency passed, whether at least one caller-supplied expected
identity matched, and explicitly reports `native_handoff_replayed: false` and
`catalog_input_erc_replayed: false`. Optional `--expected-archive-sha256` and
`--expected-bundle-sha256` values are validated before success and retained in
the result as external identity roots. Without one of those values from a
trusted channel, verification proves internal consistency only, not who
created the ZIP. A matched caller-supplied digest is only as trustworthy as
the channel that supplied it.

Extraction first completes the identical in-memory verification. It never
uses archive-controlled paths: the six constants above are written to a newly
reserved, private destination directory with atomic no-clobber file writes,
and `manifest.json` is written last as the commit marker. Existing files or
directories, direct or ancestor links/reparse points, concurrent destination
reservation, unexpected directory entries, content changes, write failures,
and synchronization failures fail without overwriting an existing object.
Caught failures remove only directory and file identities that the invocation
can prove it created. If identity inspection itself fails, the reservation is
left untouched rather than risking deletion of a concurrent replacement. An
abrupt process or host crash may likewise leave a reserved incomplete directory
without a trustworthy commit; downstream consumers must rerun the verifier and
must never accept mere directory existence. Rollback is a
live-state cleanup guarantee, not a claim that directory metadata deletion is
crash-durable on every filesystem; filesystems that reject directory `fsync`
retain no portable Python durability primitive.

## Trust boundary

The archive is an approved **deterministic electrical handoff**, not an AI
approval or production authorization. By itself it does not obtain or verify
AI signatures, multi-reviewer quorum, human escalation, supplier inventory or
catalog-provenance authenticity, native KiCad ERC, board binding,
placement/routing, PCB DRC/DFM, firmware, manufacturing data, or a factory
order. A v1.451 native-enabled replay result adds only the exact native-KiCad
assertion described above. A v1.452 result adds the exact schema-v1 AI quorum
assertion and may include that native assertion. A v1.453 result additionally
revalidates the retained v1.421 catalog graph against caller-supplied historical
sidecars. A v1.454 result adds only the retained-board, retained-report,
geometry-free electrical binding described above. None elevates the archive
into a production authorization or grants any other approval. Use the existing
live/artifact-bound AI review gates and the normal board, pipeline, procurement,
manufacturing, and fabrication gates explicitly downstream. In particular, an
`approved: true` handoff manifest, board-binding report, or native ERC decision
must never be interpreted as permission to fabricate.

The v1 archive is unsigned and its logical `bundle_sha256` covers the five
manifest-described artifacts, not the outer ZIP or `manifest.json` bytes.
Likewise, a catalog-resolved schema-v2 generation bundle does not retain the
original pre-selection check bytes that the producer replayed. The offline
consumer can revalidate every retained and reconstructable edge, but it still
does not run that omitted catalog check. v1.450's replay command can freshly
run the check and reproduce the complete archive, but the supplied `pcbex`
binary and its claimed version are caller inputs and are not authenticated;
matching `engine_version` is therefore a byte-reproduction implication, not a
provenance statement. v1.451 can optionally run real KiCad native schematic ERC,
but both the supplied pcbex command and selected `kicad-cli` executable remain
unauthenticated caller inputs and are not sandboxed. Offline verify/extract and
v1 replay remain native-KiCad-free. v1.452 can cryptographically reverify a
retained schema-v1 AI quorum, but it does not authenticate the supplied pcbex
binary or obtain a human decision. v1.453 can revalidate exact historical
catalog linkage without authenticating the supplier, TLS transport, endpoint,
or omitted raw HTTP response, and without establishing current inventory,
price, or reservation. v1.454 can compare a retained raw board and compact
board-binding report to a fresh geometry-free electrical binding, but it does
not authenticate KiCad/pcbex/toolchain provenance, placement or footprint
geometry, routing or copper, PCB DRC/DFM, Gerber/BOM/CPL, manufacturing or
fabrication data, procurement, or supplier state. No replay mode authenticates
its toolchain, binds or approves a PCB/layout, checks placement, routing, PCB
DRC/DFM, approves
manufacturing, or authorizes procurement or fabrication. Use a trusted
expected digest/signature, a protected toolchain, and the existing supplier,
AI, board, pipeline, procurement, manufacturing, and fabrication gates when
those properties are required.
