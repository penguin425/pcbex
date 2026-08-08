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
  extract-circuit-handoff-bundle build/circuit-handoff.zip \
  --output-dir build/verified-circuit-handoff

PYTHONPATH=agent/src python3 -m pcbex_agent \
  circuit-handoff-bundle-result-schema

PYTHONPATH=agent/src python3 -m pcbex_agent \
  circuit-handoff-bundle-replay-result-schema

PYTHONPATH=agent/src python3 -m pcbex_agent \
  circuit-handoff-bundle-native-erc-replay-result-schema
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
assertion described above; it does not elevate the archive or grant any other
approval. The generation bundle does not contain the original supplier
snapshot, so procurement must separately validate the v1.421
catalog-generation provenance against that snapshot. Use the existing
live/artifact-bound AI review gates and the normal board, pipeline, and
manufacturing gates explicitly downstream. In particular, an `approved: true`
handoff manifest or native ERC decision must never be interpreted as permission
to fabricate.

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
v1 replay remain native-KiCad-free. No mode authenticates supplier/catalog
provenance, obtains AI or human approval, binds a PCB, checks placement/routing/
PCB DRC/DFM, or authorizes manufacturing. Use a trusted expected
digest/signature, a protected toolchain, and the existing supplier-provenance,
AI, board, pipeline, and manufacturing gates when those properties are required.
