# Bounded natural-language circuit generation

`pcbex-agent generate-circuit` converts natural-language requirements into a
closed circuit specification, but the model never emits executable Python or
edits KiCad files. Every candidate is passed unchanged to the Rust engine,
normalized as `circuit-spec-v2`, converted into the canonical schematic IR,
and checked by the same deterministic electrical rules used for imported
KiCad schematics. v1.412 can then resolve every MPN against a caller-supplied
catalog snapshot and run the native check a second time on that resolved
specification before publishing anything.

The Rust contracts are available with:

```sh
pcbex circuit-spec-v2-schema
pcbex circuit-spec-check-schema
```

The optional catalog contracts are available from the Python agent:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent catalog-snapshot-schema
PYTHONPATH=agent/src python3 -m pcbex_agent catalog-selection-receipt-schema
PYTHONPATH=agent/src python3 -m pcbex_agent catalog-fetch-receipt-schema
PYTHONPATH=agent/src python3 -m pcbex_agent catalog-generation-provenance-schema
```

The closed generation-bundle schema can embed those exact native contracts:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent circuit-generation-schema \
  --pcbex target/release/pcbex --output circuit-generation.schema.json
```

Omit `--pcbex` for the dependency-free built-in bundle-shape schema; use
`--pcbex` when consumers must validate the exact native item, text, and value
bounds as well. Output paths are no-clobber destinations and are checked
before any child process or model provider is started.

A standalone candidate can be checked without an AI provider:

```sh
pcbex check-circuit-spec circuit-spec-v2.json \
  --output circuit-check.json --require-approved
```

Natural-language generation uses a shell-free command adapter. The adapter
reads one prompt from standard input and must write one JSON object to standard
output:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent generate-circuit \
  requirements.txt \
  --output circuit-generation.json \
  --skidl-output circuit.py \
  --pcbex target/release/pcbex \
  --catalog-snapshot examples/catalog-snapshot-v1.json \
  --require-basic \
  --max-attempts 3 \
  --provider-command ./structured-circuit-provider --model circuit-model
```

`--provider-command` consumes the remaining arguments and therefore must be
the final pcbex-agent option. The command is executed directly without a
shell. Standard input, standard output, standard error, process lifetime, and
the complete descendant process tree use the shared bounded-process policy.
Schema loading, every provider attempt, and every Rust check share one
monotonic deadline rather than receiving a fresh timeout per retry.

These process and byte limits are not a network or filesystem sandbox. The
caller-supplied provider may perform its own I/O, including live supplier
queries, under the permissions of its environment. Only pcbex's catalog
selection step is offline and bound exclusively to the supplied snapshot.

`--catalog-snapshot` is optional. `--allow-out-of-stock`, `--require-basic`,
and `--allow-footprint-fallback` are selection policies and require a snapshot;
the last option is disabled by default so a footprint-only guess cannot be
silently substituted for a text match. The checked-in
`examples/catalog-snapshot-v1.json` demonstrates the closed snapshot shape;
its seven-day validity window must be refreshed with new inventory for a real
run.

To bind a retained v1.420 fetch to the exact v1.421 generation outputs, add
both `--catalog-fetch-receipt FETCH.json` and
`--catalog-provenance-output PROVENANCE.json`. The pair requires the snapshot,
is validated before any provider/native child starts, and evaluates selection
at the receipt's fetch timestamp. It performs no network operation. The
sidecar is separate so `circuit-generation-v2` remains byte/schema compatible
for existing consumers.

## Correction and acceptance rules

The provider receives the exact Rust JSON Schema and untrusted requirements.
Malformed JSON, an unknown field, an invalid connection, or a native ERC
finding becomes bounded correction feedback. A prior candidate is included as
quoted data, never as instructions.

The loop fails closed when any of these conditions occurs:

- the configured limit of one to four attempts is exhausted;
- a raw response or normalized circuit is repeated;
- a valid replacement does not strictly reduce the native ERC error count;
- a response, prompt, file, process output, or aggregate deadline exceeds its
  limit; or
- the Rust check envelope or one of its digests is inconsistent.

Only a native electrical review with `approved: true` and zero errors can be
published. The built-in error rules remain the immutable ERC safety floor:
generation cannot disable, demote, waive, or replace them with model judgment.
The result records bounded per-attempt response and prompt digests, the
normalized circuit-spec digest, the electrical-review digest, and the exact
namespace-isolated SKiDL source digest. With catalog selection, each attempt
also records initial versus resolved spec/check/review digests and the
catalog-receipt digest. Invalid model payloads are not copied into output
artifacts. The optional standalone SKiDL file is published only after
generation succeeds; the JSON bundle always contains the same source.

## Catalog resolution and the second Rust gate

When a snapshot is supplied, acceptance is deliberately two-stage:

```text
provider candidate
  -> Rust check-circuit-spec (v2 + immutable ERC, zero errors)
  -> closed snapshot selection and digest-bound receipt
  -> Rust check-circuit-spec again on the MPN-resolved spec
  -> final bundle and SKiDL
```

The selector verifies prefilled MPNs first, reserves stock, then assigns
missing MPNs in deterministic reference order using value/description/library
text and catalog tags. A candidate with no positive text match is rejected
unless `--allow-footprint-fallback` is explicitly enabled. Selection changes
only MPN fields; the second native check rejects any changed connectivity,
power metadata, pin data, or electrical finding. The receipt commits the
source basename/bytes/digest, normalized catalog digest, input and resolved
spec digests, policy, and every `assigned`/`verified` selection. A catalog
policy mismatch may request another provider candidate; a forged receipt or a
failed resolved Rust review fails closed.

The generation result is the closed `circuit-generation-v2` bundle. Its
`catalog_receipt` and `catalog_receipt_sha256` are null without a snapshot and
non-null when resolution is enabled. Consumers must branch on bundle
`schema_version: 2`, not infer the contract from the package version.

When the provenance flag pair is present, the CLI revalidates the fetch
receipt, normalized snapshot, embedded selection receipt, reconstructed input
spec, resolved spec, final native check/history, exact bundle bytes, and exact
SKiDL bytes before publishing. The closed sidecar records their SHA-256
bindings plus provider, endpoint identity, normalized catalog digest, and
evaluation timestamp; it contains no credential or local path. Bundle and
optional SKiDL publication are individually atomic, and the sidecar is
published last. See [Catalog snapshots and MPN selection](CATALOG_SELECTION.md)
for the complete replay contract and intentional per-file transaction limit.

## Circuit-spec v2 boundary

The v2 contract uses explicit pin electrical types and integer microvolts.
Parts carry closed power metadata, pins declare either one net or an explicit
no-connect state, and every net repeats its complete connection set. The Rust
normalizer verifies both representations agree, rejects duplicate or
cross-net pin use, applies fixed item/text/work ceilings, and sorts all
identity-bearing collections before hashing or conversion.

The Python envelope validator repeats the v2 null/type and complete pin/net
coverage invariants before rendering. Its compatibility SKiDL adapter drops
no-connect pins from the legacy v1 net map only after validation, carries their
reference/pin pairs in a deterministic private side channel, and emits
`_pcbex_parts[...][...] += NC` before ordinary net assignments. No synthetic
ordinary `Net("NC")` is introduced, and schema-v1 `generate-skidl` output is
unchanged when no v2 marker is present. SKiDL itself remains optional; this
boundary validates source syntax and evidence without importing the package.

Nominal rail and maximum input values are facts supplied by the circuit
requirements; pcbex does not invent datasheet ratings. Supplier/datasheet
verification is a separate boundary. The generated review proves that the
declared intent is internally consistent, not that an unverified model chose
the correct real-world component rating.

## Scope and KiCad handoff

Generation still ends at a checked circuit specification and deterministic
SKiDL source. It never queries live supplier inventory implicitly. The
standalone v1.420 `fetch-catalog-snapshot` pre-step may acquire a caller-owned
closed feed before generation, but generation itself consumes only that
retained local snapshot. The v1.421 provenance option verifies and binds the
retained fetch evidence but does not repeat the request. It does not map
arbitrary supplier-native responses or verify datasheet ratings. Generation
bundle v2 itself still stops at the checked circuit specification and SKiDL.
As an explicit downstream v1.422 step,
`write-circuit-spec-kicad-schematic` can convert that approved specification
to the closed flat/single-unit `.kicad_sch` subset, re-import it, and require
the existing semantic handoff to pass before publication. Version 1.423 makes
that same explicit step available through MCP and the root Action with
digest-only response metadata and no implicit pipeline substitution. It does
not place or route a board or authorize fabrication. See
[Deterministic circuit-spec v2 to KiCad schematic writer](CIRCUIT_KICAD_SCHEMATIC_WRITER.md) and
[Circuit-spec v2 to KiCad schematic handoff
verification](CIRCUIT_KICAD_HANDOFF.md) for the generation and comparison
boundaries. v1.416 additionally provides the standalone
`verify-circuit-kicad-board-binding` gate, which recalculates that handoff from
the raw inputs and binds it to an actual `.kicad_pcb`.  It does not generate or
modify a board or run geometry/routing/DRC/DFM checks; see [Circuit-spec v2 to
KiCad schematic and board binding verification](CIRCUIT_KICAD_BOARD_BINDING.md).
Version 1.448.0 adds the explicit downstream
[`handoff-circuit`](CIRCUIT_HANDOFF_BUNDLE.md) command for a saved generation
bundle. It revalidates its closed shape and every retained or reconstructable
generation relationship, replays catalog input ERC when present, and reruns
the final native check, writer, and semantic handoff under one deadline, then atomically publishes
their exact bytes in one deterministic no-clobber ZIP. It does not rerun the
model or convert deterministic electrical approval into AI or manufacturing
approval. The saved bundle does not retain the original supplier snapshot, so
inventory/catalog authenticity remains the separate v1.421 provenance gate.
Version 1.449.0 adds the matching offline
[`verify-circuit-handoff-bundle` and `extract-circuit-handoff-bundle`](CIRCUIT_HANDOFF_BUNDLE.md)
consumer. It accepts only the canonical six-entry archive, revalidates the
complete retained digest and semantic graph without executing provider/SKiDL/
native content, and exposes optional expected outer/logical digests for an
external identity root. Extraction publishes only fixed names to a newly
reserved no-clobber directory with the manifest written last; it still does
not authenticate the producer or replace any downstream approval gate. The
closed result makes the offline boundary machine-readable by reporting that
native handoff and omitted catalog-input ERC replay were not performed.
Version 1.450.0 adds the explicit
[`replay-circuit-handoff-bundle`](CIRCUIT_HANDOFF_BUNDLE.md) handoff-chain
replay gate.
It accepts the same six-entry archive and a caller-supplied `--pcbex` command,
reconstructs the catalog pre-selection circuit when a catalog receipt is
present, and reruns its native ERC before rerunning the resolved ERC, schematic
writer, and semantic KiCad handoff gate. The freshly generated archive and
manifest must reproduce the retained bytes exactly; the replay emits the
closed `circuit-generation-kicad-handoff-bundle-replay-result-v1` result and
writes no final artifact. One aggregate monotonic deadline covers archive
input, every native child, temporary evidence, and the final byte comparison.
The engine-version match implied by exact reproduction is not binary
authentication. The supplied executable is untrusted caller input, real
KiCad `kicad-cli sch erc` is not run, and supplier/catalog provenance,
AI/human approval, board/PCB DRC/DFM, and manufacturing authorization remain
separate gates. The v1.449 offline verify/extract commands remain unchanged
and do not execute native content.
Version 1.451.0 adds an explicit optional native-KiCad assertion to that replay.
When `--native-kicad-erc-report` is supplied, the six-entry archive must first
reproduce exactly; the retained report and optional exact warning policy are
then replayed against the reproduced schematic with the caller-selected
`kicad-cli`. The bounded sidecars remain outside the archive, and omitting the
report preserves the v1 result and starts no KiCad child. The native-enabled
path emits a closed path-free v2 result that binds the exact report, run,
decision, counts, and optional policy identities under the same aggregate
deadline. Exact replay is not toolchain authentication, AI/human approval,
board approval, or manufacturing authorization.
Version 1.452.0 adds an independent optional AI schematic quorum assertion.
A complete non-session schema-v1 request, retained quorum report, organization
policy pack, and order-paired signed approvals/responses are bounded and
stable-read before producer replay. After the six-entry archive reproduces
exactly (and after optional native ERC), the existing `verify-ai-quorum
--schematic` gate reruns against the exact privately staged schematic and
verifier inputs. Its fresh report must match the retained bytes exactly; all
sidecars are then reread before the optional final quorum requirement is
enforced.
Success emits a closed path-free v3 result with explicit threshold, count,
decision, report, and source identities. Omitting every AI option preserves
the exact v1 or native-enabled v2 result, and no sidecar is added to the archive.
The schema-v1 binding compares imported schematic semantics rather than raw
source formatting. Session/routing modes, tool provenance, native KiCad
authorization, board approval, and manufacturing authorization remain separate
boundaries.
The v1.417 [bounded-input deterministic runner](DETERMINISTIC_PIPELINE_RUNNER.md)
can recompute that standalone binding beside the unchanged `pipeline-verify`
gate from one digest-bound snapshot plan. A generated design must still
pass complete coverage ERC, simulation evidence, AI/human approval policy, PCB
DRC, and manufacturing gates before production.
