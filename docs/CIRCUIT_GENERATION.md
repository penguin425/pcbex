# Bounded natural-language circuit generation

`pcbex-agent generate-circuit` converts natural-language requirements into a
closed circuit specification, but the model never emits executable Python or
edits KiCad files. Every candidate is passed unchanged to the Rust engine,
normalized as `circuit-spec-v2`, converted into the canonical schematic IR,
and checked by the same deterministic electrical rules used for imported
KiCad schematics.

The Rust contracts are available with:

```sh
pcbex circuit-spec-v2-schema
pcbex circuit-spec-check-schema
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
  --max-attempts 3 \
  --provider-command ./structured-circuit-provider --model circuit-model
```

`--provider-command` consumes the remaining arguments and therefore must be
the final pcbex-agent option. The command is executed directly without a
shell. Standard input, standard output, standard error, process lifetime, and
the complete descendant process tree use the shared bounded-process policy.
Schema loading, every provider attempt, and every Rust check share one
monotonic deadline rather than receiving a fresh timeout per retry.

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
namespace-isolated SKiDL source digest. Invalid model payloads are not copied
into output artifacts. The optional standalone SKiDL file is published only
after generation succeeds; the JSON bundle always contains the same source.

## Circuit-spec v2 boundary

The v2 contract uses explicit pin electrical types and integer microvolts.
Parts carry closed power metadata, pins declare either one net or an explicit
no-connect state, and every net repeats its complete connection set. The Rust
normalizer verifies both representations agree, rejects duplicate or
cross-net pin use, applies fixed item/text/work ceilings, and sorts all
identity-bearing collections before hashing or conversion.

Nominal rail and maximum input values are facts supplied by the circuit
requirements; pcbex does not invent datasheet ratings. Supplier/datasheet
verification is a separate boundary. The generated review proves that the
declared intent is internally consistent, not that an unverified model chose
the correct real-world component rating.

## Scope

This release ends at a checked circuit specification and deterministic SKiDL
source. It does not produce a `.kicad_sch`, choose live supplier inventory,
place or route a board, or authorize fabrication. A generated design must
still pass the normal KiCad import, complete-coverage ERC, simulation evidence,
AI/human approval policy, PCB DRC, and manufacturing gates before production.
