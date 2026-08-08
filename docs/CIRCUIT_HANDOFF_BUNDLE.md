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
```

The command consumes a saved bundle; it does not call an LLM, supplier API,
SKiDL, KiCad GUI, or shell. The bundle's SKiDL text and provider metadata are
validated as inert evidence and are never executed.

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

## Trust boundary

This is an approved **deterministic electrical handoff**, not an AI approval
or production authorization. It does not obtain or verify AI signatures,
multi-reviewer quorum, human escalation, supplier inventory or
catalog-provenance authenticity, native KiCad ERC, board binding,
placement/routing, PCB DRC/DFM, firmware, manufacturing data, or a factory
order. The generation bundle does not contain the original supplier snapshot;
procurement must separately validate the v1.421 catalog-generation provenance
against that snapshot. Use the existing live/artifact-bound AI review gates
and the normal board, pipeline, and manufacturing gates explicitly downstream. In
particular, an `approved: true` handoff manifest must never be interpreted as
permission to fabricate.
