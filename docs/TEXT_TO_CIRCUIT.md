# Text-to-Circuit contract

`pcbex-agent generate-skidl` converts a closed, machine-readable circuit
specification into deterministic SKiDL source. An LLM may produce the JSON
specification from natural language, but it does not get to emit arbitrary
Python: references, pins, nets, and connectivity are validated before any
source is written.

The versioned contract is available with:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent circuit-spec-schema
```

Generate a circuit:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent generate-skidl \
  examples/circuit-spec.json --output build/circuit.py
```

The compatibility `--catalog` option accepts the legacy normalized array of
`CatalogPart` values. Missing `mpn` values can be filled while requiring stock
and JLCPCB-style basic parts:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent generate-skidl \
  examples/circuit-spec.json --catalog catalog.json \
  --require-basic --output build/circuit.py
```

The catalog adapter is intentionally vendor-neutral. LCSC, DigiKey, and
other connectors must normalize their responses into `mpn`, `description`,
`footprint`, `tags`, `vendor`, `stock`, `basic`, and `datasheet_url`. Legacy
array selection is deterministic, refuses duplicate MPNs, and fails when no
available part matches the requested footprint. It returns only the resolved
spec; it does not retain a source digest or selection receipt.

For production evidence, use the closed snapshot path in
[`docs/CATALOG_SELECTION.md`](CATALOG_SELECTION.md). `generate-circuit` accepts
`--catalog-snapshot` and emits a resolved circuit-spec-v2, a schema-versioned
catalog-selection receipt, and a second native Rust check after MPN assignment:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent generate-circuit \
  requirements.txt --pcbex target/release/pcbex \
  --catalog-snapshot examples/catalog-snapshot-v1.json \
  --output build/circuit-generation.json \
  --skidl-output build/circuit.py \
  --provider-command ./structured-circuit-provider
```

The closed snapshot and receipt contracts are available independently:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent catalog-snapshot-schema
PYTHONPATH=agent/src python3 -m pcbex_agent catalog-selection-receipt-schema
```

`--allow-out-of-stock`, `--require-basic`, and
`--allow-footprint-fallback` are explicit generation policies; all require a
snapshot. Footprint-only fallback is disabled by default and is recorded when
enabled. The generated SKiDL source keeps MPN evidence in the sorted
`_PCBEX_MPN_BY_REFERENCE` map rather than passing an unsupported `mpn=` keyword
to `Part`; catalog generation also embeds `_PCBEX_CATALOG_RECEIPT_SHA256`.

The generation bundle is `schema_version: 2`; consumers should select this
contract by its schema version and accept nullable catalog receipt fields when
no snapshot is used. SKiDL remains an optional runtime dependency; the
generated file can be executed in a separate environment that installs SKiDL.

External net names and part references are retained as quoted mapping keys in
the generated Python instead of being interpolated as Python identifiers. This
keeps common rail names such as `5V`, punctuation-bearing names such as `USB+`,
and names that overlap Python or SKiDL symbols executable without renaming the
electrical design.
