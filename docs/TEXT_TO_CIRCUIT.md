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

If a vendor connector returns the normalized catalog array described by
`CatalogPart`, missing `mpn` values can be filled while requiring stock and
JLCPCB-style basic parts:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent generate-skidl \
  examples/circuit-spec.json --catalog catalog.json \
  --require-basic --output build/circuit.py
```

The catalog adapter is intentionally vendor-neutral. LCSC, DigiKey, and
other connectors must normalize their responses into `mpn`, `description`,
`footprint`, `tags`, `vendor`, `stock`, `basic`, and `datasheet_url`. Selection
is deterministic, refuses duplicate MPNs, and fails when no available part
matches the requested footprint. SKiDL remains an optional runtime dependency;
the generated file can be executed in a separate environment that installs
SKiDL.

External net names and part references are retained as quoted mapping keys in
the generated Python instead of being interpolated as Python identifiers. This
keeps common rail names such as `5V`, punctuation-bearing names such as `USB+`,
and names that overlap Python or SKiDL symbols executable without renaming the
electrical design.
