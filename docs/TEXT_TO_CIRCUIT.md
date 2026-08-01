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

For live inventory, point the same generator at an HTTPS catalog gateway:

```sh
PCBEX_CATALOG_TOKEN="..." \
PYTHONPATH=agent/src python3 -m pcbex_agent generate-skidl \
  examples/circuit-spec.json --catalog-endpoint https://catalog.example/v1/parts \
  --catalog-provider digikey \
  --catalog-bearer-token-environment PCBEX_CATALOG_TOKEN \
  --require-basic --output build/circuit.py
```

The gateway returns either a part array or `{ "parts": [...] }` using the
normalized fields (legacy aliases `part_number`, `package`, and `quantity` are
accepted). Responses are capped at 4 MiB, redirects and endpoint query strings
are rejected, HTTPS is required, and the bearer token is read only from the
named environment variable. Local HTTP is available only for loopback tests
with `--allow-http-loopback`.
