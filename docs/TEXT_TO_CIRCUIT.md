# Text-to-Circuit contract

`pcbex-agent generate-skidl` converts a closed, machine-readable circuit
specification into deterministic SKiDL source. An LLM may produce the JSON
specification from natural language, but it does not get to emit arbitrary
Python: references, pins, nets, and connectivity are validated before any
source is written.

For a bounded command-provider flow, `generate-circuit` performs that natural
language step and writes both an auditable JSON bundle and optional SKiDL source:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent generate-circuit \
  requirements.txt --provider-command ./my-structured-json-model \
  --max-attempts 3 -o build/circuit-generation.json \
  --skidl-output build/circuit.py
```

The provider receives only a closed schema prompt and cannot write files. Each
response is validated for complete pin/net coverage; invalid JSON or an
electrical shape error is returned to the model as a bounded correction request.
The same bounded correction loop runs a deterministic circuit ERC after
connectivity validation. Explicit rail voltages, power-output metadata,
per-pin maximum voltage ratings, and decoupling requirements reject rail
shorts, over-voltage inputs, incompatible power drivers, and missing bypass
capacitors before SKiDL is written. The ERC finding text is included in the
next provider prompt, so an electrical failure cannot silently become a layout
input.
After the attempt limit, generation fails closed. Catalog assignment happens
after validation and the bundle re-renders SKiDL from the exact normalized spec,
so the source and the recorded JSON cannot diverge.

The versioned contract is available with:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent circuit-spec-schema
```

Generate a circuit:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent generate-skidl \
  examples/circuit-spec.json --output build/circuit.py \
  --erc-output build/circuit-erc.json
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
accepted). Native LCSC aliases (`partNumber`, `packageType`, `stockQty`) and
DigiKey aliases (`ProductNumber`, `PackageType`, `QuantityAvailable`) are also
normalized, while the provider identity remains an explicit request header.
Responses are capped at 4 MiB, redirects and endpoint query strings
are rejected, HTTPS is required, and the bearer token is read only from the
named environment variable. Local HTTP is available only for loopback tests
with `--allow-http-loopback`.

`circuit-generation-schema` prints the closed result contract used by the
natural-language command. It contains the normalized circuit spec, deterministic
ERC report, attempt count, repair flag, and generated SKiDL source. The ERC
contract alone is available with `circuit-erc-schema`.

Electrical metadata is optional for non-power nets and is explicit when needed:

```json
{
  "reference": "U1",
  "lib_id": "MCU:Example",
  "value": "controller",
  "footprint": "Package_QFN:QFN-16",
  "pins": {"1": "5V", "2": "GND"},
  "electrical": {
    "pin_max_voltage_v": {"1": 3.3},
    "requires_decoupling": true
  }
}
```

Nets may declare `voltage_v`; common `5V`, `3V3`, and `1V8` rail names are
recognized conservatively when no explicit value is present. Capacitor parts
are marked with `electrical.decoupling: true` on the same supply net.
