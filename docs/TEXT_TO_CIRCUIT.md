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
so the source and the recorded JSON cannot diverge. Generated SKiDL also carries
the normalized `PCBEX_ELECTRICAL_JSON` string so a later schematic/netlist
importer can preserve the same electrical evidence instead of guessing ratings.

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

For a direct DigiKey Product Information v4 KeywordSearch call, provide the
official endpoint, a query, and two-legged OAuth credentials by environment
name:

```sh
PCBEX_DK_ID="..." PCBEX_DK_SECRET="..." \
PYTHONPATH=agent/src python3 -m pcbex_agent generate-skidl \
  examples/circuit-spec.json --catalog-provider digikey \
  --catalog-endpoint https://api.digikey.com/products/v4/search/keyword \
  --catalog-query "3.3V level shifter" \
  --catalog-client-id-environment PCBEX_DK_ID \
  --catalog-client-secret-environment PCBEX_DK_SECRET \
  --output build/circuit.py
```

The adapter obtains a short-lived OAuth token, posts the bounded KeywordSearch
request, maps `Products`/`QuantityAvailable`/`ProductVariations` into the
deterministic catalog contract, and still applies the local in-stock and
footprint checks. For an approved JLCPCB or LCSC Components API endpoint,
supplying `--catalog-query` switches the selected provider to a bounded POST
request with `{"query": ..., "limit": 50, "offset": 0}`, optional bearer
authentication, and normalization of common `parts`/`items`/`data` wrappers.
Omitting the query retains the normalized HTTPS gateway GET mode. Their official
API accounts still require separate approval and provider-specific endpoint and
application credentials, so no undocumented URL or ordering schema is
hard-coded into pcbex.

`circuit-generation-schema` prints the closed result contract used by the
natural-language command. It contains the normalized circuit spec, deterministic
ERC report, attempt count, repair flag, and generated SKiDL source. The ERC
contract alone is available with `circuit-erc-schema`.

Electrical metadata is optional for non-power nets and is explicit when needed:

The PCB handoff can bind reviewed, real KiCad footprint geometry instead of
the deterministic placeholder pads used for development. The footprint library
is a bounded JSON object whose keys are part references or footprint names and
whose values are complete single-footprint `.kicad_mod` S-expressions:

The map contract is emitted by `verified-footprint-library-schema` and is
bounded to reviewed, non-empty footprint expressions.

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent circuit-to-kicad \
  examples/circuit-spec.json --footprint-sizes build/footprints.json \
  --footprint-library build/verified-footprints.json \
  --require-verified-footprints --board-width-nm 60000000 \
  --board-height-nm 40000000 --output build/circuit.kicad_pcb
```

Every circuit pin must have exactly one matching library pad. The renderer
retains the library's copper, mask, courtyard, and silkscreen geometry while
binding placement, references, and deterministic net ids. With
`--require-verified-footprints`, a missing library entry, duplicate pad number,
or missing pin pad rejects the handoff before placement; without the flag,
unresolved parts are explicitly reported as development placeholders.

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

## Handing the circuit to pcbex

The normalized spec or a `generate-circuit` bundle can be converted without
executing model-produced Python. First provide deterministic dimensions for the
selected footprints:

```json
{
  "MCU:Example": {"width_nm": 6000000, "height_nm": 6000000},
  "Package_QFN:QFN-16": {"width_nm": 4000000, "height_nm": 4000000}
}
```

Then emit the exact placement contract consumed by `pcbex place`:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent circuit-to-placement \
  build/circuit-generation.json --footprint-sizes build/footprints.json \
  --board-width-nm 60000000 --board-height-nm 40000000 \
  --grid-nm 250000 --output build/placement.json
pcbex place build/placement.json --output build/placement-result.json
```

For KiCad/DRC and the existing `place-kicad`/`route-kicad` commands, the same
validated graph can be rendered as a library-independent PCB handoff:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent circuit-to-kicad \
  build/circuit-generation.json --footprint-sizes build/footprints.json \
  --board-width-nm 60000000 --board-height-nm 40000000 \
  --output build/circuit.kicad_pcb
pcbex place-kicad build/circuit.kicad_pcb \
  --output build/placed.kicad_pcb --json-output build/placement.json
```

The handoff preserves references, pin numbers, net names, and net IDs. The
generated footprints are deliberately placeholders; a project may replace them
with verified library geometry before manufacturing.

For an intermediate artifact that does not depend on KiCad or a footprint
library, use `circuit-to-netlist`. It writes canonical sorted parts/nets and a
SHA-256 digest that the pipeline retains as `netlist.json`:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent circuit-to-netlist \
  build/circuit-generation.json --output build/netlist.json
```

To retain a schematic artifact as well, emit a self-contained KiCad schematic
whose embedded `PCBEX:*` symbols and repeated net labels preserve every pin:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent circuit-to-schematic \
  build/circuit-generation.json --project-name pcbex-demo \
  --output build/circuit.kicad_sch
```

The pipeline always runs the deterministic circuit ERC. With `--kicad-erc`, it
also runs the installed KiCad native ERC at error severity and retains its
report; warnings about a project-specific symbol library remain visible for
the later library replacement step.
