# Headless end-to-end pipeline

`pcbex-agent pipeline-run` is the integration boundary between the natural
language circuit contract and the existing Rust/KiCad tools. It creates a new
output directory and stops at the first failed phase while retaining
`pipeline.json`.

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent pipeline-run \
  requirements.txt \
  --provider-command ./model-json \
  --footprint-sizes build/footprints.json \
  --board-width-nm 60000000 --board-height-nm 40000000 \
  --mcu-reference U1 --pcbex ./target/release/pcbex \
  --physical-profile nes-profile.json --fab jlcpcb-2layer \
  --convergence-rounds 4 --max-copper-layers 4 \
  --require-factory --factory-provider jlcpcb \
  --factory-endpoint https://factory.example/api/quote \
  --output build/pipeline
```

The model command receives the closed circuit-spec prompt on stdin and must
return JSON only. Every external command is executed without a shell, with a
timeout and bounded output. The phases are:

1. natural-language circuit generation and deterministic ERC;
2. validated circuit → KiCad PCB handoff;
3. `pcbex place-kicad` placement;
4. `pcbex route-kicad` with physical/DFM profile, convergence and DRC;
5. `pcbex fabricate`, BOM/CPL plus a digest-bound ZIP manifest;
6. pinout-bound C11/C++17/Python firmware generation and tests; and
7. optional/required factory DFM receipt.

`submit-factory` can also be used directly. It sends the ZIP as
`application/zip`, binds the package SHA-256 in the request and receipt, and
normalizes `accepted`, `dfm_passed`/`dfm.passed`, quote, and DFM findings. The
Bearer token is read only from the named environment variable. HTTP is refused
except for loopback test fixtures.

For a site-specific repair service, the factory command file is a JSON string
array. Its stdin is the manufacturing ZIP, and the package path, SHA-256, and
provider are exposed as `PCBEX_PACKAGE_PATH`, `PCBEX_PACKAGE_SHA256`, and
`PCBEX_FACTORY_PROVIDER`. The command must return a JSON object with
`accepted: true` and `dfm_passed: true` when `--require-factory` is used.

`pipeline-schema` emits the closed report schema. The Rust binary used by the
runner must include the autonomous-routing and physical-profile options when
those options are requested; an older binary is rejected rather than silently
falling back to a less constrained route.

`--physical-profile` and the built-in `--fab` alias may be supplied together:
the fabrication profile is applied first, then the physical profile's board,
keepout, and manufacturing-rule declarations are applied last. This lets a
mechanical connector profile carry project-specific DFM overrides while still
starting from a named factory baseline.
