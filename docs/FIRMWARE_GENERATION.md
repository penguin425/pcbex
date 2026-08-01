# Circuit-bound firmware generation

The default firmware bundle emits a deterministic `pinout.h`, C11/C++17
smoke-build, and Python host self-test. For a parallel ROM or bus reader, an
explicit interface profile adds real GPIO write/read logic and a matching host
frame decoder; it never guesses a pin from a net name.

```json
{
  "schema_version": 1,
  "kind": "parallel-rom-reader",
  "address_nets": ["A0", "A1", "A2"],
  "data_nets": ["D0", "D1", "D2", "D3"],
  "read_net": "RD_N",
  "active_low": true
}
```

Every listed net must exist in the validated circuit and have a GPIO mapping
for the selected MCU pin. The generated C++ API drives the address pins,
checks the read strobe, samples the data pins, and returns one byte; the
generated `host.py` decodes little-endian address/data frames from stdin.
Templates cannot silently replace this profile's generated logic.

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent firmware-interface-schema \
  -o build/firmware-interface-schema.json
PYTHONPATH=agent/src python3 -m pcbex_agent generate-firmware \
  examples/circuit-spec.json --mcu-reference U1 --gpio-map build/gpio.json \
  --interface-profile build/parallel-rom-reader.json -o build/firmware
```

`pipeline-run` accepts the same profile with `--interface-profile`; the C,
C++, and Python gates remain fail-closed.
