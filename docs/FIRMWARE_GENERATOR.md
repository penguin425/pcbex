# Pinout and firmware bundle

`pcbex generate-firmware <design.kicad_sch> --mcu-reference U1
--output-dir generated/` turns the imported schematic electrical IR into a
repeatable firmware contract. Connected pins on the selected MCU symbol are
sorted by physical pin number and emitted as:

- `pinout.h`: net, physical pin, and optional GPIO macros;
- `firmware.h` / `firmware.c`: a portable C descriptor table and lookup API;
- `firmware_smoke_test.c`: a generated executable smoke test;
- `firmware.cpp` / `firmware_cpp_smoke_test.cpp`: the equivalent strict C++17
  implementation and smoke test;
- `host.py`: a standard-library-only PC helper with lookup and `--self-test`;
- `manifest.json`: pin assignments, generated files, and build/test commands.

Use `--pin-map gpio.json` to map schematic pin numbers to MCU GPIO names, for
example `{ "1": "PA0", "2": "VDD" }`. The generator rejects blank/oversized
entries, requires at least one connected MCU pin, and rejects incomplete
schematic coverage unless `--allow-incomplete` is explicit.

By default it runs strict C11 and C++17 compile/link/smoke tests using `cc` and
`c++`, plus Python syntax and self-tests using `python3`. `--cxx` selects a
different C++ compiler. `--skip-build` is available for source generation-only
workflows, but leaves all build gates marked as not attempted.
`pcbex firmware-schema` prints the manifest schema.
