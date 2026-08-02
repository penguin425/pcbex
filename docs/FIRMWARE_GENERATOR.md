# Canonical-IR firmware bundle generator

`pcbex generate-firmware <design.kicad_sch> --mcu-reference U1
--output-dir generated/` imports the KiCad schematic into pcbex's canonical
electrical IR, derives the selected MCU pinout, and publishes a deterministic
firmware source bundle. The manifest records the canonical IR SHA-256 (not a
path or an unaudited source-text hash), so the generated firmware remains bound
to the exact schematic identity used by the electrical and pipeline gates.

## Published sources

The output directory contains exactly these seven source artifacts, in this
order:

1. `pinout.h` — selected MCU reference, net, physical-pin, and optional GPIO macros;
2. `firmware.h` — the portable descriptor and lookup API;
3. `firmware.c` — the C11 descriptor implementation;
4. `firmware_smoke_test.c` — the C smoke executable;
5. `firmware.cpp` — the equivalent C++17 implementation;
6. `firmware_cpp_smoke_test.cpp` — the C++ smoke executable; and
7. `host.py` — a standard-library-only host helper with the selected MCU
   reference and `--self-test`.

`manifest.json` is the separate, closed v2 control artifact. Its only top-level
fields are `schema_version`, `engine`, `engine_version`, `schematic_sha256`,
`artifacts`, `c_build`, `cpp_build`, and `python_check`; unknown fields are
rejected. The ordered seven-entry `artifacts` array contains only `path`,
positive `bytes`, and lowercase `sha256` descriptors. Each build record includes
`attempted`, `passed`, the bounded argv `command`, an `exit_code`, and a nested
smoke record with the same fields. MCU/pin metadata is represented by the
generated source files, not added as extra manifest fields. `pinout.h` and
`host.py` record the exact selected MCU reference, while the GPIO values record
the effective pin map; their artifact digests make both choices auditable.

Pin assignments are sorted by physical pin number (numeric values before
non-numeric values). Use `--pin-map gpio.json` to map schematic pin numbers to
MCU GPIO names, for example `{ "1": "PA0", "2": "VDD" }`. Blank or oversized
mapping entries, missing MCU references, and MCUs with no connected pins fail
closed. Unsupported or incomplete schematic coverage requires an explicit
`--allow-incomplete` opt-in.

## Build and publication boundary

Unless `--skip-build` is supplied, generation performs all of the following:

- compiles and links the C sources as strict C11, then executes the C smoke
  binary;
- compiles and links the C++ sources as strict C++17, then executes the C++
  smoke binary; and
- runs `python -m py_compile host.py`, followed by the host `--self-test`.

The C and C++ smoke programs verify the exported count, lookup behavior, and
the net, physical-pin, and GPIO strings for every generated descriptor.

Compiler and Python invocations are argv-only subprocesses: pcbex does not
insert a command shell, and it discards child stdout and stderr instead of
buffering them. `--cc`, `--cxx`, and `--python` accept printable-ASCII bare
executable names resolved through `PATH`; paths and path separators are
rejected so host-local directories are not embedded in the published command
evidence. Validation runs against disposable copies in a separate private
directory, and pcbex rejects any tool that changes those source copies. The
canonical source stage is never the compiler/interpreter working directory.
The compiler command line uses GCC/Clang-compatible flags; native MSVC `cl.exe`
syntax is not supported by this v2 generator.
`--timeout-seconds` selects a bounded 1–3600 second deadline per direct child
(120 seconds by default). The timeout kills and waits for that
direct child; it is not a process-tree sandbox and does not guarantee that
descendants created by a selected tool are terminated. Use trusted toolchain
executables inside a job-level sandbox when descendant containment matters. A
failed compile, link, smoke test, or Python check is retained as failed
evidence in the manifest; the downstream pipeline gate rejects any such
manifest. Source-copy mutation is an integrity failure rather than ordinary
build evidence and aborts publication entirely.

Generation writes into a private staging directory first. The requested
output's parent must already exist as a real, non-symlink directory. The output
directory itself must be new, must not alias an input, and may not contain any
symlink component. Existing files are never overwritten. The complete verified
staging directory is published with one directory rename rather than exposing
a partially moved bundle. Before publication, known validation
by-products (the private `.pcbex-firmware-c-smoke` and
`.pcbex-firmware-cpp-smoke` binaries, including Windows `.exe` variants, and
`__pycache__`) are removed. Publication then requires the staging directory to
contain exactly the seven sources plus `manifest.json`, so any other compiler
or interpreter output fails closed instead of entering the bundle.

`--skip-build` deliberately emits source-only output with every build record
marked `attempted: false` and `passed: false`. This is useful for source review,
but `pipeline-verify` rejects such a manifest in its `firmware-build` phase;
production evidence must come from a complete compile/link/smoke run.

`pcbex firmware-schema` prints the closed manifest v2 schema. Build records are
local execution evidence produced by this command, not signed attestations.
`engine_version` records a bounded semantic producer version; the v2 schema is
stable across pcbex releases that keep this manifest contract unchanged.
The generator does not claim signatures, compiler/toolchain provenance,
process-tree containment, or cross-compilation; those are later trust
boundaries.
