# Hash-bound hardware pipeline gate

`pipeline-verify` closes the design-to-package evidence chain for one
schematic and one routed board. With no factory options it preserves the
backward-compatible v1 report and its five phases. Supplying
`--factory-receipt PATH` or `--require-factory` enables the factory-bound v2
report, whose sixth and final phase is `factory-dfm`.

Production jobs should supply both `--factory-receipt` and
`--require-factory`. A supplied receipt is validated even without the require
flag; `--require-factory` by itself enables v2 and retains a failure when the
receipt is missing. The gate never submits the package or contacts the factory.

```text
pcbex pipeline-verify \
  --schematic hardware/controller.kicad_sch \
  --electrical-policy config/electrical-policy.json \
  --electrical-review build/electrical-review.json \
  --board hardware/controller.routed.kicad_pcb \
  --analysis-manifest build/analysis/run.json \
  --analysis-checks build/analysis/checks.json \
  --quality build/analysis/quality.json \
  --manufacturing-package build/manufacturing/manufacturing.zip \
  --firmware-manifest build/firmware/manifest.json \
  --factory-receipt build/factory-receipt.json \
  --require-factory \
  --output build/pipeline-gate.json
```

`--electrical-policy` is independently optional; omit it to recompute the
review with pcbex's built-in default policy. Four analysis inputs are
conditionally required: pass `--analysis-project`, `--analysis-rules`,
`--analysis-dfm-profile`, and/or `--analysis-policy-pack` exactly when
`run.json` declares the corresponding source. pcbex never dereferences the
descriptor paths embedded in `run.json`; the explicit CLI paths authorize the
files that may be read and their bytes and SHA-256 must match the descriptors.
Every other input and `--output` is required. In particular,
`--manufacturing-package` names the final ZIP selected for fabrication, not a
loose manufacturing manifest. Use
`pcbex pipeline-schema` to print the closed v1 report schema, or
`pcbex pipeline-schema --factory` for the closed v2 schema. Schema output also
follows the no-clobber rules described below.

## What is verified

The v1 report contains these five phases in order. The v2 report retains them
unchanged and appends `factory-dfm` as a strict sixth phase:

1. **electrical-erc** imports the exact schematic, loads the supplied policy
   (or the built-in default), and recomputes the complete electrical review.
   The supplied review must equal that recomputation, be approved, and contain
   zero error findings. A copied approval for another schematic or effective
   policy is rejected.
2. **analysis-drc** binds `run.json` to the exact board's byte count and
   SHA-256, safely reloads and hash-checks any explicitly supplied project,
   custom-rule, external-DFM-profile, and organization-policy inputs, then
   reimports the board with that effective configuration. A declared source
   without its matching CLI argument, or an argument without a matching
   declaration, fails closed. Its recomputed `checks.json` must exactly match
   the supplied closed report and be clean with zero violations. The remaining
   named presentation artifacts (`board.json`, SVG, SARIF, and summary) are not
   trust inputs and are not opened by this gate.
3. **routing-quality** strictly validates the quality report used above and
   requires it to exactly match routing quality recomputed from that same board
   and configuration, agree with the run totals, and contain zero unrouted
   nets.
4. **manufacturing-package** runs the complete manufacturing-package validator
   over the exact ZIP bytes. The ZIP's embedded `manifest.json`, every declared
   entry's byte count and SHA-256, required BOM/CPL/DRC, drill output, Gerber
   job, and complete declared layer set must validate. The embedded input
   descriptor must identify the exact board passed with `--board`. This proves
   internal ZIP integrity and manifest identity binding; it does not regenerate
   Gerber/BOM/CPL from the board or establish signed producer provenance.
5. **firmware-build** strictly validates the generated firmware manifest,
   binds its canonical-IR `schematic_sha256` to the recomputed electrical
   identity, requires the C11, C++17, and Python gates (including each smoke
   test) to have been attempted and passed, and verifies the byte count and
   SHA-256 of each of the seven required adjacent source artifacts. A
   source-only manifest produced with `--skip-build` is rejected.
6. **factory-dfm** (v2 only) strictly validates the normalized factory receipt
   and binds its `package_sha256`, `package_bytes`, and `request_sha256` to the
   exact final manufacturing ZIP already read by
   `manufacturing-package`. It requires an HTTPS endpoint, a 2xx `http_status`,
   explicit `accepted: true`, `dfm_passed: true`, and no finding whose severity
   is outside `info`, `notice`, or `warning`. Missing, unknown, or error-like
   severities fail closed. The receipt is not a trigger for another upload or
   a response fetch.

The command therefore records two identity chains:

```text
schematic bytes -> canonical imported IR identity -> recomputed review
                                                  `-> firmware manifest -> source artifact digests

board bytes -> analysis run -> checks + routing quality
          `-> manufacturing manifest -> exact final ZIP digest
                                             `-> factory receipt -> normalized DFM decision
```

These are identity and integrity links, not signatures. They do not establish
who produced an artifact.

## Firmware manifest v2

`generate-firmware` emits the bundle and runs its bounded build checks before
publication. `pipeline-verify` then independently validates the closed
manifest, the consistency of its recorded success fields, and every adjacent
source file. It deliberately does not execute manifest commands or generated
binaries. The build records are therefore producer-supplied local execution
evidence rather than a signed or independently replayed attestation. The
manifest has this shape (replace sizes, digests, version, and command argv with
the values actually produced; the commands below show POSIX output):

```json
{
  "schema_version": 2,
  "engine": "pcbex",
  "engine_version": "1.399.0",
  "schematic_sha256": "<canonical IR SHA-256>",
  "artifacts": [
    {"path": "pinout.h", "bytes": 123, "sha256": "<sha256>"},
    {"path": "firmware.h", "bytes": 123, "sha256": "<sha256>"},
    {"path": "firmware.c", "bytes": 123, "sha256": "<sha256>"},
    {"path": "firmware_smoke_test.c", "bytes": 123, "sha256": "<sha256>"},
    {"path": "firmware.cpp", "bytes": 123, "sha256": "<sha256>"},
    {"path": "firmware_cpp_smoke_test.cpp", "bytes": 123, "sha256": "<sha256>"},
    {"path": "host.py", "bytes": 123, "sha256": "<sha256>"}
  ],
  "c_build": {
    "attempted": true,
    "passed": true,
    "command": ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-I", ".", "firmware.c", "firmware_smoke_test.c", "-o", ".pcbex-firmware-c-smoke"],
    "exit_code": 0,
    "smoke": {
      "attempted": true,
      "passed": true,
      "command": ["./.pcbex-firmware-c-smoke"],
      "exit_code": 0
    }
  },
  "cpp_build": {
    "attempted": true,
    "passed": true,
    "command": ["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pedantic", "-I", ".", "firmware.cpp", "firmware_cpp_smoke_test.cpp", "-o", ".pcbex-firmware-cpp-smoke"],
    "exit_code": 0,
    "smoke": {
      "attempted": true,
      "passed": true,
      "command": ["./.pcbex-firmware-cpp-smoke"],
      "exit_code": 0
    }
  },
  "python_check": {
    "attempted": true,
    "passed": true,
    "command": ["python3", "-m", "py_compile", "host.py"],
    "exit_code": 0,
    "smoke": {
      "attempted": true,
      "passed": true,
      "command": ["python3", "host.py", "--self-test"],
      "exit_code": 0
    }
  }
}
```

Firmware manifest v2 replaces the five-artifact v1 contract published in
v1.397; consumers must select the schema by `schema_version` rather than infer
it from the pcbex package version. A bounded semantic `engine_version` records
the producer without requiring the verifier binary to have the identical
package version. The artifact list must contain exactly those
seven unique direct-child names in the order shown. The manifest filename must
be `manifest.json`, and its directory may contain no other entries. Each file
must be a non-symlink regular file beside the manifest and must match its
positive byte count and lowercase SHA-256. Every
build and nested smoke record must be attempted and passed with a zero exit
code; command arrays are bounded printable-ASCII argv evidence and must contain
valid strings.
Unknown manifest or nested build fields, unsafe paths, symlinks, missing or
reordered artifacts, and any failed or unattempted gate are rejected.

The generator's `--skip-build` mode intentionally leaves all three records
unattempted and is therefore not acceptable to this phase. The gate checks the
canonical schematic IR identity and source digests, but does not independently
prove that the recorded commands ran. It does not establish signatures,
compiler or toolchain provenance, process isolation, or cross-compilation
correctness. The selected MCU reference and effective GPIO mapping are retained
inside the hash-checked sources; the gate does not receive a separate expected
MCU reference, so policy that mandates one particular MCU must check the
generated `PCBEX_MCU_REFERENCE` value before invoking the gate.

## Factory receipt v1 (v2 phase)

`factory-submit` writes a closed, normalized receipt. Its top-level shape is:

```json
{
  "schema_version": 1,
  "adapter": "generic-factory-http-v1",
  "provider": "generic",
  "endpoint": "https://factory-gateway.example/v1/quote",
  "package_sha256": "<64 lowercase hexadecimal characters>",
  "package_bytes": 123,
  "request_sha256": "<same ZIP SHA-256>",
  "response_sha256": "<64 lowercase hexadecimal characters>",
  "response_bytes": 123,
  "http_status": 200,
  "status": "quoted",
  "accepted": true,
  "dfm_passed": true,
  "quote": {},
  "findings": [],
  "response": {
    "status": "quoted",
    "accepted": true,
    "dfm_passed": true,
    "quote": {},
    "findings": []
  }
}
```

Unknown top-level receipt or finding fields are rejected. The factory phase
requires an `https://` endpoint, a 2xx `http_status`, explicit
`accepted: true`, `dfm_passed: true`, and only `info`, `notice`, or `warning`
finding severities; missing or unknown severities fail closed. The receipt's
`package_sha256`, `package_bytes`, and `request_sha256` must bind to the same
single-read final manufacturing ZIP used by the `manufacturing-package` phase.
The phase does not resend that ZIP or retrieve the factory response again.
The package size and digest are independently re-derived from the selected
ZIP. `response_sha256` and `response_bytes` remain bounded transport metadata:
without the original response byte stream the offline gate cannot re-derive
them from the parsed `response` object. Receipt evidence therefore does not
prove factory authenticity or signature validity.

## Report and filesystem contract

The v1 report has `schema_version: 1`, `pipeline: "pcbex-hardware-v1"`, nullable
`identities.schematic_sha256` and `identities.board_sha256`, exactly five phase
objects, and top-level `passed` and `failures`. The v2 report has
`schema_version: 2`, `pipeline: "pcbex-hardware-v2"`, and exactly those five
phases plus `factory-dfm` at the end. Each phase contains its name, pass
decision, checks, failures, and digest evidence; host input paths are not
serialized. A report evidence descriptor has the exact shape
`{"role":"...","bytes":123,"sha256":"..."}`; it identifies the role and
the byte count and digest of the exact content read without copying a host path
into the descriptor. This differs intentionally from firmware artifact
descriptors, whose closed shape is
`{"path":"...","bytes":123,"sha256":"..."}`. The identity fields remain
`null` when the corresponding source cannot be established safely. `passed` is
true only when every phase passes.

All phases are evaluated so a rejection report retains independent failures
instead of stopping at the first bad artifact. On a normal phase rejection the
report is published before the command exits nonzero. A preflight failure, such
as an existing output or unusable output directory, occurs before validation
and therefore need not produce a report. The report includes input digests but
does not claim a self-digest; hash the completed report separately when a later
system must pin its exact bytes.

Inputs are read with fixed size and collection limits. Analysis descriptor
paths are retained only as producer metadata and are never used for I/O; every
optional analysis source requires its role-specific CLI argument. CLI inputs,
firmware artifacts, and the manufacturing package must be nonempty regular
files; a symlink at the file or in its parent path is rejected. Firmware paths are
restricted to the required adjacent names, and ZIP paths, entry counts, and
expanded sizes are bounded. The output parent must already exist. The output
must not exist, must not alias an input, and its path may not contain a symlink
component. pcbex writes and syncs a temporary file beside the destination and
publishes it atomically without overwrite.

Those checks narrow the filesystem interface; they are not a general process
sandbox or a claim of complete TOCTOU immunity. Use job-private directories and
trusted upstream producers when hostile concurrent filesystem mutation is in
scope.

## Factory and repository boundaries

The v1 gate ends at the locally validated manufacturing ZIP. The v2 factory
phase validates an already-produced receipt and enforces its normalized DFM
result, but it never submits the package, retries the network request, or
re-fetches raw response bytes. It checks the receipt's HTTPS endpoint, 2xx
status, explicit acceptance, DFM pass, and closed severity allowlist against
the exact ZIP bytes/SHA already read by `manufacturing-package`. This is an
integrity boundary, not a factory-authenticity or signature-verification
boundary. A passing pipeline report by itself is not authorization to
fabricate.

`pipeline-verify` is also not automatically wired as a repository required
status check. Once a workflow produces every input above, a team can add this
command as a CI job, retain its report on success and failure, and configure
that job's name as a required check in the repository's branch rules.

## Operational checks

Generate all inputs in one job-private directory, select the final post-repair
manufacturing ZIP, and run the gate only after the firmware manifest hashes are
final. For local v1 mode, make the following assertions in CI:

```sh
jq -e '
  .schema_version == 1 and
  .pipeline == "pcbex-hardware-v1" and
  .passed == true and
  .failures == [] and
  (.phases | length == 5) and
  (.phases | all(.passed == true)) and
  (.identities.schematic_sha256 | test("^[0-9a-f]{64}$")) and
  (.identities.board_sha256 | test("^[0-9a-f]{64}$"))
' build/pipeline-gate.json
sha256sum build/pipeline-gate.json > build/pipeline-gate.json.sha256
```

For the recommended production v2 invocation, use the receipt and require
flag, then assert the additional factory phase and decision:

```sh
jq -e '
  .schema_version == 2 and
  .pipeline == "pcbex-hardware-v2" and
  .passed == true and
  .failures == [] and
  (.phases | length == 6) and
  (.phases[5].name == "factory-dfm" and .phases[5].passed == true) and
  (.phases | all(.passed == true))
' build/pipeline-gate.json
```

Exercise the failure contract before making the job required: alter a copy of
one reviewed input and run with a fresh output path; expect a nonzero exit, an
existing report, `.passed == false`, and a nonempty `.failures`. Re-run against
an already existing output and expect refusal without changing its recorded
SHA-256. Finally, archive the failed report as well as the passing report so
the digest evidence remains inspectable.
