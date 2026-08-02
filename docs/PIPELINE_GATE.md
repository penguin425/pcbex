# Hash-bound hardware pipeline gate

`pipeline-verify` closes the local design-to-package evidence chain for one
schematic and one routed board. It validates all five phases, writes a
digest-bearing report, and exits nonzero when any phase is rejected.

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
`pcbex pipeline-schema` to print the closed report schema; its optional output
also follows the no-clobber rules described below.

## What is verified

The report always contains these five phases in order:

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
5. **firmware-build** strictly validates the external firmware manifest, binds
   its `schematic_sha256` to the recomputed electrical identity, requires the
   C and Python gates to have been attempted and passed, and verifies the byte
   count and SHA-256 of each of the five required adjacent artifacts.

The command therefore records two identity chains:

```text
schematic bytes -> imported schematic identity -> recomputed review
                                            `-> firmware manifest -> firmware artifact digests

board bytes -> analysis run -> checks + routing quality
          `-> manufacturing manifest -> exact final ZIP digest
```

These are identity and integrity links, not signatures. They do not establish
who produced an artifact.

## Firmware manifest v1

The firmware bundle is external: pcbex validates it but does not run the
recorded compiler or Python command. The manifest is closed to unknown fields
and has this exact shape (replace sizes, digests, version, and command argv
with the values actually produced):

```json
{
  "schema_version": 1,
  "engine": "pcbex",
  "engine_version": "1.396.0",
  "schematic_sha256": "<64 lowercase hexadecimal characters>",
  "artifacts": [
    {"path": "pinout.h", "bytes": 123, "sha256": "<sha256>"},
    {"path": "firmware.h", "bytes": 123, "sha256": "<sha256>"},
    {"path": "firmware.c", "bytes": 123, "sha256": "<sha256>"},
    {"path": "firmware_smoke_test.c", "bytes": 123, "sha256": "<sha256>"},
    {"path": "host.py", "bytes": 123, "sha256": "<sha256>"}
  ],
  "c_build": {
    "attempted": true,
    "passed": true,
    "command": ["cc", "-o", "firmware-smoke", "firmware.c", "firmware_smoke_test.c"]
  },
  "python_check": {
    "attempted": true,
    "passed": true,
    "command": ["python3", "-m", "py_compile", "host.py"]
  }
}
```

The artifact list must contain exactly those five unique direct-child names in
the order shown.
Each file must be a non-symlink regular file beside the manifest and must match
its positive byte count and lowercase SHA-256. Command arrays are retained as
bounded argv evidence; they must be nonempty and contain valid bounded strings,
but pcbex does not replay or sandbox them.

## Report and filesystem contract

The v1 report has `schema_version: 1`, `pipeline: "pcbex-hardware-v1"`, nullable
`identities.schematic_sha256` and `identities.board_sha256`, exactly five phase
objects, and top-level `passed` and `failures`. Each phase contains its name,
pass decision, checks, failures, and digest evidence; host input paths are not
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

This gate ends at the locally validated manufacturing ZIP. It does not submit
the package, validate a factory receipt, or enforce the factory's DFM result.
Factory receipt/DFM enforcement is a subsequent gate and must bind the receipt
to the same ZIP digest; unknown DFM severities should remain fail-closed. A
passing pipeline report by itself is not authorization to fabricate.

`pipeline-verify` is also not automatically wired as a repository required
status check. Once a workflow produces every input above, a team can add this
command as a CI job, retain its report on success and failure, and configure
that job's name as a required check in the repository's branch rules.

## Operational checks

Generate all inputs in one job-private directory, select the final post-repair
manufacturing ZIP, and run the gate only after the firmware manifest hashes are
final. Then make the following assertions in CI:

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

Exercise the failure contract before making the job required: alter a copy of
one reviewed input and run with a fresh output path; expect a nonzero exit, an
existing report, `.passed == false`, and a nonempty `.failures`. Re-run against
an already existing output and expect refusal without changing its recorded
SHA-256. Finally, archive the failed report as well as the passing report so
the digest evidence remains inspectable.
