# Fresh exact firmware-bundle build verification

Version 1.466 adds a standalone verifier for one already-generated firmware
bundle:

```sh
pcbex verify-firmware-build build/firmware/manifest.json \
  --output build/firmware-build-verification.json \
  --require-approved
pcbex firmware-build-report-schema \
  --output fresh-firmware-bundle-build-v1.schema.json
```

The verifier does not trust the historical build decisions in firmware
manifest v2. It captures and validates the exact manifest in memory,
reconstructs the seven captured source artifacts in a private temporary
directory, and performs six new checks. The manifest contract itself is
unchanged.

> **Execution trust boundary:** this command executes caller-selected
> compilers and interpreter, the C and C++ smoke binaries they produce, and
> the supplied `host.py --self-test` logic. Use it only with a trusted bundle
> and trusted toolchain. If either is untrusted, run the entire pcbex command
> in a separately enforced operating-system sandbox with appropriately limited
> filesystem, disk/storage and file-output, network, credential, memory, CPU,
> process-count, syscall, and privilege access.
> The bounded supervisor described below is not that sandbox.

## Exact-eight capture

The positional argument must name `manifest.json`. Its directory must contain
exactly these eight direct entries:

1. `manifest.json`;
2. `pinout.h`;
3. `firmware.h`;
4. `firmware.c`;
5. `firmware_smoke_test.c`;
6. `firmware.cpp`;
7. `firmware_cpp_smoke_test.cpp`; and
8. `host.py`.

The directory, its ancestors, and every entry must be free of symbolic links;
all eight entries must be nonempty regular files. The manifest is limited to
4 MiB and each source artifact to 16 MiB. pcbex requires the closed manifest-v2
shape, the exact ordered seven-artifact descriptor set, and every declared byte
count and lowercase SHA-256 to match the captured source. Historical command
arrays remain validated manifest evidence, but this verifier never executes
them. A source-only manifest whose historical records say `attempted: false`
can therefore still receive an approved fresh report.

Regular hardlinks remain allowed and are content-bound by the bytes and
SHA-256 observed through each fixed name. pcbex does not require distinct
inodes or link count one, so two fixed names or an outside pathname may alias
the same regular file. A write through such an outside alias fails closed only
when a capture or final-reread checkpoint observes the changed content.

Capture brackets the reads with exact directory enumeration and retains a
directory identity handle. Immediately before report publication, pcbex
reopens the complete exact-eight bundle and requires every filename and byte to
equal the initial capture. Added, removed, replaced, or content-mutated input
observed at either checkpoint is a hard failure with no report. These checks
are sequential change detection, not an atomic snapshot against another
process with the same OS principal that changes and restores paths or content
between them. On Unix, capture opens each fixed entry relative to the pinned
directory with no-follow and nonblocking flags, then requires a regular-file
identity and two identical bounded passes; a leaf symlink or FIFO replacement
observed at that boundary fails promptly. Non-Unix capture uses the shared
path reader and does not claim adversarial leaf link/special-file race or
blocking-open denial-of-service freedom. Neither platform prevents every
same-principal change-and-restore race. Use a private, isolated bundle directory
whose entries cannot be concurrently replaced. A mutation after the final
checkpoint can also make the caller-visible directory differ from the snapshot
after the report is published; the report binds the captured bytes, not the
later state of those pathnames.

## Six fixed fresh checks

`--cc`, `--cxx`, and `--python` select printable-ASCII bare executable names
resolved through `PATH`; defaults are `cc`, `c++`, and `python3`. Host paths and
path separators are rejected. The retained manifest argv cannot replace these
selections or add arguments.

The report always carries six checks in this order:

| Name | Fresh operation |
| --- | --- |
| `c_compile` | Compile and link the captured C sources with the fixed strict C11 warning/error flags |
| `c_smoke` | Execute the freshly produced C smoke binary |
| `cpp_compile` | Compile and link the captured C++ sources with the fixed strict C++17 warning/error flags |
| `cpp_smoke` | Execute the freshly produced C++ smoke binary |
| `python_compile` | Run the selected interpreter with `-m py_compile host.py` |
| `python_self_test` | Run the selected interpreter with `host.py --self-test` |

With the defaults on POSIX, the path-free command evidence is exactly:

```text
cc -std=c11 -Wall -Wextra -Werror -pedantic -I . firmware.c firmware_smoke_test.c -o .pcbex-firmware-c-smoke
./.pcbex-firmware-c-smoke
c++ -std=c++17 -Wall -Wextra -Werror -pedantic -I . firmware.cpp firmware_cpp_smoke_test.cpp -o .pcbex-firmware-cpp-smoke
./.pcbex-firmware-cpp-smoke
python3 -m py_compile host.py
python3 host.py --self-test
```

Windows adds `.exe` to the two output names and records the smoke commands as
`.\.pcbex-firmware-c-smoke.exe` and
`.\.pcbex-firmware-cpp-smoke.exe`. Process creation resolves each new smoke
binary to its exact private absolute path, but that private path is not retained
in evidence. The generated report schema consequently carries target-specific
smoke-command constants under the same semantic `$id`; schema bytes are not a
POSIX-to-Windows portability promise.

A failed C, C++, or Python compile check leaves its dependent smoke/self-test
unattempted with `dependency_failed`; the unrelated language families
continue. Each check has
exactly `name`, path-free `command`, `attempted`, `passed`, `exit_code`, and
`failure` fields. A successful check has exit code zero and a null failure. A
negative failure is exactly one of `dependency_failed`, `exit_failure`,
`missing_output`, `spawn_failure`, `timeout`, `stdout_limit`, `stderr_limit`, or
`supervision_failure`. It is retained as a typed outcome rather than being
confused with approval. `supervision_failure` is retained only for a post-spawn
setup or pipe-read failure after the bounded runner has successfully cleaned
and reaped the child or already observed its completion. Cancellation, invalid
core timeout, and wait/cleanup/reap failure are hard errors with no report.

`--timeout-seconds` selects a 1–3600 second deadline per attempted process and
defaults to 120. Standard output and standard error are drained concurrently,
with a 1 MiB limit for each stream of each child. The next byte, timeout,
cancellation, or process-control failure triggers termination and reaping of
ordinary managed children and descendants. Children are launched without a
shell in a private workspace containing only captured bundle content and
transient build products.

Those controls limit ordinary managed execution; they do not isolate it or
make OS waits and uninterruptible I/O strictly deadline-preemptible. A
compiler, smoke binary, or `host.py` can read or modify accessible host files,
use credentials or the network, and start other processes before cleanup. Unix
session escape and equivalent detached or privilege-escaping behavior remain
outside the ordinary managed-descendant cleanup guarantee. The stream limits
do not cap compiler outputs, Python bytecode, arbitrary private-stage files, or
aggregate disk/storage consumption; hostile code can exhaust storage before a
deadline is observed.

## Closed report and gate ordering

The Draft 2020-12 schema ID is
`https://github.com/penguin425/pcbex/schemas/fresh-firmware-bundle-build-v1.json`.
The report is pretty JSON with a final LF, is limited to 1 MiB, and has exactly
these ordered top-level fields:

1. `schema_version`: `1`;
2. `scope`: `fresh_firmware_bundle_build_v1`;
3. `engine_version`;
4. `bundle`;
5. `process_limits`;
6. `checks`;
7. `toolchain_provenance_verified`: always `false`; and
8. `approved`.

`bundle.manifest` records the byte count and SHA-256 of the exact captured
manifest. `bundle.manifest_schema_version` is `2`, `schematic_sha256` copies the
syntactically validated manifest field, and the ordered artifact descriptors
retain only each fixed relative `path`, byte count, and SHA-256. The verifier
has no schematic input: it neither recomputes canonical IR nor establishes that
the declaration binds any particular schematic. `process_limits`
records `timeout_seconds`, `stdout_bytes: 1048576`, and
`stderr_bytes: 1048576`. No caller directory, temporary directory, absolute
executable path, or other host path is serialized. `approved` is true exactly
when all six fresh checks passed.

The JSON Schema is a closed structural contract, not an approval engine.
Runtime construction and validation remain authoritative for duplicate-free
JSON, per-file and aggregate byte ceilings, exact bundle identities, fixed and
same-tool command relationships, dependency pairing, check-state invariants,
and `approved == all six passed`. A fabricated document can satisfy the schema;
schema validation alone is not authenticated fresh verification evidence.

With no `--output`, the complete LF-terminated report is written to standard
output. With `--output`, the destination parent must already exist, the path
must be symlink-free, new, non-aliased, and outside the bundle directory; pcbex
publishes the report atomically without overwrite. Output preflight occurs
before input-selected work. A valid negative build result is published before
`--require-approved` returns nonzero, so that flag is only a post-retention
gate. Atomic destination-file publication is not one transaction with the
caller-owned input capture.

Malformed, duplicate-key, symbolic-link or
junction/name-surrogate-reparse-point, special, missing, extra, empty,
oversized, descriptor-mismatched, or observed-mutated input produces no report.
An unsafe, aliased, stale, or existing output also produces no report.
The reusable core verifier treats cancellation and ambiguous child
cleanup/reaping as hard errors and returns no report object; the standalone CLI
exposes no cancellation option. External termination of the CLI likewise must
not be interpreted as retained verification evidence.

## Platform regression scope

The existing release-mode boundary matrix runs this focused integration suite
once on macOS and once on Windows, with runner-provided GNU `gcc`/`g++` and
`python` selected on Windows. Both hosts exercise the closed schema, real fresh checks, hash
rejection, missing-tool retention, exact-eight failures, no-clobber output,
rejected-report retention, and schema publication. Timeout and
link/special-file cases are Unix-only; the concurrent final-reread mutation
case is Linux-only. Version 1.466 adds no Windows Job Object cleanup or
descendant-cleanup runtime regression, so the cross-platform suite must not be
read as that coverage claim.

## Separation and nonclaims

This report is new, separate evidence. Version 1.466 does not change firmware
manifest v2, deterministic plan/report schema v1, pipeline report v1/v2, or any
fabrication approval, authorization, or reservation schema or serialized byte
contract. `pipeline-verify`, the deterministic runner, and fabrication
authorization do not invoke or consume this report. There is no MCP tool,
composite Action input/output, or pipeline/fabrication phase for this command.

An approved report means only that the captured sources passed these six local
checks under the selected executable names and recorded process limits. It does
not authenticate the bundle producer or pcbex executable. A manifest and its
matching artifact digests can be forged together. The report does not attest
compiler, interpreter, or toolchain provenance, establish reproducibility
across runs or hosts, prove cross-compilation or target MCU behavior, validate
electrical or hardware safety, or authorize pipeline approval, fabrication,
procurement, reservation, submission, ordering, payment, or deployment.
