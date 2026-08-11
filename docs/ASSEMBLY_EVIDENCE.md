# Exact per-board assembly evidence composition

Version 1.467 adds one Python-only composition boundary for evidence that was
previously verified separately. It freshly reproduces the exact schema-v6
circuit-handoff/manufacturing chain, semantically replays one retained offline
procurement intent from the generation entry inside that handoff and the
supplied historical catalog snapshot, and byte-replays one retained final-CPL
report against the same board and manufacturing package.

Run the composer and emit its closed Draft 2020-12 schema with:

```sh
PYTHONPATH=agent/src python3 -m pcbex_agent build-assembly-evidence \
  circuit-handoff.zip board.kicad_pcb manufacturing.zip \
  --board-binding-report board-binding.json \
  --procurement-intent procurement-intent.json \
  --catalog-snapshot catalog-snapshot.json \
  --final-cpl-report final-cpl.json \
  --pcbex target/release/pcbex \
  --manufacturing-kicad-cli kicad-cli \
  --output assembly-evidence.json \
  --require-complete

PYTHONPATH=agent/src python3 -m pcbex_agent assembly-evidence-schema \
  --output assembly-evidence-v1.schema.json
```

The optional manufacturing replay inputs are the same explicit inputs as the
schema-v6 handoff replay: `--board-binding-policy`,
`--manufacturing-kicad-project`, `--manufacturing-kicad-rules`, and at most one
of `--manufacturing-fab`, `--manufacturing-fab-profile`, or
`--manufacturing-physical-profile`. Optional
`--expected-handoff-archive-sha256` and
`--expected-handoff-bundle-sha256` values provide the existing external
handoff identity roots. `--timeout-seconds` defaults to 120 and accepts a
finite value from 1 through 600.

The Python API exposes `evaluate_assembly_evidence` and its artifact-oriented
alias `build_assembly_evidence`. `validate_assembly_evidence` reruns the whole
evaluation and requires the supplied retained result to match. A retained path
or bytes-like report must be the canonical pretty JSON encoding with exactly
one final LF and match byte-for-byte; a Mapping input is accepted as a bounded
semantic snapshot and is compared with strict JSON types and values.
`assembly_evidence_json_schema` returns the structural schema. Hard boundary
failures use `AssemblyEvidenceError`.

## Evaluation order

The composer freezes and boundedly captures every caller path before native
execution. It then performs these operations under one aggregate monotonic
deadline:

1. It invokes the existing handoff replay with the complete board-binding and
   manufacturing inputs. Success must be the closed schema-v6
   `deterministic-electrical-handoff-chain-manufacturing-package-replay-v6`
   result: the canonical handoff archive, retained board-binding report, and
   retained manufacturing ZIP have all been freshly reproduced.
2. It takes the exact `generation-bundle.json` bytes from the verified handoff
   archive, rather than accepting a separate generation path. Together with
   the captured board, package, supplied snapshot, and retained procurement
   intent, those bytes are passed through the complete v1.464 semantic
   procurement replay. The complete fresh result must equal the retained
   procurement-intent object.
3. It freshly invokes the final-CPL verifier for the same captured board and
   package. The complete closed report, including its final line feed, must
   equal the retained final-CPL bytes exactly.
4. It validates the complete nested contracts, enforces the shared identities,
   computes the informational BOM/CPL membership partition, and constructs and
   domain-binds the compact result. It then rereads the full staged-source
   union, takes one bounded result snapshot and runtime-validates/renders that
   snapshot under the output ceiling, and finally rereads every direct
   caller-visible source before the caller can receive or publish the result.

All child execution is direct and shell-free. Temporary generation, child
reports, and manufacturing outputs stay in private workspaces. A child
failure, malformed or noncanonical child result, report mismatch, identity
mismatch, deadline or cleanup failure, unsafe input, or observed source
mutation is a hard failure with no assembly-evidence report.

## Exact cross-bindings

Composition is stricter than placing three valid reports next to each other.
The runtime validator requires the exact shared board and manufacturing-package
byte/SHA-256 identities to agree throughout the schema-v6 manufacturing replay,
procurement intent, and final-CPL report. It also requires:

- the procurement replay's generation source to be the exact handoff archive
  `generation-bundle.json` entry;
- the package manifest identity carried through the procurement and final-CPL
  reports to agree;
- both focused reports' package-board-source identities to agree with each
  other; equality between that retained package identity and the exact captured
  board remains the corresponding child approval condition, so a truthful
  source-mismatch rejection can still be composed; and
- every retained field to satisfy its closed full or compact shape and every
  self-contained correlation enforced by the outer runtime validator.

Raw child-source authenticity and correlations omitted with the compact
projections cannot be recovered from the composed object alone. They are
established only when `evaluate_assembly_evidence` freshly constructs the
result or `validate_assembly_evidence` freshly replays a retained one.

The catalog snapshot is intentionally a procurement-only historical input. It
is replayed and identified inside the procurement evidence, but there is no
second catalog identity in the handoff-manufacturing or final-CPL children to
cross-bind. The package manifest's input filename is likewise not elevated to
an identity: source binding uses bytes and SHA-256, and the assembly result
does not claim a manifest-filename match.

## Result and completion decision

The closed path-free result uses schema version 1 and scope
`offline-exact-board-assembly-evidence-v1`. Its top level retains the exact
nested `circuit_manufacturing` and `final_cpl` evidence, validated compact
`final_bom` and `procurement` projections, direct source identities, a BOM/CPL
`membership` partition, stable `findings`, completed `validation` flags, and a
domain-separated `binding_sha256`. Construction still freshly validates and
semantically replays the full procurement object and its complete nested
final-BOM report before those compact outer projections are formed.

The closed `sources` object contains exact identities for
`circuit_handoff_bundle`, its extracted `handoff_generation_bundle`, `board`,
`manufacturing_package`, `board_binding_report`, the retained
`procurement_intent`, `catalog_snapshot`, and retained `final_cpl_report`.
Only the portable board basename accompanies its identity; no catalog basename
or host path is retained.

The compact `final_bom` projection deliberately omits `in_bom_parts`, and the
compact `procurement` projection deliberately omits its nested `final_bom` and
original `binding_sha256`; that original digest covered the omitted object and
would not be recomputable from the projection. The exact raw procurement
source identity, full fresh semantic replay, and new outer `binding_sha256`
preserve the evidence relationship without retaining a misleading inner
digest.
The compact BOM/procurement projections retain populated BOM references only
through the membership arrays and, for an approved procurement decision, the
grouped procurement line references. The exact nested `final_cpl` separately
retains its original in-position reference and coordinate records. The outer
artifact therefore does not claim to retain standalone final-BOM per-reference
value, footprint, MPN, layer, or type records; consumers needing those records
must separately retain and freshly validate the original procurement-intent
artifact.

`quantity_basis` is always `per_board`. The safety/authority fields
`assembly_ready`, `assembly_authorized`, `fabrication_authorized`,
`procurement_authorized`, `order_placed`, `adapter_network_performed`, and
`machine_operation_performed` are always false. These constants prevent a
consumer from confusing complete evidence composition with an operational
permission or side effect.

`complete` is true exactly when all three decision-bearing children are
positive:

- the freshly reproduced board-binding decision is approved;
- the freshly replayed procurement intent is approved; and
- the byte-replayed final-CPL report is approved.

The manufacturing replay itself must always verify exactly; it has no separate
fabrication or assembly approval decision. A valid negative child decision is
retained as `status: "incomplete"` evidence. `--require-complete` is a final
gate: the complete no-clobber report is published before the command exits
unsuccessfully. Malformed, forged, cross-boundary-inconsistent, or mutated
inputs are not truthful incomplete evidence and produce no output.

The `membership` object deterministically partitions populated BOM references
and in-position CPL references into the reference-sorted `both`, `bom_only`,
and `cpl_only` arrays. That partition is informational and never a completion
gate. In particular, pcbex does not require the CPL reference set to be a BOM
subset: DNP, mechanical, through-hole, and placement-excluded semantics make
that inference invalid without an explicit assembly policy. Consumers must not
reinterpret membership categories as missing-part findings or assembly
readiness.

An incomplete result has the exact applicable subset of lexicographically
sorted `board_binding_rejected`, `procurement_intent_rejected`, and
`final_cpl_rejected` findings. These findings mirror authenticated child
decisions; they do not turn a child semantic rejection into a hard composition
failure. A complete result has no findings.

## Bounds, publication, and schema authority

The composer retains the source ceilings of every nested verifier, including
the 224 MiB handoff archive, 128 MiB board and manufacturing ZIP, 12 MiB plus
one final line feed for the board-binding report, 4 MiB optional board-binding
policy, 16 MiB procurement-intent and final-CPL reports, 4 MiB catalog snapshot,
and the existing manufacturing project/rules/profile limits. All caller source
bytes share a 768 MiB aggregate ceiling. A result is limited to 32 MiB. At most
256 populated BOM references enter the membership partition and approved
procurement line references, and at most 256 CPL references enter the retained
final-CPL evidence and membership partition.

The caller-selected pcbex command and complete injected argv are limited to
256 arguments and 32,768 aggregate UTF-8 bytes. Child stdout and stderr are
independently capped at 1 MiB. Windows additionally enforces the existing
32,767-UTF-16-unit rendered-command ceiling. The outer deadline includes
capture, archive parsing, every child and nested reserve, exact comparison,
cross-binding, cleanup, final caller rereads, result construction, and the
last success check.

Inputs must be distinct, nonempty stable regular files accepted by the shared
Python bounded reader; direct and lexical-ancestor symbolic links and Windows
reparse components are rejected by that boundary. `--output` is required and
is an atomic no-clobber destination; an existing path, input/output alias, or
unsafe parent topology is rejected. Capture and final rereads are sequential
change detection, not an atomic multi-input snapshot. A same-principal process
may change and restore bytes between observations; use an independently
protected immutable snapshot when that race matters.

The emitted JSON Schema is a closed structural contract. The public
`render_assembly_evidence` helper takes one bounded semantic snapshot and
validates the retained closed shapes, types, sorting, self-contained
cross-field identities, completion invariants, binding digest, and the
reconstructible full final-CPL report identity before canonical rendering. It
cannot authenticate opaque raw handoff/procurement/final-BOM identities whose
bytes or complete objects are not retained, reproduce child tools, restore
omitted correlations, or prove producer authenticity. Fresh
`evaluate_assembly_evidence` or `validate_assembly_evidence` replay remains
authoritative for equality to the caller's source bytes, exact child report
bytes, complete child runtime contracts, omitted correlations, aggregate
input/deadline checks, and final source rereads. Neither operation authenticates
the selected producers or toolchain. Passing the schema or standalone renderer
alone is not complete assembly evidence.

## Deliberate nonclaims

This result composes exact per-board technical evidence. It does not establish
assembly readiness or authorize assembly, manufacturing, fabrication,
procurement, ordering, payment, or spend. It does not multiply a batch, panel,
build, yield, spare, loss, or order quantity; every procurement quantity remains
the retained per-board populated-reference count.

It does not prove that BOM and CPL memberships form a required subset or a
complete assembly population. It does not establish polarity, fiducials,
panelization, a vendor origin/axis/bottom-side/rotation transform, feeder or
nozzle selection, machine programming, or machine operation. No current stock,
price, lead time, lifecycle, reservation, manufacturer/supplier authenticity,
datasheet truth, or transport provenance is checked, and the adapter itself
makes no network request or external order/payment call.

The supplied pcbex and KiCad commands are unauthenticated and unsandboxed.
Shell-free argv, byte/time limits, private staging, and managed process cleanup
are not producer or toolchain provenance and are not a CPU, memory, filesystem,
network, syscall, credential, or privilege sandbox. Deliberate child escape is
outside the process-tree claim. Firmware generation, firmware build evidence,
and pipeline composition are not part of this result.

See [Circuit handoff bundle](CIRCUIT_HANDOFF_BUNDLE.md), [final BOM and
procurement intent](PROCUREMENT_INTENT.md), [final CPL](FINAL_CPL.md), and
[bounded Python execution](PYTHON_AGENT_LIMITS.md) for the authoritative child
contracts that this boundary composes.

Version 1.468 deliberately evaluates
[offline supplier-offer coverage](SUPPLIER_OFFER_COVERAGE.md) from the original
procurement intent and its four replay sources rather than from this compact
composition. A later consumer may correlate the two through their exact
procurement-intent source identity and identical compact procurement
projection; v1.468 does not alter this report or make it an offer, price,
current-stock, or procurement-authority artifact.

Version 1.470 adds the separate [exact assembly and acquired supplier-offer
evidence composition](ASSEMBLY_SUPPLIER_OFFER_EVIDENCE.md). That outer
boundary does not trust this compact result by digest alone: it freshly runs
`validate_assembly_evidence` against the original handoff, board, package,
board-binding report, intent, snapshot, and final-CPL sources from one private
staged union. It then requires this compact procurement projection and the
exact raw intent identity to equal the independently replayed v1.468 coverage
child. This schema and its canonical bytes remain unchanged.
