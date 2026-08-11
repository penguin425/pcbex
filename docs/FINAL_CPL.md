# Exact final CPL verification

Version 1.465 adds a narrow offline boundary for proving that one completely
validated manufacturing package contains the canonical pick-and-place file for
one exact KiCad board source:

```sh
pcbex verify-final-cpl \
  board.kicad_pcb manufacturing/manufacturing.zip \
  --output final-cpl.json \
  --require-approved

pcbex final-cpl-report-schema --output final-cpl-report-v1.schema.json
```

`verify-final-cpl` invokes no KiCad process and performs no network request. It
stable-reads the board and ZIP, applies the complete manufacturing-package
validator, imports the board's manufacturing parts, and regenerates `cpl.csv`
with the same plan and byte renderer used by `fabricate`. Approval requires both:

1. the regenerated canonical CPL bytes equal the package's `cpl.csv` bytes; and
2. the supplied board byte count and SHA-256 equal the package manifest's input
   byte count and SHA-256.

This composes exact board-to-package source identity with exact canonical
placement bytes. It is stricter than comparing parsed decimal values: a row
order, quoting, line-ending, precision, designator, coordinate, rotation, or
side difference remains a canonical CPL mismatch.

## Report contract

The path-free report has schema version 1 and scope
`final_cpl_source_and_canonical_placement_v1`. Its top-level keys are exactly:

- `schema_version`, `scope`, `engine_version`, and informational
  `board_basename`;
- `sources`;
- `counts`;
- `in_pos_parts`;
- `findings`; and
- `approved`.

`sources` records exact byte-count/SHA-256 identities for:

- `board`;
- `manufacturing_package`;
- the validated `manifest` bytes;
- the package's actual `cpl` bytes;
- the freshly regenerated `canonical_cpl` bytes; and
- `package_board_source`, copied from the manifest's input descriptor.

`counts` contains `board_parts`, `board_in_pos_parts`, `package_parts`,
`package_placement_parts`, and `findings`. `in_pos_parts` contains at most 256
entries sorted by strict reference order. Each entry is the exact closed object
`{reference, x_nm, y_nm, rotation_mdeg, layer}`: X/Y use signed integer
nanometres, rotation uses signed integer milli-degrees, and layer is `F` or `B`.
The inventory is extracted from the supplied board, while the package CPL is
represented by its exact identity and canonical byte comparison.

The only finding codes are:

- `canonical_cpl_mismatch`; and
- `package_board_source_mismatch`.

Findings are stable and sorted, `counts.findings` equals their length, and
`approved` is true exactly when neither finding is present. The board basename
is informational. The package manifest's recorded input filename is neither
reported nor compared; source approval uses exact byte count and SHA-256.

## Placement selection and coordinates

The verifier uses the existing manufacturing-part interpretation. A footprint
appears in `in_pos_parts` and canonical `cpl.csv` only when it is surface mount,
is not DNP, and is not marked `exclude_from_pos_files`. BOM inclusion is an
independent property: CPL designators are not required to be a BOM subset.

Coordinates are the KiCad footprint's original absolute board coordinates,
converted to exact integer nanometres by the existing bounded importer. Rotation
is the stored footprint rotation converted to integer milli-degrees. The
canonical renderer sorts by reference and emits millimetre X/Y, decimal-degree
rotation, and `F`/`B` side under the existing vendor-neutral convention: it does
not negate bottom-side X or invent another board origin.

The complete package validator independently requires the exact CPL header,
unique nonempty references, finite checked decimal coordinate/rotation fields,
`F`/`B` layers, and a placement-row count equal to the manifest. Exact canonical
byte equality then binds that validated package row set and serialization to the
supplied board's complete in-position inventory.

## Retained mismatch and hard errors

A fully valid package whose canonical CPL or board-source identity differs is a
truthful semantic rejection. Without `--require-approved`, the command emits or
publishes that report and exits successfully. With the gate, it publishes the
same report first and then exits nonzero. This keeps reviewable mismatch evidence
without treating it as approval.

A malformed, unsafe, oversized, linked, aliased, or concurrently changed input
is a hard error and publishes no report. `--output` must name a new regular-file
destination: existing files, links, input aliases, and unsafe parent topology are
rejected. Omitting it emits the same bounded pretty JSON plus one final LF to
standard output.

The board and package are each nonempty and capped at 128 MiB. The manufacturing
ZIP retains the complete 4,096-entry, 512 MiB expanded-payload, 1 MiB manifest,
100,000-part, classic-ZIP, portable-name, and semantic BOM/CPL limits. No more
than 256 board in-position references enter this focused report; each retained
reference is capped at 4,096 UTF-8 bytes and rejects NUL. The report is capped
at 16 MiB. Runtime checks are authoritative for UTF-8 byte and aggregate limits,
source identities, canonical rendering, sorting, and cross-field invariants;
the Draft 2020-12 JSON Schema is the closed structural contract.

Inputs are captured before validation and reread immediately before optional
publication. This detects a replacement or byte change observed at those
sequential checkpoints, but it is not an atomic multi-input snapshot. A process
running as the same principal can change and restore bytes between observations;
use an OS-enforced immutable snapshot or separately trusted workspace when that
race is in scope.

## Explicit nonclaims

The report proves only the exact board/source and canonical vendor-neutral CPL
relationship described above. It does not prove that a circuit, schematic,
placement optimizer, or human author selected or approved the coordinates. It
does not authenticate the pcbex binary, KiCad, a footprint library, a vendor, or
a factory; prove connectivity, routing, clearance, DRC/DFM, manufacturability,
component polarity, fiducials, panelization, or assembly readiness; or apply a
vendor-specific origin, axis, bottom-side, rotation, panel, feeder, nozzle, or
machine transform.

The verifier does not operate assembly equipment, submit the package, contact a
supplier, reserve inventory, authorize fabrication or procurement, place an
order, make a payment, or spend funds. Those remain separate deployment-owned
boundaries.

Version 1.467 can byte-replay this complete retained report inside the separate
exact per-board [assembly-evidence composition](ASSEMBLY_EVIDENCE.md), using
the same captured board and manufacturing ZIP as its handoff/manufacturing and
procurement children. The composer requires the final-BOM and final-CPL
manifest identities to agree and separately requires their retained
package-board-source identities to agree. Equality between that package source
and the supplied board remains each child report's approval condition, so a
truthful source-mismatch rejection can remain visible. The informational
BOM/CPL reference partition does not require CPL membership to be a BOM subset
and does not establish assembly readiness.
