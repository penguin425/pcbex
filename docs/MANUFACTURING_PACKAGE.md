# Manufacturing package

`pcbex fabricate <board.kicad_pcb> --output-dir <directory>` is the headless
manufacturing gate. It first runs KiCad DRC and stops on any DRC violation;
only then are manufacturing artifacts written.

The command emits the KiCad Gerber and Excellon files plus:

- `bom.csv`: grouped, deterministic BOM rows (`Comment`, `Designator`,
  `Footprint`, `Quantity`, `MPN`, `Layer`, and `Type`);
- `cpl.csv`: surface-mount pick-and-place rows with absolute board coordinates
  in millimetres and milli-degree precision rendered as decimal degrees;
- `drc.rpt`: the KiCad DRC report when KiCad produced one;
- `manifest.json`: schema version, source digest, component counts, and SHA-256
  digests for every artifact; and
- `manufacturing.zip`: a sorted archive containing the generated directory
  files (the archive itself is intentionally excluded to avoid a hash cycle).

Component metadata is read from KiCad `property` fields and legacy `fp_text`
fields. `Reference` and `Value` are required for a manufacturing row. `MPN`,
`LCSC`, `JLCPCB`, `DigiKey`, and equivalent normalized property names are
accepted as manufacturer-part-number aliases. KiCad
`exclude_from_bom`/`exclude_from_pos_files`, `DNP`, and `Do Not Populate`
markers are honored deterministically.

Coordinates in `cpl.csv` are the original KiCad board coordinates, rather than
the normalized coordinates used internally by the router. This keeps the file
directly consumable by factory placement tooling.
