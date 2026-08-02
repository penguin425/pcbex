# Manufacturing package

`pcbex fabricate <board.kicad_pcb> --output-dir <directory>` is the headless
manufacturing gate. It first runs KiCad DRC and stops on any DRC violation;
only then are manufacturing artifacts published.

The board and adjacent same-stem `.kicad_pro`/`.kicad_dru` inputs are copied to
a private staging directory before KiCad is started. This preserves project
DRC context without writing `.kicad_prl` or DRC sidecars beside the source.
Gerber layers are derived from the validated KiCad layer table: every declared
copper layer, front/back paste, mask and silkscreen, plus `Edge.Cuts`. Four-layer
and larger boards therefore retain every inner copper plane. KiCad may omit an
empty optional layer (for example `F.Paste`/`B.Paste`) from its export; such an
omission is not an error, while a declared copper layer and `Edge.Cuts` remain
mandatory.

The command emits the KiCad Gerber and Excellon files plus:

- `bom.csv`: grouped, deterministic BOM rows (`Comment`, `Designator`,
  `Footprint`, `Quantity`, `MPN`, `Layer`, and `Type`);
- `cpl.csv`: surface-mount pick-and-place rows with absolute board coordinates
  in millimetres and milli-degree precision rendered as decimal degrees;
- `drc.rpt`: the KiCad DRC report; this artifact is mandatory even when the
  report contains zero violations;
- `manifest.json`: schema version, pcbex/KiCad versions, board and project-input
  digests, component counts, and SHA-256 digests for every exported artifact;
  and
- `manufacturing.zip`: a sorted archive containing the generated directory
  files (the archive itself is intentionally excluded to avoid a hash cycle).

KiCad embeds wall-clock creation times in DRC, Gerber, Gerber-job, and drill
files. pcbex replaces only those volatile timestamp fields with a fixed epoch;
the exact KiCad CLI build version and a SHA-256 fingerprint of its `about`
report remain in the manifest. With identical input bytes, filenames, pcbex
version, and KiCad build, `manufacturing.zip` is byte-for-byte reproducible.
The ZIP uses sorted names, fixed entry metadata, and contains `manifest.json`;
the manifest's artifact array intentionally omits itself and the archive.

Generation occurs entirely in the private stage. Contents of files already
present in the requested output directory are never read or added to the
manifest/ZIP, and unrelated files are left untouched. A destination path or
any parent component that is a symlink is rejected before KiCad or private
staging is started. A generated manufacturing filename left by a previous run
but absent from the current staged set (for
example an obsolete inner-copper Gerber) is treated as stale and causes the
command to fail; use a fresh, dedicated output directory. Current generated
filenames are replaced only after every destination is preflighted and copied
to a temporary regular file.

For manufacturing upload, treat `manufacturing.zip` as the canonical package
boundary. The sibling files are useful for inspection and review, but the ZIP
is the reproducible, hash-bound artifact to submit to a fabrication service.

Component metadata is read from KiCad `property` fields and legacy `fp_text`
fields. `Reference` and `Value` are required for a manufacturing row. `MPN`,
`LCSC`, `JLCPCB`, `DigiKey`, and equivalent normalized property names are
accepted as manufacturer-part-number aliases. KiCad
`exclude_from_bom`/`exclude_from_pos_files`, `DNP`, and `Do Not Populate`
markers are honored deterministically. Duplicate aliases are rejected rather
than resolved by order. A footprint identifier and reference are mandatory,
and populated BOM rows must also have a non-empty value. Common fields such as
`LCSC Part #` and `JLCPCB Part #` are normalized as MPN aliases.

Coordinates in `cpl.csv` are the original KiCad board coordinates, rather than
the normalized coordinates used internally by the router. The contract uses
the board origin, does not negate bottom-side X, preserves the footprint's
stored rotation, and writes `F`/`B` as the side. Factory-specific origin,
bottom-rotation, and axis transformations must be applied by a DFM/factory
profile before upload; the vendor-neutral CPL must not be assumed to match
every assembler's convention.
