# Full hardware pipeline gate

The individual commands intentionally produce inspectable artifacts. The final
gate is:

```text
pcbex pipeline-verify \
  --electrical-review build/electrical-review.json \
  --analysis-manifest build/analysis/run.json \
   --quality build/routed/quality.json \
   --manufacturing-manifest build/manufacturing/manifest.json \
   --firmware-manifest build/firmware/manifest.json \
   --factory-receipt build/manufacturing/factory-receipt.json \
   --require-factory \
   --output build/pipeline.json
```

It verifies five phases in order:

1. **electrical-erc** — the review is approved and has zero error findings;
2. **analysis-drc** — the analysis manifest reports a clean board and zero
   violations;
3. **routing-quality** — no unrouted nets remain;
4. **manufacturing-package** — BOM/CPL/DRC report and ZIP exist, every
   manifest artifact uses a safe relative path, and every SHA-256 matches; and
5. **firmware-build** — generated C, C++, and Python gates passed and all
   declared source artifacts exist; and
6. **factory-dfm** — the quote/DFM receipt is accepted, explicitly passed,
   contains no severe findings, uses HTTPS, and its package digest/size matches
   the manufacturing ZIP.

`--require-factory` makes the sixth phase mandatory. Without it, the command
retains the backward-compatible five-phase behavior when no receipt is supplied.
When a receipt is supplied, the factory phase is always checked.

The command always writes a phase-by-phase report. It exits nonzero after the
report is written if any phase is missing, tampered with, or rejected. This
keeps the final decision independent from terminal output and makes the gate
safe to run as a required GitHub Actions check. `pcbex pipeline-schema` emits
the report schema.
