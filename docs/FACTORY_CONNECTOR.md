# Factory quote and DFM connector

`pcbex factory-submit <manufacturing.zip> --provider <jlcpcb|pcbway|generic>
--endpoint <https-url> --output receipt.json` sends a factory-ready ZIP to a
configured adapter endpoint. The endpoint is intentionally supplied by the
deployment: JLCPCB and PCBWay change their authentication and quote APIs, so
pcbex does not embed credentials or pretend that one undocumented URL is stable.

The request is a bounded raw ZIP upload with these headers:

- `X-PCBEX-Adapter` (`jlcpcb-http-v1`, `pcbway-http-v1`, or
  `generic-factory-http-v1`);
- `X-PCBEX-Schema-Version: 1`; and
- `X-PCBEX-Package-SHA256`.

HTTPS is required. HTTP is accepted only for loopback test endpoints with the
hidden `--allow-http-loopback` flag. Bearer tokens are read from the named
environment variable and are never written to the receipt. Redirects are
disabled, endpoint query strings/userinfo are rejected, package uploads are
limited to 128 MiB, and responses to 8 MiB. Before network access, pcbex opens
the package once and verifies the schema-v1 `manifest.json`, safe and unique ZIP
entry names, every declared artifact's byte count and SHA-256, a 4,096-entry
ceiling, and a 512 MiB expanded-artifact ceiling. Missing, unlisted, duplicate,
or self-referential entries fail closed.

The adapter accepts a provider response such as:

```json
{
  "status": "quoted",
  "dfm_passed": true,
  "quote": {"total": 12.50, "currency": "USD", "lead_time_days": 5},
  "dfm_findings": []
}
```

It writes a deterministic receipt containing request/response SHA-256 digests,
HTTP status, normalized quote/DFM status, sorted findings, and the raw JSON
response. `--require-dfm-pass` turns the receipt into a manufacturing gate and
fails unless the HTTP response is successful, `accepted` and `dfm_passed` are
both explicitly true, and every finding has a known non-fatal severity
(`info`, `notice`, or `warning`). Unknown or error/critical/fatal severities fail
closed. A non-2xx response is a transport failure and does not produce a
receipt; deployment adapters should return normalized DFM rejection evidence in
a successful JSON response. Receipt and schema outputs are atomically published
with no-overwrite semantics, so an existing regular file or symlink fails
closed and a failed submission leaves no partial output.

Use `pcbex factory-schema` to obtain the closed receipt JSON Schema for CI
artifacts. `pcbex capabilities` advertises both the HTTPS integration and the
versioned receipt contract for automated discovery.

## Bounded DFM repair loop

For an autonomous repair workflow, use `factory-feedback-loop`. It submits the
current ZIP, invokes an optional repair executable when the response fails DFM,
and resubmits the repaired ZIP for at most four attempts:

```text
pcbex factory-feedback-loop manufacturing.zip \
  --endpoint https://factory.example/api/quote \
  --provider jlcpcb \
  --repair-command ./repair-dfm \
  --output factory-loop.json \
  --final-receipt factory-receipt.json \
  --final-package manufacturing-final.zip
```

The repair executable is launched directly (no shell) with stdout/stderr
discarded and a ten-minute wall-clock limit. It receives the normalized failed
receipt as JSON on stdin and these environment variables:

- `PCBEX_FACTORY_REPAIR_INPUT_PACKAGE`: current ZIP path (read-only);
- `PCBEX_FACTORY_REPAIR_OUTPUT_PACKAGE`: path where the next ZIP must be written;
- `PCBEX_FACTORY_REPAIR_RECEIPT_JSON=stdin`: identifies the receipt transport.

The output must be a non-empty ZIP no larger than 128 MiB. A missing output,
non-zero exit, timeout, or invalid package stops the loop and records the
failure. `factory-feedback-loop-schema` prints the closed report schema. The
report contains every bounded attempt and `--final-receipt` writes the last
receipt in the format accepted by the pipeline factory gate. Use
`--final-package` when the repaired ZIP must be handed to a later fabrication
or pipeline step; the temporary working files are always removed.
