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
limited to 128 MiB, and responses to 8 MiB.

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
fails unless `dfm_passed` is explicitly true and no error/critical/fatal finding
is returned.

Use `pcbex factory-schema` to obtain the receipt JSON Schema for CI artifacts.
