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
the real, non-symlink package file once and verifies the closed schema-v1
`manifest.json`, safe and unique ZIP entry names, non-empty descriptors, every
declared artifact's byte count and SHA-256, a 4,096-entry ceiling, and a 512 MiB
expanded-artifact ceiling. A complete package must contain BOM, CPL, DRC,
Excellon drill, and exactly one Gerber job. That job must bind every declared
copper layer plus profile, top/bottom mask, and top/bottom legend outputs;
unbound Gerbers and unsupported artifact classes fail closed. Missing,
unlisted, duplicate, or self-referential entries also fail closed.
The Gerber job must declare 2 to 32 copper layers, including `F.Cu` and
`B.Cu`; all intermediate layers are allowed when each one is explicitly bound.

The adapter accepts a provider response such as:

```json
{
  "status": "quoted",
  "accepted": true,
  "dfm_passed": true,
  "quote": {"total": 12.50, "currency": "USD", "lead_time_days": 5},
  "dfm_findings": []
}
```

It writes a deterministic receipt containing request/response SHA-256 digests,
HTTP status, normalized quote/DFM status, sorted findings, and the raw JSON
response. The adapter must explicitly return `accepted: true`; status text is
never treated as acceptance. A response that reflects the configured Bearer
token anywhere in its raw or decoded JSON is rejected before any receipt or
repair input can be created. `--require-dfm-pass` turns the receipt into a
manufacturing gate and fails unless the HTTP response is successful,
`accepted` and `dfm_passed` are both explicitly true, and every finding has a
known non-fatal severity
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

Use `factory-feedback-loop` to resubmit DFM repairs produced by a trusted,
deployment-owned wrapper. The initial submission counts as one attempt;
`--max-attempts` may reduce the limit but cannot exceed four. The complete loop
has a 900-second deadline, and each direct repair child has a 600-second limit
that is also constrained by the remaining overall time:

```text
pcbex factory-feedback-loop manufacturing.zip \
  --endpoint https://factory.example/api/quote \
  --provider jlcpcb \
  --repair-command ./repair-dfm \
  --output factory-loop.json \
  --final-receipt factory-receipt.json \
  --final-package manufacturing-final.zip
```

The input is copied into a private temporary workspace and fully validated
before it becomes the first known-good package. Here, "known-good" means that
the ZIP and its manifest are structurally and cryptographically valid; it does
not mean that the factory has accepted its DFM. After each rejection, the
wrapper writes to a fresh candidate path. pcbex performs the complete
closed schema-v1 manifest, complete manufacturing artifact set, Gerber-job
layer binding, entry-name, entry-count, expanded-size, artifact-size, and
artifact-digest validation again before that candidate may replace the
known-good package or reach the network. The original input is never a repair
output or fallback target.

The wrapper is launched directly without a shell. pcbex concurrently drains
stdout and stderr up to 1 MiB each and discards the captured bytes after the
status decision. It receives the normalized failed receipt from a seek-rewound
temporary file on stdin and these environment variables:

- `PCBEX_FACTORY_REPAIR_INPUT_PACKAGE`: current ZIP path, which must remain
  unchanged;
- `PCBEX_FACTORY_REPAIR_OUTPUT_PACKAGE`: fresh path where the next ZIP must be
  written; and
- `PCBEX_FACTORY_REPAIR_RECEIPT_JSON=stdin`: identifies the receipt transport.

The wrapper inherits no caller environment. On Unix, pcbex adds only the three
protocol variables above, `PATH=/usr/bin:/bin`, and `LC_ALL=C`. On Windows, it
adds the protocol variables and a small process-launch allowlist
(`SYSTEMROOT`, `WINDIR`, `COMSPEC`, `PATHEXT`, `PATH`, `TEMP`, and `TMP`), while
case-insensitively excluding the name selected by `--bearer-token-env`.
Wrappers needing credentials, proxy settings, `HOME`, or other configuration
must obtain them through a deployment-owned mechanism rather than expecting
ambient inheritance. This is a narrow secret boundary, not a claim that
arbitrary repair programs are safe: the wrapper remains trusted deployment
code. On Unix the wrapper leads a fresh process group; on Windows it is assigned
to a kill-on-close Job Object immediately after spawn, which leaves a short
pre-assignment race. Timeout, output overflow, and direct-child completion
terminate and reap ordinary managed descendants. pcbex does not provide a full
OS sandbox: a Unix descendant can deliberately create another session, and CPU,
memory, filesystem, network, syscall, and privilege use remain outside this
boundary. Deploy it with appropriate operating-system identity, filesystem,
network, and process restrictions.

The wrapper must produce a complete, non-empty manifest ZIP no larger than 128
MiB. It cannot emit only changed Gerbers or copy a package and replace an
artifact without also rebuilding the ZIP's `manifest.json` sizes and SHA-256
digests. A missing output, input mutation, non-zero exit, timeout, output
overflow, or invalid candidate stops the loop and retains the last fully
validated package as the fallback.

After a successful wrapper exit, pcbex scans the complete private repair
workspace without following links. The same production manufacturing contract
limits it to 4,096 descendant entries, depth 16, 128 MiB per file and candidate
ZIP, 512 MiB expanded ZIP artifacts, 1 MiB manifests/Gerber jobs, 1 GiB total
bytes, and portable UTF-8 basenames of at most 255 bytes. Symlinks, sockets,
other non-regular entries, non-portable/colliding names, and a quota overage
reject the candidate before it can replace the last known-good package. This
scan occurs after the managed process has terminated; the operating-system
sandbox remains responsible for preventing live disk exhaustion or mutation
races during execution.

Once the initial package validates, submission, transport, repair, and
candidate-validation failures are captured in the closed loop report instead
of discarding the available evidence. `factory-feedback-loop-schema` prints
that report's closed JSON Schema. The report retains the bounded attempt
history and identifies the final known-good package. `--final-receipt` is
published only when the final submission produced a normalized receipt, so a
transport failure can legitimately produce a report and final package without
a final receipt. A non-passing loop still exits unsuccessfully after retaining
the available requested artifacts.

The report, schema, final-receipt, and final-package CLI outputs use atomic
no-overwrite publication. Requested loop output paths must be distinct from
one another and from the input package; an existing regular file or symlink
fails before factory or wrapper side effects. Output paths containing an
existing symlink component are rejected as well. Temporary working files are
removed after publication.

`passed: true` in the report records only the normalized factory/DFM outcome.
The CLI exits successfully only if that outcome passes and every requested
artifact is published. For example, a concurrent no-clobber collision can
leave a truthful passing report while the command exits unsuccessfully because
an optional receipt or package could not be published.

The loop's trust boundary ends at the final ZIP and its matching factory
receipt. `--final-package` copies exact ZIP bytes; it does not rebuild or
silently update a downstream pipeline/run manifest. Run `pipeline-verify`
against that exact final ZIP with `--factory-receipt` and
`--require-factory`. This emits the six-phase v2 digest manifest and binds the
receipt to the same package size and SHA-256 without another submission. Omit
both factory options only when the backward-compatible five-phase local v1
report is intentional. Do not pair a repaired ZIP with the original package's
pipeline manifest or receipt. The factory pass decision continues to use the
fail-closed severity rules above, including rejection of unknown severities.
