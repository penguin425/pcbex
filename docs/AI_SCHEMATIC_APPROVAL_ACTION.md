# Boardless AI schematic approval Action

`penguin425/pcbex/actions/ai-schematic-approval` verifies existing AI review
evidence for a KiCad schematic without requiring a PCB board. The Action is a
deterministic approval verifier, not an AI provider adapter: it accepts no API
key, provider endpoint, prompt, private signing key, or network destination.

## Trust boundary

The Action requires a live `.kicad_sch`, one unbound schema-v1 AI review
request, positionally paired signed approval and exact response files, and an
organization policy pack containing the trusted reviewer keys. It performs the
following sequence:

1. Validate every caller path as a bounded workspace-relative regular,
   non-symlink file, snapshot the ordered input set with stable reads, and
   require a fresh literal output directory.
2. Import the live schematic into pcbex's deterministic schematic IR.
3. Revalidate the request digest, require the imported IR to equal the request
   schematic, and freshly recompute the electrical review under the request
   policy.
4. Reverify each signed approval against its exact response and a trusted key,
   then enforce signer, provider, model, threshold, and optional session rules.
5. Validate and retain the closed quorum JSON, derive a fixed numeric-only
   Markdown summary from it, and compare the complete input snapshot again.
6. Scan the bounded evidence directory, revalidate the inputs, report, and
   exact canonical summary immediately before optional upload, require the
   revalidated quorum decision to equal the verifier-step decision, and
   finally enforce `require-quorum`.

Because source binding is semantic, harmless KiCad formatting or trailing
whitespace does not invalidate a request. Changes to symbols, properties,
pins, nets, labels, connectivity, or the recomputed electrical findings do.

## Usage

```yaml
- id: schematic-approval
  uses: penguin425/pcbex/actions/ai-schematic-approval@v1.440.0
  with:
    schematic: hardware/controller.kicad_sch
    request: build/ai-review-request.json
    approval-files: |
      build/reviewer-a.approval.json
      build/reviewer-b.approval.json
    response-files: |
      build/reviewer-a.response.json
      build/reviewer-b.response.json
    policy-pack: policy/organization-policy.json
    minimum-approvals: "2"
    minimum-distinct-providers: "2"
    minimum-distinct-models: "2"
    require-quorum: "true"
    upload-artifact: "true"
```

`approval-files` and `response-files` are newline-separated, non-empty lists.
They must contain the same number of entries; entry `n` in each list is one
signed-approval/exact-response pair. An optional `session` supplies the
time-bound review session used by session-bound approvals.

The Action exposes:

- `status`: `ok` only after the local verifier has checked the signed evidence
  and the wrapper has revalidated its closed report;
- `artifact-dir`: the bounded evidence directory, or empty after an
  authentication failure;
- `ai-approval-quorum` and `ai-approval-quorum-summary`: retained JSON and
  Markdown paths;
- `ai-approval-quorum-met`: the deterministic threshold decision;
- `request-sha256` and `schematic-ir-sha256`: identities validated through the
  request and quorum report;
- `input-snapshot-sha256`: the ordered aggregate digest that matched before
  and after verification and again at the publication boundary.

With `require-quorum: "false"`, a valid signed rejection, `needs_human`
decision, or insufficient provider/model diversity can retain a report with
`ai-approval-quorum-met=false`. With `require-quorum: "true"`, that same
evidence is scanned and uploaded before the final step fails. Invalid
signatures, untrusted keys, mismatched responses, request/source substitution,
malformed policy, linked paths, or stale output destinations fail closed and
do not expose an artifact directory.

Each input is limited to 32 MiB and the ordered input set to 128 MiB. The
quorum JSON is limited to 16 MiB, the generated summary to 64 KiB, and the
two-file artifact tree to 32 MiB. A valid threshold failure keeps these same
bounds and revalidation requirements.

## Deliberate limits

- Only unbound AI review request schema v1 is accepted. Schema-v2 through v4
  bind generated schematic, deterministic pipeline, and native ERC artifacts;
  verify those through the existing CLI, MCP, or root Action paths.
- The focused Action and `pcbex verify-ai-quorum --schematic` are the schema-v1
  live-source binding surfaces in this release. The root Action's legacy
  schema-v1 quorum route and the MCP quorum tool do not automatically inject a
  live schematic; use this focused Action when that binding is required.
- AI provider execution and response normalization remain separate steps.
- The verification path has no provider/network input. Like the other source
  Actions, its build step may use the runner's configured Rust toolchain and
  Cargo registry/network before the local verifier runs, and the optional
  artifact step uploads only to the caller's GitHub Actions artifact service.
- Approval signing remains a trusted step outside this public verifier; do not
  expose private signing keys to pull-request-controlled jobs.
- The Action does not run native KiCad ERC. Compose
  `actions/native-kicad-erc` when fresh native ERC evidence is required.
- Passing quorum is an evidence-policy decision, not authorization to order
  parts, submit a factory job, manufacture a board, or deploy firmware.
- The retained JSON and Markdown record the verifier's decision; they are not
  a self-contained replay bundle. Preserve the request, paired approvals and
  responses, policy pack, optional session, and schematic separately when an
  independent later replay is required.
- The caller must use an isolated runner/workspace with no untrusted
  same-user background process able to rewrite inputs or outputs. Stable reads,
  before/after snapshots, exact-file scans, and publication-time revalidation
  reject changes they observe, but a composite Action cannot make local
  verification and the GitHub artifact-service upload one atomic operation.
