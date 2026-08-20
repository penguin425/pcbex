# Fresh exact routing convergence verification

Freshly reproduce a retained routing decision from its original source closure.
Then require the routed artifact to match byte for byte.

The v1.475 verifier consumes v1.474 convergence evidence. It does not trust the
retained report as a standalone claim: it rebuilds the effective `Board`, reruns
the bounded deterministic portfolio, compares the complete typed report, and
regenerates the selected JSON or KiCad output.

## Quick start

Route Board JSON and retain the producer evidence:

```sh
pcbex route board.json \
  --output board.routed.json \
  --convergence-report board.convergence.json
```

Replay both artifacts through the fresh verifier:

```sh
pcbex verify-routing-convergence board.json \
  --routed board.routed.json \
  --report board.convergence.json \
  --output board.convergence.verification.json \
  --require-complete
```

The KiCad path uses the same rule and profile options as `route-kicad`:

```sh
pcbex verify-kicad-routing-convergence board.kicad_pcb \
  --routed board.routed.kicad_pcb \
  --report board.convergence.json \
  --project board.kicad_pro \
  --rules-file board.kicad_dru \
  --physical-profile board-physical.json \
  --output board.convergence.verification.json \
  --require-complete
```

> [!IMPORTANT]
> Pass the same grid, width, clearance, via, cost, companion-file, and profile
> selection used by the producer. A different effective `Board` fails exact
> replay; the verifier never guesses a compatible result.

## What the verifier proves

The report establishes a narrow relationship:

- **Captured sources:** Every selected raw input carries an exact byte count and
  SHA-256 identity.
- **Fresh decision:** The current verifier reproduces the complete retained
  convergence report from the reconstructed effective `Board`.
- **Exact artifact:** The freshly selected board serializes to the supplied
  routed output byte for byte.
- **Stable observation:** Every caller-visible source is reread before the
  verification report is published.

This is stronger than validating the retained JSON shape. It is still evidence,
not release authority.

## Source closure

| Mode | Required inputs | Optional inputs |
| --- | --- | --- |
| Board JSON | input Board, routed Board, retained convergence report | physical profile |
| KiCad | input PCB, routed PCB, retained convergence report | sibling or explicit project, custom rules, and exactly one built-in DFM, external DFM, policy-pack DFM, or physical profile selection |

`verify-kicad-routing-convergence` mirrors `route-kicad` companion discovery.
When `--project` or `--rules-file` is omitted, an existing same-stem
`.kicad_pro` or `.kicad_dru` file enters the closure.

All JSON-bearing sources reject duplicate object keys. The retained convergence
report must also equal its canonical pretty JSON encoding with exactly one
trailing LF. Ambiguous historical inputs do not pass the new boundary.

## Replay sequence

1. **Reserve output.** Reject an occupied destination or overlap with any input
   before reading source contents.
2. **Separate roles.** Reject source paths that resolve to the same file,
   including hard-link aliases.
3. **Capture bytes.** Read each regular non-link file twice through its bounded
   descriptor and reject observed identity or content changes.
4. **Rebuild the Board.** Parse Board JSON, or import KiCad and apply the exact
   project, rules, DFM, policy, or physical profile selection.
5. **Replay convergence.** Run the retained schema-v1 options under the current
   deterministic implementation while preserving the retained producer version
   in the reproduced nested report.
6. **Regenerate output.** Use the Board JSON renderer or the KiCad imported-board
   route writer and require exact supplied bytes.
7. **Reread and publish.** Compare every source again, render a closed bound
   report, synchronize it, and install it without replacement.

These checks are sequential. They detect mutations observed during capture or
final reread; they are not an atomic multi-file filesystem snapshot and do not
sandbox a same-principal concurrent writer.

## Outcomes

| Status | Meaning |
| --- | --- |
| `verified_complete` | Fresh replay reproduced a converged report and exact routed bytes |
| `verified_partial` | Fresh replay reproduced a valid partial improvement and exact routed bytes |
| `verified_no_admissible_candidate` | Fresh replay reproduced the bounded no-candidate outcome and exact unchanged/partial bytes |

Without `--require-complete`, all three are valid verification outcomes. With
the flag, pcbex publishes a truthful partial or no-candidate report first, then
returns nonzero.

Malformed, duplicate-key, noncanonical, oversized, aliased, changed, or
cross-bound inputs are hard failures. Report or routed-output substitution also
fails without a public verification artifact.

## Limits

| Input or output | Limit |
| --- | ---: |
| Board/KiCad input, routed output, project, or custom rules | 128 MiB each |
| Retained convergence report | 16 MiB |
| External DFM or physical profile | 4 MiB each |
| Organization policy pack | 64 MiB |
| Board JSON input aggregate | 276 MiB |
| KiCad input aggregate | 592 MiB |
| Verification report | 32 MiB |

Convergence keeps its existing maximum of eight rounds, 32 candidates per
round, eight candidate workers, eight router workers, and 2,000,000 aggregate
A* work units. Work units bound search; they are not a wall-clock deadline.

## Report contract

The outer schema is closed and path-free. It retains:

- verifier version and input kind;
- status and `routing_complete`;
- the full freshly reproduced convergence report;
- raw byte/SHA-256 identities for every selected source;
- six completed validation flags; and
- a domain-separated SHA-256 binding over every preceding report field.

Discover the exact Draft 2020-12 contract at runtime:

```sh
pcbex routing-convergence-verification-report-schema \
  --output routing-convergence-verification-report-v1.schema.json
```

The outer `engine_version` identifies the verifier. The nested convergence
`engine_version` identifies the retained producer and is reproduced exactly.
Schema-v1 behavior must remain deterministic; an incompatible future algorithm
requires a new report schema rather than silent reinterpretation.

## Nonclaims

The report keeps these fields explicitly `false`:

- `source_authenticity_verified`
- `native_kicad_drc_verified`
- `manufacturability_verified`
- `release_authorized`

It does not authenticate Git history, policy provenance, KiCad, plugins, the
host, or the person who supplied the files. It does not run native KiCad DRC,
prove global optimality, establish signal integrity, approve fabrication, or
authorize release.

> [!TIP]
> Run [Native KiCad PCB DRC](NATIVE_KICAD_DRC.md) and the relevant
> [manufacturing package](MANUFACTURING_PACKAGE.md) gates after verification.
> Consume a retained verification only when its source identities match the
> handoff you intend to use.
