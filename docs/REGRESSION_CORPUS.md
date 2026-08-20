# Practical regression corpus

The corpus contains deterministic, anonymized board topologies derived from
common production layouts. Component identities and coordinates are synthetic;
the routing constraints and failure modes are retained.

| Fixture | Scenario | Required result | Search budget |
| --- | --- | --- | ---: |
| `usb_diff.json` | USB 2 high-speed pair with a one-sided obstacle | 100% coupled, zero-skew pair | 8,000 |
| `four_layer_power.json` | Four-layer power, inner-only clock, and front signal | All three nets routed with layer rules | 15,000 |
| `bga_fanout.json` | Eight-net 1 mm-pitch BGA escape topology | All fanout nets routed | 12,000 |
| generated `large_backplane.json` | 100-net, six-layer deterministic backplane | All 100 nets routed | 100,000 |

Every fixture must pass the internal checker and a second routing pass must be
byte-for-byte identical. The state budgets are deterministic algorithmic limits,
not shared-runner timing measurements.
The large fixture is recreated by `scripts/generate-large-corpus.py` on every
run so its topology remains reviewable without committing a bulky generated
artifact.

The focused routing-convergence suite also routes the compact JSON and KiCad
fixtures through multiple deterministic objectives. It requires exact repeated
Board/report bytes, bounded aggregate allocation, DRC-valid winners, closed
schemas, retained negative reports, and no-clobber/alias rejection. Full corpus
runs remain the compatibility gate for unchanged single-pass routing.

```sh
cargo build --workspace --release --locked
scripts/regression-corpus.sh target/release/pcbex build/regression-corpus
```
