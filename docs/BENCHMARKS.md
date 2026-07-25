# Routing benchmarks

The Criterion suite measures complete deterministic routing for four scenarios:

- one net around a tall rectangular obstacle;
- five and ten parallel nets;
- one net around an internal board cutout.

Run it with:

```console
cargo bench -p pcbex-core --bench routing --locked
```

Criterion stores local baselines under `target/criterion`. GitHub Actions
compiles the suite on every pull request so API or fixture drift cannot silently
break performance measurement.
