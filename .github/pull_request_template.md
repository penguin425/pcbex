## Summary

-

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo test --workspace --locked`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo build --workspace --release --locked`
- [ ] `PYTHONPATH=agent/src python3 -m unittest discover -s agent/tests -v`
- [ ] KiCad DRC run when routing or KiCad output changed

## Risk and compatibility

-
