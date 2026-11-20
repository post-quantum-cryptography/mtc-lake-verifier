# Development

```sh
cargo build --release
cargo test --release    # --release matters: the consistency-proof vector
                         # is ~10x slower unoptimized
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

All four run in `.github/workflows/ci.yml` on every push and pull request.

## Tests

- `tests/spec_vectors.rs` checks `src/proof.rs` and `src/hash.rs` against
  the three official digests published in Appendix C.1 of the spec
  ("Accumulated Subtree Test Vectors"), including the spec's prescribed
  truncate/extend/bit-flip negative tests.
- `tests/cosign.rs` checks `src/cosign.rs` and `src/trustanchorid.rs`
  against the one worked OID example the spec gives (§5.3.1), and
  sign/verify round trips for P-256 and Ed25519.

## Building this book

```sh
mdbook build book    # output in target/book
mdbook serve book    # live-reloading local server
```
