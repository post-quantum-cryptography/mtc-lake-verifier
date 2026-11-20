# Development

```sh
cargo build --release
cargo test --release    # --release matters: the consistency-proof vector
                         # is ~10x slower unoptimized
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

All four are what `.github/workflows/ci.yml` runs on every push and pull
request against `main`.

## Building this book

```sh
mdbook build book    # output in target/book
mdbook serve book    # live-reloading local server
```

## Layout recap

```
src/            the verifier crate (see Crate architecture)
tests/
  spec_vectors.rs   reference prover + Appendix C.1 official test vectors
  cosign.rs         OID worked example + P-256/Ed25519 sign-verify round trips
book/           this book
.github/workflows/ci.yml
```
