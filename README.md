# mtc-lake-verifier

A prototype of the **verifier core** for Merkle Tree Certificates (MTC), the
piece [draft-kwiatkowski-mtc-iot](https://github.com/kwiatkowski/draft-kwiatkowski-mtc-iot)
(Merkle Tree Certificates for LAKE) needs a device to run when it checks a
landmark-relative certificate against its cached landmark.

**📖 [Read the book](https://post-quantum-cryptography.github.io/mtc-lake-verifier/)**
for the full picture: an MTC primer, how this crate maps to the spec, how
it's verified (against the spec's own official test vectors, not against
another implementation), how to run a local MTC CA to generate real test
inputs, and what's still missing before this is a usable implementation of
the IoT draft. (The link goes live once this is pushed and GitHub Pages is
enabled for the repo — see `book/` and `.github/workflows/book.yml` until
then.)

## Running it

```sh
cargo test --release    # --release matters: the Appendix C.1 consistency-
                         # proof vector is ~10x slower unoptimized
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

## Layout

```
src/            the verifier crate — see the book's "Crate architecture" chapter
tests/
  spec_vectors.rs   reference prover + Appendix C.1 official test vectors
  cosign.rs         OID worked example + P-256/Ed25519 sign-verify round trips
book/           mdBook source for the documentation linked above
.github/workflows/
  ci.yml          fmt, clippy, build, test
  book.yml        builds and (on main) deploys the book to GitHub Pages
```
