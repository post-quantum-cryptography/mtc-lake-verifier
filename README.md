# MTC verifier for LAKE protocol

A prototype of the **verifier core** for Merkle Tree Certificates (MTC), the
piece [draft-kwiatkowski-mtc-iot](https://github.com/kwiatkowski/draft-kwiatkowski-mtc-iot)
(Merkle Tree Certificates for LAKE) needs a device to run when it checks a
landmark-relative certificate against its cached landmark.

**📖 [Read the book](https://post-quantum-cryptography.github.io/mtc-lake-verifier/)**
for how this crate maps to the spec and how to run a local MTC CA to
generate real test inputs. (The Pages deploy is currently disabled in
`.github/workflows/book.yml` — this org's plan doesn't support Pages on a
private repo. Re-enable it once the repo is public; until then, build
locally with `mdbook build book`.)

## Documentation

To generate documentation:

```sh
mdbook build book    # static HTML into target/book/
mdbook serve book    # live-reloading local server (http://localhost:3000), rebuilds on save
```

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
  book.yml        builds the book on every push/PR; Pages deploy step
                  is commented out until the repo is public
```
