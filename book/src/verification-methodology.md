# Verification methodology

## Why not cross-check against another implementation

The obvious way to gain confidence in a from-scratch implementation is to
generate test inputs with somebody else's implementation and check that
this crate agrees with it. Two candidate Go implementations exist:

- [bwesterb/mtc](https://github.com/bwesterb/mtc) targets the
  pre-"photosynthesis" draft — it has no landmark or cosigner concepts at
  all, so it doesn't match the spec revision this crate (or
  `draft-kwiatkowski-mtc-iot`) is built on.
- [robstradling/mtc-demo](https://github.com/robstradling/mtc-demo) does
  match (targets draft -08, has landmarks and cosigners), and is a clean,
  spec-section-annotated implementation.

An earlier version of this crate vendored several files from
`mtc-demo` to build a Go-based test-vector generator. That had to be
undone: `mtc-demo` has **no `LICENSE` file**
(confirmed via GitHub's API, which reports `license: null`), so its code
is "all rights reserved" by default. Copying it — even into a private
prototype, even trimmed down — wasn't something to commit. (Running the
`mtc-demo` CLI as an external tool, rather than copying its source, is a
different matter and is exactly what [Running a local
PKI](./running-a-local-pki.md) does.)

There's a second reason beyond licensing: cross-checking against one other
implementation only tells you the two of you share the same understanding
of the spec. If both implementations made the same wrong assumption —
plausible, since `mtc-demo` itself credits an LLM for most of its
authorship — the cross-check would pass while both were wrong.

## What this crate checks against instead

Appendix C.1 of the spec publishes three SHA-256 digests — "Accumulated
Subtree Test Vectors" — computed by rolling together every subtree hash,
every inclusion proof, and every consistency proof for trees of size up to
130. They're specifically designed for implementers to reproduce, down to
providing runnable Python for the reference computation. This is about as
authoritative as a test vector gets: it comes from the spec itself, not
from an interpretation of it.

Reproducing them requires something that *generates* proofs — a small
reference prover — since this crate only verifies. `tests/spec_vectors.rs`
implements that prover directly from the recursive definitions quoted in
the spec text (RFC 9162 §2.1 for `MTH`/`PATH`, §4.4.1 for
`SUBTREE_SUBPROOF`), written fresh for this purpose. It then:

1. Builds `D_n` for `n` up to 130, with `d[i]` the single byte `i`.
2. For every valid `[start, end)`, computes the subtree hash, every
   inclusion proof, and every consistency proof against every tree size.
3. Rolls each into a SHA-256 digest exactly as the appendix describes, and
   asserts the result matches the three published hashes.
4. Independently, feeds every generated proof into this crate's actual
   verifier (`verify_subtree_inclusion_proof`,
   `verify_subtree_consistency_proof`) and asserts it accepts them — and
   performs the appendix's prescribed negative tests (truncate by a byte,
   truncate by a full hash, extend by a byte, extend by a hash, flip a bit
   in the subtree hash, flip a bit in the root hash), asserting every one
   of those is rejected.

All three digests match. See the test output quoted in the crate's
`README.md`, or run it yourself:

```sh
cargo test --release --test spec_vectors
```

(`--release` matters: the consistency-proof vector is roughly an order of
magnitude slower unoptimized, since it runs a verification plus six
tamper-check verifications for every valid subtree of every tree size up
to 130.)

## Cosignatures

The spec gives one worked example for the OID-name derivation
(`32473.1` → `"oid/1.3.6.1.4.1.32473.1"`, §5.3.1), which
`tests/cosign.rs` checks directly. There's no official worked
cryptographic example for a full cosignature, so those tests sign with
throwaway keys generated in the test itself — this crate only ever
verifies, so a signing counterpart has to live in test code — and check
that `verify_cosignature` accepts a genuine signature and rejects a
tampered one, for both P-256/SHA-256 and Ed25519.
