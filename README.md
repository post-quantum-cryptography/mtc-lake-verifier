# mtc-lake-verifier

A prototype of the **verifier core** for Merkle Tree Certificates (MTC), the
piece [draft-kwiatkowski-mtc-iot](https://github.com/kwiatkowski/draft-kwiatkowski-mtc-iot)
(Merkle Tree Certificates for LAKE) needs a device to run when it checks a
landmark-relative certificate against its cached landmark.

## Scope

This is step 1 of a larger implementation effort, deliberately kept small:

- **In scope**: leaf/node hashing, subtree inclusion-proof verification,
  subtree consistency-proof verification, and cosigner signature
  verification (P-256/SHA-256 and Ed25519), per
  [draft-ietf-plants-merkle-tree-certs](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/)
  §4 and §5.3. This is the math a device needs before anything else.
- **Out of scope (not built here)**: EDHOC/LAKE EAD wiring (the
  `lakers` integration), the landmark cache and sync state machine from
  `draft-kwiatkowski-mtc-iot`'s Landmark Synchronisation section, and
  C509/X.509 certificate encoding/parsing. ML-DSA cosigning is also not
  covered yet — only P-256 and Ed25519.

## How it's verified

`src/` is written directly from the spec (`draft-ietf-plants-merkle-tree-certs-08`,
fetched from the IETF archive). Rather than cross-checking against another
project's implementation — which would mean either copying code without a
license (an earlier draft of this repo did that with
[robstradling/mtc-demo](https://github.com/robstradling/mtc-demo) and had
to undo it: that repo has no LICENSE file, so its code is "all rights
reserved" by default) or trusting a second implementation that could share
the same misunderstanding of the spec — `tests/spec_vectors.rs` checks this
crate against the **official "Accumulated Subtree Test Vectors" published in
the draft's own Appendix C.1**. Those are three SHA-256 digests the spec
authors computed by rolling together every subtree hash, inclusion proof,
and consistency proof for trees of size up to 130, specifically so
implementers can self-check against them. All three match:

```
appendix_c_1_1_subtree_hashes            ... ok  (subtree hashing)
appendix_c_1_2_subtree_inclusion_proofs  ... ok  (+ the spec's truncate/extend negative tests)
appendix_c_1_3_subtree_consistency_proofs ... ok  (+ the spec's truncate/extend/bit-flip negative tests)
```

Reproducing these required a small *reference prover* (tree-hash and
proof-generation code) that the test file implements from the recursive
definitions quoted in spec §§2.1 (via RFC 9162), 4.3, and 4.4.1 — written
fresh for this purpose, not copied from anywhere. It lives only in
`tests/spec_vectors.rs`; `src/` ships a verifier, not a prover, since that's
what a device needs.

`tests/cosign.rs` separately checks `src/cosign.rs` and
`src/trustanchorid.rs`: the OID-name test uses the one worked example the
spec gives directly (`32473.1` -> `"oid/1.3.6.1.4.1.32473.1"`, §5.3.1), and
the P-256/Ed25519 cosignature tests sign with throwaway keys generated in
the test itself (the library only verifies) to check `verify_cosignature`
end-to-end.

## Running it

```sh
cargo test --release   # the consistency-proof vector is cheaper in release mode
```

## Layout

```
src/
  hash.rs          leaf/node/empty hashing (RFC 9162 §2.1.1)
  subtree.rs        subtree interval validity (§4.1)
  proof.rs          inclusion + consistency proof verification (§4.3-4.4)
  trustanchorid.rs  trust anchor ID encoding, OID names, log/landmark IDs (§5.1-5.2)
  cosign.rs         CosignedSubtree marshaling + signature verification (§5.3)
tests/
  spec_vectors.rs   reference prover + Appendix C.1 official test vectors
  cosign.rs         OID worked example + P-256/Ed25519 sign-verify round trips
```
