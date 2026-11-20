# Introduction

`mtc-lake-verifier` is a prototype of the **verifier core** for Merkle Tree
Certificates (MTC): the hashing and proof-checking logic a device needs
before it can trust a landmark-relative certificate.

It exists to de-risk one piece of
[draft-kwiatkowski-mtc-iot](https://github.com/kwiatkowski/draft-kwiatkowski-mtc-iot)
("Merkle Tree Certificates for LAKE"), which proposes carrying MTC
certificates over EDHOC/LAKE for constrained IoT devices. That draft needs a
device to, among other things, verify that a certificate it received is
included under a landmark it has cached, and that the landmark itself is
properly cosigned. This crate implements exactly that piece, independent of
the EDHOC transport around it, so the cryptographic core can be tested and
trusted on its own before anything else is built on top of it.

## Scope

**In scope**, implemented and checked against the spec:

- Leaf and node hashing (RFC 9162 §2.1.1)
- Subtree inclusion-proof verification (§4.3 of
  [draft-ietf-plants-merkle-tree-certs](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/))
- Subtree consistency-proof verification (§4.4)
- Trust anchor ID encoding and the log/landmark ID derivations (§5.1-§5.2)
- Cosigner signature verification for P-256/SHA-256 and Ed25519 (§5.3)

**Out of scope**, not built here — see [Roadmap](./roadmap.md) for the full
list and why each is a separate step:

- EDHOC/LAKE EAD wiring (the `lakers` integration)
- The landmark cache and sync state machine from
  `draft-kwiatkowski-mtc-iot`'s Landmark Synchronisation section
- C509/X.509 certificate encoding and parsing
- ML-DSA cosigning

## How to read this book

- [Merkle Tree Certificates, briefly](./mtc-primer.md) if you want the
  concepts (landmarks, subtrees, cosigners) without reading the full IETF
  drafts first.
- [Crate architecture](./architecture.md) for how the Rust modules map to
  spec sections.
- [Verification methodology](./verification-methodology.md) for how this
  crate is checked for correctness, and why it's checked against the spec's
  own published test vectors rather than against another implementation.
- [Running a local PKI](./running-a-local-pki.md) to generate real
  certificates and landmarks to test against, instead of the synthetic
  vectors used in the test suite.
- [Roadmap](./roadmap.md) for what's missing before this is a usable
  implementation of the IoT draft.
