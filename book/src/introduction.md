# Introduction

`mtc-lake-verifier` implements the device-side verification math for
Merkle Tree Certificates: hashing, inclusion-proof and consistency-proof
checking, and cosignature verification, per
[draft-ietf-plants-merkle-tree-certs](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/)
§4-§5.3.

For what MTC is, why it exists, and how it's meant to be used over
EDHOC/LAKE, see
[draft-kwiatkowski-mtc-iot](https://github.com/kwiatkowski/draft-kwiatkowski-mtc-iot)
and the base MTC draft linked above — this book only documents this crate.

- [Crate architecture](./architecture.md) — what each module does.
- [Running a local PKI](./running-a-local-pki.md) — generate real
  certificates and landmarks to test against.
- [Development](./development.md) — build, test, lint.
