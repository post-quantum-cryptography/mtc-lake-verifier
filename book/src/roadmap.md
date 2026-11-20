# Roadmap

Rough order of what unblocks the most next, not a commitment to build all
of it.

## Close to this crate

- **Real certificate parsing.** Parse an actual `cert-1.pem`-style
  certificate (the `MTCProof` X.509 extension, §6.2) into the
  `(index, start, end, proof, subtree_hash)` tuple the verifier takes.
  Lets [Running a local PKI](./running-a-local-pki.md) feed real bytes
  into an automated test instead of a manual walkthrough.
- **ML-DSA cosigning.** Only P-256/SHA-256 and Ed25519 are implemented.
  ML-DSA/SLH-DSA-sized signatures are the entire reason MTC exists per
  `draft-kwiatkowski-mtc-iot`'s Motivation section, so this is a real gap,
  not a nice-to-have.
- **Landmark-sequence logic** (§6.4 of the base MTC spec): the `W`-sized
  active-landmark window, `FindContainingLandmark`. This is pure MTC with
  no EDHOC dependency, and is what
  `draft-kwiatkowski-mtc-iot`'s Landmark Synchronisation section actually
  describes on the device side.
- **`no_std` support.** The crate currently assumes `std` (`Vec`,
  `std::error::Error`). Fine for development and CI; not yet buildable
  for the constrained-device targets this is ultimately for.

## Specific to draft-kwiatkowski-mtc-iot

- **CBOR/C509 credential encoding** — type 2 (natively-signed) / type 3
  (re-encoded X.509), per `sections/cbor-encoding.md` in the draft. This
  crate operates on raw hashes and proofs, not on the wire-format
  credential a device would actually receive over EDHOC.
- **EDHOC/LAKE EAD wiring** — hooking into
  [`lakers`](https://lakers.readthedocs.io): encoding/parsing the
  landmark-state item in `EAD_1`/`EAD_2`, and the update package in
  `EAD_4`.
- **The cache/sync state machine** — anchor tracking (number, tree size,
  root hash), delegated vs. end-to-end validation mode, rollback/recovery
  handling when anchor validation fails.
- **OSCORE-protected delegated-mode transport.**

## Engineering, lower priority

- A fuzzing harness (`cargo fuzz`) for the proof-verification functions,
  since they parse untrusted network input in the eventual deployment.
- A benchmark of verification cost on a representative constrained-device
  target, especially once ML-DSA cosigning is added (ML-DSA verification
  is far heavier than P-256/Ed25519).
