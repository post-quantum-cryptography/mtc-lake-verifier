# Crate architecture

```
src/
  hash.rs          leaf/node/empty hashing (RFC 9162 §2.1.1)
  subtree.rs       subtree interval validity (§4.1)
  proof.rs         inclusion + consistency proof verification (§4.3-§4.4)
  trustanchorid.rs trust anchor ID encoding, OID names, log/landmark IDs (§5.1-§5.2)
  cosign.rs        CosignedSubtree marshaling + signature verification (§5.3)
```

## `hash.rs`

Three functions: `hash_leaf`, `hash_node`, `hash_empty`. These are the only
primitives everything else is built from — `HASH(0x00 || d)` for a leaf,
`HASH(0x01 || left || right)` for an interior node, `HASH()` for an empty
subtree. SHA-256 only; the spec allows other tree hashes, but this crate
doesn't parametrize over them yet.

## `subtree.rs`

One predicate, `is_valid_subtree(start, end)`: checks `start <= end` and
that `start` is a multiple of `BIT_CEIL(end - start)`. This is the gate
every proof-verification function checks first — most of the security
properties of subtree proofs rest on this alignment constraint.

## `proof.rs`

The verifier's core:

- `evaluate_subtree_inclusion_proof` / `verify_subtree_inclusion_proof`
  (§4.3.2-§4.3.3)
- `verify_subtree_consistency_proof` (§4.4.3)
- `verify_inclusion_proof` / `verify_consistency_proof` — thin wrappers
  specializing the subtree versions to `[0, tree_size)`, matching plain
  RFC 9162 Merkle proofs.

Note what's *not* here: there's no proof **generation**. A device only
ever verifies proofs it receives; generating them is a CA/mirror
responsibility, out of scope for a verifier. (The test suite does
implement a reference generator, but only inside `tests/`, specifically to
exercise this verifier against known-good inputs — see
[Verification methodology](./verification-methodology.md).)

## `trustanchorid.rs`

Trust anchor IDs are sequences of base-128-encoded OID components (per
`draft-ietf-tls-trust-anchor-ids`), used to identify CAs, logs, and
cosigners. This module handles parsing (`TrustAnchorId::parse`, from a
dotted-decimal string like `"32473.1"`), the `oid_name()` ASCII form used
inside cosignatures, and the `log_id()`/`landmark_id()` derivations that
extend a CA's trust anchor ID into its log's or a specific landmark's ID.

## `cosign.rs`

Builds the exact `CosignedSubtree` byte layout a cosigner signs over
(§5.3.1: a 12-byte label, length-prefixed cosigner name and log origin,
a zero timestamp, start/end, and the subtree hash — see the struct
definition quoted in the spec), then verifies a signature over it for
either P-256/SHA-256 or Ed25519. ML-DSA is not implemented yet (see
[Roadmap](./roadmap.md)).

## What a device would still need around this

This crate answers "is this inclusion proof and these cosignatures valid,
given hashes and keys I already have." It does not:

- Parse an actual wire-format certificate into those hashes/proofs (no
  X.509 or CBOR/C509 decoding)
- Track which landmarks are active, or manage the cache window (no
  landmark-sequence logic)
- Talk to anything over a network (no EDHOC/CoAP/OSCORE)

Those are the next layers out — see [Roadmap](./roadmap.md).
