# Crate architecture

```text
src/
  hash.rs          hash_leaf, hash_node, hash_empty          (RFC 9162 §2.1.1)
  subtree.rs       is_valid_subtree                          (§4.1)
  proof.rs         verify_subtree_inclusion_proof             (§4.3.2-§4.3.3)
                   verify_subtree_consistency_proof           (§4.4.3)
                   verify_inclusion_proof / verify_consistency_proof
                     (wrappers specializing to [0, tree_size))
  trustanchorid.rs TrustAnchorId::parse/oid_name/log_id/landmark_id  (§5.1-§5.2)
  cosign.rs        verify_cosignature (P-256/SHA-256, Ed25519)       (§5.3)
```

This crate only **verifies** — there is no proof-generation code in
`src/`. A device never needs to generate a proof, only check one it
received. (`tests/spec_vectors.rs` does implement a generator, but only
as test infrastructure to produce known-good inputs — see its module
doc comment.)

Nothing here parses an actual wire-format certificate (X.509 `MTCProof`
extension, or the CBOR/C509 encoding `draft-kwiatkowski-mtc-iot` proposes)
into the `(index, start, end, proof, subtree_hash)` inputs these
functions take, and nothing here talks to a network. Those are separate,
not-yet-built layers.
