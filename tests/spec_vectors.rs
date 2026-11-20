//! Checks this crate's hashing and proof-verification code against the
//! "Accumulated Subtree Test Vectors" published in Appendix C.1 of
//! draft-ietf-plants-merkle-tree-certs-08 (fetched from
//! https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-08.txt).
//! Those are the spec authors' own official test vectors, designed
//! specifically to be reproduced by implementers; the three rolling-hash
//! digests below are quoted directly from that appendix.
//!
//! To exercise them we need something that *generates* subtree hashes,
//! inclusion proofs, and consistency proofs (a "prover"), which this crate
//! deliberately does not ship (it's a device-side verifier). So this test
//! file implements a small, independent reference prover, written directly
//! from the recursive definitions in spec sections 2.1 of [RFC9162], 4.3,
//! and 4.4.1 (quoted inline below) rather than from any other
//! implementation's code. Matching the three official digests is strong
//! evidence this crate's verifier (in src/) is spec-conformant.

use mtc_lake_verifier::hash::{hash_empty, hash_leaf, hash_node, HashValue};
use mtc_lake_verifier::proof::{verify_subtree_consistency_proof, verify_subtree_inclusion_proof};
use mtc_lake_verifier::subtree::is_valid_subtree;
use sha2::{Digest, Sha256};

const N_MAX: u64 = 130;

/// D_n leaves: d[0] = 0x00, d[1] = 0x01, ..., per Appendix C.1.
fn entries() -> Vec<Vec<u8>> {
    (0..=N_MAX).map(|i| vec![i as u8]).collect()
}

/// "Let k be the largest power of two smaller than n" (§4.4.1), used both
/// here and in RFC 9162's MTH/PATH recursion for n > 1.
fn largest_pow2_lt(n: usize) -> usize {
    debug_assert!(n > 1);
    let bit_length = 64 - (n as u64 - 1).leading_zeros();
    (1u64 << (bit_length - 1)) as usize
}

/// MTH(D_n), RFC 9162 §2.1.1: MTH({}) = HASH(); MTH({d}) = HASH(0x00||d);
/// for n > 1, MTH(D_n) = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n])).
fn mth(d: &[Vec<u8>]) -> HashValue {
    match d.len() {
        0 => hash_empty(),
        1 => hash_leaf(&d[0]),
        n => {
            let k = largest_pow2_lt(n);
            hash_node(&mth(&d[..k]), &mth(&d[k..]))
        }
    }
}

/// PATH(m, D_n), RFC 9162 §2.1.3.1: a Merkle inclusion proof for leaf m of
/// D_n, used for subtree inclusion proofs (§4.3) over the slice D[start:end].
fn path(d: &[Vec<u8>], m: usize) -> Vec<HashValue> {
    let n = d.len();
    if n <= 1 {
        return vec![];
    }
    let k = largest_pow2_lt(n);
    if m < k {
        let mut p = path(&d[..k], m);
        p.push(mth(&d[k..]));
        p
    } else {
        let mut p = path(&d[k..], m - k);
        p.push(mth(&d[..k]));
        p
    }
}

/// SUBTREE_SUBPROOF(start, end, D_n, known_hash), §4.4.1, transcribed
/// directly from the recursive cases in the spec text.
fn subtree_subproof(
    d: &[Vec<u8>],
    start: usize,
    end: usize,
    tree_start: usize,
    tree_end: usize,
    known_hash: bool,
    proof: &mut Vec<HashValue>,
) {
    let n = tree_end - tree_start;
    let sub_start = start - tree_start;
    let sub_end = end - tree_start;

    if sub_start == 0 && sub_end == n {
        if !known_hash {
            proof.push(mth(&d[tree_start..tree_end]));
        }
        return;
    }

    let k = largest_pow2_lt(n);
    if sub_end <= k {
        subtree_subproof(d, start, end, tree_start, tree_start + k, known_hash, proof);
        proof.push(mth(&d[tree_start + k..tree_end]));
    } else if sub_start >= k {
        subtree_subproof(d, start, end, tree_start + k, tree_end, known_hash, proof);
        proof.push(mth(&d[tree_start..tree_start + k]));
    } else {
        // start < k < end implies sub_start == 0.
        subtree_subproof(d, tree_start + k, end, tree_start + k, tree_end, false, proof);
        proof.push(mth(&d[tree_start..tree_start + k]));
    }
}

/// SUBTREE_PROOF(start, end, D_n), §4.4.1.
fn subtree_proof(d: &[Vec<u8>], start: usize, end: usize) -> Vec<HashValue> {
    if start == end {
        return vec![];
    }
    let mut proof = Vec::new();
    subtree_subproof(d, start, end, 0, d.len(), true, &mut proof);
    proof
}

fn concat(hashes: &[HashValue]) -> Vec<u8> {
    hashes.iter().flatten().copied().collect()
}

/// Appendix C.1.1: Subtree Hashes.
#[test]
fn appendix_c_1_1_subtree_hashes() {
    let d = entries();
    let mut rolling = Sha256::new();
    for end in 0..=N_MAX {
        for start in 0..=end {
            if !is_valid_subtree(start, end) {
                continue;
            }
            let h = mth(&d[start as usize..end as usize]);
            rolling.update(format!("[{start}, {end}) {}\n", hex::encode(h)));
        }
    }
    assert_eq!(
        hex::encode(rolling.finalize()),
        "b82806ad4265bb151c1119c0f4db437bb4d1a1f887b3a7fba1cd4ebf552e3e81"
    );
}

/// Appendix C.1.2: Subtree Inclusion Proofs. Also runs the verifier from
/// src/proof.rs against every generated proof, plus the spec's prescribed
/// truncation/extension negative tests.
#[test]
fn appendix_c_1_2_subtree_inclusion_proofs() {
    let d = entries();
    let mut rolling = Sha256::new();
    for end in 0..=N_MAX {
        for start in 0..=end {
            if !is_valid_subtree(start, end) {
                continue;
            }
            let subtree_hash = mth(&d[start as usize..end as usize]);
            for index in start..end {
                let proof = path(
                    &d[start as usize..end as usize],
                    (index - start) as usize,
                );

                let mut line = format!("{index} [{start}, {end})");
                for p in &proof {
                    line.push(' ');
                    line.push_str(&hex::encode(p));
                }
                rolling.update(format!("{line}\n"));

                let entry_hash = hash_leaf(&d[index as usize]);
                let proof_bytes = concat(&proof);

                // Step 2: a valid proof must verify.
                verify_subtree_inclusion_proof(
                    &proof_bytes,
                    index,
                    entry_hash,
                    subtree_hash,
                    start,
                    end,
                )
                .unwrap_or_else(|e| panic!("valid proof rejected: index={index} [{start},{end}): {e}"));

                if !proof_bytes.is_empty() {
                    // Step 3: truncating by one byte, or a full hash, must fail.
                    let truncated_byte = &proof_bytes[..proof_bytes.len() - 1];
                    assert!(verify_subtree_inclusion_proof(
                        truncated_byte,
                        index,
                        entry_hash,
                        subtree_hash,
                        start,
                        end
                    )
                    .is_err());

                    let truncated_hash = &proof_bytes[..proof_bytes.len() - 32];
                    assert!(verify_subtree_inclusion_proof(
                        truncated_hash,
                        index,
                        entry_hash,
                        subtree_hash,
                        start,
                        end
                    )
                    .is_err());
                }

                // Step 4: extending by one byte, or an arbitrary full hash, must fail.
                let mut extended_byte = proof_bytes.clone();
                extended_byte.push(0);
                assert!(verify_subtree_inclusion_proof(
                    &extended_byte,
                    index,
                    entry_hash,
                    subtree_hash,
                    start,
                    end
                )
                .is_err());

                let mut extended_hash = proof_bytes.clone();
                extended_hash.extend_from_slice(&[0xAB; 32]);
                assert!(verify_subtree_inclusion_proof(
                    &extended_hash,
                    index,
                    entry_hash,
                    subtree_hash,
                    start,
                    end
                )
                .is_err());
            }
        }
    }
    assert_eq!(
        hex::encode(rolling.finalize()),
        "ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f"
    );
}

/// Appendix C.1.3: Subtree Consistency Proofs. Also runs the verifier from
/// src/proof.rs against every generated proof, plus the spec's prescribed
/// truncation/extension/bit-flip negative tests.
#[test]
fn appendix_c_1_3_subtree_consistency_proofs() {
    let d = entries();
    let mut rolling = Sha256::new();
    for n in 0..=N_MAX {
        for end in 0..=n {
            for start in 0..=end {
                if !is_valid_subtree(start, end) {
                    continue;
                }
                let proof = subtree_proof(&d[..n as usize], start as usize, end as usize);

                let mut line = format!("[{start}, {end}) {n}");
                for p in &proof {
                    line.push(' ');
                    line.push_str(&hex::encode(p));
                }
                rolling.update(format!("{line}\n"));

                let node_hash = mth(&d[start as usize..end as usize]);
                let root_hash = mth(&d[..n as usize]);
                let proof_bytes = concat(&proof);

                // Step 2: a valid proof must verify.
                verify_subtree_consistency_proof(&proof_bytes, start, end, n, node_hash, root_hash)
                    .unwrap_or_else(|e| {
                        panic!("valid consistency proof rejected: [{start},{end}) n={n}: {e}")
                    });

                if !proof_bytes.is_empty() {
                    // Step 3: truncating must fail.
                    let truncated_byte = &proof_bytes[..proof_bytes.len() - 1];
                    assert!(verify_subtree_consistency_proof(
                        truncated_byte,
                        start,
                        end,
                        n,
                        node_hash,
                        root_hash
                    )
                    .is_err());

                    let truncated_hash = &proof_bytes[..proof_bytes.len() - 32];
                    assert!(verify_subtree_consistency_proof(
                        truncated_hash,
                        start,
                        end,
                        n,
                        node_hash,
                        root_hash
                    )
                    .is_err());
                }

                // Step 4: extending must fail.
                let mut extended_byte = proof_bytes.clone();
                extended_byte.push(0);
                assert!(verify_subtree_consistency_proof(
                    &extended_byte,
                    start,
                    end,
                    n,
                    node_hash,
                    root_hash
                )
                .is_err());

                let mut extended_hash = proof_bytes.clone();
                extended_hash.extend_from_slice(&[0xAB; 32]);
                assert!(verify_subtree_consistency_proof(
                    &extended_hash,
                    start,
                    end,
                    n,
                    node_hash,
                    root_hash
                )
                .is_err());

                // Step 5: flipping a bit in the subtree hash must fail.
                let mut bad_node_hash = node_hash;
                bad_node_hash[0] ^= 0x01;
                assert!(verify_subtree_consistency_proof(
                    &proof_bytes,
                    start,
                    end,
                    n,
                    bad_node_hash,
                    root_hash
                )
                .is_err());

                // Step 6: for a non-empty subtree, flipping a bit in the tree
                // hash must fail.
                if start != end {
                    let mut bad_root_hash = root_hash;
                    bad_root_hash[0] ^= 0x01;
                    assert!(verify_subtree_consistency_proof(
                        &proof_bytes,
                        start,
                        end,
                        n,
                        node_hash,
                        bad_root_hash
                    )
                    .is_err());
                }
            }
        }
    }
    assert_eq!(
        hex::encode(rolling.finalize()),
        "10fa99b37bf9bf9ffa26b412fbd98bd75363256d0b75d61bc4538b9c9c5a0a74"
    );
}
