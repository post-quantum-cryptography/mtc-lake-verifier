use crate::hash::{hash_node, HashValue, HASH_SIZE};
use crate::subtree::is_valid_subtree;

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidProof(pub String);

impl std::fmt::Display for InvalidProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid proof: {}", self.0)
    }
}
impl std::error::Error for InvalidProof {}

fn err(msg: impl Into<String>) -> InvalidProof {
    InvalidProof(msg.into())
}

/// Evaluates a subtree inclusion proof (§4.3.2) and returns the expected
/// subtree hash for the entry at `index` inside subtree [start, end).
pub fn evaluate_subtree_inclusion_proof(
    mut proof: &[u8],
    index: u64,
    entry_hash: HashValue,
    start: u64,
    end: u64,
) -> Result<HashValue, InvalidProof> {
    if !is_valid_subtree(start, end) {
        return Err(err(format!("invalid subtree [{start}, {end})")));
    }
    if index < start || index >= end {
        return Err(err(format!("index {index} not in [{start}, {end})")));
    }
    if proof.len() % HASH_SIZE != 0 {
        return Err(err(format!(
            "proof length {} not a multiple of {HASH_SIZE}",
            proof.len()
        )));
    }

    let mut fn_ = index - start;
    let mut sn = end - start - 1;
    let mut r = entry_hash;

    while !proof.is_empty() {
        if sn == 0 {
            return Err(err("proof has too many elements"));
        }
        let mut p = [0u8; HASH_SIZE];
        p.copy_from_slice(&proof[..HASH_SIZE]);
        proof = &proof[HASH_SIZE..];

        if fn_ & 1 == 1 || fn_ == sn {
            r = hash_node(&p, &r);
            // "Until LSB(fn) is set, right-shift fn and sn equally."
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            r = hash_node(&r, &p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }

    if sn != 0 {
        return Err(err("proof has too few elements"));
    }
    Ok(r)
}

/// Verifies a subtree inclusion proof (§4.3.3).
pub fn verify_subtree_inclusion_proof(
    proof: &[u8],
    index: u64,
    entry_hash: HashValue,
    subtree_hash: HashValue,
    start: u64,
    end: u64,
) -> Result<(), InvalidProof> {
    let expected = evaluate_subtree_inclusion_proof(proof, index, entry_hash, start, end)?;
    if expected != subtree_hash {
        return Err(err("computed subtree hash does not match"));
    }
    Ok(())
}

/// Verifies a standard Merkle inclusion proof for `index` in a tree of size
/// `tree_size` with root `root_hash`.
pub fn verify_inclusion_proof(
    proof: &[u8],
    index: u64,
    tree_size: u64,
    entry_hash: HashValue,
    root_hash: HashValue,
) -> Result<(), InvalidProof> {
    verify_subtree_inclusion_proof(proof, index, entry_hash, root_hash, 0, tree_size)
}

/// Verifies a subtree consistency proof (§4.4.3): that the subtree
/// [start, end) with hash `node_hash` is consistent with the full tree of
/// size `n` whose root is `root_hash`.
pub fn verify_subtree_consistency_proof(
    mut proof: &[u8],
    start: u64,
    end: u64,
    n: u64,
    node_hash: HashValue,
    root_hash: HashValue,
) -> Result<(), InvalidProof> {
    if !is_valid_subtree(start, end) {
        return Err(err(format!("invalid subtree [{start}, {end})")));
    }
    if end > n {
        return Err(err(format!("subtree end {end} > tree size {n}")));
    }
    if proof.len() % HASH_SIZE != 0 {
        return Err(err(format!(
            "proof length {} not a multiple of {HASH_SIZE}",
            proof.len()
        )));
    }

    // Step 2: empty subtree.
    if start == end {
        if !proof.is_empty() {
            return Err(err("non-empty proof for empty subtree"));
        }
        if node_hash != crate::hash::hash_empty() {
            return Err(err("empty subtree hash mismatch"));
        }
        return Ok(());
    }

    let mut fn_ = start;
    let mut sn = end - 1;
    let mut tn = n - 1;

    // Steps 3 & 4: skip to the starting node.
    if sn == tn {
        while fn_ != sn {
            fn_ >>= 1;
            sn >>= 1;
            tn >>= 1;
        }
    } else {
        while fn_ != sn && sn & 1 == 1 {
            fn_ >>= 1;
            sn >>= 1;
            tn >>= 1;
        }
    }

    // Steps 5 & 6: initialize fr and sr.
    let mut fr: HashValue;
    let mut sr: HashValue;
    if fn_ == sn {
        fr = node_hash;
        sr = node_hash;
    } else {
        if proof.is_empty() {
            return Err(err("empty proof for non-root subtree"));
        }
        let mut c = [0u8; HASH_SIZE];
        c.copy_from_slice(&proof[..HASH_SIZE]);
        proof = &proof[HASH_SIZE..];
        fr = c;
        sr = c;
    }

    // Step 7: process remaining proof elements.
    while !proof.is_empty() {
        if tn == 0 {
            return Err(err("proof has too many elements"));
        }
        let mut c = [0u8; HASH_SIZE];
        c.copy_from_slice(&proof[..HASH_SIZE]);
        proof = &proof[HASH_SIZE..];

        if sn & 1 == 1 || sn == tn {
            if fn_ < sn {
                fr = hash_node(&c, &fr);
            }
            sr = hash_node(&c, &sr);
            // "Until LSB(sn) is set, right-shift fn, sn, and tn equally."
            while sn & 1 == 0 && sn != 0 {
                fn_ >>= 1;
                sn >>= 1;
                tn >>= 1;
            }
        } else {
            sr = hash_node(&sr, &c);
        }
        fn_ >>= 1;
        sn >>= 1;
        tn >>= 1;
    }

    // Step 8: final checks.
    if tn != 0 {
        return Err(err("proof has too few elements"));
    }
    if fr != node_hash {
        return Err(err("reconstructed subtree hash does not match"));
    }
    if sr != root_hash {
        return Err(err("reconstructed root hash does not match"));
    }
    Ok(())
}

/// Verifies a standard Merkle consistency proof between a tree of size
/// `old_size` and a tree of size `new_size`.
pub fn verify_consistency_proof(
    proof: &[u8],
    old_size: u64,
    new_size: u64,
    old_root: HashValue,
    new_root: HashValue,
) -> Result<(), InvalidProof> {
    verify_subtree_consistency_proof(proof, 0, old_size, new_size, old_root, new_root)
}
