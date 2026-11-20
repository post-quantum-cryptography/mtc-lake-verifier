use sha2::{Digest, Sha256};

pub const HASH_SIZE: usize = 32;
pub type HashValue = [u8; HASH_SIZE];

/// MTH({d}) = HASH(0x00 || d), RFC 9162 §2.1.1.
pub fn hash_leaf(data: &[u8]) -> HashValue {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(data);
    h.finalize().into()
}

/// MTH({}) = HASH(), the hash of the empty string.
pub fn hash_empty() -> HashValue {
    Sha256::new().finalize().into()
}

/// HASH(0x01 || left || right), RFC 9162 §2.1.1.
pub fn hash_node(left: &HashValue, right: &HashValue) -> HashValue {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}
