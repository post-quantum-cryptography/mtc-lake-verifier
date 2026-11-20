/// Smallest power of two >= n (for n <= 2^63), mirroring Go's `bits.Len64(n-1)`.
fn bit_ceil_u64(n: u64) -> u64 {
    if n <= 1 {
        return 1;
    }
    1u64 << (64 - (n - 1).leading_zeros())
}

/// Checks whether [start, end) is a valid "subtree" interval per
/// draft-ietf-plants-merkle-tree-certs §4.1:
///   - start <= end
///   - start is a multiple of BIT_CEIL(end - start)
///
/// Empty subtrees [x, x) are valid (BIT_CEIL(0) is 1), as is [0, x) for all x.
pub fn is_valid_subtree(start: u64, end: u64) -> bool {
    if start > end {
        return false;
    }
    let size = end - start;
    if size > (1u64 << 63) {
        // bit_ceil would overflow; only [0, end) is aligned.
        return start == 0;
    }
    let ceil = bit_ceil_u64(size);
    start & (ceil - 1) == 0
}
