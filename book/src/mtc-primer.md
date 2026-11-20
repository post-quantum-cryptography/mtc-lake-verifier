# Merkle Tree Certificates, briefly

Full detail lives in
[draft-ietf-plants-merkle-tree-certs](https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs/);
this page is just enough to follow the rest of the book.

## The problem

Post-quantum signatures are big. A conventional PKI signs every certificate
individually, so every certificate pays the full cost of a post-quantum
signature — in size, in signing time, or in implementation risk, depending
on which algorithm the CA picked. MTC decouples those costs: instead of
signing each certificate, a CA appends it to an **issuance log** and signs
*the log*, periodically, as a batch. A certificate is then just a small
proof that it's included in a log state that's been signed.

## The pieces

- **Issuance log** — an append-only list of entries (one per certificate
  request). The CA builds a Merkle tree over this list.
- **Subtree** — not every `[start, end)` slice of the log is usable as a
  signable unit; §4.1 defines which intervals qualify ("valid subtrees"),
  chosen so they can be efficiently proven consistent with the full tree
  later, as the log grows.
- **Cosigners** — independent parties (possibly including the CA itself,
  as a "CA cosigner") that each sign a subtree, attesting the CA followed
  the rules. This is MTC's answer to Certificate Transparency: a device
  checking a certificate can also check it was logged under cosignatures
  it trusts, so an unauthorized certificate is detectable, not just
  revocable.
- **Landmark** — an agreed-upon log size, issued periodically (e.g.
  hourly). Certificates reference the *landmark* they fall under rather
  than carrying their own per-certificate signature; a device that already
  trusts a landmark only needs a small inclusion proof into it, not a fresh
  signature verification.
- **Inclusion proof** — proves a specific log entry is contained in a
  subtree, given the subtree's hash. This is what `src/proof.rs`'s
  `verify_subtree_inclusion_proof` checks.
- **Consistency proof** — proves a subtree's hash is consistent with a
  *later*, larger tree hash, without re-deriving the whole tree. This is
  how a device that already trusts an old landmark can efficiently extend
  that trust to a new one. `verify_subtree_consistency_proof` checks this.

## What a device actually verifies

Given a certificate claiming "I'm entry `index` in subtree `[start, end)`
of this CA's log, here's the inclusion proof, and here are cosignatures
over that subtree":

1. Evaluate the inclusion proof to get an expected subtree hash.
2. Check that hash is the one the trusted cosignatures actually signed.
3. Check the cosignatures themselves verify against cosigner keys the
   device trusts.

That's the entirety of what this crate implements — see
[Crate architecture](./architecture.md) for where each step lives.
