// Package rsmt implements verification of consistency proofs produced by the
// Rust Radix Sparse Merkle Tree library (RSMT v6a; `crates/rsmt` and
// `crates/rsmt-verify` in the aggregator repository). It is the Go
// counterpart of `crates/rsmt-verify/src/consistency.rs`.
//
// The verifier consumes a compact binary envelope (`DecodeEnvelope`) that
// carries the batch of newly inserted leaves followed by the flat
// post-order opcode stream, and recomputes the old and new SMT roots with a
// region-aware stack machine (`Verify`).
//
// Wire format (aggregator_rsmt_v1):
//
//	offset  size  field
//	0       4     leaf_count       (big-endian u32)
//	4       ...   leaves:          leaf_count × { key[32] || value_len (u16 BE) || value[value_len] }
//	...     ...   opcode stream    (flat bytes, runs to end of buffer)
//
// A leaf's `value` is the declared transaction hash, not the value the tree
// stores. The verifier derives the stored value as
//
//	LeafValue(transactionHash, referenceTime) = SHA256(CBOR([transactionHash, referenceTime]))
//
// where referenceTime is CR.IR.t, the round reference time the Core already
// checks against the previous seal. Deriving rather than accepting a supplied
// leaf value is what makes a wrong reference time unrepresentable: a shard
// that built its tree under any other reference time produces a root the Core
// does not reproduce.
//
// Leaves must be pre-sorted by plain key order (RSMT v6a: rsmt_sort_key(k)
// = k, since keys are read as big-endian bit strings), this package does
// not reorder them.
//
// Opcodes:
//
//	S(h)               0x00 || h[32]                                - opaque preserved subtree; only valid where the parent junction already existed pre-round
//	L                  0x01                                          - new leaf; next batch entry
//	N(d)               0x02 || d                                     - junction at depth d, pops two children
//	O(d,p,hL,hR)       0x03 || d || p[32] || hL[32] || hR[32]         - preserved junction, opened one level
//	O_L(k,v)           0x04 || k[32] || len(v) (u16 BE) || v          - preserved leaf, opened (v is that leaf's stored value, carried verbatim)
//
// O and O_L are required whenever a preserved subtree becomes the child of
// a junction created this round (an edge split, including the leaf-merge
// case): the verifier needs the opened preimage to check the new edge
// against the child's authenticated depth and region. An opaque S may never
// attach to a junction absent from the pre-state.
//
// Hashes (SHA-256, matching `crates/rsmt-verify/src/hash.rs`):
//
//	hash_leaf(key, value)         = SHA256(0x00 || key || value)
//	hash_node(l, r, d, region)    = SHA256(0x01 || d || region || l || r)
//
// Every internal-node hash commits to its absolute bifurcation depth and to
// its region — the key prefix [0, d) shared by every descendant key, packed
// into 32 bytes with bits [d, 256) cleared. Keys and regions are read as
// big-endian (MSB-first) bit strings: bit 0 is the most significant bit of
// byte 0.
package rsmt
