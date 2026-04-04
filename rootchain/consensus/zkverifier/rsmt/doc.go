// Package rsmt implements verification of consistency proofs produced by the
// Rust Radix Sparse Merkle Tree library (`crates/rsmt` in the aggregator
// repository). It is the Go counterpart of `crates/rsmt/src/consistency.rs`.
//
// The verifier consumes a compact binary envelope (`DecodeEnvelope`) that
// carries the batch of newly inserted leaves followed by the flat
// post-order opcode stream, and recomputes the old and new SMT roots with a
// stack machine (`Verify`).
//
// Wire format (aggregator_rsmt_v1):
//
//	offset  size  field
//	0       4     leaf_count       (big-endian u32)
//	4       ...   leaves:          leaf_count × { key[32] || value_len (u16 BE) || value[value_len] }
//	...     ...   opcode stream    (flat bytes, runs to end of buffer)
//
// Leaves must be pre-sorted by SortKey (per-byte bit-reversed key, LSB-first
// traversal order), this package does not reorder them.
//
// Opcodes:
//
//	S(h)    0x00 || h[32]   - unchanged subtree hash
//	L       0x01            - new leaf; next batch entry
//	N(d)    0x02 || d       - internal node at depth d, pops two children
//
// Hashes (SHA-256, matching `crates/rsmt/src/hash.rs`):
//
//	hash_leaf(key, value) = SHA256(0x00 || key || value)
//	hash_node(l, r, d)    = SHA256(0x01 || d   || l   || r)
package rsmt
