package rsmt

import "crypto/sha256"

// HashLeaf computes SHA256(0x00 || key || value).
// Matches `Sha256Hasher::hash_leaf` in crates/rsmt/src/hash.rs.
func HashLeaf(key [32]byte, value []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(key[:])
	h.Write(value)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// HashNode computes SHA256(0x01 || depth || left || right).
// Matches `Sha256Hasher::hash_node` in crates/rsmt/src/hash.rs.
func HashNode(left, right [32]byte, depth uint8) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01, depth})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	h.Sum(out[:0])
	return out
}
