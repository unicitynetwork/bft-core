package rsmt

import "crypto/sha256"

// HashLeaf computes SHA256(0x00 || key || value).
// Matches `Sha256Hasher::hash_leaf` in crates/rsmt-verify/src/hash.rs.
func HashLeaf(key [32]byte, value []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(key[:])
	h.Write(value)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// HashNode computes SHA256(0x01 || depth || region || left || right).
// Matches `Sha256Hasher::hash_node` in crates/rsmt-verify/src/hash.rs
// (RSMT v6a region commitment).
func HashNode(left, right [32]byte, depth uint8, region [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01, depth})
	h.Write(region[:])
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// KeyBitAt returns bit `pos` of a 256-bit key, MSB-first / big-endian
// (RSMT v6a): pos 0 is the MSB of byte 0, pos 255 is the LSB of byte 31.
// Matches `key_bit_at` in crates/rsmt-verify/src/path.rs.
func KeyBitAt(key [32]byte, pos int) byte {
	return (key[pos/8] >> uint(7-pos%8)) & 1
}

// PrefixRegion packs the `depth`-bit region (key prefix [0..depth)) into a
// 32-byte big-endian bit string: the prefix occupies the first `depth` bits
// and the remaining suffix bits are zero. Matches `prefix_region` in
// crates/rsmt-verify/src/path.rs.
func PrefixRegion(key [32]byte, depth int) [32]byte {
	var region [32]byte
	fullBytes := depth / 8
	partialBits := depth % 8
	copy(region[:fullBytes], key[:fullBytes])
	if partialBits != 0 {
		mask := byte(0xff) << uint(8-partialBits)
		region[fullBytes] = key[fullBytes] & mask
	}
	return region
}

// regionWellFormed reports whether region's bits [depth, 256) are zero —
// the packing PrefixRegion produces. Matches `region_well_formed` in
// crates/rsmt-verify/src/consistency.rs.
func regionWellFormed(region [32]byte, depth int) bool {
	return PrefixRegion(region, depth) == region
}
