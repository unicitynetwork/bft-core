package rsmt

import "crypto/sha256"

// LeafValue derives the stored SMT leaf value from a declared transaction hash
// and the round's reference time:
//
//	SHA-256( CBOR([transactionHash, referenceTime]) )
//
// The declared batch carries transaction hashes; the tree stores leaf values
// that bind the round's reference time. Deriving them here rather than
// accepting a supplied leaf value is what makes a wrong reference time
// unrepresentable: a shard that built its tree under any other reference time
// produces a root this verifier does not reproduce, so the round is rejected
// rather than merely attributable afterwards.
//
// The encoding is a two-element deterministic CBOR array: a byte string of the
// transaction hash followed by the reference time as an unsigned integer.
// Matches `leaf_value` in crates/rsmt-verify/src/leaf_value.rs.
func LeafValue(transactionHash []byte, referenceTime uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x82}) // array(2)
	h.Write(cborByteStringHeader(len(transactionHash)))
	h.Write(transactionHash)
	h.Write(cborUint(referenceTime))
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// cborByteStringHeader returns the shortest-form CBOR header for a byte string
// of n bytes.
func cborByteStringHeader(n int) []byte {
	return cborHead(2, uint64(n))
}

// cborUint returns the shortest-form CBOR encoding of an unsigned integer.
func cborUint(v uint64) []byte {
	return cborHead(0, v)
}

// cborHead encodes a CBOR head for major type t and argument n, in the
// shortest form deterministic CBOR requires.
func cborHead(t byte, n uint64) []byte {
	switch {
	case n <= 23:
		return []byte{t<<5 | byte(n)}
	case n <= 0xff:
		return []byte{t<<5 | 24, byte(n)}
	case n <= 0xffff:
		return []byte{t<<5 | 25, byte(n >> 8), byte(n)}
	case n <= 0xffffffff:
		return []byte{t<<5 | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		return []byte{
			t<<5 | 27,
			byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32),
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
		}
	}
}
