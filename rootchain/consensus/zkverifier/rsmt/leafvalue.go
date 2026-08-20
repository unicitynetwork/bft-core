package rsmt

import (
	"crypto/sha256"
	"encoding/binary"
)

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
	h.Write(cborByteStringHeader(transactionHash))
	h.Write(transactionHash)
	h.Write(cborUint(referenceTime))
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// cborByteStringHeader returns the shortest-form CBOR header for a byte
// string. Count directly into uint64 so no potentially narrowing or
// sign-changing integer conversion is involved.
func cborByteStringHeader(value []byte) []byte {
	var size uint64
	for range value {
		size++
	}
	return cborHead(2, size)
}

// cborUint returns the shortest-form CBOR encoding of an unsigned integer.
func cborUint(v uint64) []byte {
	return cborHead(0, v)
}

// cborHead encodes a CBOR head for major type t and argument n, in the
// shortest form deterministic CBOR requires.
func cborHead(t byte, n uint64) []byte {
	var encoded [9]byte
	binary.BigEndian.PutUint64(encoded[1:], n)

	switch {
	case n <= 23:
		encoded[0] = t<<5 | encoded[8]
		return encoded[:1]
	case n <= 0xff:
		encoded[0] = t<<5 | 24
		encoded[1] = encoded[8]
		return encoded[:2]
	case n <= 0xffff:
		encoded[0] = t<<5 | 25
		copy(encoded[1:3], encoded[7:9])
		return encoded[:3]
	case n <= 0xffffffff:
		encoded[0] = t<<5 | 26
		copy(encoded[1:5], encoded[5:9])
		return encoded[:5]
	default:
		encoded[0] = t<<5 | 27
		return encoded[:]
	}
}
