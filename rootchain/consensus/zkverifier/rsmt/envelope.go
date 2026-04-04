package rsmt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// MaxLeafCount bounds the number of leaves in a single envelope to prevent
// pathological allocations from malicious inputs. A batch of 1M leaves would
// already dwarf any realistic aggregator round.
const MaxLeafCount = 1 << 20

// Leaf is a single (key, value) pair in the batch carried by the envelope.
// Value is a slice into the original envelope buffer; callers must copy it
// if they need to retain it after the buffer is reused.
type Leaf struct {
	Key   [32]byte
	Value []byte
}

// Envelope is the decoded contents of a zk_proof field for the
// `aggregator_rsmt_v1` proof type.
//
// Leaves are in wire order (caller-sorted by SortKey); Proof is the flat
// opcode stream. See package doc for the full wire format.
type Envelope struct {
	Leaves []Leaf
	Proof  []byte
}

// Envelope decoding errors.
var (
	ErrEnvelopeTruncated     = errors.New("rsmt: envelope truncated")
	ErrEnvelopeTooManyLeaves = errors.New("rsmt: envelope leaf count exceeds maximum")
)

// DecodeEnvelope parses the wire format described in the package doc.
// It returns a view over the input buffer: Leaf values alias into b.
func DecodeEnvelope(b []byte) (*Envelope, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("%w: missing leaf_count", ErrEnvelopeTruncated)
	}
	count := binary.BigEndian.Uint32(b[0:4])
	if count > MaxLeafCount {
		return nil, fmt.Errorf("%w: %d > %d", ErrEnvelopeTooManyLeaves, count, MaxLeafCount)
	}
	pos := 4
	leaves := make([]Leaf, 0, count)
	for i := uint32(0); i < count; i++ {
		if pos+32+2 > len(b) {
			return nil, fmt.Errorf("%w: leaf %d header", ErrEnvelopeTruncated, i)
		}
		var key [32]byte
		copy(key[:], b[pos:pos+32])
		pos += 32
		vlen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
		pos += 2
		if pos+vlen > len(b) {
			return nil, fmt.Errorf("%w: leaf %d value (need %d, have %d)",
				ErrEnvelopeTruncated, i, vlen, len(b)-pos)
		}
		leaves = append(leaves, Leaf{Key: key, Value: b[pos : pos+vlen]})
		pos += vlen
	}
	return &Envelope{Leaves: leaves, Proof: b[pos:]}, nil
}

// EncodeEnvelope produces the wire format for the given (already sorted)
// leaves and flat opcode stream. Provided primarily for tests and fixtures;
// production envelopes are built by the Rust aggregator.
func EncodeEnvelope(leaves []Leaf, proof []byte) ([]byte, error) {
	numLeaves := len(leaves)
	if numLeaves > MaxLeafCount {
		return nil, fmt.Errorf("%w: %d > %d", ErrEnvelopeTooManyLeaves, numLeaves, MaxLeafCount)
	}
	size := 4 + len(proof)
	for i := range leaves {
		vlen := len(leaves[i].Value)
		if vlen > math.MaxUint16 {
			return nil, fmt.Errorf("rsmt: leaf %d value length %d exceeds u16 max",
				i, vlen)
		}
		size += 32 + 2 + vlen
	}
	out := make([]byte, 0, size)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(numLeaves))
	out = append(out, hdr[:]...)
	for i := range leaves {
		out = append(out, leaves[i].Key[:]...)
		var lhdr [2]byte
		vlen := len(leaves[i].Value)
		if vlen > math.MaxUint16 {
			return nil, fmt.Errorf("rsmt: leaf %d value length %d exceeds u16 max",
				i, vlen)
		}
		binary.BigEndian.PutUint16(lhdr[:], uint16(vlen))
		out = append(out, lhdr[:]...)
		out = append(out, leaves[i].Value...)
	}
	out = append(out, proof...)
	return out, nil
}
