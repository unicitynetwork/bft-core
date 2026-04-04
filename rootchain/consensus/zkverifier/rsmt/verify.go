package rsmt

import (
	"bytes"
	"errors"
	"fmt"
)

// Verification errors.
var (
	ErrBadOpcode               = errors.New("rsmt: bad opcode")
	ErrOpcodeTruncated         = errors.New("rsmt: opcode stream truncated")
	ErrStackUnderflow          = errors.New("rsmt: stack underflow")
	ErrStackFinal              = errors.New("rsmt: stack not reduced to single element")
	ErrRootMismatch            = errors.New("rsmt: recomputed root does not match claimed root")
	ErrBatchUnderrun           = errors.New("rsmt: opcode stream references more leaves than provided")
	ErrBatchUnused             = errors.New("rsmt: not all leaves consumed by opcode stream")
	ErrPostStateMissing        = errors.New("rsmt: N opcode with missing post-state child")
	ErrLeavesUnsorted          = errors.New("rsmt: leaves not sorted by SortKey")
	ErrEmptyBatchNonEmptyProof = errors.New("rsmt: empty batch but non-empty proof")
	ErrEmptyBatchRootChange    = errors.New("rsmt: empty batch but root changed")
)

// Root represents an optional 32-byte SMT root: Set == false models the
// None case (empty tree). Matches `Option<[u8;32]>` on the Rust side.
type Root struct {
	Hash [32]byte
	Set  bool
}

// RootFromBytes constructs a Root from a 0- or 32-byte slice. Empty slice or
// nil is treated as "no root" (empty tree); any other length is an error.
func RootFromBytes(b []byte) (Root, error) {
	if len(b) == 0 {
		return Root{}, nil
	}
	if len(b) != 32 {
		return Root{}, fmt.Errorf("rsmt: root must be 32 bytes, got %d", len(b))
	}
	var r Root
	copy(r.Hash[:], b)
	r.Set = true
	return r, nil
}

// stackEntry is a (pre_hash, post_hash) pair; flags track the Option<..> side.
// Matches `(Option<[u8;32]>, Option<[u8;32]>)` in crates/rsmt/src/consistency.rs.
type stackEntry struct {
	pre, post       [32]byte
	preSet, postSet bool
}

// Verify recomputes the old and new SMT roots from the envelope and checks
// them against oldRoot / newRoot. Returns nil iff the envelope is a valid
// consistency proof for the claimed transition.
//
// Leaves in env.Leaves MUST already be sorted by SortKey (with no duplicates).
// The verifier performs a single linear pre-check to enforce this invariant.
func Verify(env *Envelope, oldRoot, newRoot Root) error {
	if env == nil {
		return errors.New("rsmt: nil envelope")
	}

	// Empty batch: must have empty proof and unchanged root.
	if len(env.Leaves) == 0 {
		if len(env.Proof) != 0 {
			return ErrEmptyBatchNonEmptyProof
		}
		if oldRoot.Set != newRoot.Set || (oldRoot.Set && oldRoot.Hash != newRoot.Hash) {
			return ErrEmptyBatchRootChange
		}
		return nil
	}

	// Assert leaves are in SortKey order (also rejects duplicates).
	// TODO: remove if implementation is stable
	for i := 1; i < len(env.Leaves); i++ {
		if !sortKeyLess(env.Leaves[i-1].Key, env.Leaves[i].Key) {
			return fmt.Errorf("%w: at index %d", ErrLeavesUnsorted, i)
		}
	}

	stack := make([]stackEntry, 0, 64)
	proof := env.Proof
	bi := 0
	pi := 0

	for pi < len(proof) {
		op := proof[pi]
		pi++
		switch op {
		case 0x00: // S(h): push (h, h)
			if pi+32 > len(proof) {
				return fmt.Errorf("%w: S payload", ErrOpcodeTruncated)
			}
			var h [32]byte
			copy(h[:], proof[pi:pi+32])
			pi += 32
			stack = append(stack, stackEntry{pre: h, post: h, preSet: true, postSet: true})

		case 0x01: // L: consume next leaf
			if bi >= len(env.Leaves) {
				return ErrBatchUnderrun
			}
			leaf := &env.Leaves[bi]
			bi++
			lh := HashLeaf(leaf.Key, leaf.Value)
			stack = append(stack, stackEntry{post: lh, postSet: true})

		case 0x02: // N(depth): pop right, pop left, push combined
			if pi >= len(proof) {
				return fmt.Errorf("%w: N depth", ErrOpcodeTruncated)
			}
			depth := proof[pi]
			pi++
			if len(stack) < 2 {
				return ErrStackUnderflow
			}
			right := stack[len(stack)-1]
			left := stack[len(stack)-2]
			stack = stack[:len(stack)-2]

			// pre-state: None children propagate their sibling's pre-hash.
			var combined stackEntry
			switch {
			case !left.preSet && !right.preSet:
				// Both children new — no pre-state hash at this level.
			case !left.preSet:
				combined.pre = right.pre
				combined.preSet = right.preSet
			case !right.preSet:
				combined.pre = left.pre
				combined.preSet = left.preSet
			default:
				combined.pre = HashNode(left.pre, right.pre, depth)
				combined.preSet = true
			}

			// post-state: both children MUST have a post-hash.
			if !left.postSet || !right.postSet {
				return ErrPostStateMissing
			}
			combined.post = HashNode(left.post, right.post, depth)
			combined.postSet = true

			stack = append(stack, combined)

		default:
			return fmt.Errorf("%w: 0x%02x", ErrBadOpcode, op)
		}
	}

	if bi != len(env.Leaves) {
		return ErrBatchUnused
	}
	if len(stack) != 1 {
		return ErrStackFinal
	}

	top := stack[0]
	if top.preSet != oldRoot.Set || top.postSet != newRoot.Set {
		return ErrRootMismatch
	}
	if top.preSet && !bytes.Equal(top.pre[:], oldRoot.Hash[:]) {
		return ErrRootMismatch
	}
	if top.postSet && !bytes.Equal(top.post[:], newRoot.Hash[:]) {
		return ErrRootMismatch
	}
	return nil
}
