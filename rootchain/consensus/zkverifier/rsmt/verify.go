package rsmt

import (
	"bytes"
	"encoding/binary"
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
	ErrLeavesUnsorted          = errors.New("rsmt: leaves not sorted by key")
	ErrEmptyBatchNonEmptyProof = errors.New("rsmt: empty batch but non-empty proof")
	ErrEmptyBatchRootChange    = errors.New("rsmt: empty batch but root changed")
	ErrMalformedRegion         = errors.New("rsmt: region has nonzero bits beyond depth")
	ErrNoAdvice                = errors.New("rsmt: N opcode with no advised child")
	ErrAdviceDepth             = errors.New("rsmt: advised child depth not strictly greater than junction depth")
	ErrAdviceSide              = errors.New("rsmt: advised child region disagrees with its side at the junction depth")
	ErrRegionMismatch          = errors.New("rsmt: advised children disagree on the derived junction region")
	ErrOpaqueOnNewEdge         = errors.New("rsmt: opaque S may not attach to a junction absent from the pre-state")
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

// advice carries the depth and region of a stack entry's top node — the
// subtree's authenticated position in the key space. Set == false for
// opaque S subtrees, whose top node is not disclosed. Depth is 256 for
// leaves (wire N/O opcodes only carry uint8 depths, 0..255; 256 is an
// internal sentinel for "leaf", matching the Yellowpaper's `(256, k)`).
// Matches `Advice` in crates/rsmt-verify/src/consistency.rs.
type advice struct {
	set    bool
	depth  uint16
	region [32]byte
}

// stackEntry is a (pre_hash, post_hash, advice) triple.
// Matches the stack entries in `verify_consistency_with`
// (crates/rsmt-verify/src/consistency.rs).
type stackEntry struct {
	pre, post       [32]byte
	preSet, postSet bool
	adv             advice
}

// Verify recomputes the old and new SMT roots from the envelope and checks
// them against oldRoot / newRoot. Returns nil iff the envelope is a valid
// consistency proof for the claimed transition.
//
// Leaves in env.Leaves MUST already be sorted by plain key order (RSMT v6a:
// rsmt_sort_key(k) = k), with no duplicates. The verifier performs a single
// linear pre-check to enforce this invariant.
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

	// Assert leaves are in plain key order (also rejects duplicates).
	for i := 1; i < len(env.Leaves); i++ {
		if bytes.Compare(env.Leaves[i-1].Key[:], env.Leaves[i].Key[:]) >= 0 {
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
		case 0x00: // S(h): opaque preserved subtree — push (h, h, no advice)
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
			stack = append(stack, stackEntry{
				post: lh, postSet: true,
				adv: advice{set: true, depth: 256, region: leaf.Key},
			})

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

			// Derive the junction region from every advised child; all
			// advised children must agree, and at least one is required.
			var p [32]byte
			var pSet bool
			sides := [2]struct {
				a    advice
				side byte
			}{{left.adv, 0}, {right.adv, 1}}
			for _, s := range sides {
				if !s.a.set {
					continue
				}
				if s.a.depth <= uint16(depth) {
					return ErrAdviceDepth
				}
				if KeyBitAt(s.a.region, int(depth)) != s.side {
					return ErrAdviceSide
				}
				candidate := PrefixRegion(s.a.region, int(depth))
				if pSet && candidate != p {
					return ErrRegionMismatch
				}
				p = candidate
				pSet = true
			}
			if !pSet {
				return ErrNoAdvice
			}

			// Junction absent from the pre-state ⇒ neither child may be an
			// opaque S (no opaque child may attach to a new edge).
			isNew := !left.preSet || !right.preSet
			if isNew && (!left.adv.set || !right.adv.set) {
				return ErrOpaqueOnNewEdge
			}

			var combined stackEntry
			switch {
			case !left.preSet && !right.preSet:
				// Both children new — no pre-state hash at this level.
			case !left.preSet:
				combined.pre, combined.preSet = right.pre, right.preSet
			case !right.preSet:
				combined.pre, combined.preSet = left.pre, left.preSet
			default:
				combined.pre = HashNode(left.pre, right.pre, depth, p)
				combined.preSet = true
			}

			if !left.postSet || !right.postSet {
				return ErrPostStateMissing
			}
			combined.post = HashNode(left.post, right.post, depth, p)
			combined.postSet = true
			combined.adv = advice{set: true, depth: uint16(depth), region: p}

			stack = append(stack, combined)

		case 0x03: // O(depth, region, left, right): preserved junction, opened one level
			if pi+1+32+32+32 > len(proof) {
				return fmt.Errorf("%w: O payload", ErrOpcodeTruncated)
			}
			depth := proof[pi]
			pi++
			var region, oleft, oright [32]byte
			copy(region[:], proof[pi:pi+32])
			pi += 32
			copy(oleft[:], proof[pi:pi+32])
			pi += 32
			copy(oright[:], proof[pi:pi+32])
			pi += 32
			if !regionWellFormed(region, int(depth)) {
				return ErrMalformedRegion
			}
			h := HashNode(oleft, oright, depth, region)
			stack = append(stack, stackEntry{
				pre: h, post: h, preSet: true, postSet: true,
				adv: advice{set: true, depth: uint16(depth), region: region},
			})

		case 0x04: // O_L(key, value): preserved leaf, opened
			if pi+32+2 > len(proof) {
				return fmt.Errorf("%w: O_L header", ErrOpcodeTruncated)
			}
			var k [32]byte
			copy(k[:], proof[pi:pi+32])
			pi += 32
			vlen := int(binary.BigEndian.Uint16(proof[pi : pi+2]))
			pi += 2
			if pi+vlen > len(proof) {
				return fmt.Errorf("%w: O_L value", ErrOpcodeTruncated)
			}
			v := proof[pi : pi+vlen]
			pi += vlen
			h := HashLeaf(k, v)
			stack = append(stack, stackEntry{
				pre: h, post: h, preSet: true, postSet: true,
				adv: advice{set: true, depth: 256, region: k},
			})

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
