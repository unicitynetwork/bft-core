package rsmt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// Helpers to build opcode streams.

func opS(h [32]byte) []byte {
	out := make([]byte, 33)
	out[0] = 0x00
	copy(out[1:], h[:])
	return out
}

func opL() []byte { return []byte{0x01} }

func opN(depth uint8) []byte { return []byte{0x02, depth} }

func opO(depth uint8, region, left, right [32]byte) []byte {
	out := make([]byte, 1+1+32+32+32)
	out[0] = 0x03
	out[1] = depth
	copy(out[2:34], region[:])
	copy(out[34:66], left[:])
	copy(out[66:98], right[:])
	return out
}

func opOL(k [32]byte, v []byte) []byte {
	out := make([]byte, 0, 1+32+2+len(v))
	out = append(out, 0x04)
	out = append(out, k[:]...)
	var lhdr [2]byte
	binary.BigEndian.PutUint16(lhdr[:], uint16(len(v)))
	out = append(out, lhdr[:]...)
	out = append(out, v...)
	return out
}

func key(b byte) [32]byte {
	var k [32]byte
	k[0] = b
	return k
}

// TestKeyBitAt_MSBFirst locks in the RSMT v6a big-endian bit convention.
func TestKeyBitAt_MSBFirst(t *testing.T) {
	var k [32]byte
	k[0] = 0b1100_0010
	cases := []struct {
		pos  int
		want byte
	}{{0, 1}, {1, 1}, {2, 0}, {6, 1}, {7, 0}}
	for _, c := range cases {
		if got := KeyBitAt(k, c.pos); got != c.want {
			t.Fatalf("KeyBitAt(pos=%d) = %d, want %d", c.pos, got, c.want)
		}
	}
}

func TestPrefixRegion(t *testing.T) {
	var k [32]byte
	k[0] = 0b1111_1111
	got := PrefixRegion(k, 3)
	var want [32]byte
	want[0] = 0b1110_0000
	if got != want {
		t.Fatalf("PrefixRegion(depth=3) = %08b, want %08b", got[0], want[0])
	}
	if got := PrefixRegion(k, 0); got != ([32]byte{}) {
		t.Fatalf("PrefixRegion(depth=0) = %v, want zero", got)
	}
}

// TestVerify_EmptyBatch exercises the short-circuit: empty envelope, unchanged root.
func TestVerify_EmptyBatch(t *testing.T) {
	env := &Envelope{}
	var h [32]byte
	for i := range h {
		h[i] = 0xab
	}
	r := Root{Hash: h, Set: true}
	if err := Verify(env, r, r); err != nil {
		t.Fatalf("empty batch, equal roots: %v", err)
	}

	// Empty envelope with different roots must fail.
	var h2 [32]byte
	h2[0] = 0xff
	if err := Verify(env, r, Root{Hash: h2, Set: true}); !errors.Is(err, ErrEmptyBatchRootChange) {
		t.Fatalf("empty batch, different roots: got %v, want ErrEmptyBatchRootChange", err)
	}

	// Empty batch but non-empty proof must fail.
	env2 := &Envelope{Proof: []byte{0x00}}
	if err := Verify(env2, r, r); !errors.Is(err, ErrEmptyBatchNonEmptyProof) {
		t.Fatalf("empty batch, non-empty proof: got %v, want ErrEmptyBatchNonEmptyProof", err)
	}
}

// TestVerify_SingleLeafIntoEmptyTree inserts a single leaf into an empty tree.
// The proof stream is just [L]; after running, stack top is (None, HashLeaf(k,v)).
func TestVerify_SingleLeafIntoEmptyTree(t *testing.T) {
	k := key(0x05)
	v := []byte("hello")
	expected := HashLeaf(k, v)

	env := &Envelope{
		Leaves: []Leaf{{Key: k, Value: v}},
		Proof:  opL(),
	}
	if err := Verify(env, Root{}, Root{Hash: expected, Set: true}); err != nil {
		t.Fatalf("single leaf: %v", err)
	}

	// Wrong new root → ErrRootMismatch.
	var bad [32]byte
	if err := Verify(env, Root{}, Root{Hash: bad, Set: true}); !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("wrong new root: got %v, want ErrRootMismatch", err)
	}
	// Wrong old root (claims tree non-empty) → ErrRootMismatch.
	if err := Verify(env, Root{Hash: bad, Set: true}, Root{Hash: expected, Set: true}); !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("wrong old root: got %v, want ErrRootMismatch", err)
	}
}

// TestVerify_TwoLeavesIntoEmptyTree: two leaves diverging at bit 0 (MSB-first:
// byte 0 = 0x00 vs 0x80). Proof stream is [L, L, N(depth=0)].
func TestVerify_TwoLeavesIntoEmptyTree(t *testing.T) {
	k0 := key(0x00) // bit 0 (MSB) = 0 → goes left under a depth=0 split
	k1 := key(0x80) // bit 0 (MSB) = 1 → goes right
	v0 := []byte("v0")
	v1 := []byte("v1")

	// Leaves must be in plain key order. k0 < k1 lexicographically.
	leaves := []Leaf{{Key: k0, Value: v0}, {Key: k1, Value: v1}}

	l0 := HashLeaf(k0, v0)
	l1 := HashLeaf(k1, v1)
	region := PrefixRegion(k0, 0) // empty region at depth 0
	root := HashNode(l0, l1, 0, region)

	// Build [L, L, N(0)]
	var proof bytes.Buffer
	proof.Write(opL())
	proof.Write(opL())
	proof.Write(opN(0))

	env := &Envelope{Leaves: leaves, Proof: proof.Bytes()}
	if err := Verify(env, Root{}, Root{Hash: root, Set: true}); err != nil {
		t.Fatalf("two leaves: %v", err)
	}
}

// TestVerify_UnsortedLeavesRejected feeds two leaves in reverse key order.
func TestVerify_UnsortedLeavesRejected(t *testing.T) {
	k0 := key(0x00)
	k1 := key(0x80)
	leaves := []Leaf{
		{Key: k1, Value: []byte("v1")}, // sorts AFTER k0 — wrong order
		{Key: k0, Value: []byte("v0")},
	}
	var proof bytes.Buffer
	proof.Write(opL())
	proof.Write(opL())
	proof.Write(opN(0))
	env := &Envelope{Leaves: leaves, Proof: proof.Bytes()}
	if err := Verify(env, Root{}, Root{Set: true}); !errors.Is(err, ErrLeavesUnsorted) {
		t.Fatalf("unsorted: got %v, want ErrLeavesUnsorted", err)
	}
}

// TestVerify_DuplicateLeavesRejected: duplicate key violates strict ordering.
func TestVerify_DuplicateLeavesRejected(t *testing.T) {
	k := key(0x01)
	env := &Envelope{
		Leaves: []Leaf{
			{Key: k, Value: []byte("a")},
			{Key: k, Value: []byte("b")},
		},
		Proof: append(append(opL(), opL()...), opN(0)...),
	}
	if err := Verify(env, Root{}, Root{Set: true}); !errors.Is(err, ErrLeavesUnsorted) {
		t.Fatalf("duplicate key: got %v, want ErrLeavesUnsorted", err)
	}
}

// TestVerify_InsertIntoExistingTree: existing single leaf at key(0x00);
// new leaf at key(0x80). After insertion the tree is a 2-leaf tree. Because
// the pre-existing leaf becomes the child of a junction created this round
// (an edge split), it must be presented opened (O_L), not opaque (S).
func TestVerify_InsertIntoExistingTree(t *testing.T) {
	kOld := key(0x00) // bit 0 (MSB) = 0 → left
	vOld := []byte("old")
	kNew := key(0x80) // bit 0 (MSB) = 1 → right
	vNew := []byte("new")

	hOld := HashLeaf(kOld, vOld)
	hNew := HashLeaf(kNew, vNew)
	oldRoot := hOld // single-leaf tree
	region := PrefixRegion(kOld, 0)
	newRoot := HashNode(hOld, hNew, 0, region)

	leaves := []Leaf{{Key: kNew, Value: vNew}}

	// Proof order: left subtree first (kOld, opened since it becomes a
	// child of the new junction), then right subtree (kNew, new leaf → L),
	// then N(0).
	var proof bytes.Buffer
	proof.Write(opOL(kOld, vOld))
	proof.Write(opL())
	proof.Write(opN(0))

	env := &Envelope{Leaves: leaves, Proof: proof.Bytes()}
	if err := Verify(env, Root{Hash: oldRoot, Set: true}, Root{Hash: newRoot, Set: true}); err != nil {
		t.Fatalf("insert into existing tree: %v", err)
	}

	// The same subtree presented opaquely (as S) instead of opened (as O_L)
	// must be REJECTED: an opaque S may not attach to a new edge.
	var badProof bytes.Buffer
	badProof.Write(opS(hOld))
	badProof.Write(opL())
	badProof.Write(opN(0))
	badEnv := &Envelope{Leaves: leaves, Proof: badProof.Bytes()}
	if err := Verify(badEnv, Root{Hash: oldRoot, Set: true}, Root{Hash: newRoot, Set: true}); !errors.Is(err, ErrOpaqueOnNewEdge) {
		t.Fatalf("opaque S on new edge: got %v, want ErrOpaqueOnNewEdge", err)
	}
}

// TestVerify_DeepSplitWithO: two pre-existing leaves sharing a 4-bit prefix
// form one internal junction. A new leaf diverges from that shared prefix
// at bit 2 — before the existing junction's own depth — forcing a new
// junction above it; the preserved junction must be presented opened (O).
func TestVerify_DeepSplitWithO(t *testing.T) {
	var keyA, keyB [32]byte
	keyA[0] = 0b0000_0000 // bits 0..3 = 0000, bit 4 = 0
	keyB[0] = 0b0000_1000 // bits 0..3 = 0000, bit 4 = 1
	vA, vB := []byte("a"), []byte("b")

	hA := HashLeaf(keyA, vA)
	hB := HashLeaf(keyB, vB)
	innerRegion := PrefixRegion(keyA, 4)
	oldRoot := HashNode(hA, hB, 4, innerRegion)

	var keyC [32]byte
	keyC[0] = 0b0010_0000 // bits 0..1 = 00, bit 2 = 1: diverges before depth 4
	vC := []byte("c")
	hC := HashLeaf(keyC, vC)

	outerRegion := PrefixRegion(keyA, 2)
	newRoot := HashNode(oldRoot, hC, 2, outerRegion)

	leaves := []Leaf{{Key: keyC, Value: vC}}

	// Post-order: left subtree (the preserved junction, opened via O),
	// right subtree (new leaf → L), then the new outer junction N(2).
	var proof bytes.Buffer
	proof.Write(opO(4, innerRegion, hA, hB))
	proof.Write(opL())
	proof.Write(opN(2))

	env := &Envelope{Leaves: leaves, Proof: proof.Bytes()}
	if err := Verify(env, Root{Hash: oldRoot, Set: true}, Root{Hash: newRoot, Set: true}); err != nil {
		t.Fatalf("deep split with O: %v", err)
	}
}

// TestVerify_MalformedRegionRejected: an O opcode whose region has nonzero
// bits at or beyond its claimed depth must be rejected.
func TestVerify_MalformedRegionRejected(t *testing.T) {
	var badRegion [32]byte
	badRegion[0] = 0xFF // depth=3 region should have only the top 3 bits set
	env := singleLeafEnvelope(opO(3, badRegion, key(0x01), key(0x02)))
	if err := Verify(env, Root{}, Root{Set: true}); !errors.Is(err, ErrMalformedRegion) {
		t.Fatalf("got %v, want ErrMalformedRegion", err)
	}
}

// TestVerify_BatchUnderrun: proof references more leaves than provided.
func TestVerify_BatchUnderrun(t *testing.T) {
	env := &Envelope{
		Leaves: []Leaf{{Key: key(0x01), Value: []byte("v")}},
		Proof:  append(opL(), opL()...),
	}
	if err := Verify(env, Root{}, Root{Set: true}); !errors.Is(err, ErrBatchUnderrun) {
		t.Fatalf("got %v, want ErrBatchUnderrun", err)
	}
}

// TestVerify_BatchUnused: more leaves than opcode L references.
func TestVerify_BatchUnused(t *testing.T) {
	env := &Envelope{
		Leaves: []Leaf{
			{Key: key(0x00), Value: []byte("a")},
			{Key: key(0x80), Value: []byte("b")},
		},
		Proof: opL(),
	}
	if err := Verify(env, Root{}, Root{Set: true}); !errors.Is(err, ErrBatchUnused) {
		t.Fatalf("got %v, want ErrBatchUnused", err)
	}
}

// singleLeafEnvelope returns an envelope with one leaf so opcode-level tests
// bypass the empty-batch short-circuit.
func singleLeafEnvelope(proof []byte) *Envelope {
	return &Envelope{
		Leaves: []Leaf{{Key: key(0x01), Value: []byte("v")}},
		Proof:  proof,
	}
}

// TestVerify_TruncatedOpcodeStream: S without its 32-byte payload.
func TestVerify_TruncatedOpcodeStream(t *testing.T) {
	env := singleLeafEnvelope([]byte{0x00, 0x01, 0x02}) // S, truncated
	if err := Verify(env, Root{}, Root{Set: true}); !errors.Is(err, ErrOpcodeTruncated) {
		t.Fatalf("got %v, want ErrOpcodeTruncated", err)
	}
}

// TestVerify_BadOpcode.
func TestVerify_BadOpcode(t *testing.T) {
	env := singleLeafEnvelope([]byte{0x7f})
	if err := Verify(env, Root{}, Root{Set: true}); !errors.Is(err, ErrBadOpcode) {
		t.Fatalf("got %v, want ErrBadOpcode", err)
	}
}

// TestVerify_StackUnderflow: N without two children.
func TestVerify_StackUnderflow(t *testing.T) {
	env := singleLeafEnvelope(opN(0))
	if err := Verify(env, Root{}, Root{Set: true}); !errors.Is(err, ErrStackUnderflow) {
		t.Fatalf("got %v, want ErrStackUnderflow", err)
	}
}

func TestEnvelope_RoundTrip(t *testing.T) {
	leaves := []Leaf{
		{Key: key(0x00), Value: []byte("alpha")},
		{Key: key(0x01), Value: []byte{}},
		{Key: key(0x02), Value: bytes.Repeat([]byte{0xAB}, 1234)},
	}
	proof := []byte{0x01, 0x01, 0x01, 0x02, 0x05}
	buf, err := EncodeEnvelope(leaves, proof)
	if err != nil {
		t.Fatal(err)
	}
	env, err := DecodeEnvelope(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(env.Leaves) != len(leaves) {
		t.Fatalf("leaf count: got %d, want %d", len(env.Leaves), len(leaves))
	}
	for i := range leaves {
		if env.Leaves[i].Key != leaves[i].Key {
			t.Errorf("leaf %d key mismatch", i)
		}
		if !bytes.Equal(env.Leaves[i].Value, leaves[i].Value) {
			t.Errorf("leaf %d value mismatch", i)
		}
	}
	if !bytes.Equal(env.Proof, proof) {
		t.Errorf("proof mismatch")
	}
}

func TestEnvelope_Truncated(t *testing.T) {
	if _, err := DecodeEnvelope([]byte{0x00, 0x00, 0x00}); !errors.Is(err, ErrEnvelopeTruncated) {
		t.Fatalf("short header: got %v", err)
	}
	// leaf_count = 1, but only half a key present
	buf := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00}
	if _, err := DecodeEnvelope(buf); !errors.Is(err, ErrEnvelopeTruncated) {
		t.Fatalf("short leaf header: got %v", err)
	}
	// leaf_count = 1, full key, value_len=10, but value missing
	buf = make([]byte, 4+32+2)
	buf[3] = 0x01    // leaf_count = 1
	buf[4+32+1] = 10 // value_len = 10
	if _, err := DecodeEnvelope(buf); !errors.Is(err, ErrEnvelopeTruncated) {
		t.Fatalf("short value: got %v", err)
	}
}

func TestEnvelope_TooManyLeaves(t *testing.T) {
	buf := []byte{0xFF, 0xFF, 0xFF, 0xFF} // leaf_count = 2^32-1
	if _, err := DecodeEnvelope(buf); !errors.Is(err, ErrEnvelopeTooManyLeaves) {
		t.Fatalf("got %v, want ErrEnvelopeTooManyLeaves", err)
	}
}

func TestEnvelope_MaxValueLen(t *testing.T) {
	oversize := make([]byte, 0x10000) // 65536 > u16::max
	_, err := EncodeEnvelope([]Leaf{{Value: oversize}}, nil)
	if err == nil {
		t.Fatalf("expected oversize value to fail encode")
	}
}

func TestRootFromBytes(t *testing.T) {
	if r, err := RootFromBytes(nil); err != nil || r.Set {
		t.Fatalf("nil: got %+v, %v", r, err)
	}
	if r, err := RootFromBytes([]byte{}); err != nil || r.Set {
		t.Fatalf("empty: got %+v, %v", r, err)
	}
	if _, err := RootFromBytes([]byte{1, 2, 3}); err == nil {
		t.Fatalf("expected error on 3-byte input")
	}
	thirtyTwo := make([]byte, 32)
	thirtyTwo[5] = 0xAA
	r, err := RootFromBytes(thirtyTwo)
	if err != nil || !r.Set || r.Hash[5] != 0xAA {
		t.Fatalf("32 bytes: got %+v, %v", r, err)
	}
}
