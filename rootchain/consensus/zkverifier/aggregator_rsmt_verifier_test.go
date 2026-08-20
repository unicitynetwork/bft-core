package zkverifier

import (
	"bytes"
	"errors"
	"testing"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier/rsmt"
	"github.com/unicitynetwork/bft-go-base/types"
)

// verifierTestReferenceTime is the round reference time these tests certify
// under; only aggregator proofs derive leaf values from it.
const verifierTestReferenceTime uint64 = 1755000000

// newLeafValue derives the value the tree stores for a leaf inserted this
// round. The envelope declares the transaction hash and the verifier derives
// this from it, so the expected root has to be built the same way.
func newLeafValue(declared []byte) []byte {
	v := rsmt.LeafValue(declared, verifierTestReferenceTime)
	return v[:]
}

func TestAggregatorRSMTVerifier_SingleLeafIntoEmptyTree(t *testing.T) {
	var k [32]byte
	k[0] = 0x05
	v := []byte("hello")
	leafHash := rsmt.HashLeaf(k, newLeafValue(v))

	env, err := rsmt.EncodeEnvelope(
		[]rsmt.Leaf{{Key: k, Value: v}},
		[]byte{0x01}, // L
	)
	if err != nil {
		t.Fatal(err)
	}

	ver := NewAggregatorRSMTVerifier()
	if !ver.IsEnabled() {
		t.Fatal("expected IsEnabled()")
	}
	if ver.ProofType() != ProofTypeAggregatorRSMTv1 {
		t.Fatalf("unexpected ProofType %q", ver.ProofType())
	}

	// Genesis-to-first-leaf: prev nil, new = hashLeaf.
	if err := ver.VerifyProof(env, nil, leafHash[:], nil, verifierTestReferenceTime); err != nil {
		t.Fatalf("VerifyProof: %v", err)
	}

	// Wrong new root.
	bad := make([]byte, 32)
	if err := ver.VerifyProof(env, nil, bad, nil, verifierTestReferenceTime); !errors.Is(err, ErrProofVerificationFailed) {
		t.Fatalf("wrong root: got %v, want ErrProofVerificationFailed", err)
	}

	// Malformed envelope.
	if err := ver.VerifyProof([]byte{0x00}, nil, leafHash[:], nil, verifierTestReferenceTime); !errors.Is(err, ErrInvalidProofFormat) {
		t.Fatalf("malformed envelope: got %v, want ErrInvalidProofFormat", err)
	}

	// Wrong-length previous root.
	if err := ver.VerifyProof(env, []byte{1, 2, 3}, leafHash[:], nil, verifierTestReferenceTime); !errors.Is(err, ErrInvalidProofFormat) {
		t.Fatalf("bad prev root length: got %v, want ErrInvalidProofFormat", err)
	}
}

// A round built under a reference time other than CR.IR.t produces a root the
// Core does not reproduce. This is what makes a wrong reference time
// unrepresentable rather than merely attributable afterwards.
func TestAggregatorRSMTVerifier_RejectsWrongReferenceTime(t *testing.T) {
	var k [32]byte
	k[0] = 0x05
	v := []byte("hello")
	leafHash := rsmt.HashLeaf(k, newLeafValue(v))

	env, err := rsmt.EncodeEnvelope(
		[]rsmt.Leaf{{Key: k, Value: v}},
		[]byte{0x01},
	)
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}

	ver := NewAggregatorRSMTVerifier()
	if err := ver.VerifyProof(env, nil, leafHash[:], nil, verifierTestReferenceTime); err != nil {
		t.Fatalf("baseline VerifyProof: %v", err)
	}
	if err := ver.VerifyProof(env, nil, leafHash[:], nil, verifierTestReferenceTime+1); err == nil {
		t.Fatal("VerifyProof accepted a round built under a different reference time")
	}
}

func TestAggregatorRSMTVerifier_TwoLeaves(t *testing.T) {
	var k0, k1 [32]byte
	k0[0] = 0x00 // bit 0 (MSB) = 0 → left under depth-0 split
	k1[0] = 0x80 // bit 0 (MSB) = 1 → right
	v0 := []byte("v0")
	v1 := []byte("v1")

	h0 := rsmt.HashLeaf(k0, newLeafValue(v0))
	h1 := rsmt.HashLeaf(k1, newLeafValue(v1))
	region := rsmt.PrefixRegion(k0, 0)
	newRoot := rsmt.HashNode(h0, h1, 0, region)

	var proof bytes.Buffer
	proof.WriteByte(0x01) // L (k0)
	proof.WriteByte(0x01) // L (k1)
	proof.WriteByte(0x02) // N
	proof.WriteByte(0x00) //   depth=0

	env, err := rsmt.EncodeEnvelope(
		[]rsmt.Leaf{{Key: k0, Value: v0}, {Key: k1, Value: v1}},
		proof.Bytes(),
	)
	if err != nil {
		t.Fatal(err)
	}

	ver := NewAggregatorRSMTVerifier()
	if err := ver.VerifyProof(env, nil, newRoot[:], nil, verifierTestReferenceTime); err != nil {
		t.Fatalf("VerifyProof: %v", err)
	}
}

func TestRegistry_AggregatorRSMT(t *testing.T) {
	reg := NewRegistry()
	params := map[string]string{ParamProofType: string(ProofTypeAggregatorRSMTv1)}
	v, err := reg.GetVerifier(types.PartitionID(42), types.ShardID{}, 0, params)
	if err != nil {
		t.Fatalf("GetVerifier: %v", err)
	}
	if _, ok := v.(*AggregatorRSMTVerifier); !ok {
		t.Fatalf("registry returned %T, want *AggregatorRSMTVerifier", v)
	}
	if !v.IsEnabled() {
		t.Fatalf("verifier not enabled")
	}
	if v.ProofType() != ProofTypeAggregatorRSMTv1 {
		t.Fatalf("wrong proof type %q", v.ProofType())
	}

	// Cached on repeat call.
	v2, err := reg.GetVerifier(types.PartitionID(42), types.ShardID{}, 0, params)
	if err != nil {
		t.Fatal(err)
	}
	if v != v2 {
		t.Fatalf("registry did not cache verifier")
	}
}
