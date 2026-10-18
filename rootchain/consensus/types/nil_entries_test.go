package types

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

type acceptAllVerifier struct{}

func (acceptAllVerifier) GetQuorum() uint64                                               { return 1 }
func (acceptAllVerifier) GetTotalNodes() uint64                                           { return 10 }
func (acceptAllVerifier) ValidRequest(req *certification.BlockCertificationRequest) error { return nil }

// CBOR nulls inside the collections of a block payload decode to nil entries; they are rejected before anything
// dereferences them (bft-go-base#17 follow-up: reachable from unsigned messages).
func TestNilEntries_InPayloadAndIRChangeRequests(t *testing.T) {
	t.Run("nil IR change request in the payload", func(t *testing.T) {
		p := &Payload{Requests: []*IRChangeReq{nil}}
		require.NotPanics(t, func() { require.ErrorContains(t, p.IsValid(), "IR change request 0 is nil") })
		b := &BlockData{Round: 5, Payload: p, Qc: &QuorumCert{}}
		require.NotPanics(t, func() { require.Error(t, b.IsValid()) })
	})
	t.Run("nil IR change request", func(t *testing.T) {
		var r *IRChangeReq
		require.Error(t, r.IsValid())
	})
	t.Run("nil certification request in an IR change request", func(t *testing.T) {
		r := &IRChangeReq{Partition: 1, CertReason: Quorum, Requests: []*certification.BlockCertificationRequest{nil}}
		require.NotPanics(t, func() {
			_, err := r.Verify(acceptAllVerifier{}, &types.UnicityCertificate{}, 5, 1)
			require.ErrorContains(t, err, "certification request 0 is nil")
		})
	})
	t.Run("nil entries in a timeout certificate", func(t *testing.T) {
		tc := &TimeoutCert{Timeout: &Timeout{Round: 2}, Signatures: map[string]*TimeoutVote{"a": nil}}
		require.ErrorContains(t, tc.IsValid(), "timeout vote of \"a\" is nil")
		var tmo *Timeout
		require.Error(t, tmo.IsValid())
	})
}
