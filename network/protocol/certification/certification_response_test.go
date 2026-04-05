package certification

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-go-base/types"
)

func Test_CertificationResponse_IsValid(t *testing.T) {
	validCR := func(t *testing.T) *CertificationResponse {
		cr := &CertificationResponse{
			Partition: 1,
			Shard:     types.ShardID{},
			UC: types.UnicityCertificate{
				Version: 1,
				UnicityTreeCertificate: &types.UnicityTreeCertificate{
					Version:   1,
					Partition: 1,
				},
			},
		}
		require.NoError(t,
			cr.SetTechnicalRecord(TechnicalRecord{
				Round:    99,
				Epoch:    8,
				Leader:   "1",
				StatHash: []byte{1},
				FeeHash:  []byte{2},
			}))

		return cr
	}
	require.NoError(t, validCR(t).IsValid())

	t.Run("nil", func(t *testing.T) {
		var cr *CertificationResponse
		require.EqualError(t, cr.IsValid(), `nil CertificationResponse`)
	})

	t.Run("invalid partition", func(t *testing.T) {
		cr := validCR(t)
		cr.Partition++
		require.EqualError(t, cr.IsValid(), `partition 00000002 doesn't match UnicityTreeCertificate partition 00000001`)

		cr.Partition = 0
		require.EqualError(t, cr.IsValid(), `partition ID is unassigned`)
	})

	t.Run("TechnicalRecord", func(t *testing.T) {
		cr := validCR(t)
		round := cr.Technical.Round
		cr.Technical.Round = 0
		require.EqualError(t, cr.IsValid(), `invalid TechnicalRecord: round is unassigned`)

		// restore round to wrong value - should trigger the hash check
		cr.Technical.Round = round + 1
		require.EqualError(t, cr.IsValid(), `comparing TechnicalRecord hash to UC.TRHash: hash mismatch`)

		cr = validCR(t)
		cr.UC.TRHash = append(cr.UC.TRHash, 0)
		require.EqualError(t, cr.IsValid(), `comparing TechnicalRecord hash to UC.TRHash: hash mismatch`)
	})
}

func Test_CertificationResponse_IsValid_NonOKStatus(t *testing.T) {
	// Status != OK must NOT cause IsValid to fail — the wrapped UC is still
	// the last-good certificate and callers may want to forward it.
	cr := &CertificationResponse{
		Partition: 1,
		Shard:     types.ShardID{},
		UC: types.UnicityCertificate{
			Version: 1,
			UnicityTreeCertificate: &types.UnicityTreeCertificate{
				Version:   1,
				Partition: 1,
			},
		},
		Status:  CertStatusProofInvalid,
		Message: "envelope truncated: missing leaf_count",
	}
	require.NoError(t, cr.SetTechnicalRecord(TechnicalRecord{
		Round: 99, Epoch: 8, Leader: "1", StatHash: []byte{1}, FeeHash: []byte{2},
	}))
	require.NoError(t, cr.IsValid())
	require.False(t, cr.IsAccepted())

	cr.Status = CertStatusOK
	require.True(t, cr.IsAccepted())
}

func Test_CertificationResponse_CBOR_RoundTrip_WithStatus(t *testing.T) {
	orig := &CertificationResponse{
		Partition: 1,
		Shard:     types.ShardID{},
		UC: types.UnicityCertificate{
			Version: 1,
			UnicityTreeCertificate: &types.UnicityTreeCertificate{
				Version: 1, Partition: 1,
			},
		},
		Status:  CertStatusRequestInvalid,
		Message: "stale round: expected 42 got 41",
	}
	require.NoError(t, orig.SetTechnicalRecord(TechnicalRecord{
		Round: 99, Epoch: 8, Leader: "1", StatHash: []byte{1}, FeeHash: []byte{2},
	}))

	buf, err := types.Cbor.Marshal(orig)
	require.NoError(t, err)

	var decoded CertificationResponse
	require.NoError(t, types.Cbor.Unmarshal(buf, &decoded))
	require.Equal(t, orig.Status, decoded.Status)
	require.Equal(t, orig.Message, decoded.Message)
	require.Equal(t, orig.Partition, decoded.Partition)
	require.Equal(t, orig.Technical.Round, decoded.Technical.Round)
}

func Test_SendRejection_TruncationBoundary(t *testing.T) {
	// Sanity: verify that MaxStatusMessageLen is a reasonable cap and that
	// a message exactly at the cap survives round-trip.
	msg := strings.Repeat("x", MaxStatusMessageLen)
	cr := &CertificationResponse{
		Partition: 1,
		UC: types.UnicityCertificate{
			Version: 1,
			UnicityTreeCertificate: &types.UnicityTreeCertificate{Version: 1, Partition: 1},
		},
		Status:  CertStatusFatal,
		Message: msg,
	}
	require.NoError(t, cr.SetTechnicalRecord(TechnicalRecord{
		Round: 1, Epoch: 1, Leader: "1", StatHash: []byte{1}, FeeHash: []byte{1},
	}))
	buf, err := types.Cbor.Marshal(cr)
	require.NoError(t, err)
	var out CertificationResponse
	require.NoError(t, types.Cbor.Unmarshal(buf, &out))
	require.Len(t, out.Message, MaxStatusMessageLen)
}

func Test_CertificationResponse_SetTechnicalRecord(t *testing.T) {
	tr := TechnicalRecord{Round: 123, Epoch: 4, Leader: "567890"}
	cr := CertificationResponse{}
	require.NoError(t, cr.SetTechnicalRecord(tr))
	require.Equal(t, tr, cr.Technical)

	trh, err := tr.Hash()
	require.NoError(t, err)
	require.Equal(t, cr.UC.TRHash, hex.Bytes(trh))
}
