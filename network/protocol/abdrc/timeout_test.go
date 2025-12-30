package abdrc

import (
	gocrypto "crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/internal/testutils/sig"
	testtb "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/testutils"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

func TestTimeoutMsg_Bytes(t *testing.T) {
	timeoutMsg := &TimeoutMsg{
		Timeout: &types.Timeout{
			Round: 10,
			Epoch: types.GenesisRootEpoch,
			HighQc: &types.QuorumCert{
				VoteInfo: &types.RoundInfo{
					RoundNumber:       9,
					Epoch:             types.GenesisRootEpoch,
					Timestamp:         0x0010670314583523,
					ParentRoundNumber: 8,
					CurrentRootHash:   []byte{0, 1, 3}},
			},
		},
		Author:    "test",
		Signature: []byte{1, 2, 3},
	}
	serialized := []byte{
		0, 0, 0, 0, 0, 0, 0, 10,
		0, 0, 0, 0, 0, 0, 0, 1,
		0, 0, 0, 0, 0, 0, 0, 9,
		't', 'e', 's', 't',
	}
	require.Equal(t, serialized, timeoutMsg.Bytes())
}

func TestBytesFromTimeoutVote(t *testing.T) {
	timeoutMsg := &TimeoutMsg{
		Timeout: &types.Timeout{
			Round: 10,
			Epoch: types.GenesisRootEpoch,
			HighQc: &types.QuorumCert{
				VoteInfo: &types.RoundInfo{
					RoundNumber:       9,
					Epoch:             types.GenesisRootEpoch,
					Timestamp:         0x0010670314583523,
					ParentRoundNumber: 8,
					CurrentRootHash:   []byte{0, 1, 3}},
			},
		},
		Author:    "test",
		Signature: []byte{1, 2, 3},
	}
	// Require serialization is equal
	bytes := types.BytesFromTimeoutVote(timeoutMsg.Timeout, "test", &types.TimeoutVote{HqcRound: 9, Signature: []byte{1, 2, 3}})
	require.Equal(t, timeoutMsg.Bytes(), bytes)
}

func TestTimeoutMsg_IsValid(t *testing.T) {
	type fields struct {
		Timeout   *types.Timeout
		Author    string
		Signature []byte
		LastTC    *types.TimeoutCert
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Invalid, timeout info is nil",
			fields: fields{
				Timeout:   nil,
				Author:    "test",
				Signature: []byte{0, 1, 2},
			},
			wantErr: true,
		},
		{
			name: "Invalid, high QC not valid",
			fields: fields{
				Timeout: &types.Timeout{
					Round: 10,
					Epoch: types.GenesisRootEpoch,
					HighQc: &types.QuorumCert{
						VoteInfo: testutils.NewDummyRootRoundInfo(10),
						//LedgerCommitInfo: NewDummyCommitInfo(gocrypto.SHA256, NewDummyVoteInfo(9)),
						Signatures: map[string]hex.Bytes{"1": {0, 1, 2, 3}},
					},
				},
				Author:    "",
				Signature: []byte{0, 1, 2},
			},
			wantErr: true,
		},
		{
			name: "Invalid, no author",
			fields: fields{
				Timeout: &types.Timeout{
					Round: 10,
					Epoch: types.GenesisRootEpoch,
					HighQc: &types.QuorumCert{
						VoteInfo: testutils.NewDummyRootRoundInfo(9),
						//LedgerCommitInfo: NewDummyCommitInfo(gocrypto.SHA256, NewDummyVoteInfo(9)),
						Signatures: map[string]hex.Bytes{"1": {0, 1, 2, 3}},
					},
				},
				Author:    "",
				Signature: []byte{0, 1, 2},
			},
			wantErr: true,
		},
		{
			name: "Invalid, no lastTC",
			fields: fields{
				Timeout: &types.Timeout{
					Round: 10,
					Epoch: types.GenesisRootEpoch,
					HighQc: &types.QuorumCert{
						VoteInfo:   testutils.NewDummyRootRoundInfo(8),
						Signatures: map[string]hex.Bytes{"1": {0, 1, 2, 3}},
					},
				},
				Author:    "",
				Signature: []byte{0, 1, 2},
				LastTC:    nil, // if highQC is not for the previous round then lastTC must be present
			},
			wantErr: true,
		},
		{
			name: "Invalid, lastTC for wrong round",
			fields: fields{
				Timeout: &types.Timeout{
					Round: 10,
					Epoch: types.GenesisRootEpoch,
					HighQc: &types.QuorumCert{
						VoteInfo:   testutils.NewDummyRootRoundInfo(7),
						Signatures: map[string]hex.Bytes{"1": {0, 1, 2, 3}},
					},
				},
				Author:    "",
				Signature: []byte{0, 1, 2},
				LastTC: &types.TimeoutCert{
					Timeout: &types.Timeout{Round: 8},
				},
			},
			wantErr: true,
		},
		{
			name: "Valid",
			fields: fields{
				Timeout: &types.Timeout{
					Round: 10,
					Epoch: types.GenesisRootEpoch,
					HighQc: &types.QuorumCert{
						VoteInfo:         testutils.NewDummyRootRoundInfo(9),
						LedgerCommitInfo: testutils.NewDummyCommitInfo(t, gocrypto.SHA256, testutils.NewDummyRootRoundInfo(9)),
						Signatures:       map[string]hex.Bytes{"1": {0, 1, 2, 3}},
					},
				},
				Author:    "test",
				Signature: []byte{0, 1, 2},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := &TimeoutMsg{
				Timeout:   tt.fields.Timeout,
				Author:    tt.fields.Author,
				Signature: tt.fields.Signature,
				LastTC:    tt.fields.LastTC,
			}
			if err := x.IsValid(); (err != nil) != tt.wantErr {
				t.Errorf("IsValid() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTimeoutMsg_Sign(t *testing.T) {
	s1, _ := testsig.CreateSignerAndVerifier(t)
	// create timeout message without author, verify sign fails
	x := &TimeoutMsg{
		Timeout: &types.Timeout{
			Round: 10,
			Epoch: types.GenesisRootEpoch,
			HighQc: &types.QuorumCert{
				VoteInfo:         testutils.NewDummyRootRoundInfo(9),
				LedgerCommitInfo: testutils.NewDummyCommitInfo(t, gocrypto.SHA256, testutils.NewDummyRootRoundInfo(9)),
				Signatures:       map[string]hex.Bytes{"1": {0, 1, 2, 3}},
			},
		},
		Author: "",
	}
	require.ErrorContains(t, x.Sign(s1), "timeout validation failed, timeout message is missing author")
	require.Nil(t, x.Signature)
	// add author
	x.Author = "test"
	require.NoError(t, x.Sign(s1))
	require.NotNil(t, x.Signature)
}

func TestVoteMsg_PureTimeoutVoteVerifyOk(t *testing.T) {
	const votedRound = 10
	s1, _ := testsig.CreateSignerAndVerifier(t)
	s2, _ := testsig.CreateSignerAndVerifier(t)
	s3, _ := testsig.CreateSignerAndVerifier(t)
	rootTrust := testtb.NewTrustBaseFromSigners(t, map[string]crypto.Signer{"1": s1, "2": s2, "3": s3})

	tbs, err := trustbase.NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)
	require.NoError(t, tbs.Store(rootTrust))

	commitQcInfo := testutils.NewDummyRootRoundInfo(votedRound - 1)
	commitInfo := testutils.NewDummyCommitInfo(t, gocrypto.SHA256, commitQcInfo)
	sig1, err := s1.SignBytes(testcertificates.UnicitySealBytes(t, commitInfo))
	require.NoError(t, err)
	sig2, err := s2.SignBytes(testcertificates.UnicitySealBytes(t, commitInfo))
	require.NoError(t, err)
	sig3, err := s3.SignBytes(testcertificates.UnicitySealBytes(t, commitInfo))
	require.NoError(t, err)
	highQc := &types.QuorumCert{
		VoteInfo:         commitQcInfo,
		LedgerCommitInfo: commitInfo,
		Signatures:       map[string]hex.Bytes{"1": sig1, "2": sig2, "3": sig3},
	}
	// unknown signer
	tmoMsg := NewTimeoutMsg(types.NewTimeout(votedRound, types.GenesisRootEpoch, highQc), "12", nil)
	require.NoError(t, tmoMsg.Sign(s1))
	require.ErrorContains(t, tmoMsg.Verify(tbs), `author '12' is not part of the trust base`)

	// all ok
	lastTC := &types.TimeoutCert{
		Timeout: types.NewTimeout(highQc.GetRound()+1, types.GenesisRootEpoch, highQc),
		Signatures: map[string]*types.TimeoutVote{
			"1": {HqcRound: highQc.GetRound(), Signature: testutils.CalcTimeoutSig(t, s1, highQc.GetRound()+1, types.GenesisRootEpoch, highQc.GetRound(), "1")},
			"2": {HqcRound: highQc.GetRound(), Signature: testutils.CalcTimeoutSig(t, s2, highQc.GetRound()+1, types.GenesisRootEpoch, highQc.GetRound(), "2")},
			"3": {HqcRound: highQc.GetRound(), Signature: testutils.CalcTimeoutSig(t, s3, highQc.GetRound()+1, types.GenesisRootEpoch, highQc.GetRound(), "3")},
		},
	}
	tmoMsg = NewTimeoutMsg(types.NewTimeout(highQc.GetRound()+2, types.GenesisRootEpoch, highQc), "1", lastTC)
	require.NoError(t, tmoMsg.Sign(s1))
	require.NoError(t, tmoMsg.Verify(tbs))

	// adjust after signing
	tmoMsg.Timeout.Epoch = 99
	require.ErrorContains(t, tmoMsg.Verify(tbs), "failed to get trust base for timeout verification, epoch 99: trust base not found")

	// check that lastTC.Verify is called
	tmoMsg.Timeout.Epoch = types.GenesisRootEpoch
	tmoMsg.LastTC.Timeout.Epoch = 99
	require.ErrorContains(t, tmoMsg.Verify(tbs), "invalid last TC: failed to get trust base for vote verification, epoch 99: trust base not found")
}

func TestTimeoutMsg_GetRound(t *testing.T) {
	var tmoMsg *TimeoutMsg = nil
	require.Equal(t, uint64(0), tmoMsg.GetRound())
	tmoMsg = &TimeoutMsg{Timeout: nil}
	require.Equal(t, uint64(0), tmoMsg.GetRound())
	tmoMsg = &TimeoutMsg{Timeout: &types.Timeout{Round: 10}}
	require.Equal(t, uint64(10), tmoMsg.GetRound())
}
