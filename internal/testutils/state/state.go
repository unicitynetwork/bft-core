package teststate

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/state"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"
)

func CreateUC(t *testing.T, s *state.State, summaryValue uint64, summaryHash []byte) *types.UnicityCertificate {
	roundNumber := uint64(0)
	committed, err := s.IsCommitted()
	require.NoError(t, err)
	if committed {
		roundNumber = s.CommittedUC().GetRoundNumber() + 1
	}

	return &types.UnicityCertificate{
		Version: 1,
		InputRecord: &types.InputRecord{
			Version:      1,
			RoundNumber:  roundNumber,
			Hash:         summaryHash,
			SummaryValue: util.Uint64ToBytes(summaryValue),
			Timestamp:    types.NewTimestamp(),
		},
	}
}

func CommitWithUC(t *testing.T, s *state.State) {
	summaryValue, summaryHash, err := s.CalculateRoot()
	require.NoError(t, err)
	require.NoError(t, s.Commit(CreateUC(t, s, summaryValue, summaryHash)))
}
