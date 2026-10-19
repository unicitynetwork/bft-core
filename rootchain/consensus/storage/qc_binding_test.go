package storage

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

func Test_CheckQcOfBlock(t *testing.T) {
	block := &ExecutedBlock{
		BlockData: &rctypes.BlockData{Round: 5, Epoch: 3, Timestamp: 1000, Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 4}}},
		RootHash:  []byte{1, 2, 3},
	}
	qc := func(change func(*rctypes.RoundInfo)) *rctypes.QuorumCert {
		vi := &rctypes.RoundInfo{RoundNumber: 5, ParentRoundNumber: 4, Epoch: 3, Timestamp: 1000, CurrentRootHash: []byte{1, 2, 3}}
		if change != nil {
			change(vi)
		}
		return &rctypes.QuorumCert{VoteInfo: vi}
	}
	require.NoError(t, CheckQcOfBlock(qc(nil), block))
	for name, c := range map[string]struct {
		qc   *rctypes.QuorumCert
		want string
	}{
		"round":        {qc(func(vi *rctypes.RoundInfo) { vi.RoundNumber = 6 }), "QC is of round 6"},
		"parent round": {qc(func(vi *rctypes.RoundInfo) { vi.ParentRoundNumber = 3 }), "parent round"},
		"epoch":        {qc(func(vi *rctypes.RoundInfo) { vi.Epoch = 4 }), "epoch or timestamp"},
		"timestamp":    {qc(func(vi *rctypes.RoundInfo) { vi.Timestamp = 1001 }), "epoch or timestamp"},
		"state root":   {qc(func(vi *rctypes.RoundInfo) { vi.CurrentRootHash = []byte{9} }), "state root"},
		"nil QC":       {nil, "missing"},
		"no vote info": {&rctypes.QuorumCert{}, "missing"},
	} {
		t.Run(name, func(t *testing.T) { require.ErrorContains(t, CheckQcOfBlock(c.qc, block), c.want) })
	}
	require.Error(t, CheckQcOfBlock(qc(nil), nil))
	require.Error(t, CheckQcOfBlock(qc(nil), &ExecutedBlock{}))
}

// A QC of another timestamp than the one of the local block is not attached to it: not in memory and not in the
// database, which still has the block without a QC after it is reopened.
func Test_Chain_QCOfAnotherTimestampIsNotAttached(t *testing.T) {
	c := newTestChain(t, chainShard{partition: 1, epochStarts: []uint64{1}})
	c.next()
	c.next()
	parent := c.round
	round := parent + 1
	local := &rctypes.BlockData{Author: "chain", Round: round, Epoch: rctypes.GenesisRootEpoch, Timestamp: types.GenesisTime + round + 1, Payload: &rctypes.Payload{}, Qc: c.highQc}
	root, err := c.store.Add(local, chainVerifier{c.store})
	require.NoError(t, err)
	honest := &rctypes.RoundInfo{Version: 1, RoundNumber: round, ParentRoundNumber: parent, Epoch: local.Epoch, Timestamp: local.Timestamp - 1, CurrentRootHash: root}
	vh, err := honest.Hash(crypto.SHA256)
	require.NoError(t, err)
	parentBlock, err := c.store.Block(parent)
	require.NoError(t, err)
	qc := &rctypes.QuorumCert{
		VoteInfo: honest,
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: parent, Epoch: parentBlock.BlockData.Epoch,
			Timestamp: parentBlock.BlockData.Timestamp, Hash: parentBlock.RootHash, PreviousHash: vh},
		Signatures: map[string]hex.Bytes{"x": {1}},
	}

	highBefore := c.store.GetHighQc()
	rootBefore := c.store.blockTree.root.data.GetRound()
	_, err = c.store.ProcessQc(qc)
	require.ErrorContains(t, err, "does not certify the local block")
	require.Same(t, highBefore, c.store.GetHighQc(), "the high QC did not change")
	b, err := c.store.Block(round)
	require.NoError(t, err)
	require.Nil(t, b.Qc)
	require.EqualValues(t, rootBefore, c.store.blockTree.root.data.GetRound(), "nothing was committed")

	// reopen the database of the node
	bolt, ok := c.store.storage.(BoltDB)
	require.True(t, ok)
	path := bolt.db.Path()
	require.NoError(t, bolt.Close())
	reopened, err := NewBoltStorage(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	store, err := New(crypto.SHA256, reopened, c.orch, c.log)
	require.NoError(t, err)
	b, err = store.Block(round)
	require.NoError(t, err)
	require.Nil(t, b.Qc, "nothing was persisted for the QC")
	require.EqualValues(t, highBefore.GetRound(), store.GetHighQc().GetRound())
}

// The last vote and the voting rounds survive a reopening of the database: they restore the pacemaker and are the
// barrier against signing a round twice.
func Test_BoltDB_LastVoteAndVotingRoundsSurviveReopen(t *testing.T) {
	path := t.TempDir() + "/votes.db"
	db, err := NewBoltStorage(path)
	require.NoError(t, err)
	vote := &abdrc.VoteMsg{
		VoteInfo:         &rctypes.RoundInfo{Version: 1, RoundNumber: 7, ParentRoundNumber: 6, Epoch: 1, Timestamp: 99},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, PreviousHash: []byte{1}},
		Author:           "node", Signature: []byte{4, 5},
	}
	require.NoError(t, db.WriteVote(vote))
	require.NoError(t, db.SetHighestQcRound(6, 7))
	require.NoError(t, db.Close())

	db, err = NewBoltStorage(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	msg, err := db.ReadLastVote()
	require.NoError(t, err)
	got, ok := msg.(*abdrc.VoteMsg)
	require.True(t, ok)
	require.EqualValues(t, 7, got.VoteInfo.RoundNumber)
	require.Equal(t, vote.Signature, got.Signature)
	require.EqualValues(t, 7, db.GetHighestVotedRound())
	require.EqualValues(t, 6, db.GetHighestQcRound())
}

// ProcessQc checks a retained block against a QC at or below the high QC too (a higher QC is not proof of the binding
// of an older block); genuinely pruned history stays a no-op.
func Test_Chain_StaleQCIsCheckedAgainstTheRetainedBlock(t *testing.T) {
	c := newTestChain(t, chainShard{partition: 1, epochStarts: []uint64{1}})
	for range 4 {
		c.next()
	}
	high := c.store.GetHighQc()
	root := c.store.blockTree.root.data
	require.Less(t, root.GetRound(), high.GetRound())
	require.Greater(t, root.GetRound(), uint64(1), "round 1 is pruned")

	t.Run("exact match: a no-op", func(t *testing.T) {
		for _, qc := range []*rctypes.QuorumCert{high, root.Qc} {
			certs, err := c.store.ProcessQc(qc)
			require.NoError(t, err)
			require.Nil(t, certs)
		}
		require.Same(t, high, c.store.GetHighQc())
	})

	t.Run("retained block of another timestamp, epoch, parent or root: refused", func(t *testing.T) {
		for name, change := range map[string]func(*rctypes.RoundInfo){
			"timestamp": func(vi *rctypes.RoundInfo) { vi.Timestamp++ },
			"epoch":     func(vi *rctypes.RoundInfo) { vi.Epoch++ },
			"parent":    func(vi *rctypes.RoundInfo) { vi.ParentRoundNumber-- },
			"root":      func(vi *rctypes.RoundInfo) { vi.CurrentRootHash = []byte{1} },
		} {
			vi := *high.VoteInfo
			change(&vi)
			stale := &rctypes.QuorumCert{VoteInfo: &vi, LedgerCommitInfo: high.LedgerCommitInfo, Signatures: high.Signatures}
			_, err := c.store.ProcessQc(stale)
			require.ErrorContains(t, err, "does not certify the local block", name)
		}
		require.Same(t, high, c.store.GetHighQc())
	})

	t.Run("pruned history: a no-op whatever the QC says", func(t *testing.T) {
		old := &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 1, ParentRoundNumber: 0, Epoch: 9, Timestamp: 5, CurrentRootHash: []byte{7}}}
		certs, err := c.store.ProcessQc(old)
		require.NoError(t, err)
		require.Nil(t, certs)
	})
}
