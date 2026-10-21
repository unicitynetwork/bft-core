package storage

import (
	"crypto"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

// validateLikeManager is what the consensus manager does with a state message: the staged validation first, the
// real recovery (head, pending blocks) only if it passed. It returns the real storage to check what was written.
func validateLikeManager(t *testing.T, c *testChain, sm *abdrc.StateMsg, toRound uint64) (PersistentStore, *BlockStore, error) {
	t.Helper()
	db, err := NewBoltStorage(filepath.Join(t.TempDir(), "node.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	verifier := func(bs *BlockStore) (IRChangeReqVerifier, error) { return chainVerifier{bs}, nil }
	if err := ValidateRecoveryState(crypto.SHA256, sm, toRound, c.orch, db, verifier, c.log); err != nil {
		return db, nil, err
	}
	bs, err := NewFromState(crypto.SHA256, sm.CommittedHead, db, c.orch, c.log)
	require.NoError(t, err)
	v, _ := verifier(bs)
	for i, b := range sm.Pending {
		_, err := bs.ProcessQc(b.Qc)
		require.True(t, err == nil || (i == 0 && errorsIsCommitFailed(err)), "%v", err)
		_, err = bs.Add(b, v)
		require.NoError(t, err)
	}
	return db, bs, nil
}

func errorsIsCommitFailed(err error) bool { return errors.Is(err, ErrCommitFailed) }

// pendingChain: shard 1 changes in the block of the head, shard 2 in the pending block which the head's commit QC
// certifies (a shard does not change in two consecutive blocks: its request is built on the response of the
// committed state the block extends).
func pendingChain(t *testing.T) *testChain {
	c := newTestChain(t, chainShard{partition: 1, epochStarts: []uint64{1}}, chainShard{partition: 2, epochStarts: []uint64{1}})
	for _, changed := range [][]types.PartitionID{nil, nil, {1}, {2}} {
		c.next(changed...)
	}
	return c
}

func requireNothingPersisted(t *testing.T, db PersistentStore) {
	t.Helper()
	blocks, err := db.LoadBlocks()
	require.NoError(t, err)
	require.Empty(t, blocks, "no head, no pending block, nothing may have been written")
}

// The case of the architect's review: all certificates are validly signed, the payload of the pending block (which
// the head's commit QC certifies) is changed, so executing it gives another root than the QC certifies. Neither
// StateMsg.Verify, nor NewFromState, nor the "already known QC" shortcut of ProcessQc notices.
func Test_RecoveryPending_CertifiedBlockMustMatchItsQC(t *testing.T) {
	c := pendingChain(t)
	sm := received(t, c.state())
	root := testutils.NewTestNode(t)
	ni := root.NodeInfo(t)
	tb, err := types.NewTrustBase(5, []*types.NodeInfo{ni})
	require.NoError(t, err)
	signQC := func(q *rctypes.QuorumCert) {
		if q == nil {
			return
		}
		q.LedgerCommitInfo.Signatures = nil
		require.NoError(t, q.LedgerCommitInfo.Sign(ni.NodeID, root.Signer))
		q.Signatures = q.LedgerCommitInfo.Signatures
	}
	signQC(sm.CommittedHead.Block.Qc)
	signQC(sm.CommittedHead.Qc)
	signQC(sm.CommittedHead.CommitQc)
	for _, p := range sm.Pending {
		signQC(p.Qc)
	}
	for i := range sm.CommittedHead.ShardInfo {
		s := sm.CommittedHead.ShardInfo[i].UC.UnicitySeal
		s.Signatures = nil
		require.NoError(t, s.Sign(ni.NodeID, root.Signer))
	}
	require.NoError(t, sm.Verify(crypto.SHA256, tb), "valid signed control")
	sm = received(t, sm)

	// control: the honest signed message is accepted and recovers
	toRound := sm.CommittedHead.GetRound() + 1
	_, bs, err := validateLikeManager(t, c, sm, toRound)
	require.NoError(t, err)
	require.Equal(t, bs.GetHighQc().VoteInfo.CurrentRootHash, bs.blockTree.roundToNode[toRound].data.RootHash)

	// the manipulation: the pending payload is changed, every signed certificate is untouched
	require.Len(t, sm.Pending, 1)
	require.NotEmpty(t, sm.Pending[0].Payload.Requests)
	sm.Pending[0].Payload.Requests = nil
	sm = received(t, sm)
	require.NoError(t, sm.Verify(crypto.SHA256, tb), "the signed certificates still verify")
	db, _, err := validateLikeManager(t, c, sm, toRound)
	require.Error(t, err)
	require.ErrorContains(t, err, "commit QC of the head")
	requireNothingPersisted(t, db)
}

func Test_RecoveryPending_BindingOfThePendingChain(t *testing.T) {
	c := pendingChain(t)
	good := received(t, c.state())
	toRound := good.CommittedHead.GetRound() + 1
	_, _, err := validateLikeManager(t, c, received(t, good), toRound)
	require.NoError(t, err, "control")

	cases := []struct {
		name string
		mut  func(*abdrc.StateMsg)
		to   uint64
		want string
	}{
		{"QC of the parent of another state root", func(sm *abdrc.StateMsg) { sm.Pending[0].Qc.VoteInfo.CurrentRootHash[0] ^= 1 }, toRound, "state root"},
		{"QC of the parent of another epoch", func(sm *abdrc.StateMsg) { sm.Pending[0].Qc.VoteInfo.Epoch++ }, toRound, "epoch or timestamp"},
		{"QC of the parent of another timestamp", func(sm *abdrc.StateMsg) { sm.Pending[0].Qc.VoteInfo.Timestamp++ }, toRound, "epoch or timestamp"},
		{"QC of the parent with another parent round", func(sm *abdrc.StateMsg) { sm.Pending[0].Qc.VoteInfo.ParentRoundNumber-- }, toRound, "parent round"},
		{"parent which is not part of the recovered state", func(sm *abdrc.StateMsg) { sm.Pending[0].Qc.VoteInfo.RoundNumber-- }, toRound, "parent round"},
		{"commit QC of the head certifies another root", func(sm *abdrc.StateMsg) { sm.CommittedHead.CommitQc.VoteInfo.CurrentRootHash = []byte{1} }, toRound, "commit QC of the head"},
		{"no block for the target round", func(sm *abdrc.StateMsg) {}, toRound + 3, "target round"},
		{"missing QC", func(sm *abdrc.StateMsg) { sm.Pending[0].Qc = nil }, toRound, "no QC"},
		{"null block", func(sm *abdrc.StateMsg) { sm.Pending = append(sm.Pending, nil) }, toRound, "no QC"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sm := received(t, good)
			tc.mut(sm)
			db, _, err := validateLikeManager(t, c, sm, tc.to)
			require.Error(t, err)
			require.ErrorContains(t, err, tc.want)
			requireNothingPersisted(t, db)
		})
	}

	t.Run("a block executing differently under the ordinary rules is rejected too", func(t *testing.T) {
		sm := received(t, good)
		// a request signed by nobody known: the ordinary verification of the change request fails
		sm.Pending[0].Payload.Requests[0].Requests[0].Signature = []byte{1, 2, 3}
		db, _, err := validateLikeManager(t, c, sm, toRound)
		require.Error(t, err)
		requireNothingPersisted(t, db)
	})
}

// Every head of a run, with the pending blocks (the tip has no QC) of the honest node, passes the staged validation.
func Test_RecoveryPending_HonestStatesPass(t *testing.T) {
	c := newTestChain(t, chainShard{partition: 1, epochStarts: []uint64{1, 5}}, chainShard{partition: 2, epochStarts: []uint64{1, 7, 10}})
	for _, changed := range [][]types.PartitionID{nil, nil, {1, 2}, nil, {1}, {2}, {1}, {2}, {1}, {2}, nil, {1, 2}} {
		c.next(changed...)
		sm := received(t, c.state())
		toRound := sm.CommittedHead.GetRound()
		if len(sm.Pending) > 0 {
			toRound = sm.Pending[len(sm.Pending)-1].GetRound()
		}
		_, bs, err := validateLikeManager(t, c, sm, toRound)
		require.NoError(t, err, "head round %d", sm.CommittedHead.GetRound())
		require.NotNil(t, bs)
	}
}

// Different shards switch epochs at different rounds, each needs the configuration of ITS previous epoch.
func Test_RecoveryBinding_ShardsWithDifferentEpochStarts(t *testing.T) {
	c := newTestChain(t, chainShard{partition: 1, epochStarts: []uint64{1, 5}}, chainShard{partition: 2, epochStarts: []uint64{1, 7, 10}})
	c.next()
	c.next()
	for c.round < 11 {
		c.next(1, 2)
	}
	sm := received(t, c.state())
	require.EqualValues(t, 10, sm.CommittedHead.GetRound())
	// the map iteration order used to decide: repeat
	for i := 0; i < 60; i++ {
		_, err := NewRootBlock(sm.CommittedHead, crypto.SHA256, c.orch)
		require.NoError(t, err, "attempt %d", i)
	}
	// and every other head of the run
	c2 := newTestChain(t, chainShard{partition: 1, epochStarts: []uint64{1, 5}}, chainShard{partition: 2, epochStarts: []uint64{1, 7, 10}})
	c2.next()
	c2.next()
	for c2.round < 14 {
		c2.next(1, 2)
		for i := 0; i < 10; i++ {
			_, _, err := c2.recoverInto(received(t, c2.state()))
			require.NoError(t, err, "head round %d", c2.store.blockTree.root.data.GetRound())
		}
	}
}
