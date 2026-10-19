package storage

import (
	"crypto"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// The recovery state is validated against its authenticated root and the local configuration before anything is
// written (validateRecoveredHead, validateRecoveredShard).

func recoveryChain(t *testing.T) *testChain {
	c := newTestChain(t, chainShard{partition: 1, epochStarts: []uint64{1, 5}}, chainShard{partition: 2, epochStarts: []uint64{1}})
	return c
}

// ---- positive: what honest nodes send is accepted ----

func Test_RecoveryBinding_Accepts(t *testing.T) {
	t.Run("genesis head", func(t *testing.T) {
		c := recoveryChain(t)
		sm := received(t, c.state())
		require.EqualValues(t, 1, sm.CommittedHead.GetRound())
		bs, _, err := c.recoverInto(sm)
		require.NoError(t, err)
		require.EqualValues(t, 1, bs.blockTree.root.data.GetRound())
	})

	t.Run("every head of a run with changed and unchanged shards and an epoch transition", func(t *testing.T) {
		c := recoveryChain(t)
		// shard 1 starts its epoch 1 at root round 5; shard 2 changes rarely and keeps older UCs
		for i, changed := range [][]types.PartitionID{nil, nil, {1, 2}, {1}, {1}, {1}, {1}, {1, 2}, {1}, {1}, {1}} {
			c.next(changed...)
			sm := received(t, c.state())
			bs, _, err := c.recoverInto(sm)
			require.NoError(t, err, "head round %d (step %d)", sm.CommittedHead.GetRound(), i)
			require.Equal(t, c.store.blockTree.root.data.RootHash, bs.blockTree.root.data.RootHash)
		}
	})

	t.Run("unchanged shard keeps its older UC", func(t *testing.T) {
		c := recoveryChain(t)
		c.next()
		c.next()
		c.next(1, 2)
		c.next(1)
		c.next(1)
		sm := received(t, c.state())
		bs, _, err := c.recoverInto(sm)
		require.NoError(t, err)
		si2 := bs.ShardInfo(2, types.ShardID{})
		si1 := bs.ShardInfo(1, types.ShardID{})
		require.NotNil(t, si2.LastCR)
		require.Less(t, si2.LastCR.UC.GetRootRoundNumber(), si1.LastCR.UC.GetRootRoundNumber(),
			"the response of the unchanged shard is older than the one of the changed shard")
	})

	t.Run("the epoch transition head itself", func(t *testing.T) {
		c := recoveryChain(t)
		var transition bool
		for _, changed := range [][]types.PartitionID{nil, nil, {1}, {1}, {1}, {1}, {1}} {
			c.next(changed...)
			si := c.store.blockTree.root.data.ShardState.States[types.PartitionShardID{PartitionID: 1, ShardID: types.ShardID{}.Key()}]
			if si != nil && si.TR.Epoch == 1 && si.IR.Epoch == 0 && si.Fees != nil {
				bs, _, err := c.recoverInto(received(t, c.state()))
				require.NoError(t, err, "head round %d", c.store.blockTree.root.data.GetRound())
				_ = bs
				transition = transition || si.ShardConfHash != nil
			}
		}
		require.True(t, transition)
	})
}

// ---- negative: every manipulation is rejected before anything is persisted ----

type manipulation struct {
	name string
	mut  func(t *testing.T, sm *abdrc.StateMsg)
	// want is a part of the expected error
	want string
}

func shardEntry(sm *abdrc.StateMsg, partition types.PartitionID) *abdrc.ShardInfo {
	for i := range sm.CommittedHead.ShardInfo {
		if sm.CommittedHead.ShardInfo[i].Partition == partition {
			return &sm.CommittedHead.ShardInfo[i]
		}
	}
	panic("no such shard")
}

func Test_RecoveryBinding_RejectsBeforePersistence(t *testing.T) {
	c := recoveryChain(t)
	for _, changed := range [][]types.PartitionID{nil, nil, {1, 2}, {1}, {1}} {
		c.next(changed...)
	}
	good := received(t, c.state())
	_, _, err := c.recoverInto(received(t, good))
	require.NoError(t, err, "control: the unmodified message")

	cases := []manipulation{
		// the state: the rebuilt tree must be the committed one
		{"current IR changed", func(t *testing.T, sm *abdrc.StateMsg) {
			si := shardEntry(sm, 1)
			si.IR.Timestamp++
			si.UC.InputRecord.Timestamp++ // consistent with the UC: only the root can tell
		}, "differs from the root"},
		{"current IR changed, UC left", func(t *testing.T, sm *abdrc.StateMsg) { shardEntry(sm, 1).IR.SumOfEarnedFees++ }, "another input record"},
		{"technical record round changed", func(t *testing.T, sm *abdrc.StateMsg) { shardEntry(sm, 2).IRTR.Round++ }, "technical record of the last response differs"},
		{"technical record epoch changed (inconsistent IRTR epoch)", func(t *testing.T, sm *abdrc.StateMsg) { shardEntry(sm, 2).IRTR.Epoch += 3 }, "technical record"},
		{"committed root changed in the commit QC", func(t *testing.T, sm *abdrc.StateMsg) { sm.CommittedHead.CommitQc.LedgerCommitInfo.Hash[0] ^= 1 }, "committed by the commit QC"},
		{"root changed in the QC of the block", func(t *testing.T, sm *abdrc.StateMsg) { sm.CommittedHead.Qc.VoteInfo.CurrentRootHash[0] ^= 1 }, "QC"},
		// fees and statistics
		{"fees changed", func(t *testing.T, sm *abdrc.StateMsg) {
			for k := range shardEntry(sm, 1).Fees {
				shardEntry(sm, 1).Fees[k]++
			}
		}, "commitments"},
		{"statistics changed", func(t *testing.T, sm *abdrc.StateMsg) { shardEntry(sm, 1).Stat.Blocks += 5 }, "commitments"},
		{"previous epoch fees changed", func(t *testing.T, sm *abdrc.StateMsg) {
			shardEntry(sm, 2).PrevEpochFees = []byte{0xa1, 0x61, 0x78, 0x01}
		}, "commitments"},
		{"timeout changed", func(t *testing.T, sm *abdrc.StateMsg) { shardEntry(sm, 1).T2Timeout *= 2 }, "T2 timeout"},
		{"fee list of other validators", func(t *testing.T, sm *abdrc.StateMsg) {
			si := shardEntry(sm, 2)
			si.Fees = map[string]uint64{"somebody else": 0}
		}, "validator"},
		{"root hash field changed", func(t *testing.T, sm *abdrc.StateMsg) { shardEntry(sm, 2).RootHash = []byte{7} }, "last certified root hash"},
		{"configuration hash changed", func(t *testing.T, sm *abdrc.StateMsg) { shardEntry(sm, 2).ShardConfHash[0] ^= 1 }, "shard conf hash"},
		// last responses
		{"missing UC and TR of a certified shard", func(t *testing.T, sm *abdrc.StateMsg) {
			shardEntry(sm, 1).UC, shardEntry(sm, 1).TR = nil, nil
		}, "last response"},
		{"UC without TR", func(t *testing.T, sm *abdrc.StateMsg) { shardEntry(sm, 1).TR = nil }, "last response"},
		{"UC of another shard", func(t *testing.T, sm *abdrc.StateMsg) {
			*shardEntry(sm, 1).UC = *shardEntry(sm, 2).UC
		}, "another shard"},
		{"older genuine UC of the same shard", func(t *testing.T, sm *abdrc.StateMsg) {
			si := shardEntry(sm, 2)
			si.UC.InputRecord = &types.InputRecord{Version: 1}
		}, "another input record"},
		{"TR of the last response replaced", func(t *testing.T, sm *abdrc.StateMsg) {
			tr := *shardEntry(sm, 1).TR
			tr.Round++
			shardEntry(sm, 1).TR = &tr
		}, "technical record of the last response"},
		{"UC of another shard configuration", func(t *testing.T, sm *abdrc.StateMsg) { shardEntry(sm, 1).UC.ShardConfHash = []byte{1, 2, 3} }, "configuration hash"},
		// the shard set
		{"duplicate shard", func(t *testing.T, sm *abdrc.StateMsg) {
			sm.CommittedHead.ShardInfo = append(sm.CommittedHead.ShardInfo, *shardEntry(sm, 1))
		}, "more than once"},
		{"missing shard", func(t *testing.T, sm *abdrc.StateMsg) {
			sm.CommittedHead.ShardInfo = sm.CommittedHead.ShardInfo[:1]
		}, "lacks the active shard"},
		{"unexpected shard", func(t *testing.T, sm *abdrc.StateMsg) {
			extra := *shardEntry(sm, 2)
			extra.Partition = 99
			sm.CommittedHead.ShardInfo = append(sm.CommittedHead.ShardInfo, extra)
		}, "not active"},
		// block, QC and commit QC
		{"QC of another round", func(t *testing.T, sm *abdrc.StateMsg) { sm.CommittedHead.Qc.VoteInfo.RoundNumber++ }, "QC is of round"},
		{"commit QC does not commit the block", func(t *testing.T, sm *abdrc.StateMsg) { sm.CommittedHead.CommitQc.VoteInfo.ParentRoundNumber-- }, "commit QC"},
		{"commit info of another round", func(t *testing.T, sm *abdrc.StateMsg) {
			sm.CommittedHead.CommitQc.LedgerCommitInfo.RootChainRoundNumber++
		}, "commit info"},
		{"commit QC of a non consecutive round", func(t *testing.T, sm *abdrc.StateMsg) { sm.CommittedHead.CommitQc.VoteInfo.RoundNumber += 2 }, "commit QC"},
		{"block epoch changed", func(t *testing.T, sm *abdrc.StateMsg) { sm.CommittedHead.Block.Epoch++ }, "epoch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sm := received(t, good)
			tc.mut(t, sm)
			db, err := NewBoltStorage(filepath.Join(t.TempDir(), "recovered.db"))
			require.NoError(t, err)
			defer db.Close()
			store, err := NewFromState(crypto.SHA256, sm.CommittedHead, db, c.orch, c.log)
			require.Error(t, err)
			require.Nil(t, store)
			require.ErrorContains(t, err, tc.want)
			// nothing was written
			blocks, err := db.LoadBlocks()
			require.NoError(t, err)
			require.Empty(t, blocks, "storage must stay empty")
		})
	}

	t.Run("genesis block which is not the local genesis", func(t *testing.T) {
		g := recoveryChain(t)
		sm := received(t, g.state())
		sm.CommittedHead.Block.Timestamp++
		db, err := NewBoltStorage(filepath.Join(t.TempDir(), "recovered.db"))
		require.NoError(t, err)
		defer db.Close()
		_, err = NewFromState(crypto.SHA256, sm.CommittedHead, db, g.orch, g.log)
		require.ErrorContains(t, err, "genesis block differs from the local genesis")
		blocks, err := db.LoadBlocks()
		require.NoError(t, err)
		require.Empty(t, blocks)
	})

	t.Run("genesis head with shards", func(t *testing.T) {
		g := recoveryChain(t)
		sm := received(t, g.state())
		sm.CommittedHead.ShardInfo = append(sm.CommittedHead.ShardInfo, abdrc.ShardInfo{Partition: 1})
		_, _, err := g.recoverInto(sm)
		require.Error(t, err)
	})
}

// Every shard of a committed head has a last response (a newly activated shard gets its first one when the block of
// the activation is committed): leaving it out is rejected even for a shard whose state is the initial one, a peer
// could otherwise strip it from a certified shard.
func Test_RecoveryBinding_LastResponseIsRequired(t *testing.T) {
	conf := newShardConf(t)
	si, err := NewShardInfo(conf, crypto.SHA256)
	require.NoError(t, err)
	d := abdrc.ShardInfo{
		Partition: si.PartitionID, Shard: si.ShardID, T2Timeout: si.T2Timeout, RootHash: si.RootHash, PrevEpochStat: si.PrevEpochStat,
		Stat: si.Stat, PrevEpochFees: si.PrevEpochFees, Fees: si.Fees, IR: si.IR, IRTR: si.TR, ShardConfHash: si.ShardConfHash,
	}
	_, err = validateRecoveredShard(&d, shardConfPair{current: conf}, crypto.SHA256)
	require.ErrorContains(t, err, "last response")
}

// What the next consumers do with a shard without a last response must not crash either (defence in depth, the
// state itself is rejected before it gets here).
func Test_ShardWithoutLastResponseIsSafe(t *testing.T) {
	si := &ShardInfo{PartitionID: 1, ShardID: types.ShardID{}, Fees: map[string]uint64{}, IR: &types.InputRecord{Version: 1, Epoch: 0},
		TR: certification.TechnicalRecord{Epoch: 7}}
	k := types.PartitionShardID{PartitionID: 1, ShardID: types.ShardID{}.Key()}
	ss := ShardStates{States: map[types.PartitionShardID]*ShardInfo{k: si}, Changed: ShardSet{}}
	confs := map[types.PartitionShardID]*types.PartitionDescriptionRecord{k: {Epoch: 3, Validators: make([]*types.NodeInfo, 1)}}
	require.NotPanics(t, func() {
		_, err := ss.nextBlock(confs, crypto.SHA256)
		require.ErrorContains(t, err, fmt.Sprintf("creating ShardInfo %s - %s of the next epoch", si.PartitionID, si.ShardID))
	})
	require.NotPanics(t, func() {
		require.Error(t, si.ValidRequest(&certification.BlockCertificationRequest{}))
	})
	si.trustBase = nil
	require.NotPanics(t, func() { require.Error(t, si.ValidRequest(&certification.BlockCertificationRequest{NodeID: "a"})) })
}

// The genesis QC is unsigned: a genesis head is accepted only with the local genesis QC in every field.
func Test_RecoveryBinding_GenesisQcIsTheLocalOne(t *testing.T) {
	g := recoveryChain(t)
	_, _, err := g.recoverInto(received(t, g.state()))
	require.NoError(t, err)
	for name, mut := range map[string]func(*abdrc.StateMsg){
		"timestamp":     func(sm *abdrc.StateMsg) { sm.CommittedHead.Qc.VoteInfo.Timestamp++ },
		"epoch":         func(sm *abdrc.StateMsg) { sm.CommittedHead.Qc.VoteInfo.Epoch++ },
		"root":          func(sm *abdrc.StateMsg) { sm.CommittedHead.Qc.VoteInfo.CurrentRootHash = []byte{1} },
		"commit info":   func(sm *abdrc.StateMsg) { sm.CommittedHead.Qc.LedgerCommitInfo.Timestamp++ },
		"previous hash": func(sm *abdrc.StateMsg) { sm.CommittedHead.Qc.LedgerCommitInfo.PreviousHash = []byte{9} },
	} {
		t.Run(name, func(t *testing.T) {
			sm := received(t, g.state())
			mut(sm)
			db, err := NewBoltStorage(filepath.Join(t.TempDir(), "recovered.db"))
			require.NoError(t, err)
			defer db.Close()
			_, err = NewFromState(crypto.SHA256, sm.CommittedHead, db, g.orch, g.log)
			require.ErrorContains(t, err, "genesis QC differs")
			requireNothingPersisted(t, db)
		})
	}
}
