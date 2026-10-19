package storage

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

// Honest heads around shard epoch changes, recovered at every step of a run: the shard info is switched to the new
// epoch only by the first change request of the shard in it, and while the shard is idle (does not certify) every
// block starts the next epoch of the info again. The review of bft-core#48 found heads of these kinds rejected.

// overlaps tells whether a shard changes in both blocks. The request of a shard in a block is built on the response
// of the committed state the block extends, and the shard gets a new response only when its previous change is
// committed, so a correct network has no such overlap; the chain driver tolerates it (it verifies against the state
// of its time) but replaying the pending block against the later committed state, as a recovering node does, can
// not accept it.
func overlaps(a, b []types.PartitionID) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func recoverEveryHead(t *testing.T, c *testChain, steps [][]types.PartitionID) {
	t.Helper()
	var prev []types.PartitionID
	for i, changed := range steps {
		overlap := overlaps(prev, changed)
		prev = changed
		c.next(changed...)
		sm := received(t, c.state())
		head := sm.CommittedHead.GetRound()
		bs, _, err := c.recoverInto(sm)
		require.NoError(t, err, "step %d, head round %d, changed %v", i, head, changed)
		require.Equal(t, c.store.blockTree.root.data.RootHash, bs.blockTree.root.data.RootHash)
		if overlap {
			continue
		}
		// the staged validation (also of the pending tip) accepts it too
		toRound := head
		if n := len(sm.Pending); n > 0 {
			toRound = sm.Pending[n-1].GetRound()
		}
		_, _, err = validateLikeManager(t, c, received(t, c.state()), toRound)
		require.NoError(t, err, "staged validation, step %d, head round %d", i, head)
	}
}

// a shard idle across its EpochStart (blocker 2 of the review): the info is still of the previous epoch
func Test_RecoveryEpochs_IdleAcrossEpochStart(t *testing.T) {
	c := newTestChain(t, chainShard{partition: 1, epochStarts: []uint64{1, 5}}, chainShard{partition: 2, epochStarts: []uint64{1}})
	recoverEveryHead(t, c, [][]types.PartitionID{nil, nil, {1, 2}, {2}, {2}, {2}, {2}, {1}, {2}, {2}, {2}, {1}, {2}})
}

// a shard idle for several rounds after its transition (blocker 1)
func Test_RecoveryEpochs_IdleAfterTransition(t *testing.T) {
	c := newTestChain(t, chainShard{partition: 1, epochStarts: []uint64{1, 5}}, chainShard{partition: 2, epochStarts: []uint64{1}})
	recoverEveryHead(t, c, [][]types.PartitionID{nil, nil, {1, 2}, {1}, {2}, {2}, {2}, {2}, {1}, {2}})
}

// shards whose epochs start at different rounds, both changing every round (blocker 3): the map iteration order
// used to decide
func Test_RecoveryEpochs_StaggeredEpochStarts(t *testing.T) {
	for run := 0; run < 6; run++ {
		c := newTestChain(t, chainShard{partition: 1, epochStarts: []uint64{1, 4}}, chainShard{partition: 2, epochStarts: []uint64{1, 5, 10}})
		for i, ch := range [][]types.PartitionID{nil, nil, {1, 2}, {1, 2}, {1, 2}, {1, 2}, {1, 2}, {1, 2}, {1, 2}, {1, 2}, {1, 2}} {
			c.next(ch...)
			_, _, err := c.recoverInto(received(t, c.state()))
			require.NoError(t, err, "run %d step %d head %d", run, i, c.store.blockTree.root.data.GetRound())
		}
	}
}

// several epochs per shard, shards that are idle most of the time and one which changes all the time; each shard
// certifies in its epoch before the next one starts (the state transition requires it: epochs must be consecutive)
func Test_RecoveryEpochs_MultiEpochWithIdleShards(t *testing.T) {
	c := newTestChain(t,
		chainShard{partition: 1, epochStarts: []uint64{1, 4, 10, 16}},
		chainShard{partition: 2, epochStarts: []uint64{1, 6, 13}},
		chainShard{partition: 3, epochStarts: []uint64{1, 5}})
	steps := [][]types.PartitionID{
		nil, nil, {1, 2, 3}, nil, {1}, {2, 3}, nil, {2}, {1}, {3}, nil, {1, 2}, nil, {2}, {1}, nil, nil, {1}, nil, nil, {2}, nil,
	}
	recoverEveryHead(t, c, steps)
}

// The stripping of the last response of a certified shard (major 1 of the review), with real signatures through
// StateMsg.Verify: the state verifies, but it is rejected by the recovery and nothing is written.
func Test_RecoveryEpochs_StrippedLastResponseIsRejected(t *testing.T) {
	c := newTestChain(t, chainShard{partition: 1, epochStarts: []uint64{1}}, chainShard{partition: 2, epochStarts: []uint64{1}})
	for _, ch := range [][]types.PartitionID{nil, nil, {1}, nil, {1}} {
		c.next(ch...)
	}
	require.NotNil(t, c.store.ShardInfo(2, types.ShardID{}).LastCR, "the honest head has the activation response of the idle shard")
	sm := received(t, c.state())
	root := testutils.NewTestNode(t)
	ni := root.NodeInfo(t)
	tb, err := types.NewTrustBase(5, []*types.NodeInfo{ni})
	require.NoError(t, err)
	signQC := func(q *rctypes.QuorumCert) {
		if q == nil || q.GetRound() == rctypes.GenesisRootRound {
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
		if uc := sm.CommittedHead.ShardInfo[i].UC; uc != nil {
			uc.UnicitySeal.Signatures = nil
			require.NoError(t, uc.UnicitySeal.Sign(ni.NodeID, root.Signer))
		}
	}
	require.NoError(t, sm.Verify(crypto.SHA256, tb), "signed control")
	toRound := sm.CommittedHead.GetRound()
	_, _, err = validateLikeManager(t, c, received(t, sm), toRound)
	require.NoError(t, err, "control through the recovery")

	var stripped *abdrc.StateMsg = received(t, sm)
	si := shardEntry(stripped, 2)
	si.UC, si.TR = nil, nil
	require.NoError(t, stripped.Verify(crypto.SHA256, tb), "StateMsg.Verify skips a shard without UC")
	db, _, err := validateLikeManager(t, c, stripped, toRound)
	require.ErrorContains(t, err, "last response")
	requireNothingPersisted(t, db)
}

// The shard info of an idle shard which has not certified in its new epoch has no free value: zero current accounting
// and the canonical zero encoding of the previous accounting, byte for byte (see isNewEpochAccounting).
func Test_RecoveryEpochs_RepeatedSwitchStateIsStrict(t *testing.T) {
	c := newTestChain(t, chainShard{partition: 1, epochStarts: []uint64{1, 5}}, chainShard{partition: 2, epochStarts: []uint64{1}})
	for _, ch := range [][]types.PartitionID{nil, nil, {1, 2}, nil, {1}, nil, nil, nil} {
		c.next(ch...)
	}
	good := received(t, c.state())
	d := shardEntry(good, 1)
	require.NotEqual(t, d.IR.Epoch, d.IRTR.Epoch, "shard 1 is between its epoch change and its first certification in the new epoch")
	_, _, err := c.recoverInto(received(t, good))
	require.NoError(t, err)
	for name, mut := range map[string]func(*abdrc.ShardInfo){
		"fees": func(si *abdrc.ShardInfo) {
			for k := range si.Fees {
				si.Fees[k] = 5
			}
		},
		"statistics":               func(si *abdrc.ShardInfo) { si.Stat.Blocks = 1 },
		"fee list of other nodes":  func(si *abdrc.ShardInfo) { si.PrevEpochFees = []byte{0xa1, 0x61, 0x78, 0x01} },
		"not a statistical record": func(si *abdrc.ShardInfo) { si.PrevEpochStat = []byte{1, 2, 3} },
		// well formed and canonical, but not the canonical zero encoding
		"non-zero previous fees": func(si *abdrc.ShardInfo) {
			fees := map[string]uint64{}
			for k := range si.Fees {
				fees[k] = 7
			}
			b, err := types.Cbor.Marshal(fees)
			require.NoError(t, err)
			si.PrevEpochFees = b
		},
		"non-zero previous statistics": func(si *abdrc.ShardInfo) {
			b, err := types.Cbor.Marshal(certification.StatisticalRecord{Blocks: 4, BlockFees: 9})
			require.NoError(t, err)
			si.PrevEpochStat = b
		},
		"non canonical serialization": func(si *abdrc.ShardInfo) { si.PrevEpochFees = append([]byte{0xb8, 0x01}, si.PrevEpochFees[1:]...) },
	} {
		t.Run(name, func(t *testing.T) {
			sm := received(t, good)
			mut(shardEntry(sm, 1))
			db, _, err := c.recoverInto(sm)
			_ = db
			require.Error(t, err)
		})
	}
}
