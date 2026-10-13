package storage

import (
	"crypto"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	testpartition "github.com/unicitynetwork/bft-core/rootchain/partitions/testutils"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

func initBlockStoreFromGenesis(t *testing.T, shardConf *types.PartitionDescriptionRecord) *BlockStore {
	t.Helper()
	dir := t.TempDir()

	db, err := NewBoltStorage(filepath.Join(dir, "blocks.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	log := logger.New(t)
	orchestration, err := partitions.NewOrchestration(5, filepath.Join(dir, "orchestration.db"), log)
	require.NoError(t, err)
	if shardConf != nil {
		require.NoError(t, orchestration.AddShardConfig(shardConf))
		require.NoError(t, db.WriteBlock(genesisBlockWithShard(t, shardConf), true))
	}
	t.Cleanup(func() { _ = orchestration.Close() })

	bStore, err := New(crypto.SHA256, db, orchestration, log)
	require.NoError(t, err)
	return bStore
}

func Test_BlockStore_New(t *testing.T) {
	t.Run("invalid arguments", func(t *testing.T) {
		bs, err := New(crypto.SHA256, nil, nil, nil)
		require.EqualError(t, err, `storage is nil`)
		require.Nil(t, bs)
	})

	t.Run("loading tree failure", func(t *testing.T) {
		expErr := errors.New("failure to load blocks")
		db := mockPersistentStore{
			loadBlocks: func() ([]*ExecutedBlock, error) { return nil, expErr },
		}
		bs, err := New(crypto.SHA256, db, nil, nil)
		require.ErrorIs(t, err, expErr)
		require.Nil(t, bs)
	})

	t.Run("loading existing state success", func(t *testing.T) {
		orchestration := mockOrchestration{
			shardConfigs: func(rootRound uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
				return nil, nil
			},
		}

		rootBlock := ExecutedBlock{BlockData: &rctypes.BlockData{Round: 90}, CommitQc: &rctypes.QuorumCert{}}
		db := mockPersistentStore{
			loadBlocks: func() ([]*ExecutedBlock, error) { return []*ExecutedBlock{&rootBlock}, nil },
		}
		bs, err := New(crypto.SHA256, db, orchestration, nil)
		require.NoError(t, err)
		require.NotNil(t, bs)

		b, err := bs.Block(rootBlock.GetRound())
		require.NoError(t, err)
		require.Equal(t, &rootBlock, b)
	})
}

func TestHandleTcError(t *testing.T) {
	bStore := initBlockStoreFromGenesis(t, nil)
	require.ErrorContains(t, bStore.ProcessTc(nil), "tc is nil")
	tc := &rctypes.TimeoutCert{
		Timeout: &rctypes.Timeout{
			Round: 3,
		},
	}
	// For now ignore if we do not have a block that timeouts
	require.NoError(t, bStore.ProcessTc(tc))
}

/*
Round can get both TC and QC - validators vote for the proposal and then time out, the QC
can be formed of the votes sent before the timeout. The block of the round must be still
usable after the TC has been processed.
*/
func Test_BlockStore_lateQcAfterTc(t *testing.T) {
	irVer := mockIRVerifier{verify: func(uint64, *rctypes.IRChangeReq) (*types.InputRecord, error) {
		return nil, errors.New("no IR changes in this test")
	}}
	tc3 := &rctypes.TimeoutCert{Timeout: &rctypes.Timeout{Round: 3}}
	// creates chain B1--> B2--> B3 where round 3 has got TC, returns the store, QC
	// for the round 2 (current high QC) and (unprocessed) QC for the round 3
	setup := func(t *testing.T) (bs *BlockStore, qc2, qc3 *rctypes.QuorumCert) {
		bs = initBlockStoreFromGenesis(t, nil)
		rh2, err := bs.Add(&rctypes.BlockData{Round: 2, Payload: &rctypes.Payload{}, Qc: bs.GetHighQc()}, irVer)
		require.NoError(t, err)
		qc2 = qcFor(2, 1, rh2, 0)
		_, err = bs.ProcessQc(qc2)
		require.NoError(t, err)
		rh3, err := bs.Add(&rctypes.BlockData{Round: 3, Payload: &rctypes.Payload{}, Qc: qc2}, irVer)
		require.NoError(t, err)

		require.NoError(t, bs.ProcessTc(tc3))
		// the block stays in the tree and in the DB
		b, err := bs.Block(3)
		require.NoError(t, err)
		require.EqualValues(t, 3, b.GetRound())
		require.Len(t, bs.blockTree.allUncommittedNodes(), 2)
		require.Equal(t, []uint64{3, 2, 1}, persistedRounds(t, bs.GetDB()))
		require.Equal(t, qc2, bs.GetHighQc())
		return bs, qc2, qcFor(3, 2, rh3, 0)
	}
	// loads new store from the DB of the bs
	reload := func(t *testing.T, bs *BlockStore) *BlockStore {
		bs, err := New(crypto.SHA256, bs.GetDB(), bs.orchestration, bs.log)
		require.NoError(t, err)
		return bs
	}

	t.Run("late QC is processed and proposal extending it is accepted", func(t *testing.T) {
		bs, _, qc3 := setup(t)
		_, err := bs.ProcessQc(qc3)
		require.NoError(t, err)
		require.Equal(t, qc3, bs.GetHighQc())

		_, err = bs.Add(&rctypes.BlockData{Round: 4, Payload: &rctypes.Payload{}, Qc: qc3}, irVer)
		require.NoError(t, err)
		require.Equal(t, []uint64{4, 3, 2, 1}, persistedRounds(t, bs.GetDB()))
		// state sent to recovering nodes contains the block
		state, err := bs.GetState()
		require.NoError(t, err)
		require.Len(t, state.Pending, 3)
	})

	t.Run("proposal extending the late QC is accepted", func(t *testing.T) {
		// the QC itself is not processed, ie it is considered to be stale
		bs, _, qc3 := setup(t)
		_, err := bs.Add(&rctypes.BlockData{Round: 4, Payload: &rctypes.Payload{}, Qc: qc3}, irVer)
		require.NoError(t, err)
		require.Len(t, bs.blockTree.allUncommittedNodes(), 3)
	})

	t.Run("repeated TC is harmless", func(t *testing.T) {
		bs, _, qc3 := setup(t)
		require.NoError(t, bs.ProcessTc(tc3))
		_, err := bs.ProcessQc(qc3)
		require.NoError(t, err)
		// TC after the QC
		require.NoError(t, bs.ProcessTc(tc3))
		require.Equal(t, qc3, bs.GetHighQc())
		_, err = bs.Add(&rctypes.BlockData{Round: 4, Payload: &rctypes.Payload{}, Qc: qc3}, irVer)
		require.NoError(t, err)
	})

	t.Run("TC for a round the node has no block for", func(t *testing.T) {
		bs, _, _ := setup(t)
		require.NoError(t, bs.ProcessTc(&rctypes.TimeoutCert{Timeout: &rctypes.Timeout{Round: 4}}))
		require.Len(t, bs.blockTree.allUncommittedNodes(), 2)
	})

	t.Run("late QC after restart", func(t *testing.T) {
		bs, _, qc3 := setup(t)
		bs = reload(t, bs)
		_, err := bs.ProcessQc(qc3)
		require.NoError(t, err)
		_, err = bs.Add(&rctypes.BlockData{Round: 4, Payload: &rctypes.Payload{}, Qc: qc3}, irVer)
		require.NoError(t, err)
	})

	t.Run("chain continues from the previous round", func(t *testing.T) {
		bs, qc2, qc3 := setup(t)
		// B2--> B3
		//  ╰--> B4--> B5
		rh4, err := bs.Add(&rctypes.BlockData{Round: 4, Payload: &rctypes.Payload{}, Qc: qc2}, irVer)
		require.NoError(t, err)
		// node can be restarted while there are multiple branches
		bs = reload(t, bs)
		require.Len(t, bs.blockTree.allUncommittedNodes(), 3)
		qc4 := qcFor(4, 2, rh4, 0)
		_, err = bs.ProcessQc(qc4)
		require.NoError(t, err)
		_, err = bs.Add(&rctypes.BlockData{Round: 5, Payload: &rctypes.Payload{}, Qc: qc4}, irVer)
		require.NoError(t, err)
		// block of the timeout round is still there...
		_, err = bs.Block(3)
		require.NoError(t, err)
		state, err := bs.GetState()
		require.NoError(t, err)
		require.Len(t, state.Pending, 4)
		// ...until QC for round 5 commits round 4
		_, err = bs.ProcessQc(qcFor(5, 4, nil, 4))
		require.NoError(t, err)
		require.EqualValues(t, 4, bs.blockTree.Root().GetRound())
		require.Equal(t, []uint64{5, 4}, persistedRounds(t, bs.GetDB()))

		_, err = bs.Block(3)
		require.EqualError(t, err, "block for round 3 not found")
		_, err = bs.ProcessQc(qc3)
		require.NoError(t, err, "stale QC is ignored")
		_, err = bs.Add(&rctypes.BlockData{Round: 6, Payload: &rctypes.Payload{}, Qc: qc3}, irVer)
		require.EqualError(t, err, "add block failed: parent round 3 not found, recover")
	})
}

/*
Only the changes in the branch the new block extends are in the way of a new change of the
shard, at most one of the branches is committed.
*/
func Test_BlockStore_IsChangeInProgress(t *testing.T) {
	shardConf := newShardConf(t)
	partition, shard := shardConf.PartitionID, shardConf.ShardID
	bs := initBlockStoreFromGenesis(t, shardConf)
	ir := func(round uint64) *types.InputRecord {
		return &types.InputRecord{Version: 1, RoundNumber: round, Hash: []byte{byte(round)}, BlockHash: []byte{1}, SummaryValue: []byte{2}}
	}
	// what IRChangeReqVerifier does: no new change while one is in progress in the branch the block extends
	irVer := mockIRVerifier2(func(round, parentRound uint64, req *rctypes.IRChangeReq) (*types.InputRecord, error) {
		if bs.IsChangeInProgress(parentRound, req.Partition, req.Shard) != nil {
			return nil, errors.New("shard has pending changes in pipeline")
		}
		return ir(round), nil
	})
	change := &rctypes.Payload{Requests: []*rctypes.IRChangeReq{{Partition: partition, Shard: shard, CertReason: rctypes.T2Timeout}}}

	// B1 (root)--> B2--> B3 (changes the shard, gets TC)
	//               ╰--> B4 (changes the shard)--> B5
	rh2, err := bs.Add(&rctypes.BlockData{Round: 2, Payload: &rctypes.Payload{}, Qc: bs.GetHighQc()}, irVer)
	require.NoError(t, err)
	qc2 := qcFor(2, 1, rh2, 0)
	_, err = bs.ProcessQc(qc2)
	require.NoError(t, err)
	require.Nil(t, bs.IsChangeInProgress(2, partition, shard))

	rh3, err := bs.Add(&rctypes.BlockData{Round: 3, Payload: change, Qc: qc2}, irVer)
	require.NoError(t, err)
	require.Equal(t, ir(3), bs.IsChangeInProgress(3, partition, shard))
	require.Nil(t, bs.IsChangeInProgress(2, partition, shard))
	require.NoError(t, bs.ProcessTc(&rctypes.TimeoutCert{Timeout: &rctypes.Timeout{Round: 3}}))
	require.Equal(t, ir(3), bs.IsChangeInProgress(3, partition, shard))

	// block extending the round 2 can change the shard again...
	rh4, err := bs.Add(&rctypes.BlockData{Round: 4, Payload: change, Qc: qc2}, irVer)
	require.NoError(t, err)
	require.Equal(t, ir(4), bs.IsChangeInProgress(4, partition, shard))
	require.Equal(t, ir(3), bs.IsChangeInProgress(3, partition, shard))
	require.Nil(t, bs.IsChangeInProgress(2, partition, shard))
	// ...but block extending the round 3 or 4 can't
	_, err = bs.Add(&rctypes.BlockData{Round: 5, Payload: change, Qc: qcFor(3, 2, rh3, 0)}, irVer)
	require.ErrorContains(t, err, "shard has pending changes in pipeline")
	qc4 := qcFor(4, 2, rh4, 0)
	_, err = bs.Add(&rctypes.BlockData{Round: 5, Payload: change, Qc: qc4}, irVer)
	require.ErrorContains(t, err, "shard has pending changes in pipeline")

	_, err = bs.ProcessQc(qc4)
	require.NoError(t, err)
	rh5, err := bs.Add(&rctypes.BlockData{Round: 5, Payload: &rctypes.Payload{}, Qc: qc4}, irVer)
	require.NoError(t, err)
	// change is in progress in all the blocks of the branch until it is committed
	require.Equal(t, ir(4), bs.IsChangeInProgress(5, partition, shard))

	// QC for round 5 commits round 4 - the change of round 4 is certified, the one of round 3 is dropped
	qc5 := qcFor(5, 4, rh5, 4)
	qc5.LedgerCommitInfo.Hash = rh4
	crs, err := bs.ProcessQc(qc5)
	require.NoError(t, err)
	require.Len(t, crs, 1)
	require.Equal(t, ir(4), crs[0].UC.InputRecord)
	for round := uint64(2); round <= 6; round++ {
		require.Nil(t, bs.IsChangeInProgress(round, partition, shard), "round %d", round)
	}
}

func TestHandleQcError(t *testing.T) {
	bStore := initBlockStoreFromGenesis(t, nil)
	ucs, err := bStore.ProcessQc(nil)
	require.ErrorContains(t, err, "qc is nil")
	require.Nil(t, ucs)
	// qc for non-existing round
	qc := &rctypes.QuorumCert{
		VoteInfo: &rctypes.RoundInfo{
			RoundNumber:       3,
			ParentRoundNumber: 2,
		},
	}
	ucs, err = bStore.ProcessQc(qc)
	require.ErrorContains(t, err, "block for round 3 not found")
	require.Nil(t, ucs)
}

func TestBlockStoreAdd(t *testing.T) {
	bStore := initBlockStoreFromGenesis(t, nil)
	rBlock := bStore.blockTree.Root()
	mockBlockVer := mockIRVerifier{
		verify: func(round uint64, irChReq *rctypes.IRChangeReq) (*types.InputRecord, error) {
			luc, err := bStore.GetCertificate(irChReq.Partition, irChReq.Shard)
			if err != nil {
				return nil, fmt.Errorf("invalid payload: partition %s state is missing: %w", irChReq.Partition, err)
			}
			switch irChReq.CertReason {
			case rctypes.Quorum:
				// NB! there was at least one request, otherwise we would not be here
				return irChReq.Requests[0].InputRecord, nil
			case rctypes.QuorumNotPossible:
			case rctypes.T2Timeout:
				return luc.UC.InputRecord, nil
			}
			return nil, fmt.Errorf("unknown certification reason %v", irChReq.CertReason)
		},
	}
	block := &rctypes.BlockData{
		Round:   rctypes.GenesisRootRound,
		Payload: &rctypes.Payload{},
		Qc:      nil,
	}
	_, err := bStore.Add(block, mockBlockVer)
	require.ErrorContains(t, err, "add block failed: different block for round 1 is already in store")
	block = &rctypes.BlockData{
		Round:   rctypes.GenesisRootRound + 1,
		Payload: &rctypes.Payload{},
		Qc:      bStore.GetHighQc(), // the qc is genesis qc
	}
	// Proposal always comes with Qc and Block, process Qc first and then new block
	// add stale qc for block 1 - this is already present as highQC from genesis block
	ucs, err := bStore.ProcessQc(block.Qc)
	require.NoError(t, err)
	require.Nil(t, ucs)

	// and the new block 2 - since there is no shards, RootHash stays nil
	rh, err := bStore.Add(block, mockBlockVer)
	require.NoError(t, err)
	require.Nil(t, rh)

	// add qc for round 3, commits round 1
	vInfo := &rctypes.RoundInfo{
		RoundNumber:       rctypes.GenesisRootRound + 1,
		ParentRoundNumber: rctypes.GenesisRootRound,
		CurrentRootHash:   rh,
	}
	qc := &rctypes.QuorumCert{
		VoteInfo: vInfo,
		LedgerCommitInfo: &types.UnicitySeal{
			Version:              1,
			Hash:                 rBlock.RootHash,
			RootChainRoundNumber: rctypes.GenesisRootRound,
		},
	}
	ucs, err = bStore.ProcessQc(qc)
	require.NoError(t, err)
	require.Empty(t, ucs)

	b, err := bStore.Block(rctypes.GenesisRootRound + 1)
	require.NoError(t, err)
	require.EqualValues(t, rctypes.GenesisRootRound+1, b.BlockData.Round)

	// add block 3
	// qc for round 2, does not commit a round
	block = &rctypes.BlockData{
		Round:   rctypes.GenesisRootRound + 2,
		Payload: &rctypes.Payload{},
		Qc:      qc,
	}
	rh, err = bStore.Add(block, mockBlockVer)
	require.NoError(t, err)
	require.Nil(t, rh)
	// prepare block 4
	vInfo = &rctypes.RoundInfo{
		RoundNumber:       rctypes.GenesisRootRound + 2,
		ParentRoundNumber: rctypes.GenesisRootRound + 1,
		CurrentRootHash:   rh,
	}
	qc = &rctypes.QuorumCert{
		VoteInfo: vInfo,
		LedgerCommitInfo: &types.UnicitySeal{
			Version:              1,
			Hash:                 rBlock.RootHash,
			RootChainRoundNumber: rctypes.GenesisRootRound + 1,
		},
	}
	// qc for round 4, commits round 2
	block = &rctypes.BlockData{
		Round:   rctypes.GenesisRootRound + 3,
		Payload: &rctypes.Payload{},
		Qc:      qc,
	}
	// Add
	ucs, err = bStore.ProcessQc(qc)
	require.NoError(t, err)
	require.Empty(t, ucs)
	// add block 4
	rh, err = bStore.Add(block, mockBlockVer)
	require.NoError(t, err)
	require.Nil(t, rh)
	rBlock = bStore.blockTree.Root()
	// block in round 2 becomes root
	require.Equal(t, uint64(2), rBlock.BlockData.Round)
	hQc := bStore.GetHighQc()
	require.Equal(t, uint64(3), hQc.VoteInfo.RoundNumber)
	// try to read a non-existing block
	b, err = bStore.Block(100)
	require.ErrorContains(t, err, "block for round 100 not found")
	require.Nil(t, b)
}

func Test_BlockStoreStore_LastVote(t *testing.T) {
	// just check that calls are routed to persistent storage,
	// there is no other logic in these methods
	orchestration := mockOrchestration{
		shardConfigs: func(rootRound uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
			return nil, nil
		},
	}

	rootBlock := ExecutedBlock{BlockData: &rctypes.BlockData{Round: 4}, CommitQc: &rctypes.QuorumCert{}}
	var msg any
	db := mockPersistentStore{
		// to avoid init of genesis return committed block
		loadBlocks: func() ([]*ExecutedBlock, error) { return []*ExecutedBlock{&rootBlock}, nil },
		// returning the value passed to write from read verifies that the persistent store methods are called
		readVote: func() (any, error) { return msg, nil },
		writeVote: func(vote any) error {
			msg = vote
			return nil
		},
	}

	bStore, err := New(crypto.SHA256, db, orchestration, nil)
	require.NoError(t, err)
	// the message type is verified by the storage!
	require.NoError(t, bStore.StoreLastVote(920))
	vote, err := bStore.ReadLastVote()
	require.NoError(t, err)
	require.Equal(t, 920, vote)
}

func Test_BlockStore_ShardInfo(t *testing.T) {
	shardConf := newShardConf(t)
	bStore := initBlockStoreFromGenesis(t, shardConf)
	si := bStore.ShardInfo(0xFFFFFFFF, types.ShardID{})
	require.Nil(t, si)
}

func Test_BlockStore_StateRoundtrip(t *testing.T) {
	shardConf := newShardConf(t)
	storeA := initBlockStoreFromGenesis(t, shardConf)
	// the genesis block is created with the shard marked as "changed" - clear
	// it as the state message does not carry that information
	clear(storeA.blockTree.root.data.ShardState.Changed)

	// modify Fees to see if they are restored correctly
	si := storeA.ShardInfo(shardConf.PartitionID, shardConf.ShardID)
	si.Fees[si.nodeIDs[0]] = 10

	state, err := storeA.GetState()
	require.NoError(t, err)
	require.NotNil(t, state)

	db, err := NewBoltStorage(filepath.Join(t.TempDir(), "blocks.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	// state msg is used to init "shard info registry", the orchestration provides data which is not part of state msg
	storeB, err := NewFromState(crypto.SHA256, state.CommittedHead, db, storeA.orchestration, logger.New(t))
	require.NoError(t, err)
	require.NotNil(t, storeB)

	// two stores should have the same state now
	require.Equal(t, storeA.blockTree.root.data.ShardState.States, storeB.blockTree.root.data.ShardState.States)
	require.Equal(t, storeA.blockTree.root.data.ShardState.Changed, storeB.blockTree.root.data.ShardState.Changed)
	require.Equal(t, storeA.blockTree.root.data.RootHash, storeB.blockTree.root.data.RootHash, "root hash")
	require.Equal(t, storeA.blockTree.root.child, storeB.blockTree.root.child)
	require.Len(t, storeB.blockTree.roundToNode, len(storeA.blockTree.roundToNode))
	for k, v := range storeA.blockTree.roundToNode {
		bNode, ok := storeB.blockTree.roundToNode[k]
		require.True(t, ok)
		require.ElementsMatch(t, v.child, bNode.child)
	}
	require.Equal(t, storeA.blockTree.highQc, storeB.blockTree.highQc)

	siA := storeA.ShardInfo(shardConf.PartitionID, shardConf.ShardID)
	require.NoError(t, err)
	require.NotNil(t, siA)
	require.NoError(t, siA.IsValid())

	siB := storeB.ShardInfo(shardConf.PartitionID, shardConf.ShardID)
	require.NoError(t, err)
	require.NotNil(t, siB)
	require.NoError(t, siB.IsValid())

	require.Equal(t, siA, siB)
}

func Test_BlockStore_persistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "blocks.db")
	// init new (empty) DB from genesis
	db, err := NewBoltStorage(dbPath)
	require.NoError(t, err)
	log := logger.New(t)
	shardConf := newShardConf(t)
	blockA := genesisBlockWithShard(t, shardConf)
	require.NoError(t, db.WriteBlock(blockA, false))

	orchestration := testpartition.NewOrchestration(t, log)
	require.NoError(t, orchestration.AddShardConfig(shardConf))
	storeA, err := New(crypto.SHA256, db, orchestration, log)
	require.NoError(t, err)
	require.NotNil(t, storeA)

	// load new DB instance from the non-empty file - must get the same state
	require.NoError(t, db.Close())
	db, err = NewBoltStorage(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// to make sure we load the state from db send in empty genesis record
	storeB, err := New(crypto.SHA256, db, orchestration, log)
	require.NoError(t, err)

	siA := blockA.ShardState.States[types.PartitionShardID{PartitionID: shardConf.PartitionID, ShardID: shardConf.ShardID.Key()}]
	siB := storeB.ShardInfo(shardConf.PartitionID, shardConf.ShardID)
	require.NoError(t, err)
	require.Equal(t, siA, siB)

	blockB, err := storeB.Block(blockA.GetRound())
	require.NoError(t, err)
	require.Equal(t, blockA, blockB)
}

func newShardConf(t *testing.T) *types.PartitionDescriptionRecord {
	node := testutils.NewTestNode(t)
	return &types.PartitionDescriptionRecord{
		Version:         1,
		NetworkID:       5,
		PartitionID:     1,
		PartitionTypeID: 1,
		ShardID:         types.ShardID{},
		UnitIDLen:       256,
		TypeIDLen:       32,
		T2Timeout:       2500 * time.Millisecond,
		Validators:      []*types.NodeInfo{node.NodeInfo(t)},
	}
}

func genesisBlockWithShard(t *testing.T, shardConf *types.PartitionDescriptionRecord) *ExecutedBlock {
	hashAlgo := crypto.SHA256
	genesisBlock := &rctypes.BlockData{
		Version:   1,
		Author:    "testgenesis",
		Round:     rctypes.GenesisRootRound,
		Epoch:     rctypes.GenesisRootEpoch,
		Timestamp: types.GenesisTime,
	}

	si, err := NewShardInfo(shardConf, hashAlgo)
	require.NoError(t, err)
	psID := types.PartitionShardID{PartitionID: si.PartitionID, ShardID: si.ShardID.Key()}
	commitQc := &rctypes.QuorumCert{
		VoteInfo: &rctypes.RoundInfo{
			Version:           1,
			RoundNumber:       genesisBlock.Round,
			Epoch:             genesisBlock.Epoch,
			Timestamp:         genesisBlock.Timestamp,
			ParentRoundNumber: 0, // no parent block
		},
		LedgerCommitInfo: &types.UnicitySeal{
			Version:              1,
			NetworkID:            5,
			RootChainRoundNumber: 4,
			Epoch:                rctypes.GenesisRootEpoch,
			Timestamp:            123,
			Hash:                 []byte{1, 2, 3},
			PreviousHash:         []byte{3, 2, 1},
		},
	}

	eb := &ExecutedBlock{
		BlockData: genesisBlock,
		HashAlgo:  hashAlgo,
		ShardState: ShardStates{
			States:  map[types.PartitionShardID]*ShardInfo{psID: si},
			Changed: ShardSet{psID: struct{}{}},
		},
		Qc:       commitQc,
		CommitQc: commitQc,
	}
	ut, _, err := eb.ShardState.UnicityTree(hashAlgo)
	require.NoError(t, err)
	eb.RootHash = ut.RootHash()
	commitQc.VoteInfo.CurrentRootHash = eb.RootHash

	return eb
}

// qcFor returns QC for the "round", when commitRound != 0 the QC commits the (parent) round
func qcFor(round, parent uint64, rootHash []byte, commitRound uint64) *rctypes.QuorumCert {
	return &rctypes.QuorumCert{
		VoteInfo:         &rctypes.RoundInfo{RoundNumber: round, ParentRoundNumber: parent, CurrentRootHash: rootHash},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, RootChainRoundNumber: commitRound},
	}
}

// persistedRounds returns the rounds of the blocks in the DB (in descending order)
func persistedRounds(t *testing.T, db PersistentStore) (rounds []uint64) {
	t.Helper()
	blocks, err := db.LoadBlocks()
	require.NoError(t, err)
	for _, b := range blocks {
		rounds = append(rounds, b.GetRound())
	}
	return rounds
}

type mockPersistentStore struct {
	loadBlocks func() ([]*ExecutedBlock, error)
	writeBlock func(block *ExecutedBlock, root bool) error
	readVote   func() (msg any, err error)
	writeVote  func(vote any) error
	writeTC    func(tc *rctypes.TimeoutCert) error
	readLastTC func() (*rctypes.TimeoutCert, error)
}

func (mps mockPersistentStore) LoadBlocks() ([]*ExecutedBlock, error) {
	return mps.loadBlocks()
}

func (mps mockPersistentStore) WriteBlock(block *ExecutedBlock, root bool) error {
	return mps.writeBlock(block, root)
}

func (mps mockPersistentStore) ReadLastVote() (msg any, err error) {
	return mps.readVote()
}

func (mps mockPersistentStore) WriteVote(vote any) error {
	return mps.writeVote(vote)
}

func (mps mockPersistentStore) WriteTC(tc *rctypes.TimeoutCert) error {
	return mps.writeTC(tc)
}

func (mps mockPersistentStore) ReadLastTC() (*rctypes.TimeoutCert, error) {
	return mps.readLastTC()
}
