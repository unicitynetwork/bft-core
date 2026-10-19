package storage

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

// testChain drives a real BlockStore through the production sequence (add block, process the QC which also commits
// the parent) so that the state messages it produces have the relationships between the block, the QCs, the shard
// states and the committed root which a recovering node has to check.
type testChain struct {
	t       *testing.T
	orch    *partitions.Orchestration
	store   *BlockStore
	nodes   map[types.PartitionID]*chainNode
	highQc  *rctypes.QuorumCert
	round   uint64
	log     *slog.Logger
	counter uint64
}

// chainNode is the single validator of a test shard.
type chainNode struct {
	info   *types.NodeInfo
	signer abcrypto.Signer
}

type chainShard struct {
	partition types.PartitionID
	// key, if set, makes the validator deterministic (the configuration hash is then the same in every process)
	key string
	// epochs lists the root rounds at which the epochs 0, 1, ... of the shard start
	epochStarts []uint64
}

func newTestChain(t *testing.T, shards ...chainShard) *testChain {
	t.Helper()
	return newTestChainIn(t, t.TempDir(), shards...)
}

// newTestChainIn is newTestChain with the databases in the given directory (which outlives the test).
func newTestChainIn(t *testing.T, dir string, shards ...chainShard) *testChain {
	t.Helper()
	db, err := NewBoltStorage(filepath.Join(dir, "blocks.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return newTestChainOn(t, dir, db, shards...)
}

// newTestChainOn is newTestChainIn with the given block storage.
func newTestChainOn(t *testing.T, dir string, db PersistentStore, shards ...chainShard) *testChain {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	orch, err := partitions.NewOrchestration(5, filepath.Join(dir, "orchestration.db"), log)
	require.NoError(t, err)
	t.Cleanup(func() { _ = orch.Close() })
	c := &testChain{t: t, orch: orch, nodes: map[types.PartitionID]*chainNode{}, log: log, round: 1}
	for _, s := range shards {
		var node *chainNode
		if s.key != "" {
			k := sha256.Sum256([]byte(s.key))
			signer, err := abcrypto.NewInMemorySecp256K1SignerFromKey(k[:])
			require.NoError(t, err)
			verifier, err := signer.Verifier()
			require.NoError(t, err)
			pub, err := verifier.MarshalPublicKey()
			require.NoError(t, err)
			node = &chainNode{info: &types.NodeInfo{NodeID: s.key, SigKey: pub, Stake: 1}, signer: signer}
		} else {
			tn := testutils.NewTestNode(t)
			node = &chainNode{info: tn.NodeInfo(t), signer: tn.Signer}
		}
		c.nodes[s.partition] = node
		for epoch, start := range s.epochStarts {
			require.NoError(t, orch.AddShardConfig(&types.PartitionDescriptionRecord{
				Version: 1, NetworkID: 5, PartitionID: s.partition, PartitionTypeID: 1, ShardID: types.ShardID{},
				UnitIDLen: 256, TypeIDLen: 32, T2Timeout: 2500 * time.Millisecond,
				Validators: []*types.NodeInfo{node.info}, Epoch: uint64(epoch), EpochStart: start,
			}))
		}
	}
	c.store, err = New(crypto.SHA256, db, orch, log)
	require.NoError(t, err)
	c.highQc = c.store.GetHighQc()
	return c
}

// chainVerifier verifies IR change requests the way the consensus manager does: against the last response of the
// shard in the committed state.
type chainVerifier struct{ store *BlockStore }

func (v chainVerifier) VerifyIRChangeReq(round, _ uint64, req *rctypes.IRChangeReq) (*types.InputRecord, error) {
	si := v.store.ShardInfo(req.Partition, req.Shard)
	if si == nil || si.LastCR == nil {
		return nil, fmt.Errorf("shard %d has no certification response yet", req.Partition)
	}
	luc := si.LastCR.UC
	return req.Verify(si, &luc, round, 10)
}

// next adds the next round block with a quorum change request for each of the partitions (the shards which are
// not listed are unchanged) and processes the QC of it, which commits the previous round.
func (c *testChain) next(changed ...types.PartitionID) {
	c.t.Helper()
	parent := c.round
	c.round++
	c.counter++
	payload := &rctypes.Payload{}
	for _, p := range changed {
		si := c.store.ShardInfo(p, types.ShardID{})
		require.NotNil(c.t, si, "a shard can change after its first certification only")
		require.NotNil(c.t, si.LastCR, "a shard can change after its first certification only")
		ir := &types.InputRecord{
			Version: 1, RoundNumber: si.LastCR.Technical.Round, Epoch: si.LastCR.Technical.Epoch, PreviousHash: si.RootHash,
			Hash: []byte{byte(c.counter), byte(p), 1}, BlockHash: []byte{byte(c.counter), 2}, SummaryValue: []byte{},
			Timestamp: si.LastCR.UC.UnicitySeal.Timestamp, SumOfEarnedFees: 3,
		}
		bcr := &certification.BlockCertificationRequest{PartitionID: p, ShardID: types.ShardID{}, NodeID: c.nodes[p].info.NodeID, InputRecord: ir, BlockSize: 5, StateSize: 7}
		require.NoError(c.t, bcr.Sign(c.nodes[p].signer))
		payload.Requests = append(payload.Requests, &rctypes.IRChangeReq{Partition: p, CertReason: rctypes.Quorum, Requests: []*certification.BlockCertificationRequest{bcr}})
	}
	bd := &rctypes.BlockData{Author: "chain", Round: c.round, Epoch: rctypes.GenesisRootEpoch, Timestamp: types.GenesisTime + c.round, Payload: payload, Qc: c.highQc}
	root, err := c.store.Add(bd, chainVerifier{c.store})
	require.NoError(c.t, err)
	vi := &rctypes.RoundInfo{Version: 1, RoundNumber: c.round, ParentRoundNumber: parent, Epoch: bd.Epoch, Timestamp: bd.Timestamp, CurrentRootHash: root}
	vh, err := vi.Hash(crypto.SHA256)
	require.NoError(c.t, err)
	parentBlock, err := c.store.Block(parent)
	require.NoError(c.t, err)
	qc := &rctypes.QuorumCert{
		VoteInfo: vi,
		// the commit info is the one of the committed (parent) round, as the safety module builds it
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: parent, Epoch: parentBlock.BlockData.Epoch, Timestamp: parentBlock.BlockData.Timestamp,
			Hash: parentBlock.RootHash, PreviousHash: vh},
		Signatures: map[string]hex.Bytes{"x": {1}},
	}
	_, err = c.store.ProcessQc(qc)
	require.NoError(c.t, err)
	c.highQc = qc
}

func (c *testChain) state() *abdrc.StateMsg {
	c.t.Helper()
	sm, err := c.store.GetState()
	require.NoError(c.t, err)
	return sm
}

// received is the state message as it arrives from the network.
func received(t *testing.T, sm *abdrc.StateMsg) *abdrc.StateMsg {
	t.Helper()
	raw, err := types.Cbor.Marshal(sm)
	require.NoError(t, err)
	var out abdrc.StateMsg
	require.NoError(t, types.Cbor.Unmarshal(raw, &out))
	return &out
}

func (c *testChain) recoverInto(sm *abdrc.StateMsg) (*BlockStore, PersistentStore, error) {
	c.t.Helper()
	db, err := NewBoltStorage(filepath.Join(c.t.TempDir(), "recovered.db"))
	require.NoError(c.t, err)
	c.t.Cleanup(func() { _ = db.Close() })
	bs, err := NewFromState(crypto.SHA256, sm.CommittedHead, db, c.orch, c.log)
	return bs, db, err
}

func Test_Chain_NormalRecoveryRoundTrip(t *testing.T) {
	c := newTestChain(t, chainShard{partition: 1, epochStarts: []uint64{1}}, chainShard{partition: 2, epochStarts: []uint64{1}})
	c.next() // round 2 activates the shards, the commit of it (by round 3) certifies them
	c.next()
	c.next(1)    // round 4: shard 1 changes
	c.next(1, 2) // round 5
	c.next(1)    // round 6: shard 2 unchanged since round 5
	sm := received(t, c.state())
	bs, _, err := c.recoverInto(sm)
	require.NoError(t, err)
	require.Equal(t, c.store.blockTree.root.data.RootHash, bs.blockTree.root.data.RootHash)
}

// consistentHeadQCs returns the QC of the block and the commit QC which commits it, with the relationships the
// consensus produces (see validateRecoveredHead).
func consistentHeadQCs(t *testing.T, b *ExecutedBlock) (qc, commitQc *rctypes.QuorumCert) {
	t.Helper()
	bd := b.BlockData
	qc = &rctypes.QuorumCert{
		VoteInfo:         &rctypes.RoundInfo{Version: 1, RoundNumber: bd.Round, ParentRoundNumber: bd.GetParentRound(), Epoch: bd.Epoch, Timestamp: bd.Timestamp, CurrentRootHash: b.RootHash},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, NetworkID: 5, PreviousHash: []byte{1}},
		Signatures:       map[string]hex.Bytes{"x": {1}},
	}
	vi := &rctypes.RoundInfo{Version: 1, RoundNumber: bd.Round + 1, ParentRoundNumber: bd.Round, Epoch: bd.Epoch, Timestamp: bd.Timestamp + 1, CurrentRootHash: []byte{2}}
	vh, err := vi.Hash(crypto.SHA256)
	require.NoError(t, err)
	commitQc = &rctypes.QuorumCert{
		VoteInfo:         vi,
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: bd.Round, Epoch: bd.Epoch, Timestamp: bd.Timestamp, Hash: b.RootHash, PreviousHash: vh},
		Signatures:       map[string]hex.Bytes{"x": {1}},
	}
	return qc, commitQc
}
