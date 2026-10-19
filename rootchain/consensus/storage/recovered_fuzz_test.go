package storage

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	testtb "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
)

// FuzzRecoveredState drives an arbitrary decoded StateMsg through everything a recovering root node does with it:
// StateMsg.Verify (with a trust base which accepts every signature, the worst case), NewFromState, and then the
// code that only runs after recovery - certification requests of the shard validators, further blocks (empty,
// with quorum and timeout IR change requests), the commit of them (certificates are generated and kept as the
// last responses) and the state message the node would send on. A panic anywhere is a bug: the state message is
// a peer's input.
//
// The seed corpus (testdata/fuzz/FuzzRecoveredState) is the state of the genesis fixture and variants of it. Bounded run
// (iteration count):
//
//	go test ./rootchain/consensus/storage -run '^$' -fuzz FuzzRecoveredState -fuzztime 300000x
func FuzzRecoveredState(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		env := recoveredEnv(t)
		var sm abdrc.StateMsg
		if types.Cbor.Unmarshal(data, &sm) != nil {
			return
		}
		env.exercise(&sm)
	})
}

type recFuzzEnv struct {
	orch   Orchestration
	db     PersistentStore
	conf   *types.PartitionDescriptionRecord
	signer abcrypto.Signer
	nodeID string
	log    *slog.Logger
	state  []byte // the encoded genesis state (seed)
}

var recFuzz struct {
	once sync.Once
	env  *recFuzzEnv
}

func recoveredEnv(t *testing.T) *recFuzzEnv {
	recFuzz.once.Do(func() { recFuzz.env = newRecFuzzEnv(t) })
	return recFuzz.env
}

// newRecFuzzEnv builds the deterministic fixture: one shard with one validator of a fixed key (so that the
// configuration hash, which the state message carries, is the same in every process).
func newRecFuzzEnv(t *testing.T) *recFuzzEnv {
	key := sha256.Sum256([]byte("recovered state fuzz validator"))
	signer, err := abcrypto.NewInMemorySecp256K1SignerFromKey(key[:])
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	pub, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	const nodeID = "recovered-state-fuzz-node"
	conf := &types.PartitionDescriptionRecord{
		Version: 1, NetworkID: 5, PartitionID: 1, PartitionTypeID: 1, ShardID: types.ShardID{},
		UnitIDLen: 256, TypeIDLen: 32, T2Timeout: 2500 * time.Millisecond,
		Validators: []*types.NodeInfo{{NodeID: nodeID, SigKey: pub, Stake: 1}},
	}
	dir, err := os.MkdirTemp("", "recovered-fuzz")
	require.NoError(t, err)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	orch, err := partitions.NewOrchestration(5, filepath.Join(dir, "orchestration.db"), log)
	require.NoError(t, err)
	require.NoError(t, orch.AddShardConfig(conf))
	db, err := NewBoltStorage(filepath.Join(dir, "blocks.db"))
	require.NoError(t, err)
	require.NoError(t, db.WriteBlock(genesisBlockWithShard(t, conf), true))
	store, err := New(crypto.SHA256, db, orch, log)
	require.NoError(t, err)
	// the fixture shard is certified for real: the genesis block generates its certification response
	// (a UC consistent with the trees), which becomes the last response kept in the recovery shard info
	genesis := store.blockTree.root.data
	genesis.BlockData.Payload = &rctypes.Payload{}
	vi := &rctypes.RoundInfo{Version: 1, RoundNumber: genesis.GetRound(), Epoch: genesis.BlockData.Epoch, Timestamp: genesis.BlockData.Timestamp, CurrentRootHash: genesis.RootHash}
	vh, err := vi.Hash(crypto.SHA256)
	require.NoError(t, err)
	commitQc := &rctypes.QuorumCert{
		VoteInfo:         vi,
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: 4, Epoch: genesis.BlockData.Epoch, Timestamp: types.GenesisTime + 1, Hash: genesis.RootHash, PreviousHash: vh},
		Signatures:       map[string]hex.Bytes{"fuzz": {1}}, // the trust base of the fuzz accepts it
	}
	genesis.Qc, genesis.CommitQc = commitQc, commitQc
	_, err = genesis.GenerateCertificates(commitQc)
	require.NoError(t, err)
	require.NotNil(t, store.ShardInfo(conf.PartitionID, conf.ShardID).LastCR)
	clear(genesis.ShardState.Changed)
	state, err := store.GetState()
	require.NoError(t, err)
	raw, err := types.Cbor.Marshal(state)
	require.NoError(t, err)
	return &recFuzzEnv{orch: orch, db: db, conf: conf, signer: signer, nodeID: nodeID, log: log, state: raw}
}

// fuzzIRVerifier verifies IR change requests the way the consensus manager does (against the last response of
// the shard of the parent block).
type fuzzIRVerifier struct{ parent *ExecutedBlock }

func (v fuzzIRVerifier) VerifyIRChangeReq(round, parentRound uint64, req *rctypes.IRChangeReq) (*types.InputRecord, error) {
	if req == nil {
		return nil, fmt.Errorf("IR change request is nil")
	}
	si := v.parent.ShardState.States[types.PartitionShardID{PartitionID: req.Partition, ShardID: req.Shard.Key()}]
	if si == nil {
		return nil, fmt.Errorf("missing shard info")
	}
	if si.LastCR == nil {
		return nil, fmt.Errorf("shard has no certification response yet")
	}
	luc := si.LastCR.UC
	return req.Verify(si, &luc, round, 4)
}

func (e *recFuzzEnv) signedRequests(si *ShardInfo) []*certification.BlockCertificationRequest {
	round, epoch, ts := uint64(1), uint64(0), uint64(1731504540)
	round, epoch = si.TR.Round, si.TR.Epoch
	if si.LastCR != nil {
		round, epoch = si.LastCR.Technical.Round, si.LastCR.Technical.Epoch
		if si.LastCR.UC.UnicitySeal != nil {
			ts = si.LastCR.UC.UnicitySeal.Timestamp
		}
	}
	var out []*certification.BlockCertificationRequest
	for _, dr := range []uint64{0, 1} {
		bcr := &certification.BlockCertificationRequest{
			PartitionID: si.PartitionID, ShardID: si.ShardID, NodeID: e.nodeID,
			InputRecord: &types.InputRecord{Version: 1, RoundNumber: round + dr, Epoch: epoch, PreviousHash: si.RootHash,
				Hash: []byte{2, 2}, BlockHash: []byte{3}, SummaryValue: []byte{}, Timestamp: ts},
		}
		if bcr.Sign(e.signer) == nil {
			out = append(out, bcr)
		}
	}
	return out
}

// reached tells how far a state message got.
type reached struct {
	verified, installed bool
	blocks              int
}

func (e *recFuzzEnv) exercise(sm *abdrc.StateMsg) (r reached) {
	r.verified = sm.Verify(crypto.SHA256, &testtb.AlwaysValidTrustBase{}) == nil
	_ = sm.CanRecoverToRound(sm.CommittedHead.GetRound())
	if sm.CommittedHead == nil {
		return
	}
	store, err := NewFromState(crypto.SHA256, sm.CommittedHead, e.db, e.orch, e.log)
	if err != nil {
		return
	}
	r.installed = true
	if !r.verified {
		// a node never installs (or runs on) a state message which did not verify: NewFromState above is
		// exercised on every input as defensive code, the post-recovery steps only on verified ones
		return
	}
	root := store.blockTree.root.data
	_, _ = store.GetState()
	_ = store.GetCertificates()
	_ = store.GetHighQc()

	// certification requests of the shard validators
	var shards []*ShardInfo
	for _, si := range root.ShardState.States {
		shards = append(shards, si)
		_ = si.IsValid()
		for _, bcr := range e.signedRequests(si) {
			_ = si.ValidRequest(bcr)
		}
	}

	// further blocks: empty, then with quorum and timeout change requests; commit them
	parent := root
	qc := store.GetHighQc()
	for step := 0; step < 3; step++ {
		round := parent.GetRound() + 1
		payload := &rctypes.Payload{}
		if step > 0 {
			for _, si := range parent.ShardState.States {
				if step == 1 {
					if reqs := e.signedRequests(si); len(reqs) > 0 {
						payload.Requests = append(payload.Requests, &rctypes.IRChangeReq{Partition: si.PartitionID, Shard: si.ShardID, CertReason: rctypes.Quorum, Requests: reqs[:1]})
					}
				} else {
					payload.Requests = append(payload.Requests, &rctypes.IRChangeReq{Partition: si.PartitionID, Shard: si.ShardID, CertReason: rctypes.T2Timeout})
				}
			}
		}
		bd := &rctypes.BlockData{Author: "fuzz", Round: round, Epoch: parent.BlockData.Epoch, Timestamp: types.GenesisTime + round, Payload: payload, Qc: qc}
		if _, err := store.Add(bd, fuzzIRVerifier{parent: parent}); err != nil {
			break
		}
		r.blocks++
		eb, err := store.Block(round)
		if err != nil || eb == nil {
			break
		}
		// commit it: the certificates of the changed shards become the last responses
		cqc := &rctypes.QuorumCert{
			VoteInfo:         &rctypes.RoundInfo{Version: 1, RoundNumber: round, ParentRoundNumber: parent.GetRound(), Epoch: bd.Epoch, Timestamp: bd.Timestamp},
			LedgerCommitInfo: &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: round, Epoch: bd.Epoch, Timestamp: bd.Timestamp, Hash: eb.RootHash, PreviousHash: []byte{1}},
			Signatures:       map[string]hex.Bytes{"fuzz": {1}},
		}
		_, _ = eb.GenerateCertificates(cqc)
		_, _ = toRecoveryShardInfo(eb)
		parent, qc = eb, cqc
	}
	_, _ = store.GetState()
	for _, si := range shards {
		_ = si.IsValid()
	}
	return r
}

// The seeds really reach the code which runs after recovery.
func TestRecoveredFuzzSeedsReachPostRecoveryCode(t *testing.T) {
	env := recoveredEnv(t)
	decode := func(raw []byte) *abdrc.StateMsg {
		var sm abdrc.StateMsg
		require.NoError(t, types.Cbor.Unmarshal(raw, &sm))
		return &sm
	}
	t.Log("verify error:", decode(env.state).Verify(crypto.SHA256, &testtb.AlwaysValidTrustBase{}))
	r := env.exercise(decode(env.state))
	require.True(t, r.verified && r.installed, "%+v", r)
	require.GreaterOrEqual(t, r.blocks, 1, "blocks were added after recovery")
	// a shard without UC/TR: installed and driven on
	sm := decode(env.state)
	sm.CommittedHead.ShardInfo[0].UC, sm.CommittedHead.ShardInfo[0].TR = nil, nil
	r = env.exercise(sm)
	require.True(t, r.verified && r.installed, "%+v", r)
}

// UPDATE_FUZZ_SEEDS=1 go test ./rootchain/consensus/storage -run TestWriteRecoveredFuzzSeeds rewrites the seed corpus.
func TestWriteRecoveredFuzzSeeds(t *testing.T) {
	if os.Getenv("UPDATE_FUZZ_SEEDS") == "" {
		t.Skip("set UPDATE_FUZZ_SEEDS=1 to rewrite the seed corpus")
	}
	env := recoveredEnv(t)
	var base abdrc.StateMsg
	require.NoError(t, types.Cbor.Unmarshal(env.state, &base))
	enc := func(mut func(*abdrc.StateMsg)) []byte {
		var sm abdrc.StateMsg
		require.NoError(t, types.Cbor.Unmarshal(env.state, &sm))
		mut(&sm)
		b, err := types.Cbor.Marshal(&sm)
		require.NoError(t, err)
		return b
	}
	seeds := [][]byte{
		env.state,
		enc(func(sm *abdrc.StateMsg) {
			sm.CommittedHead.ShardInfo[0].UC, sm.CommittedHead.ShardInfo[0].TR = nil, nil
		}),
		enc(func(sm *abdrc.StateMsg) {
			si := &sm.CommittedHead.ShardInfo[0]
			si.UC, si.TR = nil, nil
			si.IRTR.Epoch = si.IR.Epoch + 7
		}),
		enc(func(sm *abdrc.StateMsg) { sm.CommittedHead.ShardInfo[0].IR.Hash = []byte{9, 9} }),
		enc(func(sm *abdrc.StateMsg) { sm.CommittedHead.ShardInfo[0].Fees = map[string]uint64{"x": 5} }),
		enc(func(sm *abdrc.StateMsg) {
			sm.CommittedHead.ShardInfo = append(sm.CommittedHead.ShardInfo, sm.CommittedHead.ShardInfo[0])
		}),
		enc(func(sm *abdrc.StateMsg) { sm.CommittedHead.ShardInfo = nil }),
	}
	dir := filepath.Join("testdata", "fuzz", "FuzzRecoveredState")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	for i, s := range seeds {
		body := fmt.Sprintf("go test fuzz v1\n[]byte(%q)\n", s)
		require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("seed-%d", i)), []byte(body), 0o644))
	}
}
