package storage

import (
	"cmp"
	"crypto"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	testtb "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
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
// configuration hash, which the state message carries, is the same in every process) driven through the production
// sequence for a few rounds (testChain), and its state message.
func newRecFuzzEnv(t *testing.T) *recFuzzEnv {
	dir, err := os.MkdirTemp("", "recovered-fuzz")
	require.NoError(t, err)
	const nodeID = "recovered-state-fuzz-node"
	c := newTestChainIn(t, dir, chainShard{partition: 1, key: nodeID, epochStarts: []uint64{1}})
	c.next()
	c.next()
	c.next(1)
	c.next(1)
	raw, err := types.Cbor.Marshal(c.state())
	require.NoError(t, err)
	db, err := NewBoltStorage(filepath.Join(dir, "recovered.db"))
	require.NoError(t, err)
	conf := c.store.ShardInfo(1, types.ShardID{})
	require.NotNil(t, conf.LastCR)
	return &recFuzzEnv{orch: c.orch, db: db, signer: c.nodes[1].signer, nodeID: nodeID, log: c.log, state: raw}
}

// fuzzIRVerifier verifies IR change requests the way the consensus manager does (against the last response of
// the shard of the parent block).
type fuzzIRVerifier struct{ store *BlockStore }

func (v fuzzIRVerifier) VerifyIRChangeReq(round, parentRound uint64, req *rctypes.IRChangeReq) (*types.InputRecord, error) {
	if req == nil {
		return nil, fmt.Errorf("IR change request is nil")
	}
	parent, err := v.store.Block(parentRound)
	if err != nil || parent == nil {
		return nil, fmt.Errorf("parent block: %v", err)
	}
	si := parent.ShardState.States[types.PartitionShardID{PartitionID: req.Partition, ShardID: req.Shard.Key()}]
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

	// the pending blocks of the message, the way the consensus manager adds them
	verifier := fuzzIRVerifier{store: store}
	pending := slices.Clone(sm.Pending)
	slices.SortFunc(pending, func(a, b *rctypes.BlockData) int { return cmp.Compare(a.GetRound(), b.GetRound()) })
	for _, b := range pending {
		if b == nil {
			continue
		}
		if b.Qc != nil {
			_, _ = store.ProcessQc(b.Qc)
		}
		_, _ = store.Add(b, verifier) // may legitimately fail: it was verified against another committed state
	}

	// further blocks: empty, then with quorum and timeout change requests; commit them
	for step := 0; step < 3; step++ {
		// extend the tip (the highest QC, if its block could be added) or else the committed head
		qc := store.GetHighQc()
		parent, err := store.Block(qc.GetRound())
		if err != nil || parent == nil {
			parent, qc = root, root.Qc
			if qc == nil || qc.GetRound() != parent.GetRound() {
				break
			}
		}
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
		root, err := store.Add(bd, verifier)
		if err != nil {
			break
		}
		r.blocks++
		eb, err := store.Block(round)
		if err != nil || eb == nil {
			break
		}
		// the QC of the block commits its parent when the rounds are consecutive
		vi := &rctypes.RoundInfo{Version: 1, RoundNumber: round, ParentRoundNumber: parent.GetRound(), Epoch: bd.Epoch, Timestamp: bd.Timestamp, CurrentRootHash: root}
		vh, _ := vi.Hash(crypto.SHA256)
		nqc := &rctypes.QuorumCert{
			VoteInfo: vi,
			LedgerCommitInfo: &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: parent.GetRound(), Epoch: parent.BlockData.Epoch,
				Timestamp: parent.BlockData.Timestamp, Hash: parent.RootHash, PreviousHash: vh},
			Signatures: map[string]hex.Bytes{"fuzz": {1}},
		}
		_, _ = store.ProcessQc(nqc)
		_, _ = toRecoveryShardInfo(eb)
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
	// a certified shard without UC/TR passes StateMsg.Verify but is not installed (recovery binding)
	sm := decode(env.state)
	sm.CommittedHead.ShardInfo[0].UC, sm.CommittedHead.ShardInfo[0].TR = nil, nil
	r = env.exercise(sm)
	require.True(t, r.verified, "%+v", r)
	require.False(t, r.installed, "%+v", r)
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
