package storage

import (
	"bytes"
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
//
// The fixture belongs to the fuzz function (and so to the process which runs it): it is built from f before f.Fuzz, and
// its databases and temporary directory are released by the cleanup of f, not by the cleanup of the first input (every
// input is a test of its own and ends before the next one starts). In seed mode a checked-in valid seed must reach the
// post-recovery code, which is asserted; for arbitrary inputs only a panic is a failure, and the progress of the run
// (how many inputs were decoded, verified, installed, extended) is reported, see recFuzzProgress.
func FuzzRecoveredState(f *testing.F) {
	env := newRecFuzzEnv(f)
	// the checked-in seeds which are states of the fixture run (the first ones, the rest are manipulated variants)
	valid := readFuzzSeeds(f)[:len(env.states)]
	f.Fuzz(func(t *testing.T, data []byte) {
		var sm abdrc.StateMsg
		if types.Cbor.Unmarshal(data, &sm) != nil {
			env.progress.record(reached{})
			return
		}
		r := env.exercise(&sm)
		env.progress.record(r)
		if i := indexOfSeed(valid, data); i >= 0 {
			require.True(t, r.verified && r.installed, "valid seed %d: %+v", i, r)
			if i > 3 {
				require.GreaterOrEqual(t, r.blocks, 1, "valid seed %d: blocks were added after recovery", i)
			}
		}
	})
}

type recFuzzEnv struct {
	dir      string
	orch     Orchestration
	db       BoltDB
	nodes    map[types.PartitionID]*chainNode
	log      *slog.Logger
	states   [][]byte // the encoded state messages of the heads of the fixture run (seeds)
	state    []byte   // the one of the last head
	progress *recFuzzProgress
}

func indexOfSeed(seeds [][]byte, data []byte) int {
	for i, s := range seeds {
		if bytes.Equal(s, data) {
			return i
		}
	}
	return -1
}

// recFuzzProgress counts how far the inputs of a run got, so that "executions" is not mistaken for coverage: most
// mutated inputs of a CBOR decoder never decode. If FUZZ_PROGRESS_DIR is set the counters of the process are written
// there (progress-<pid>.json, replaced every 100 inputs and at the cleanup), one file per fuzz worker.
type recFuzzProgress struct {
	m                                                  sync.Mutex
	dir                                                string
	executions, decoded, verified, installed, extended int
}

func (p *recFuzzProgress) record(r reached) {
	p.m.Lock()
	defer p.m.Unlock()
	p.executions++
	if r.decoded {
		p.decoded++
	}
	if r.verified {
		p.verified++
	}
	if r.installed {
		p.installed++
	}
	if r.blocks > 0 {
		p.extended++
	}
	if p.dir != "" && p.executions%100 == 0 {
		p.flushLocked()
	}
}

func (p *recFuzzProgress) flush() {
	p.m.Lock()
	defer p.m.Unlock()
	if p.dir != "" {
		p.flushLocked()
	}
}

func (p *recFuzzProgress) flushLocked() {
	body := fmt.Sprintf(`{"executions":%d,"decoded":%d,"verified":%d,"installed":%d,"extended":%d}`+"\n",
		p.executions, p.decoded, p.verified, p.installed, p.extended)
	_ = os.WriteFile(filepath.Join(p.dir, fmt.Sprintf("progress-%d.json", os.Getpid())), []byte(body), 0o644)
}

func (p *recFuzzProgress) counts() (executions, decoded, verified, installed, extended int) {
	p.m.Lock()
	defer p.m.Unlock()
	return p.executions, p.decoded, p.verified, p.installed, p.extended
}

// openFixtureBolt opens the disposable database of the recovering node of the fixture without fsync: it is thrown
// away with the test, nothing has to survive a crash, and the sync dominates the cost of an input. The production
// durability of BoltDB is not touched, NewBoltStorage is what the node uses.
func openFixtureBolt(file string) (BoltDB, error) {
	db, err := NewBoltStorage(file)
	if err != nil {
		return db, err
	}
	db.db.NoSync = true
	return db, nil
}

// newRecFuzzEnv builds the deterministic fixture: three shards with validators of fixed keys (so that the
// configuration hashes, which the state message carries, are the same in every process), with several epochs
// each, driven through the production sequence (testChain). The shards are busy, idle, switching epochs at
// different rounds, idle across their epoch start and idle after their switch, so the state messages of the
// run reach the epoch transition paths of the recovery. The state message of every head is a seed.
//
// The environment belongs to tb: its temporary directory, its orchestration database and the database of the recovering
// node are released by the cleanup of tb, in this order: the databases are closed, then the directory is removed.
func newRecFuzzEnv(tb testing.TB) *recFuzzEnv {
	tb.Helper()
	dir := tb.TempDir()
	c := newTestChainOn(tb, dir, newMemoryStore(),
		chainShard{partition: 1, key: "recovered-fuzz-node-1", epochStarts: []uint64{1, 4, 10}},
		chainShard{partition: 2, key: "recovered-fuzz-node-2", epochStarts: []uint64{1, 6}},
		chainShard{partition: 3, key: "recovered-fuzz-node-3", epochStarts: []uint64{1, 8}})
	env := &recFuzzEnv{dir: dir, orch: c.orch, nodes: c.nodes, log: c.log, progress: &recFuzzProgress{dir: os.Getenv("FUZZ_PROGRESS_DIR")}}
	tb.Cleanup(env.progress.flush)
	for _, changed := range [][]types.PartitionID{nil, nil, {1, 2, 3}, nil, {1}, {2}, nil, {1}, {3}, nil, {1, 3}, nil, {2}, {1}, nil, nil} {
		c.next(changed...)
		raw, err := types.Cbor.Marshal(c.state())
		require.NoError(tb, err)
		env.states = append(env.states, raw)
		env.state = raw
	}
	// the storage of the recovering node stays on bolt: the inputs persist and reload blocks built from a peer's
	// state (bolt, ShardStates/ShardSet CBOR); only the fixture chain above is in memory
	var err error
	env.db, err = openFixtureBolt(filepath.Join(dir, "recovered.db"))
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = env.db.Close() })
	return env
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
		node := e.nodes[si.PartitionID]
		if node == nil {
			continue
		}
		bcr := &certification.BlockCertificationRequest{
			PartitionID: si.PartitionID, ShardID: si.ShardID, NodeID: node.info.NodeID,
			InputRecord: &types.InputRecord{Version: 1, RoundNumber: round + dr, Epoch: epoch, PreviousHash: si.RootHash,
				Hash: []byte{2, 2}, BlockHash: []byte{3}, SummaryValue: []byte{}, Timestamp: ts},
		}
		if bcr.Sign(node.signer) == nil {
			out = append(out, bcr)
		}
	}
	return out
}

// reached tells how far a state message got.
type reached struct {
	decoded, verified, installed bool
	blocks                       int
}

func (e *recFuzzEnv) exercise(sm *abdrc.StateMsg) (r reached) {
	r.decoded = true
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

// The seeds really reach the code which runs after recovery, on every head of the run, among them the ones with
// shards in the middle of an epoch change.
func TestRecoveredFuzzSeedsReachPostRecoveryCode(t *testing.T) {
	env := newRecFuzzEnv(t)
	decode := func(raw []byte) *abdrc.StateMsg {
		var sm abdrc.StateMsg
		require.NoError(t, types.Cbor.Unmarshal(raw, &sm))
		return &sm
	}
	switching := 0
	for i, raw := range env.states {
		sm := decode(raw)
		r := env.exercise(sm)
		require.True(t, r.verified && r.installed, "head %d: %+v", sm.CommittedHead.GetRound(), r)
		if i > 3 {
			require.GreaterOrEqual(t, r.blocks, 1, "head %d: blocks were added after recovery", sm.CommittedHead.GetRound())
		}
		for _, si := range sm.CommittedHead.ShardInfo {
			if si.IR.Epoch != si.IRTR.Epoch {
				switching++
			}
		}
	}
	require.Greater(t, switching, 2, "heads with a shard between the epoch change and its first certification in the new epoch")
	// a certified shard without UC/TR passes StateMsg.Verify but is not installed (recovery binding)
	sm := decode(env.state)
	sm.CommittedHead.ShardInfo[0].UC, sm.CommittedHead.ShardInfo[0].TR = nil, nil
	r := env.exercise(sm)
	require.True(t, r.verified, "%+v", r)
	require.False(t, r.installed, "%+v", r)
}

// UPDATE_FUZZ_SEEDS=1 go test ./rootchain/consensus/storage -run TestWriteRecoveredFuzzSeeds rewrites the seed corpus:
// the state message of every head of the fixture run, and manipulated variants of the last ones.
func TestWriteRecoveredFuzzSeeds(t *testing.T) {
	if os.Getenv("UPDATE_FUZZ_SEEDS") == "" {
		t.Skip("set UPDATE_FUZZ_SEEDS=1 to rewrite the seed corpus")
	}
	env := newRecFuzzEnv(t)
	enc := func(raw []byte, mut func(*abdrc.StateMsg)) []byte {
		var sm abdrc.StateMsg
		require.NoError(t, types.Cbor.Unmarshal(raw, &sm))
		mut(&sm)
		b, err := types.Cbor.Marshal(&sm)
		require.NoError(t, err)
		return b
	}
	var seeds [][]byte
	seeds = append(seeds, env.states...)
	last := env.state
	seeds = append(seeds,
		enc(last, func(sm *abdrc.StateMsg) {
			sm.CommittedHead.ShardInfo[0].UC, sm.CommittedHead.ShardInfo[0].TR = nil, nil
		}),
		enc(last, func(sm *abdrc.StateMsg) { sm.CommittedHead.ShardInfo[0].IRTR.Epoch += 7 }),
		enc(last, func(sm *abdrc.StateMsg) { sm.CommittedHead.ShardInfo[1].IR.Hash = []byte{9, 9} }),
		enc(last, func(sm *abdrc.StateMsg) { sm.CommittedHead.ShardInfo[1].Fees = map[string]uint64{"x": 5} }),
		enc(last, func(sm *abdrc.StateMsg) { sm.CommittedHead.ShardInfo[2].PrevEpochFees = []byte{0xa1, 0x61, 0x78, 0x01} }),
		enc(last, func(sm *abdrc.StateMsg) {
			sm.CommittedHead.ShardInfo = append(sm.CommittedHead.ShardInfo, sm.CommittedHead.ShardInfo[0])
		}),
		enc(last, func(sm *abdrc.StateMsg) { sm.CommittedHead.ShardInfo = sm.CommittedHead.ShardInfo[:1] }),
		enc(last, func(sm *abdrc.StateMsg) { sm.CommittedHead.CommitQc.LedgerCommitInfo.Hash = []byte{1} }),
		enc(last, func(sm *abdrc.StateMsg) { sm.CommittedHead.ShardInfo = nil }),
	)
	dir := filepath.Join("testdata", "fuzz", "FuzzRecoveredState")
	require.NoError(t, os.RemoveAll(dir))
	require.NoError(t, os.MkdirAll(dir, 0o755))
	for i, s := range seeds {
		body := fmt.Sprintf("go test fuzz v1\n[]byte(%q)\n", s)
		require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("seed-%02d", i)), []byte(body), 0o644))
	}
}
