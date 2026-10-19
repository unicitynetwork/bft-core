package storage

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	rcnet "github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-go-base/types"
)

// transition flow: partition 1 has two shards (A, B), partition 2 is a single shard (C).
type tsEnv struct {
	t                *testing.T
	pdrA, pdrB, pdrC *types.PartitionDescriptionRecord
	pdrA2            *types.PartitionDescriptionRecord // next epoch of A
	psA, psB, psC    types.PartitionShardID
	nodes            []*types.NodeInfo
}

func newTSEnv(t *testing.T) *tsEnv {
	_, nodes := testutils.CreateTestNodes(t, 3)
	a, b := types.ShardID{}.Split()
	mk := func(p types.PartitionID, id types.ShardID) *types.PartitionDescriptionRecord {
		return &types.PartitionDescriptionRecord{Version: 1, PartitionID: p, ShardID: id, EpochStart: 1, Validators: nodes, T2Timeout: 2500000000}
	}
	e := &tsEnv{t: t, nodes: nodes, pdrA: mk(1, a), pdrB: mk(1, b), pdrC: mk(2, types.ShardID{})}
	pdr2 := *e.pdrA
	pdr2.Epoch = 1
	pdr2.EpochStart = 7
	e.pdrA2 = &pdr2
	key := func(p *types.PartitionDescriptionRecord) types.PartitionShardID {
		return types.PartitionShardID{PartitionID: p.PartitionID, ShardID: p.ShardID.Key()}
	}
	e.psA, e.psB, e.psC = key(e.pdrA), key(e.pdrB), key(e.pdrC)
	return e
}

func (e *tsEnv) orchestration(a *types.PartitionDescriptionRecord) mockOrchestration {
	return mockOrchestration{shardConfigs: func(round uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
		cur := a
		if a == e.pdrA2 && round < e.pdrA2.EpochStart { // the configuration of a round is the one of its epoch
			cur = e.pdrA
		}
		return map[types.PartitionShardID]*types.PartitionDescriptionRecord{e.psA: cur, e.psB: e.pdrB, e.psC: e.pdrC}, nil
	}}
}

func (e *tsEnv) genesis() (*ExecutedBlock, []*certification.CertificationResponse) {
	ss := ShardStates{States: map[types.PartitionShardID]*ShardInfo{}, Changed: ShardSet{}}
	for ps, pdr := range map[types.PartitionShardID]*types.PartitionDescriptionRecord{e.psA: e.pdrA, e.psB: e.pdrB, e.psC: e.pdrC} {
		si, err := NewShardInfo(pdr, crypto.SHA256)
		require.NoError(e.t, err)
		ss.States[ps] = si
		ss.Changed[ps] = struct{}{}
	}
	ut, _, err := ss.UnicityTree(crypto.SHA256)
	require.NoError(e.t, err)
	b := &ExecutedBlock{
		BlockData: &drctypes.BlockData{Author: "test", Round: drctypes.GenesisRootRound, Payload: &drctypes.Payload{}},
		HashAlgo:  crypto.SHA256, RootHash: ut.RootHash(), ShardState: ss,
	}
	crs, err := b.GenerateCertificates(fxCommitQc(b), logger.New(e.t))
	require.NoError(e.t, err)
	return b, crs
}

// ir returns the IR of the shard's next round on top of "prev"; with change false
// it is the empty block IR (state hash unchanged, no block hash).
func tsIR(prev *types.InputRecord, label string, change bool) *types.InputRecord {
	ir := &types.InputRecord{
		Version: 1, RoundNumber: prev.RoundNumber + 1, Epoch: prev.Epoch,
		PreviousHash: bytes.Clone(prev.Hash), Hash: bytes.Clone(prev.Hash), SummaryValue: []byte{},
		Timestamp: 1731504540 + prev.RoundNumber + 1,
	}
	if change {
		ir.Hash = fxHash(label)
		ir.BlockHash = fxHash("block " + label)
	}
	if len(ir.PreviousHash) == 0 && !change {
		ir.PreviousHash, ir.Hash = []byte{}, []byte{}
	}
	return ir
}

type tsReq struct {
	ps      types.PartitionShardID
	timeout bool
	ir      *types.InputRecord // for quorum requests
}

// step extends "parent" with a block carrying the requests and commits it.
func (e *tsEnv) step(parent *ExecutedBlock, orc mockOrchestration, reqs ...tsReq) (*ExecutedBlock, []*certification.CertificationResponse) {
	payload := &drctypes.Payload{}
	repeat := map[types.PartitionID]*types.InputRecord{}
	for _, r := range reqs {
		pdr := map[types.PartitionShardID]*types.PartitionDescriptionRecord{e.psA: e.pdrA, e.psB: e.pdrB, e.psC: e.pdrC}[r.ps]
		ch := &drctypes.IRChangeReq{Partition: r.ps.PartitionID, Shard: pdr.ShardID}
		if r.timeout {
			ch.CertReason = drctypes.T2Timeout
			repeat[r.ps.PartitionID] = parent.ShardState.States[r.ps].IR.NewRepeatIR()
		} else {
			ch.CertReason = drctypes.Quorum
			ch.Requests = []*certification.BlockCertificationRequest{{
				PartitionID: pdr.PartitionID, ShardID: pdr.ShardID, NodeID: e.nodes[0].NodeID, InputRecord: r.ir,
			}}
		}
		payload.Requests = append(payload.Requests, ch)
	}
	verifier := mockIRVerifier2(func(round, _ uint64, ch *drctypes.IRChangeReq) (*types.InputRecord, error) {
		if len(ch.Requests) > 0 {
			return ch.Requests[0].InputRecord, nil
		}
		return repeat[ch.Partition], nil
	})
	bd := &drctypes.BlockData{Author: "test", Round: parent.GetRound() + 1, Payload: payload}
	b, err := parent.Extend(bd, verifier, orc, crypto.SHA256, logger.New(e.t))
	require.NoError(e.t, err)
	crs, err := b.GenerateCertificates(fxCommitQc(b), logger.New(e.t))
	require.NoError(e.t, err)
	return b, crs
}

func lastCRBytes(t *testing.T, si *ShardInfo) []byte {
	if si.LastCR == nil {
		return nil
	}
	b, err := types.Cbor.Marshal(si.LastCR)
	require.NoError(t, err)
	return b
}

// checkVector asserts the partition 1 vector carried by every response of the block:
// complete (unchanged leaves too), exactly the committed shard state (IR, TRHash,
// ShardConfHash), reproducing each response's UC through native reconstruction, and that
// unchanged shards keep their previous response bytes (and view).
func (e *tsEnv) checkVector(parent, b *ExecutedBlock, crs []*certification.CertificationResponse, wantChanged ...types.PartitionShardID) {
	t := e.t
	require.Len(t, crs, len(wantChanged), "response count follows the changed shards only")
	for _, ps := range wantChanged {
		require.Contains(t, b.ShardState.Changed, ps)
	}
	require.Len(t, b.ShardState.Changed, len(wantChanged))

	scheme := types.ShardingScheme{e.pdrA.ShardID, e.pdrB.ShardID}
	topo := types.PartitionViewTopology{Scheme: scheme, ShardConfHashes: map[string][]byte{
		e.pdrA.ShardID.Key(): b.ShardState.States[e.psA].ShardConfHash,
		e.pdrB.ShardID.Key(): b.ShardState.States[e.psB].ShardConfHash,
	}}
	for _, cr := range crs {
		if cr.Partition != e.pdrA.PartitionID {
			continue
		}
		view, err := types.DecodePartitionViewV1(cr.PartitionView)
		require.NoError(t, err)
		require.Len(t, view.Leaves, 2)
		for i, ps := range []types.PartitionShardID{e.psA, e.psB} {
			si := b.ShardState.States[ps]
			l := view.Leaves[i]
			require.True(t, l.ShardID.Equal(si.ShardID))
			eq, err := types.EqualIR(si.IR, l.InputRecord)
			require.NoError(t, err)
			require.True(t, eq, "leaf %d IR", i)
			trHash, err := si.TR.Hash()
			require.NoError(t, err)
			require.Equal(t, trHash, l.TRHash, "leaf %d TRHash", i)
			require.Equal(t, si.ShardConfHash, l.ShardConfHash, "leaf %d ShardConfHash", i)
		}
		enclosing := cr.UC
		ucs, err := view.AssembleCertificates(&enclosing, cr.Partition, topo, acceptSeal{}, crypto.SHA256)
		require.NoError(t, err)
		want, err := cr.UC.MarshalCBOR()
		require.NoError(t, err)
		for _, uc := range ucs {
			if uc.ShardTreeCertificate.Shard.Equal(cr.Shard) {
				got, err := uc.MarshalCBOR()
				require.NoError(t, err)
				require.Equal(t, want, got)
			}
		}
	}
	for ps, si := range b.ShardState.States {
		if _, changed := b.ShardState.Changed[ps]; changed {
			continue
		}
		old := parent.ShardState.States[ps]
		require.Equal(t, lastCRBytes(t, old), lastCRBytes(t, si), "unchanged shard %v keeps its response", ps)
		if old.LastCR != nil {
			require.Equal(t, old.LastCR.PartitionView, si.LastCR.PartitionView)
		}
	}
}

func decodeView(t *testing.T, cr *certification.CertificationResponse) *types.PartitionViewV1 {
	v, err := types.DecodePartitionViewV1(cr.PartitionView)
	require.NoError(t, err)
	return v
}

func Test_PartitionView_Transitions(t *testing.T) {
	e := newTSEnv(t)
	orc := e.orchestration(e.pdrA)
	g, gcrs := e.genesis()
	require.Len(t, gcrs, 3)
	for _, cr := range gcrs {
		require.NotEmpty(t, cr.PartitionView)
	}
	irOf := func(b *ExecutedBlock, ps types.PartitionShardID) *types.InputRecord {
		return b.ShardState.States[ps].IR
	}

	// quorum with a state change on A
	b1, crs := e.step(g, orc, tsReq{ps: e.psA, ir: tsIR(irOf(g, e.psA), "a1", true)})
	e.checkVector(g, b1, crs, e.psA)
	v1 := decodeView(t, crs[0])
	trA1 := v1.Leaves[0].TRHash
	// the unchanged leaf of B is the very same as in the previous vector
	require.Equal(t, decodeView(t, gcrs[indexOfShard(gcrs, e.pdrB)]).Leaves[1], v1.Leaves[1])

	// timeout: the IR is preserved (repeat) while the TR (and so TRHash) moves on
	b2, crs := e.step(b1, orc, tsReq{ps: e.psA, timeout: true})
	e.checkVector(b1, b2, crs, e.psA)
	v2 := decodeView(t, crs[0])
	eq, err := types.EqualIR(v1.Leaves[0].InputRecord, v2.Leaves[0].InputRecord)
	require.NoError(t, err)
	require.True(t, eq, "timeout repeats the IR")
	require.NotEqual(t, trA1, v2.Leaves[0].TRHash, "timeout round changes the technical record")
	require.Equal(t, b1.ShardState.States[e.psA].TR.Round+1, b2.ShardState.States[e.psA].TR.Round)

	// empty block IR: state hash unchanged, no block hash
	b3, crs := e.step(b2, orc, tsReq{ps: e.psA, ir: tsIR(irOf(b2, e.psA), "", false)})
	e.checkVector(b2, b3, crs, e.psA)
	l := decodeView(t, crs[0]).Leaves[0]
	require.Equal(t, l.InputRecord.Hash, l.InputRecord.PreviousHash)
	require.Empty(t, l.InputRecord.BlockHash)

	// both shards of the partition change in one block: two responses, one shared vector
	b4, crs := e.step(b3, orc,
		tsReq{ps: e.psA, ir: tsIR(irOf(b3, e.psA), "a4", true)},
		tsReq{ps: e.psB, ir: tsIR(irOf(b3, e.psB), "b4", true)})
	e.checkVector(b3, b4, crs, e.psA, e.psB)
	require.Same(t, &crs[0].PartitionView[0], &crs[1].PartitionView[0])

	// a block without changes certifies nothing
	b5, crs := e.step(b4, orc)
	require.Empty(t, crs)
	require.Empty(t, b5.ShardState.Changed)

	// epoch switch of A: the request in block N signals the new epoch in the TR only
	orcEp := e.orchestration(e.pdrA2)
	oldConf, err := e.pdrA.Hash(crypto.SHA256)
	require.NoError(t, err)
	newConf, err := e.pdrA2.Hash(crypto.SHA256)
	require.NoError(t, err)
	require.NotEqual(t, oldConf, newConf)
	b6, crs := e.step(b5, orcEp, tsReq{ps: e.psA, ir: tsIR(irOf(b5, e.psA), "a6", true)})
	e.checkVector(b5, b6, crs, e.psA)
	v6 := decodeView(t, crs[0])
	require.EqualValues(t, 1, b6.ShardState.States[e.psA].TR.Epoch, "TR signals the next epoch")
	require.Equal(t, oldConf, v6.Leaves[0].ShardConfHash, "still the configuration of the old epoch")
	aCR6 := crs[0]

	// block N+1: A moves to the new epoch state but has no change; B's vector carries A's new config hash
	b7, crs := e.step(b6, orcEp, tsReq{ps: e.psB, ir: tsIR(irOf(b6, e.psB), "b7", true)})
	e.checkVector(b6, b7, crs, e.psB)
	v7 := decodeView(t, crs[0])
	require.Equal(t, newConf, v7.Leaves[0].ShardConfHash)
	require.Equal(t, newConf, b7.ShardState.States[e.psA].ShardConfHash)
	// A's own last response (and its vector with the old config hash) is untouched
	require.Same(t, aCR6, b7.ShardState.States[e.psA].LastCR)
	require.Equal(t, oldConf, decodeView(t, b7.ShardState.States[e.psA].LastCR).Leaves[0].ShardConfHash)

	t.Run("recovery", func(t *testing.T) {
		e.checkRecovery(b7, orcEp)
	})
}

func indexOfShard(crs []*certification.CertificationResponse, pdr *types.PartitionDescriptionRecord) int {
	for i, cr := range crs {
		if cr.Partition == pdr.PartitionID && cr.Shard.Equal(pdr.ShardID) {
			return i
		}
	}
	return -1
}

/*
checkRecovery recovers the block through its real recovery payload (as sent to a node which
rejoins) and asserts that the recovered responses keep the exact older UC but never a vector,
also after another shard has produced a newer one.
*/
func (e *tsEnv) checkRecovery(committed *ExecutedBlock, orc mockOrchestration) {
	t := e.t
	committed.Qc, committed.CommitQc = consistentHeadQCs(t, committed)
	infos, err := toRecoveryShardInfo(committed)
	require.NoError(t, err)
	payload := &rcnet.CommittedBlock{Block: committed.BlockData, ShardInfo: infos, Qc: committed.Qc, CommitQc: committed.CommitQc}
	wire, err := types.Cbor.Marshal(payload)
	require.NoError(t, err)
	var received rcnet.CommittedBlock
	require.NoError(t, types.Cbor.Unmarshal(wire, &received))

	recovered, err := NewRootBlock(&received, crypto.SHA256, orc)
	require.NoError(t, err)
	require.Equal(t, []byte(committed.RootHash), []byte(recovered.RootHash))

	checkOlder := func(rb *ExecutedBlock) {
		for ps, orig := range committed.ShardState.States {
			got := rb.ShardState.States[ps]
			require.NotNil(t, got.LastCR)
			origUC, err := orig.LastCR.UC.MarshalCBOR()
			require.NoError(t, err)
			gotUC, err := got.LastCR.UC.MarshalCBOR()
			require.NoError(t, err)
			require.Equal(t, origUC, gotUC, "recovered UC is the exact older UC of %v", ps)
			require.Equal(t, orig.LastCR.Technical, got.LastCR.Technical)
		}
	}
	checkOlder(recovered)
	for ps, si := range recovered.ShardState.States {
		require.Nil(t, si.LastCR.PartitionView, "recovered %v has no vector", ps)
	}
	// the original in-memory responses did have one (so the omission above is meaningful)
	require.NotEmpty(t, committed.ShardState.States[e.psB].LastCR.PartitionView)

	// another shard produces a newer vector: only its own response has it
	irB := recovered.ShardState.States[e.psB].IR
	next, crs := e.step(recovered, orc, tsReq{ps: e.psB, ir: tsIR(irB, "after recovery", true)})
	require.Len(t, crs, 1)
	require.NotEmpty(t, crs[0].PartitionView)
	e.checkVector(recovered, next, crs, e.psB)
	checkOlder2 := func() {
		for _, ps := range []types.PartitionShardID{e.psA, e.psC} {
			got := next.ShardState.States[ps]
			orig := committed.ShardState.States[ps]
			origUC, err := orig.LastCR.UC.MarshalCBOR()
			require.NoError(t, err)
			gotUC, err := got.LastCR.UC.MarshalCBOR()
			require.NoError(t, err)
			require.Equal(t, origUC, gotUC)
			require.Nil(t, got.LastCR.PartitionView, "the newer vector is never attached to the older UC of %v", ps)
		}
	}
	checkOlder2()
}
