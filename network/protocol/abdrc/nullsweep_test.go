package abdrc

import (
	"bytes"
	gocrypto "crypto"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	testtb "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/testutils"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// The messages of the root chain protocol are decoded from the network and validated before any signature is
// looked at, so a CBOR null (a nil pointer, nil collection entry) anywhere in them must produce an error, never a
// nil pointer dereference (bft-go-base#17 and its follow-ups). This file replaces every CBOR item of a valid message
// by a null (and a few other shapes) and runs the whole validation path with trust bases which accept every
// signature: the worst case, nothing but structure protects.

// ---- minimal CBOR item walker (definite lengths, what the encoder produces) ----

type span struct{ start, end int }

func cborItems(t testing.TB, b []byte) []span {
	t.Helper()
	var out []span
	var walk func(i int) int
	walk = func(i int) int {
		start := i
		ib := b[i]
		major, ai := ib>>5, ib&31
		i++
		var n uint64
		switch {
		case ai < 24:
			n = uint64(ai)
		case ai >= 24 && ai <= 27:
			size := 1 << (ai - 24)
			for _, c := range b[i : i+size] {
				n = n<<8 | uint64(c)
			}
			i += size
		default:
			t.Fatalf("unsupported additional information %d at %d", ai, start)
		}
		switch major {
		case 2, 3:
			i += int(n)
		case 4:
			for k := uint64(0); k < n; k++ {
				i = walk(i)
			}
		case 5:
			for k := uint64(0); k < 2*n; k++ {
				i = walk(i)
			}
		case 6:
			i = walk(i)
		}
		out = append(out, span{start, i})
		return i
	}
	require.Equal(t, len(b), walk(0))
	return out
}

var replacements = map[string][]byte{
	"null": {0xf6}, "empty array": {0x80}, "empty map": {0xa0}, "[null]": {0x81, 0xf6}, "empty bytes": {0x40}, "zero": {0x00},
}

// ---- fixtures ----

type sweepEnv struct {
	tbs   *trustbase.TrustBaseStore // real signatures are required (the fixtures verify completely)
	alive types.RootTrustBase       // accepts every signature (state and ir change messages)
}

func sweepSigners(t testing.TB) map[string]crypto.Signer {
	t.Helper()
	out := map[string]crypto.Signer{}
	for _, id := range []string{"1", "2", "3"} {
		k := sha256.Sum256([]byte("abdrc null sweep signer " + id))
		s, err := crypto.NewInMemorySecp256K1SignerFromKey(k[:])
		require.NoError(t, err)
		out[id] = s
	}
	return out
}

func newSweepEnv(t testing.TB) *sweepEnv {
	t.Helper()
	tbs, err := trustbase.NewTrustBaseStore(memorydb.New(), logger.New(t.(*testing.T)))
	require.NoError(t, err)
	require.NoError(t, tbs.Store(testtb.NewTrustBaseFromSigners(t.(*testing.T), sweepSigners(t))))
	return &sweepEnv{tbs: tbs, alive: &testtb.AlwaysValidTrustBase{}}
}

type stubVerifier struct{}

func (stubVerifier) GetQuorum() uint64                                               { return 1 }
func (stubVerifier) GetTotalNodes() uint64                                           { return 10 }
func (stubVerifier) ValidRequest(req *certification.BlockCertificationRequest) error { return nil }

func sweepRequests() []*certification.BlockCertificationRequest {
	ir := &types.InputRecord{Version: 1, RoundNumber: 1, PreviousHash: []byte{1}, Hash: []byte{2}, BlockHash: []byte{3}, SummaryValue: []byte{}, Timestamp: 1731504540}
	return []*certification.BlockCertificationRequest{{PartitionID: 1, NodeID: "a", InputRecord: ir, Signature: []byte{1}}, {PartitionID: 1, NodeID: "b", InputRecord: ir, Signature: []byte{1}}}
}

func irChangeReq(reason drctypes.IRChangeReason, partition ...types.PartitionID) *drctypes.IRChangeReq {
	r := &drctypes.IRChangeReq{Partition: 1, CertReason: reason}
	if len(partition) > 0 {
		r.Partition = partition[0]
	}
	if reason != drctypes.T2Timeout {
		r.Requests = sweepRequests()
	}
	return r
}

func sweepQC(t *testing.T, round uint64) *drctypes.QuorumCert {
	vi := testutils.NewDummyRootRoundInfo(round)
	h, err := vi.Hash(gocrypto.SHA256)
	require.NoError(t, err)
	qc := &drctypes.QuorumCert{VoteInfo: vi, LedgerCommitInfo: &types.UnicitySeal{Version: 1, PreviousHash: h, Hash: []byte{9}},
		Signatures: map[string]hex.Bytes{}}
	for id, s := range sweepSigners(t) {
		addQCSignature(t, qc, id, s)
	}
	return qc
}

type sweepMsg struct {
	name string
	kind uint8
	data []byte
}

func sweepMessages(t *testing.T) []sweepMsg {
	t.Helper()
	signers := sweepSigners(t)
	s1 := signers["1"]
	enc := func(v any) []byte {
		b, err := types.Cbor.Marshal(v)
		require.NoError(t, err)
		return b
	}
	qc := sweepQC(t, 9)
	tc := &drctypes.TimeoutCert{
		Timeout:    drctypes.NewTimeout(10, drctypes.GenesisRootEpoch, qc),
		Signatures: map[string]*drctypes.TimeoutVote{},
	}
	for id, s := range signers {
		tc.Signatures[id] = &drctypes.TimeoutVote{HqcRound: 9, Signature: testutils.CalcTimeoutSig(t, s, 10, drctypes.GenesisRootEpoch, 9, id)}
	}
	proposal := func(round uint64, tc *drctypes.TimeoutCert) []byte {
		p := &ProposalMsg{LastRoundTc: tc, Block: &drctypes.BlockData{Author: "1", Round: round, Epoch: drctypes.GenesisRootEpoch, Timestamp: 1234, Qc: qc,
			Payload: &drctypes.Payload{Requests: []*drctypes.IRChangeReq{irChangeReq(drctypes.Quorum), irChangeReq(drctypes.QuorumNotPossible, 2)}}}}
		require.NoError(t, p.Sign(s1))
		return enc(p)
	}
	voteInfo := testutils.NewDummyRootRoundInfo(10)
	vh, err := voteInfo.Hash(gocrypto.SHA256)
	require.NoError(t, err)
	vote := &VoteMsg{VoteInfo: voteInfo, LedgerCommitInfo: &types.UnicitySeal{Version: 1, PreviousHash: vh}, HighQc: qc, Author: "1"}
	require.NoError(t, vote.Sign(s1))
	tmo := NewTimeoutMsg(drctypes.NewTimeout(11, drctypes.GenesisRootEpoch, qc), "1", tc)
	require.NoError(t, tmo.Sign(s1))
	irMsg := func(reason drctypes.IRChangeReason) []byte {
		m := &IrChangeReqMsg{Author: "1", IrChangeReq: irChangeReq(reason)}
		require.NoError(t, m.Sign(s1))
		return enc(m)
	}
	stateMsg, _ := stateMsgFixture(t)
	sm := stateMsg()
	sm.Pending[0].Payload = &drctypes.Payload{Requests: []*drctypes.IRChangeReq{irChangeReq(drctypes.Quorum)}}
	sm.CommittedHead.Block.Payload = &drctypes.Payload{Requests: []*drctypes.IRChangeReq{irChangeReq(drctypes.QuorumNotPossible)}}

	return []sweepMsg{
		{"proposal", 0, proposal(10, nil)},
		{"proposal with TC", 0, proposal(11, tc)},
		{"vote", 1, enc(vote)},
		{"timeout", 2, enc(tmo)},
		{"ir change request", 3, irMsg(drctypes.Quorum)},
		{"ir change request, no quorum possible", 3, irMsg(drctypes.QuorumNotPossible)},
		{"state", 4, enc(&sm)},
	}
}

var luc = &types.UnicityCertificate{Version: 1, InputRecord: &types.InputRecord{Version: 1}, UnicitySeal: &types.UnicitySeal{Version: 1}}

// processMessage decodes data as the message of the kind and runs everything a root node does with it before
// and around the signature checks.
func (e *sweepEnv) processMessage(kind uint8, data []byte) {
	verifyPayload := func(p *drctypes.Payload) {
		if p == nil {
			return
		}
		for _, r := range p.Requests { // the consensus path (the nil entries are rejected by IsValid; callers may differ)
			if r != nil {
				_, _ = r.Verify(stubVerifier{}, luc, 5, 1)
			}
		}
	}
	switch kind {
	case 0:
		var m ProposalMsg
		if types.Cbor.Unmarshal(data, &m) != nil {
			return
		}
		_ = m.IsValid()
		_ = m.Verify(e.tbs)
		if m.Block != nil {
			verifyPayload(m.Block.Payload)
			_, _ = m.Block.Bytes()
			_ = m.Block.IsValid()
		}
	case 1:
		var m VoteMsg
		if types.Cbor.Unmarshal(data, &m) != nil {
			return
		}
		_ = m.Verify(e.tbs)
	case 2:
		var m TimeoutMsg
		if types.Cbor.Unmarshal(data, &m) != nil {
			return
		}
		_ = m.IsValid()
		_ = m.Verify(e.tbs)
		_ = m.GetRound()
	case 3:
		var m IrChangeReqMsg
		if types.Cbor.Unmarshal(data, &m) != nil {
			return
		}
		_ = m.IsValid()
		_ = m.Verify(e.alive)
		if m.IrChangeReq != nil {
			_, _ = m.IrChangeReq.Verify(stubVerifier{}, luc, 5, 1)
		}
	case 4:
		var m StateMsg
		if types.Cbor.Unmarshal(data, &m) != nil {
			return
		}
		_ = m.Verify(gocrypto.SHA256, e.alive)
		_ = m.CanRecoverToRound(6)
		_ = m.CanRecoverToRound(5)
		if m.CommittedHead != nil {
			_ = m.CommittedHead.GetRound()
		}
		for _, p := range m.Pending {
			if p != nil {
				verifyPayload(p.Payload)
			}
		}
	}
}

// recovered returns the panic of f with the first frame in the repository's own code (the site to fix).
func recovered(f func()) (site any) {
	defer func() {
		if p := recover(); p != nil {
			site = fmt.Sprintf("%v at %s", p, panicSite(debug.Stack()))
		}
	}()
	f()
	return nil
}

func panicSite(stack []byte) string {
	seenPanic := false
	for _, l := range strings.Split(string(stack), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "panic(") {
			seenPanic = true
			continue
		}
		if !seenPanic || !strings.Contains(l, ".go:") || strings.Contains(l, "/runtime/") || strings.Contains(l, "nullsweep_test.go") {
			continue
		}
		if i := strings.Index(l, " +0x"); i > 0 {
			l = l[:i]
		}
		return l
	}
	return "?"
}

// Every single CBOR item of every message replaced by null and the other shapes: no panic.
func TestRootMessages_NullAnywhereNeverPanics(t *testing.T) {
	env := newSweepEnv(t)
	total := 0
	sites := map[string]int{}
	for _, m := range sweepMessages(t) {
		require.Nil(t, recovered(func() { env.processMessage(m.kind, m.data) }), "%s: the unmodified message", m.name)
		items := cborItems(t, m.data)
		for idx, it := range items {
			for rname, repl := range replacements {
				mut := append(append(append([]byte(nil), m.data[:it.start]...), repl...), m.data[it.end:]...)
				if bytes.Equal(mut, m.data) {
					continue
				}
				total++
				if p := recovered(func() { env.processMessage(m.kind, mut) }); p != nil {
					sites[fmt.Sprintf("%v", p)]++
					if sites[fmt.Sprintf("%v", p)] == 1 {
						t.Errorf("%s: item %d (bytes %d..%d) replaced by %s panics: %v", m.name, idx, it.start, it.end, rname, p)
					}
				}
			}
		}
	}
	t.Logf("%d mutants", total)
	require.Greater(t, total, 4000)
}

var fuzzEnv struct {
	once sync.Once
	env  *sweepEnv
}

// FuzzRootMessages decodes arbitrary bytes as one of the root chain messages (kind 0 proposal, 1 vote, 2 timeout,
// 3 ir change request, 4 state) and runs the validation path. The seed corpus (testdata/fuzz/FuzzRootMessages) is the
// encoding of the fixtures. Bounded run (iteration count):
//
//	go test ./network/protocol/abdrc -run '^$' -fuzz FuzzRootMessages -fuzztime 2000000x
func FuzzRootMessages(f *testing.F) {
	f.Fuzz(func(t *testing.T, kind uint8, data []byte) {
		fuzzEnv.once.Do(func() { fuzzEnv.env = newSweepEnv(t) })
		fuzzEnv.env.processMessage(kind%5, data)
	})
}

// UPDATE_FUZZ_SEEDS=1 go test ./network/protocol/abdrc -run TestWriteFuzzSeeds rewrites the seed corpus.
func TestWriteFuzzSeeds(t *testing.T) {
	if os.Getenv("UPDATE_FUZZ_SEEDS") == "" {
		t.Skip("set UPDATE_FUZZ_SEEDS=1 to rewrite the seed corpus")
	}
	dir := filepath.Join("testdata", "fuzz", "FuzzRootMessages")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	for i, m := range sweepMessages(t) {
		body := fmt.Sprintf("go test fuzz v1\nbyte(%d)\n[]byte(%q)\n", m.kind, m.data)
		require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("seed-%d", i)), []byte(body), 0o644))
	}
}
