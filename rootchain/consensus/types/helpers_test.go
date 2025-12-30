package types

import (
	"crypto"
	"testing"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/internal/testutils"
	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
)

/*
structBuilder is helper to build *valid* data structures for tests.
Generally fields are filled with random data but the data struct should
succeed IsValid and Verify checks.
*/
type structBuilder struct {
	verifiers      map[string]abcrypto.Verifier
	signers        map[string]abcrypto.Signer
	trustBaseStore *trustbase.TrustBaseStore
}

func newStructBuilder(t *testing.T, peerCnt int) *structBuilder {
	t.Helper()

	tbs, err := trustbase.NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)

	sb := &structBuilder{
		verifiers:      map[string]abcrypto.Verifier{},
		signers:        map[string]abcrypto.Signer{},
		trustBaseStore: tbs,
	}

	var nodes []*types.NodeInfo
	for i := 0; i < peerCnt; i++ {
		signer, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)

		verifier, err := signer.Verifier()
		require.NoError(t, err)

		pubKey, err := verifier.MarshalPublicKey()
		require.NoError(t, err)
		pub, err := p2pcrypto.UnmarshalSecp256k1PublicKey(pubKey)
		require.NoError(t, err)
		id, err := peer.IDFromPublicKey(pub)
		require.NoError(t, err)

		nodeID := id.String()
		sb.signers[nodeID] = signer
		sb.verifiers[nodeID] = verifier
		nodes = append(nodes, &types.NodeInfo{NodeID: nodeID, SigKey: pubKey, Stake: 1})
	}

	tb, err := types.NewTrustBase(5, nodes)
	if err != nil {
		require.NoError(t, err)
	}
	for _, node := range nodes {
		require.NoError(t, tb.Sign(node.NodeID, sb.signers[node.NodeID]))
	}
	require.NoError(t, sb.trustBaseStore.Store(tb))

	return sb
}

/*
Verifiers returns map of Verifier-s which is usable as trust base for data structs created by the builder.
NB! returned map should be treated as read only!
*/
func (sb structBuilder) Verifiers() map[string]abcrypto.Verifier {
	return sb.verifiers
}

/*
RandomPeerID returns random peer ID from trust base.
*/
func (sb structBuilder) RandomPeerID(t *testing.T) string {
	for k := range sb.verifiers {
		return k
	}

	t.Fatal("it appears that the verifiers map is empty")
	return ""
}

/*
QC returns valid QC (with random data) for round "round"
*/
func (sb structBuilder) QC(t *testing.T, round uint64) *QuorumCert {
	voteInfo := &RoundInfo{RoundNumber: round, ParentRoundNumber: round - 1, Epoch: GenesisRootEpoch,
		Timestamp: 1670314583523, CurrentRootHash: test.RandomBytes(32)}
	h, err := voteInfo.Hash(crypto.SHA256)
	require.NoError(t, err)
	commitInfo := &types.UnicitySeal{Version: 1, PreviousHash: h}
	qc := &QuorumCert{
		VoteInfo:         voteInfo,
		LedgerCommitInfo: commitInfo,
		Signatures:       map[string]hex.Bytes{},
	}

	cib := testcertificates.UnicitySealBytes(t, commitInfo)
	for k, v := range sb.signers {
		sig, err := v.SignBytes(cib)
		require.NoError(t, err)
		qc.Signatures[k] = sig
	}
	return qc
}

func (sb structBuilder) Timeout(t *testing.T) *Timeout {
	var round uint64 = 11
	qcRound := round - 1

	return &Timeout{
		Epoch:  GenesisRootEpoch,
		Round:  round,
		HighQc: sb.QC(t, qcRound),
	}
}

func (sb structBuilder) TimeoutCert(t *testing.T) *TimeoutCert {
	tc := &TimeoutCert{
		Timeout:    sb.Timeout(t),
		Signatures: map[string]*TimeoutVote{},
	}

	for k, v := range sb.signers {
		sig := calcTimeoutSig(t, v, tc.Timeout.Round, tc.Timeout.Epoch, tc.Timeout.GetHqcRound(), k)
		tc.Signatures[k] = &TimeoutVote{HqcRound: tc.Timeout.GetHqcRound(), Signature: sig}
	}
	return tc
}

func (sb structBuilder) BlockData(t *testing.T) *BlockData {
	block := &BlockData{
		Author:    sb.RandomPeerID(t),
		Round:     21,
		Epoch:     0,
		Timestamp: 0x0102030405060708,
		Payload:   &Payload{}, // empty payload is valid
	}
	block.Qc = sb.QC(t, block.Round-1)

	return block
}

func Test_structBuilder(t *testing.T) {
	sb := newStructBuilder(t, 3)
	tb, err := sb.trustBaseStore.LoadFirst()
	require.NoError(t, err)
	require.NotNil(t, tb)
	require.Equal(t, len(sb.signers), len(sb.verifiers))
	for k := range sb.verifiers {
		require.NotNil(t, sb.signers[k], "missing signer %q", k)
	}

	// make sure we get valid objects from builder
	qc := sb.QC(t, 42)
	require.NoError(t, qc.IsValid())
	require.NoError(t, qc.Verify(tb))

	tc := sb.TimeoutCert(t)
	require.NoError(t, tc.Verify(sb.trustBaseStore))

	to := sb.Timeout(t)
	require.NoError(t, to.IsValid())
	require.NoError(t, to.Verify(sb.trustBaseStore))

	bd := sb.BlockData(t)
	require.NoError(t, bd.IsValid())
	require.NoError(t, bd.Verify(tb))
}
