package consensus

import (
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
	"testing"
)

// A higher QC does not prove that a retained recovered leaf is what an older QC certifies. Forked pending tree: the
// committed B1, B2, the altered-timestamp leaf B4 (extending QC2) and another branch B5, B7 carrying a valid QC5. A
// signed leader proposal B8 extends the honest QC4 (TC7). Recovery installs the higher QC5; replaying the trigger,
// the stale QC4 is checked against the retained B4 and refused: no execution, no vote, recovery restarted.
func Test_Followup_RecoveryRetainedParentMustMatchStaleQC(t *testing.T) {
	f := newFollowup(t, 3, func(_ *abdrc.StateMsg, tip *drctypes.BlockData) { tip.Timestamp++ })
	cm := f.cm
	// Construct an honest second branch rooted at B2, certified at B5. B4 remains an uncertified leaf.
	bs, err := storage.NewFromState(cm.params.HashAlgorithm, clone(t, f.honest.CommittedHead), f.peerDB, cm.orchestration, cm.log)
	require.NoError(t, err)
	verifier, err := NewIRChangeReqVerifier(cm.params, bs)
	require.NoError(t, err)
	for _, b := range f.honest.Pending {
		_, err = bs.ProcessQc(b.Qc)
		// First pending QC may refer to already-pruned history.
		if err != nil {
			require.ErrorIs(t, err, storage.ErrCommitFailed)
		}
		_, err = bs.Add(clone(t, b), verifier)
		require.NoError(t, err)
	}
	b5 := clone(t, f.block4)
	b5.Round = 5
	b5.Timestamp += 2
	root5, err := bs.Add(b5, verifier)
	require.NoError(t, err)
	mkTC := func(round uint64, qc *drctypes.QuorumCert) *drctypes.TimeoutCert {
		var tc *drctypes.TimeoutCert
		for r := qc.GetRound() + 1; r <= round; r++ {
			timeout := drctypes.NewTimeout(r, b5.Epoch, qc)
			msg := abdrc.NewTimeoutMsg(timeout, cm.id.String(), tc)
			require.NoError(t, cm.safety.Sign(msg))
			tc = &drctypes.TimeoutCert{Timeout: timeout, Signatures: map[string]*drctypes.TimeoutVote{cm.id.String(): {HqcRound: qc.GetRound(), Signature: msg.Signature}}}
			require.NoError(t, tc.Verify(cm.trustBaseStore))
		}
		return tc
	}

	vote5, err := cm.safety.MakeVote(b5, root5, b5.Qc, mkTC(4, b5.Qc))
	require.NoError(t, err)
	qc5 := drctypes.NewQuorumCertificateFromVote(vote5.VoteInfo, vote5.LedgerCommitInfo, map[string]hex.Bytes{vote5.Author: vote5.Signature})
	require.NoError(t, qc5.Verify(cm.trustBase.Load()))
	b7 := clone(t, b5)
	b7.Round, b7.Timestamp, b7.Qc = 7, b5.Timestamp+2, qc5
	f.state.Pending = append(f.state.Pending, b5, b7)
	require.NoError(t, f.state.Verify(cm.params.HashAlgorithm, cm.trustBase.Load()))
	require.NoError(t, storage.ValidateRecoveryState(cm.params.HashAlgorithm, f.state, 4, cm.orchestration, cm.blockStore.GetDB(), func(bs *storage.BlockStore) (storage.IRChangeReqVerifier, error) {
		return NewIRChangeReqVerifier(cm.params, bs)
	}, cm.log))
	// A signed round-8 proposal extends the honest QC4; recovery installs a higher QC5 from the other branch.
	b8 := clone(t, f.block4)
	b8.Round, b8.Timestamp, b8.Qc = 8, b7.Timestamp+1, f.qc4
	prop := f.signed(b8, mkTC(7, f.qc4))
	f.ingress(prop)
	err = cm.onStateResponse(f.ctx, f.state)
	require.EqualValues(t, 5, cm.blockStore.GetHighQc().GetRound())
	parent, readErr := cm.blockStore.Block(4)
	require.NoError(t, readErr)
	require.Error(t, storage.CheckQcOfBlock(f.qc4, parent), "recovered parent does not match the signed QC")
	served, serveErr := cm.blockStore.GetState()
	require.NoError(t, serveErr)
	validationErr := storage.ValidateRecoveryState(cm.params.HashAlgorithm, served, 4, cm.orchestration, f.peerDB, func(bs *storage.BlockStore) (storage.IRChangeReqVerifier, error) {
		return NewIRChangeReqVerifier(cm.params, bs)
	}, cm.log)
	t.Logf("served state validation error: %v", validationErr)
	t.Logf("completion error=%v, votes=%d, voted round=%d", err, len(f.votes()), cm.safety.storage.GetHighestVotedRound())
	require.Error(t, err, "must refuse replay on a retained parent/QC mismatch even with a higher QC")
	require.Empty(t, f.votes(), "must not vote on top of a mismatched recovered parent")
	require.True(t, cm.recovery.InRecovery(), "recovery is restarted")
	_, addErr := cm.blockStore.Block(8)
	require.Error(t, addErr, "the proposal was not executed")
}
