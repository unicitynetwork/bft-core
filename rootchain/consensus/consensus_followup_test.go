package consensus

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

/*
Regressions of the post-merge review of the recovery tip identity (#50): the QC-bound fields of a recovered tip are
checked when the QC arrives, the recovery-completion vote has the admission rules of an ordinary proposal, the
completion bookkeeping is not skipped by the abstentions, and the vote is stored as on the normal path.

The tree of the setup (see recoveryTreeSetup): head round 1, pending B2 (QC 1) and the tip B4 (QC 2, after the timeout
of round 3); QC(4) is not part of the state message. The node under test is made to be "behind": it knows the
committed head only, so that the signed proposals below really trigger the recovery.
*/

type followup struct {
	t      *testing.T
	cm     *ConsensusManager
	net    *testnetwork.MockNet
	ctx    context.Context
	state  *abdrc.StateMsg // the state message, with the changes of the test
	honest *abdrc.StateMsg // the state message of the honest peer
	qc4    *drctypes.QuorumCert
	tc     *drctypes.TimeoutCert
	block4 *drctypes.BlockData // the honest block of round 4
	db     *spyDB
	peerDB storage.PersistentStore // another node: it knows the genesis only

	m       sync.Mutex
	emitted int
}

// spyDB records the last votes which are written and can fail the write.
type spyDB struct {
	storage.PersistentStore
	m         sync.Mutex
	votes     []any
	failWrite bool
}

func (s *spyDB) WriteVote(vote any) error {
	s.m.Lock()
	defer s.m.Unlock()
	if s.failWrite {
		return errors.New("last vote write failed")
	}
	s.votes = append(s.votes, vote)
	return s.PersistentStore.WriteVote(vote)
}

func (s *spyDB) written() []any {
	s.m.Lock()
	defer s.m.Unlock()
	return append([]any(nil), s.votes...)
}

func clone[T any](t *testing.T, v *T) *T {
	t.Helper()
	raw, err := types.Cbor.Marshal(v)
	require.NoError(t, err)
	out := new(T)
	require.NoError(t, types.Cbor.Unmarshal(raw, out))
	return out
}

// newFollowup sets the node under test up. votedRound is the highest round it has voted in (the setup voted in round
// 4 already), change forges the state message of the peer.
func newFollowup(t *testing.T, votedRound uint64, change func(state *abdrc.StateMsg, tip *drctypes.BlockData)) *followup {
	cm, state, qc4, _, mockNet := recoveryTreeSetup(t)
	f := &followup{t: t, cm: cm, net: mockNet, qc4: qc4, honest: clone(t, state)}
	tip := state.Pending[len(state.Pending)-1]
	require.EqualValues(t, 4, tip.Round)
	f.block4 = clone(t, tip)
	if change != nil {
		change(state, tip)
	}
	f.state = state
	var err error
	f.tc, err = cm.blockStore.GetLastTC()
	require.NoError(t, err)
	require.NotNil(t, f.tc)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f.ctx = ctx
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-cm.ucSink:
				f.m.Lock()
				f.emitted++
				f.m.Unlock()
			}
		}
	}()

	// the node is at its genesis (a fresh database on bolt), has not voted in round 4 (the durable vote state is monotonic)
	blocks, err := cm.blockStore.GetDB().LoadBlocks()
	require.NoError(t, err)
	var genesis *storage.ExecutedBlock
	for _, b := range blocks {
		if b.GetRound() == drctypes.GenesisRootRound {
			genesis = b
		}
	}
	require.NotNil(t, genesis)
	behindDB, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "behind.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = behindDB.Close() })
	require.NoError(t, behindDB.WriteBlock(genesis, true))
	peerDB, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "peer.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = peerDB.Close() })
	require.NoError(t, peerDB.WriteBlock(genesis, true))
	f.peerDB = peerDB
	f.db = &spyDB{PersistentStore: behindDB}
	bs, err := storage.New(cm.params.HashAlgorithm, f.db, cm.orchestration, cm.log)
	require.NoError(t, err)
	cm.blockStore = bs
	cm.irReqVerifier, err = NewIRChangeReqVerifier(cm.params, bs)
	require.NoError(t, err)
	cm.pacemaker.Reset(ctx, bs.GetHighQc().GetRound(), nil, nil)
	cm.safety.storage = &votedRoundStorage{SafetyStorage: cm.safety.storage, round: votedRound}
	cm.recovery = &recoveryState{}
	mockNet.ResetSentMessages(network.ProtocolRootVote)
	return f
}

func (f *followup) signed(block *drctypes.BlockData, tc *drctypes.TimeoutCert) *abdrc.ProposalMsg {
	f.t.Helper()
	prop := &abdrc.ProposalMsg{Block: block, LastRoundTc: tc}
	require.NoError(f.t, f.cm.safety.Sign(prop))
	return prop
}

// proposal4 is the honest signed proposal of round 4 (extends QC(2), carries TC(3)).
func (f *followup) proposal4() *abdrc.ProposalMsg { return f.signed(clone(f.t, f.block4), f.tc) }

// proposal5 is a signed proposal of round 5 which carries the honest QC(4).
func (f *followup) proposal5() *abdrc.ProposalMsg {
	b := &drctypes.BlockData{
		Version: 1, Author: f.cm.id.String(), Round: 5, Epoch: f.block4.Epoch, Timestamp: f.block4.Timestamp + 1,
		Payload: &drctypes.Payload{}, Qc: clone(f.t, f.qc4),
	}
	return f.signed(b, nil)
}

func (f *followup) votes() []testnetwork.PeerMessage {
	return f.net.SentMessages(network.ProtocolRootVote)
}

func (f *followup) emittedCount() int {
	f.m.Lock()
	defer f.m.Unlock()
	return f.emitted
}

func (f *followup) persisted(round uint64) *storage.ExecutedBlock {
	f.t.Helper()
	blocks, err := f.cm.blockStore.GetDB().LoadBlocks()
	require.NoError(f.t, err)
	for _, b := range blocks {
		if b.GetRound() == round {
			return b
		}
	}
	return nil
}

// ingress passes the signed proposal through the real admission of the node, which must trigger the recovery.
func (f *followup) ingress(prop *abdrc.ProposalMsg) {
	f.t.Helper()
	err := f.cm.onProposalMsg(f.ctx, prop)
	require.ErrorContains(f.t, err, "proposal triggers recovery")
	require.True(f.t, f.cm.recovery.InRecovery())
}

func Test_Followup_QCBindsTheTimestampOfTheRecoveredTip(t *testing.T) {
	for name, forge := range map[string]func(tip *drctypes.BlockData){
		"timestamp":        func(tip *drctypes.BlockData) { tip.Timestamp++ },
		"author+timestamp": func(tip *drctypes.BlockData) { tip.Timestamp += 3; tip.Author = "forged-author" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFollowup(t, 3, func(_ *abdrc.StateMsg, tip *drctypes.BlockData) { forge(tip) })

			// the honest signed proposal of round 4 triggers the recovery; the peer's state carries the forged tip
			f.ingress(f.proposal4())
			err := f.cm.onStateResponse(f.ctx, f.state)
			require.ErrorContains(t, err, "already in store", "abstains on the honest proposal")
			require.Empty(t, f.votes())
			require.EqualValues(t, 3, f.cm.safety.storage.GetHighestVotedRound())
			require.Empty(t, f.db.written())

			tip, err := f.cm.blockStore.Block(4)
			require.NoError(t, err)
			require.Nil(t, tip.Qc)
			highQc := f.cm.blockStore.GetHighQc()
			emitted := f.emittedCount()
			require.False(t, f.cm.recovery.InRecovery())

			// the honest QC(4) arrives with the proposal of round 5: it is not attached to the forged block
			err = f.cm.onProposalMsg(f.ctx, f.proposal5())
			require.ErrorContains(t, err, "proposal triggers recovery")
			require.True(t, f.cm.recovery.InRecovery(), "the QC starts a recovery")
			tip, err = f.cm.blockStore.Block(4)
			require.NoError(t, err)
			require.Nil(t, tip.Qc, "the QC was not attached to the local block")
			require.Same(t, highQc, f.cm.blockStore.GetHighQc(), "the high QC did not change")
			require.Equal(t, emitted, f.emittedCount(), "no certificates were emitted")
			require.Empty(t, f.votes(), "no vote on top of that QC")
			require.Empty(t, f.db.written())
			require.EqualValues(t, 3, f.cm.safety.storage.GetHighestVotedRound())
			stored := f.persisted(4)
			require.NotNil(t, stored)
			require.Nil(t, stored.Qc, "nothing was persisted for the QC")
			root, err := f.cm.blockStore.GetState()
			require.NoError(t, err)
			require.EqualValues(t, 1, root.CommittedHead.GetRound(), "nothing was committed")

			// the repair: the honest state replaces the inconsistent one, the QC certifies the block, the vote follows
			require.NoError(t, f.cm.onStateResponse(f.ctx, clone(t, f.honest)))
			tip, err = f.cm.blockStore.Block(4)
			require.NoError(t, err)
			require.NotNil(t, tip.Qc)
			require.EqualValues(t, 4, f.cm.blockStore.GetHighQc().GetRound())
			require.Len(t, f.votes(), 1)
			require.EqualValues(t, 5, f.votes()[0].Message.(*abdrc.VoteMsg).VoteInfo.RoundNumber)
			require.EqualValues(t, 5, f.cm.safety.storage.GetHighestVotedRound())
			require.NotNil(t, f.persisted(4).Qc)

			// the served state passes the verification and the staged recovery of another node
			served, err := f.cm.blockStore.GetState()
			require.NoError(t, err)
			require.NoError(t, served.Verify(crypto.SHA256, f.cm.trustBase.Load()))
			require.NoError(t, storage.ValidateRecoveryState(crypto.SHA256, clone(t, served), served.CommittedHead.GetRound(), f.cm.orchestration, f.peerDB,
				func(bs *storage.BlockStore) (storage.IRChangeReqVerifier, error) {
					return NewIRChangeReqVerifier(f.cm.params, bs)
				}, f.cm.log))

			// the safety rounds were not reset by any of it: the same round cannot be signed twice
			f.net.ResetSentMessages(network.ProtocolRootVote)
			f.cm.recovery = &recoveryState{}
			_, err = f.cm.recovery.Set(f.proposal5())
			require.NoError(t, err)
			err = f.cm.onStateResponse(f.ctx, clone(t, f.honest))
			require.ErrorContains(t, err, "already voted for round 5")
			require.Empty(t, f.votes())
			require.EqualValues(t, 5, f.cm.safety.storage.GetHighestVotedRound())
		})
	}
}

// errLeader is a leader selection which fails.
type errLeader struct{}

func (errLeader) GetLeaderForRound(uint64) (peer.ID, error) {
	return "", errors.New("no leader for the round")
}

func (errLeader) Update(*drctypes.QuorumCert, uint64, leader.BlockLoader) error { return nil }

func (errLeader) UpdateWithTrustBase(types.RootTrustBase, uint64) error { return nil }

// failingVoteNet fails to send votes.
type failingVoteNet struct {
	RootNet
	sent int
}

func (n *failingVoteNet) Send(ctx context.Context, msg any, receivers ...peer.ID) error {
	if _, ok := msg.(*abdrc.VoteMsg); ok {
		n.sent++
		return errors.New("network is down")
	}
	return n.RootNet.Send(ctx, msg, receivers...)
}

func (f *followup) bufferStaleVotes(n int) {
	for i := range n {
		id := fmt.Sprintf("stale-%d", i)
		f.cm.voteBuffer[id] = &abdrc.VoteMsg{Author: id, VoteInfo: &drctypes.RoundInfo{RoundNumber: 1}}
	}
}

// validVote is a vote of the node itself for a round, as the replay would admit it.
func (f *followup) validVote(round uint64) *abdrc.VoteMsg {
	f.t.Helper()
	vi := &drctypes.RoundInfo{Version: 1, RoundNumber: round, ParentRoundNumber: 2, Epoch: f.block4.Epoch, Timestamp: f.block4.Timestamp, CurrentRootHash: []byte{1}}
	h, err := vi.Hash(crypto.SHA256)
	require.NoError(f.t, err)
	v := &abdrc.VoteMsg{VoteInfo: vi, LedgerCommitInfo: &types.UnicitySeal{Version: 1, PreviousHash: h}, HighQc: clone(f.t, f.block4.Qc), Author: f.cm.id.String()}
	require.NoError(f.t, v.Sign(f.cm.safety.signer))
	return v
}

// replayed tells whether the vote was registered by the replay: registering it again is a duplicate.
func (f *followup) replayed(v *abdrc.VoteMsg) bool {
	_, _, err := f.cm.pacemaker.RegisterVote(v, f.cm.trustBase.Load())
	f.t.Logf("registering the vote again: %v", err)
	return err != nil && strings.Contains(err.Error(), "duplicate vote")
}

func Test_Followup_LeaderOfTheRoundBeforeTheRecoveryVote(t *testing.T) {
	absentTip := func(state *abdrc.StateMsg, _ *drctypes.BlockData) {
		state.Pending = state.Pending[:len(state.Pending)-1]
	}
	other, _, _, _ := generatePeerData(t)

	t.Run("the leader: votes, the vote is stored", func(t *testing.T) {
		f := newFollowup(t, 3, absentTip)
		f.ingress(f.proposal4())
		require.NoError(t, f.cm.onStateResponse(f.ctx, f.state))
		require.Len(t, f.votes(), 1)
		require.Len(t, f.db.written(), 1)
	})

	for name, selector := range map[string]Leader{
		"genuinely signed proposal of a validator which is not the leader": constLeader{leader: other},
		"leader lookup error": errLeader{},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFollowup(t, 3, absentTip)
			f.cm.leaderSelector = selector
			f.ingress(f.proposal4())
			f.bufferStaleVotes(3)
			before, err := f.db.ReadLastVote()
			require.NoError(t, err)

			err = f.cm.onStateResponse(f.ctx, f.state)
			if _, ok := selector.(errLeader); ok {
				require.ErrorContains(t, err, "could not determine leader for round 4")
			} else {
				require.ErrorContains(t, err, "to be leader of the round 4")
			}
			// not executed, not signed, not stored, not sent
			_, err = f.cm.blockStore.Block(4)
			require.Error(t, err, "the proposal was not executed")
			require.Empty(t, f.votes())
			require.Empty(t, f.db.written())
			after, err := f.db.ReadLastVote()
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Nil(t, f.cm.pacemaker.GetVoted())
			require.EqualValues(t, 3, f.cm.safety.storage.GetHighestVotedRound())
			// the installed recovery is complete and the buffer is housekept
			require.False(t, f.cm.recovery.InRecovery())
			require.Empty(t, f.cm.voteBuffer)
			require.EqualValues(t, 2, f.cm.blockStore.GetHighQc().GetRound())
		})
	}

	t.Run("stale trigger", func(t *testing.T) {
		f := newFollowup(t, 3, absentTip)
		prop := f.proposal4()
		f.cm.pacemaker.Reset(f.ctx, 9, nil, nil)
		err := f.cm.voteAfterRecovery(f.ctx, prop)
		require.ErrorContains(t, err, "stale proposal for round 4")
		require.Empty(t, f.votes())
		require.Empty(t, f.db.written())
		require.EqualValues(t, 3, f.cm.safety.storage.GetHighestVotedRound())
	})
}

func Test_Followup_QCTupleOnTheLivePath(t *testing.T) {
	cm, state, qc4, _, _ := recoveryTreeSetup(t)
	tip := state.Pending[len(state.Pending)-1]
	require.EqualValues(t, 4, tip.Round)
	qc := func(change func(*drctypes.RoundInfo)) *drctypes.QuorumCert {
		q := clone(t, qc4)
		change(q.VoteInfo)
		return q
	}
	require.NoError(t, cm.checkRecoveryNeeded(qc4), "exact match")
	for name, c := range map[string]struct {
		change func(*drctypes.RoundInfo)
		want   string
	}{
		"epoch":         {func(vi *drctypes.RoundInfo) { vi.Epoch++ }, "epoch or timestamp"},
		"timestamp":     {func(vi *drctypes.RoundInfo) { vi.Timestamp++ }, "epoch or timestamp"},
		"parent round":  {func(vi *drctypes.RoundInfo) { vi.ParentRoundNumber-- }, "parent round"},
		"state root":    {func(vi *drctypes.RoundInfo) { vi.CurrentRootHash = append([]byte{9}, vi.CurrentRootHash...) }, "state root"},
		"missing block": {func(vi *drctypes.RoundInfo) { vi.RoundNumber = 9; vi.ParentRoundNumber = 8 }, "failed to read root hash for round 9"},
	} {
		t.Run(name, func(t *testing.T) {
			err := cm.checkRecoveryNeeded(qc(c.change))
			require.ErrorContains(t, err, c.want)
		})
	}

	t.Run("author only: the tuple predicate accepts, the whole block comparison abstains", func(t *testing.T) {
		f := newFollowup(t, 3, func(_ *abdrc.StateMsg, tip *drctypes.BlockData) { tip.Author = "forged-author" })
		f.ingress(f.proposal4())
		err := f.cm.onStateResponse(f.ctx, f.state)
		require.ErrorContains(t, err, "already in store")
		require.Empty(t, f.votes())
		// the QC does not contain the author: it is bound to the block as far as it can be
		require.NoError(t, f.cm.checkRecoveryNeeded(f.qc4))
		err = f.cm.onProposalMsg(f.ctx, f.proposal5())
		require.NotContains(t, fmt.Sprint(err), "triggers recovery")
		tip, err := f.cm.blockStore.Block(4)
		require.NoError(t, err)
		require.NotNil(t, tip.Qc, "accepted: the known limitation, not an authentication of the author")
	})
}

func Test_Followup_RecoveryBookkeeping(t *testing.T) {
	forged := func(_ *abdrc.StateMsg, tip *drctypes.BlockData) { tip.Timestamp++ }

	t.Run("abstention on a conflicting tip drains stale votes, the original error stays", func(t *testing.T) {
		f := newFollowup(t, 3, forged)
		f.ingress(f.proposal4())
		f.bufferStaleVotes(4)
		err := f.cm.onStateResponse(f.ctx, f.state)
		require.ErrorContains(t, err, "already in store")
		require.Empty(t, f.cm.voteBuffer, "a later set of votes cannot trigger recovery with the stale count")
		require.False(t, f.cm.recovery.InRecovery())
	})

	t.Run("post-install voting failure: same housekeeping, original error", func(t *testing.T) {
		f := newFollowup(t, 4, nil) // already voted in round 4
		f.ingress(f.proposal4())
		f.bufferStaleVotes(2)
		err := f.cm.onStateResponse(f.ctx, f.state)
		require.ErrorContains(t, err, "already voted for round 4")
		require.Empty(t, f.cm.voteBuffer)
		require.Empty(t, f.votes())
		require.Empty(t, f.db.written())
	})

	for name, change := range map[string]func(*abdrc.StateMsg, *drctypes.BlockData){"success": nil, "abstention": forged} {
		t.Run("valid buffered votes of the current round still replay: "+name, func(t *testing.T) {
			f := newFollowup(t, 3, change)
			f.ingress(f.proposal4())
			vote := f.validVote(4)
			f.cm.voteBuffer[vote.Author] = vote
			err := f.cm.onStateResponse(f.ctx, f.state)
			if change == nil {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "already in store")
			}
			require.EqualValues(t, 4, f.cm.pacemaker.GetCurrentRound())
			require.True(t, f.replayed(vote), "the buffered vote was replayed")
			require.Empty(t, f.cm.voteBuffer)
		})
	}

	t.Run("an invalid recovery response leaves the active recovery and the buffer intact", func(t *testing.T) {
		f := newFollowup(t, 3, nil)
		prop := f.proposal4()
		f.ingress(prop)
		f.bufferStaleVotes(2)
		bad := clone(t, f.state)
		bad.Pending[len(bad.Pending)-1].Qc.VoteInfo.CurrentRootHash = []byte{1, 2, 3}
		err := f.cm.onStateResponse(f.ctx, bad)
		require.Error(t, err)
		require.True(t, f.cm.recovery.InRecovery())
		require.Len(t, f.cm.voteBuffer, 2)
		require.Empty(t, f.votes())
	})

	t.Run("a recovery started while completing is kept, with the buffered votes", func(t *testing.T) {
		f := newFollowup(t, 3, nil)
		// a QC of round 5 whose block the state does not carry: processing it after the recovery fails
		qc5 := clone(t, f.qc4)
		qc5.VoteInfo.RoundNumber, qc5.VoteInfo.ParentRoundNumber = 5, 4
		_, err := f.cm.recovery.Set(qc5)
		require.NoError(t, err)
		f.bufferStaleVotes(2)
		future := f.validVote(9)
		f.cm.voteBuffer[future.Author] = future
		err = f.cm.onStateResponse(f.ctx, f.state)
		require.ErrorContains(t, err, "QC after recovery")
		require.True(t, f.cm.recovery.InRecovery(), "the new recovery is not cleared by the old completion")
		require.Len(t, f.cm.voteBuffer, 1, "the stale votes are dropped, the vote which may belong to the new recovery stays")
		require.Contains(t, f.cm.voteBuffer, future.Author)
	})
}

func Test_Followup_LastVoteOfTheRecoveryVote(t *testing.T) {
	t.Run("stored, and restored to the pacemaker as on restart", func(t *testing.T) {
		f := newFollowup(t, 3, nil)
		f.ingress(f.proposal4())
		require.NoError(t, f.cm.onStateResponse(f.ctx, f.state))
		require.Len(t, f.votes(), 1)
		sent := f.votes()[0].Message.(*abdrc.VoteMsg)
		require.Equal(t, []any{sent}, f.db.written())
		read, err := f.db.PersistentStore.ReadLastVote()
		require.NoError(t, err)
		restored, ok := read.(*abdrc.VoteMsg)
		require.True(t, ok)
		require.Equal(t, sent.Author, restored.Author)
		require.Equal(t, sent.Signature, restored.Signature)
		require.Equal(t, sent.VoteInfo.RoundNumber, restored.VoteInfo.RoundNumber)
		require.Equal(t, sent.LedgerCommitInfo.PreviousHash, restored.LedgerCommitInfo.PreviousHash)
		// a restart reads the last vote from the database and resets the pacemaker with it
		f.cm.pacemaker.Reset(f.ctx, f.cm.blockStore.GetHighQc().GetRound(), f.tc, read)
		require.Equal(t, sent.Signature, f.cm.pacemaker.GetVoted().Signature)
		require.EqualValues(t, 4, f.cm.pacemaker.GetVoted().VoteInfo.RoundNumber)
	})

	t.Run("a failing last vote write only warns: highest voted round advanced, no second signature", func(t *testing.T) {
		f := newFollowup(t, 3, nil)
		f.db.failWrite = true
		f.ingress(f.proposal4())
		require.NoError(t, f.cm.onStateResponse(f.ctx, f.state))
		require.Len(t, f.votes(), 1)
		require.Empty(t, f.db.written())
		require.EqualValues(t, 4, f.cm.safety.storage.GetHighestVotedRound())
		f.net.ResetSentMessages(network.ProtocolRootVote)
		_, err := f.cm.recovery.Set(f.proposal4())
		require.NoError(t, err)
		err = f.cm.onStateResponse(f.ctx, clone(t, f.state))
		require.ErrorContains(t, err, "already voted for round 4")
		require.Empty(t, f.votes())
		require.EqualValues(t, 4, f.cm.safety.storage.GetHighestVotedRound())
	})

	t.Run("a failing send: the vote is stored and set, the round is never signed twice", func(t *testing.T) {
		f := newFollowup(t, 3, nil)
		down := &failingVoteNet{RootNet: f.cm.net}
		f.cm.net = down
		f.ingress(f.proposal4())
		err := f.cm.onStateResponse(f.ctx, f.state)
		require.ErrorContains(t, err, "failed to send vote to next leader")
		require.Equal(t, 1, down.sent)
		require.Len(t, f.db.written(), 1)
		require.NotNil(t, f.cm.pacemaker.GetVoted())
		require.EqualValues(t, 4, f.cm.safety.storage.GetHighestVotedRound())
		_, err = f.cm.recovery.Set(f.proposal4())
		require.NoError(t, err)
		err = f.cm.onStateResponse(f.ctx, clone(t, f.state))
		require.ErrorContains(t, err, "already voted for round 4")
		require.Equal(t, 1, down.sent, "no second signature to send")
		require.Len(t, f.db.written(), 1)
	})
}
