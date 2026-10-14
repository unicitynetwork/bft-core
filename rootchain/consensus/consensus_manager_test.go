package consensus

import (
	"cmp"
	"context"
	"crypto"
	"crypto/rand"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime/pprof"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	p2ptest "github.com/libp2p/go-libp2p/core/test"
	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	test "github.com/unicitynetwork/bft-core/internal/testutils"
	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	testobservability "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	abdrctu "github.com/unicitynetwork/bft-core/rootchain/consensus/testutils"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

const partitionID types.PartitionID = 0x00FF0001

var shardID = types.ShardID{}

func readResult(ch <-chan *certification.CertificationResponse, timeout time.Duration) (*types.UnicityCertificate, error) {
	select {
	case result, ok := <-ch:
		if !ok {
			return nil, fmt.Errorf("failed to read from channel")
		}
		return &result.UC, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout")
	}
}

func initConsensusManager(t *testing.T, rootNet RootNet, opts ...Option) (*ConsensusManager, *testutils.TestNode, []*testutils.TestNode) {
	rootNode := testutils.NewTestNode(t)
	shardNodes, shardNodeInfos := testutils.CreateTestNodes(t, 3)
	trustBase := trustbase.NewTrustBaseFromSigners(t, map[string]abcrypto.Signer{
		rootNode.PeerConf.ID.String(): rootNode.Signer,
	})
	observe := testobservability.Default(t)

	shardConf := &types.PartitionDescriptionRecord{
		Version:         1,
		NetworkID:       5,
		PartitionID:     partitionID,
		ShardID:         shardID,
		PartitionTypeID: 999,
		TypeIDLen:       8,
		UnitIDLen:       256,
		T2Timeout:       2500 * time.Millisecond,
		Validators:      shardNodeInfos,
		Epoch:           0,
		EpochStart:      1,
	}

	rootSigners := map[string]abcrypto.Signer{
		rootNode.PeerConf.ID.String(): rootNode.Signer,
	}
	rootDB, orchestration := createStorage(t, shardConf, rootSigners, observe)

	trustBaseStore, err := tbstore.NewTrustBaseStore(memorydb.New(), observe.Logger())
	require.NoError(t, err)
	require.NoError(t, trustBaseStore.Store(trustBase))

	cm, err := NewConsensusManager(
		rootNode.PeerConf.ID,
		trustBaseStore,
		orchestration,
		rootNet,
		rootNode.Signer,
		rootDB,
		observe,
		opts...,
	)
	require.NoError(t, err)

	return cm, rootNode, shardNodes
}

func buildBlockCertificationRequest(t *testing.T, shardNodes []*testutils.TestNode, lastCR *certification.CertificationResponse) []*certification.BlockCertificationRequest {
	t.Helper()
	timestamp := uint64(1)
	if lastCR != nil {
		timestamp = lastCR.UC.UnicitySeal.Timestamp
	}
	newIR := &types.InputRecord{
		Version:      1,
		PreviousHash: nil,
		Hash:         test.RandomBytes(32),
		BlockHash:    test.RandomBytes(32),
		SummaryValue: []byte{2, 3, 4},
		RoundNumber:  1,
		Timestamp:    timestamp,
	}
	requests := make([]*certification.BlockCertificationRequest, len(shardNodes))
	for i, n := range shardNodes {
		requests[i] = testutils.CreateBlockCertificationRequest(t, newIR, partitionID, n)
	}
	return requests
}

func Test_ConsensusManager_onPartitionIRChangeReq(t *testing.T) {
	mockNet := testnetwork.NewRootMockNetwork()
	cm, _, shardNodes := initConsensusManager(t, mockNet)

	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	go func() { require.ErrorIs(t, cm.Run(ctx), context.Canceled) }()

	require.Eventually(t, func() bool {
		return cm.pacemaker.GetCurrentRound() > 0
	}, test.WaitDuration, test.WaitShortTick)

	si, err := cm.ShardInfo(partitionID, shardID)
	require.NoError(t, err)

	req := &IRChangeRequest{
		Partition: partitionID,
		Reason:    Quorum,
		Requests:  buildBlockCertificationRequest(t, shardNodes, si.LastCR),
	}

	require.NoError(t, cm.onPartitionIRChangeReq(context.Background(), req))
	// since there is only one root node, it is the next leader, the request will be buffered
	require.True(t, cm.irReqBuffer.IsChangeInBuffer(partitionID, shardID))
}

func Test_ConsensusManager_onIRChangeMsg_ErrInvalidSignature(t *testing.T) {
	mockNet := testnetwork.NewRootMockNetwork()
	cm, _, shardNodes := initConsensusManager(t, mockNet)

	req := &abdrc.IrChangeReqMsg{
		Author: cm.id.String(),
		IrChangeReq: &drctypes.IRChangeReq{
			Partition:  partitionID,
			CertReason: drctypes.Quorum,
			Requests:   buildBlockCertificationRequest(t, shardNodes, nil),
		},
		Signature: []byte{1, 2, 3, 4},
	}
	// verify that error is printed and author ID is also present
	require.ErrorContains(t, cm.onIRChangeMsg(context.Background(), req),
		fmt.Sprintf("invalid IR change request from node %s: signature verification failed", cm.id.String()))
}

func TestIRChangeRequestFromRootValidator_RootTimeoutOnFirstRound(t *testing.T) {
	var lastProposalMsg *abdrc.ProposalMsg = nil
	var lastVoteMsg *abdrc.VoteMsg = nil
	var lastTimeoutMsg *abdrc.TimeoutMsg = nil

	mockNet := testnetwork.NewRootMockNetwork()
	cm, _, _ := initConsensusManager(t, mockNet)

	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	go func() { require.ErrorIs(t, cm.Run(ctx), context.Canceled) }()

	// Await proposal
	lastProposalMsg = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
	require.Equal(t, uint64(2), lastProposalMsg.Block.Round)
	// Quick hack to trigger timeout
	// simulate local timeout by calling the method -> race/hack accessing from different go routines not safe
	cm.onLocalTimeout(ctx)
	// await timeout vote
	lastTimeoutMsg = testutils.MockAwaitMessage[*abdrc.TimeoutMsg](t, mockNet, network.ProtocolRootTimeout)
	require.Equal(t, uint64(2), lastTimeoutMsg.Timeout.Round)
	// simulate TC not achieved and make sure the same timeout message is sent again
	// Quick hack to trigger next timeout
	// simulate local timeout by calling the method -> race/hack accessing from different go routines not safe
	cm.onLocalTimeout(ctx)
	lastTimeoutMsg = testutils.MockAwaitMessage[*abdrc.TimeoutMsg](t, mockNet, network.ProtocolRootTimeout)
	require.Equal(t, uint64(2), lastTimeoutMsg.Timeout.Round)
	// route timeout message back
	// route the timeout message back to trigger timeout certificate and new round
	mockNet.WaitReceive(t, lastTimeoutMsg)
	// This triggers TC and next round, wait for proposal
	lastProposalMsg = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
	require.True(t, lastProposalMsg.Block.Payload.IsEmpty())
	require.Equal(t, uint64(3), lastProposalMsg.Block.Round)
	require.NotNil(t, lastProposalMsg.LastRoundTc)
	require.Equal(t, uint64(2), lastProposalMsg.LastRoundTc.Timeout.Round)
	// route the proposal back
	mockNet.WaitReceive(t, lastProposalMsg)
	// wait for the vote message
	lastVoteMsg = testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
	require.Equal(t, uint64(3), lastVoteMsg.VoteInfo.RoundNumber)
	// round 3 is skipped, as it timeouts
	require.Equal(t, uint64(1), lastVoteMsg.VoteInfo.ParentRoundNumber)
	require.Equal(t, uint64(1), lastVoteMsg.VoteInfo.Epoch)
	require.Nil(t, lastVoteMsg.LedgerCommitInfo.Hash)
}

// pendingRounds returns the rounds of the uncommitted blocks in the state message
func pendingRounds(msg *abdrc.StateMsg) (rounds []uint64) {
	for _, b := range msg.Pending {
		rounds = append(rounds, b.Round)
	}
	return rounds
}

func TestIRChangeRequestFromRootValidator_RootTimeout(t *testing.T) {
	mockNet := testnetwork.NewRootMockNetwork()
	cm, rootNode, shardNodes := initConsensusManager(t, mockNet)

	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	go func() { require.ErrorIs(t, cm.Run(ctx), context.Canceled) }()

	si, err := cm.ShardInfo(partitionID, shardID)
	require.NoError(t, err)
	require.NotNil(t, si)

	// simulate IR change request message
	irChReqMsg := &abdrc.IrChangeReqMsg{
		Author: rootNode.PeerConf.ID.String(),
		IrChangeReq: &drctypes.IRChangeReq{
			Partition:  partitionID,
			CertReason: drctypes.Quorum,
			Requests:   buildBlockCertificationRequest(t, shardNodes[0:2], si.LastCR),
		},
	}
	require.NoError(t, irChReqMsg.Sign(rootNode.Signer))

	// advance round
	lastProposalMsg := testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
	mockNet.WaitReceive(t, lastProposalMsg)
	mockNet.WaitReceive(t, irChReqMsg)
	voteMsg := testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
	mockNet.WaitReceive(t, voteMsg)
	lastProposalMsg = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)

	// round 1 committed, round 2 quorum
	require.Equal(t, uint64(1), cm.blockStore.GetHighQc().GetCommitRound())
	require.Equal(t, uint64(2), cm.blockStore.GetHighQc().GetRound())
	require.Equal(t, uint64(3), cm.pacemaker.GetCurrentRound())
	require.Equal(t, partitionID, lastProposalMsg.Block.Payload.Requests[0].Partition)
	require.Equal(t, drctypes.Quorum, lastProposalMsg.Block.Payload.Requests[0].CertReason)
	require.Len(t, lastProposalMsg.Block.Payload.Requests[0].Requests, 2)

	// advance round
	mockNet.WaitReceive(t, lastProposalMsg)
	lastVoteMsg := testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
	mockNet.WaitReceive(t, lastVoteMsg)
	lastProposalMsg = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)

	// round 2 committed, round 3 quorum
	require.Equal(t, uint64(2), cm.blockStore.GetHighQc().GetCommitRound())
	require.Equal(t, uint64(3), cm.blockStore.GetHighQc().GetRound())
	require.Equal(t, uint64(4), cm.pacemaker.GetCurrentRound())
	// no additional requests have been received, meaning payload is empty
	require.True(t, lastProposalMsg.Block.Payload.IsEmpty())

	// advance round with timeout
	mockNet.WaitReceive(t, lastProposalMsg)
	lastVoteMsg = testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
	// Avoid waiting for the default LocalTimeout (10s), and
	// simulate local timeout by calling the method -> race/hack accessing from different go routines not safe
	cm.onLocalTimeout(ctx)
	lastTimeoutMsg := testutils.MockAwaitMessage[*abdrc.TimeoutMsg](t, mockNet, network.ProtocolRootTimeout)
	require.Equal(t, uint64(4), lastTimeoutMsg.Timeout.Round)
	// route the timeout message back to trigger timeout certificate and new round
	mockNet.WaitReceive(t, lastTimeoutMsg)
	lastProposalMsg = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)

	// round 2 committed, round 3 quorum - timeout cert didn't change that
	require.Equal(t, uint64(2), cm.blockStore.GetHighQc().GetCommitRound())
	require.Equal(t, uint64(3), cm.blockStore.GetHighQc().GetRound())
	require.Equal(t, uint64(4), lastProposalMsg.LastRoundTc.Timeout.Round)
	require.Equal(t, uint64(5), lastProposalMsg.Block.Round)
	require.Equal(t, uint64(5), cm.pacemaker.GetCurrentRound())
	require.NotNil(t, lastProposalMsg.LastRoundTc)

	// no changes in round 5, but...
	require.True(t, lastProposalMsg.Block.Payload.IsEmpty())
	// changes from round 3 are still in progress (uncommitted), since nothing gets committed with a timeout cert
	require.Equal(t, irChReqMsg.IrChangeReq.Requests[0].InputRecord, cm.blockStore.IsChangeInProgress(cm.blockStore.GetHighQc().GetRound(), partitionID, shardID))

	// advance round
	mockNet.WaitReceive(t, lastProposalMsg)
	lastVoteMsg = testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
	// Check state before routing vote back to root
	getStateMsg := &abdrc.StateRequestMsg{
		NodeId: shardNodes[0].PeerConf.ID.String(),
	}
	mockNet.WaitReceive(t, getStateMsg)
	stateMsg := testutils.MockAwaitMessage[*abdrc.StateMsg](t, mockNet, network.ProtocolRootStateResp)
	// commit head is still at round 3, as round 5 that would have committed 4 resulted in timeout
	require.Equal(t, uint64(2), stateMsg.CommittedHead.Block.Round)
	// block of the round 4 stays in the tree although the round resulted in timeout quorum (the round
	// might still get QC too), it is pruned when round 5 gets committed
	require.ElementsMatch(t, []uint64{3, 4, 5}, pendingRounds(stateMsg))
	// send vote back to validator
	mockNet.WaitReceive(t, lastVoteMsg)
	lastProposalMsg = mockNet.WaitRootProposal(t)

	// round 2 committed, round 5 quorum
	// round 5 did not commit anything because round 4 was timeout, need two consecutive QC-s to commit
	require.Equal(t, uint64(0), cm.blockStore.GetHighQc().GetCommitRound())
	require.Equal(t, uint64(5), cm.blockStore.GetHighQc().GetRound())
	require.Equal(t, uint64(6), lastProposalMsg.Block.Round)
	require.Equal(t, uint64(6), cm.pacemaker.GetCurrentRound())
	require.Nil(t, lastProposalMsg.LastRoundTc)

	// advance round
	mockNet.WaitReceive(t, lastProposalMsg)
	lastVoteMsg = testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
	require.Equal(t, uint64(6), lastVoteMsg.VoteInfo.RoundNumber)
	require.NotEqual(t, uint64(0), lastVoteMsg.LedgerCommitInfo.RootChainRoundNumber)
	// Check state before routing vote back to root
	mockNet.WaitReceive(t, getStateMsg)
	stateMsg = testutils.MockAwaitMessage[*abdrc.StateMsg](t, mockNet, network.ProtocolRootStateResp)
	// commit head is still at round 2, rounds 3, 5 and 6 are added, 6 will commit 5 when it reaches quorum, but
	// this happens after vote is routed back, so current expected state is:
	require.Equal(t, uint64(2), stateMsg.CommittedHead.Block.Round)
	require.ElementsMatch(t, []uint64{3, 4, 5, 6}, pendingRounds(stateMsg))
	mockNet.WaitReceive(t, lastVoteMsg)
	lastProposalMsg = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)

	// after two successful rounds since timeout the IR change will be finally committed and UC is returned
	result, err := readResult(cm.CertificationResult(), time.Second)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, partitionID, result.UnicityTreeCertificate.Partition)
	require.Nil(t, cm.blockStore.IsChangeInProgress(cm.blockStore.GetHighQc().GetRound(), partitionID, shardID))

	// verify certificates have been updated when recovery query is sent
	mockNet.WaitReceive(t, getStateMsg)
	stateMsg = testutils.MockAwaitMessage[*abdrc.StateMsg](t, mockNet, network.ProtocolRootStateResp)
	require.Equal(t, 1, len(stateMsg.CommittedHead.ShardInfo))
	idx := slices.IndexFunc(stateMsg.CommittedHead.ShardInfo, func(c abdrc.ShardInfo) bool {
		return c.UC.UnicityTreeCertificate.Partition == partitionID
	})
	require.False(t, idx == -1)
	// at this stage the committed round is 6 and round 7 block is pending
	require.Equal(t, uint64(5), stateMsg.CommittedHead.Block.Round)
	require.Equal(t, uint64(5), stateMsg.CommittedHead.ShardInfo[idx].UC.UnicitySeal.RootChainRoundNumber)
	require.Equal(t, 1, len(stateMsg.Pending))
	require.Equal(t, uint64(6), stateMsg.Pending[0].Round)
}

func TestIRChangeRequestFromRootValidator(t *testing.T) {
	var lastProposalMsg *abdrc.ProposalMsg = nil
	var lastVoteMsg *abdrc.VoteMsg = nil

	mockNet := testnetwork.NewRootMockNetwork()
	cm, rootNode, shardNodes := initConsensusManager(t, mockNet)

	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	go func() { require.ErrorIs(t, cm.Run(ctx), context.Canceled) }()

	si, err := cm.ShardInfo(partitionID, shardID)
	require.NoError(t, err)

	// simulate IR change request message
	irChReqMsg := &abdrc.IrChangeReqMsg{
		Author: rootNode.PeerConf.ID.String(),
		IrChangeReq: &drctypes.IRChangeReq{
			Partition:  partitionID,
			CertReason: drctypes.Quorum,
			Requests:   buildBlockCertificationRequest(t, shardNodes[0:2], si.LastCR),
		},
	}
	require.NoError(t, irChReqMsg.Sign(rootNode.Signer))

	// advance round
	mockNet.WaitReceive(t, irChReqMsg)
	lastProposalMsg = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)

	require.Equal(t, partitionID, lastProposalMsg.Block.Payload.Requests[0].Partition)
	require.Equal(t, drctypes.Quorum, lastProposalMsg.Block.Payload.Requests[0].CertReason)
	require.Len(t, lastProposalMsg.Block.Payload.Requests[0].Requests, 2)
	// route the proposal back
	mockNet.WaitReceive(t, lastProposalMsg)
	// wait for the vote message
	lastVoteMsg = testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
	require.Equal(t, uint64(2), lastVoteMsg.VoteInfo.RoundNumber)
	require.Equal(t, uint64(1), lastVoteMsg.VoteInfo.ParentRoundNumber)
	require.Equal(t, uint64(1), lastVoteMsg.VoteInfo.Epoch)
	require.NotNil(t, lastVoteMsg.LedgerCommitInfo.Hash)

	// send vote back to validator
	mockNet.WaitReceive(t, lastVoteMsg)
	// this will trigger next proposal since QC is achieved
	lastProposalMsg = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
	// no additional requests have been received, meaning payload is empty
	require.True(t, lastProposalMsg.Block.Payload.IsEmpty())

	// route the proposal back to trigger new vote
	mockNet.WaitReceive(t, lastProposalMsg)
	// wait for the vote message
	lastVoteMsg = testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
	require.Equal(t, uint64(3), lastVoteMsg.VoteInfo.RoundNumber)
	require.NotNil(t, lastVoteMsg.LedgerCommitInfo.Hash)
	// send vote back to validator
	mockNet.WaitReceive(t, lastVoteMsg)
	// after two successful rounds the IR change will be committed and UC is returned
	result, err := readResult(cm.CertificationResult(), time.Second)
	require.NoError(t, err)

	shardConf, err := cm.orchestration.ShardConfig(partitionID, shardID, 1)
	require.NoError(t, err)
	shardConfHash, err := shardConf.Hash(crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, result.Verify(cm.trustBase.Load(), crypto.SHA256, partitionID, shardID, shardConfHash))

	// root will continue and next proposal is also triggered by the same QC
	lastProposalMsg = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
	require.True(t, lastProposalMsg.Block.Payload.IsEmpty())
	require.NoError(t, err)
}

func TestPartitionTimeoutFromRootValidator(t *testing.T) {
	var lastProposalMsg *abdrc.ProposalMsg = nil
	var lastVoteMsg *abdrc.VoteMsg = nil

	mockNet := testnetwork.NewRootMockNetwork()
	cm, _, _ := initConsensusManager(t, mockNet)

	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	go func() { require.ErrorIs(t, cm.Run(ctx), context.Canceled) }()

	shardConf, err := cm.orchestration.ShardConfig(partitionID, shardID, 1)
	require.NoError(t, err)

	roundNo := uint64(1) // 1 is genesis
	// run a loop of 11 rounds to produce a root chain timeout
	for i := 0; i < int(shardConf.T2Timeout/(cm.params.BlockRate/2)); i++ {
		//for i := 0; i < int(shardConf.T2Timeout/(cm.params.BlockRate/2)); i++ {
		// proposal rounds 2..
		roundNo++
		lastProposalMsg = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
		require.Empty(t, lastProposalMsg.Block.Payload.Requests)
		// route the proposal back
		mockNet.WaitReceive(t, lastProposalMsg)
		// wait for the vote message
		lastVoteMsg = testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
		require.Equal(t, roundNo, lastVoteMsg.VoteInfo.RoundNumber)
		mockNet.WaitReceive(t, lastVoteMsg)
	}

	// proposal round 7 with timeout
	roundNo++
	lastProposalMsg = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
	require.NotEmpty(t, lastProposalMsg.Block.Payload.Requests)
	require.Equal(t, drctypes.T2Timeout, lastProposalMsg.Block.Payload.Requests[0].CertReason)
	mockNet.WaitReceive(t, lastProposalMsg)
	// wait for the vote message
	lastVoteMsg = testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
	require.Equal(t, roundNo, lastVoteMsg.VoteInfo.RoundNumber)
	mockNet.WaitReceive(t, lastVoteMsg)
	// new proposal round 8
	roundNo++
	lastProposalMsg = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
	require.Empty(t, lastProposalMsg.Block.Payload.Requests)
	mockNet.WaitReceive(t, lastProposalMsg)
	// voting round 8
	lastVoteMsg = testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
	require.Equal(t, roundNo, lastVoteMsg.VoteInfo.RoundNumber)
	mockNet.WaitReceive(t, lastVoteMsg)
	// triggers timeout certificates for in round 8 to be committed
	result, err := readResult(cm.CertificationResult(), time.Second)
	require.NoError(t, err)
	require.NotNil(t, result)
	// round 7 got certified in round 8
	require.Equal(t, roundNo-1, result.UnicitySeal.RootChainRoundNumber)
	// proposal in round 9 should be empty again
	roundNo++
	lastProposalMsg = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
	require.True(t, lastProposalMsg.Block.Payload.IsEmpty())
	mockNet.WaitReceive(t, lastProposalMsg)
	// vote round 9
	lastVoteMsg = testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
	require.Equal(t, roundNo, lastVoteMsg.VoteInfo.RoundNumber)
	mockNet.WaitReceive(t, lastVoteMsg)
	// proposal round 10
	lastProposalMsg = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
	require.True(t, lastProposalMsg.Block.Payload.IsEmpty())
	mockNet.WaitReceive(t, lastProposalMsg)
}

func TestGetState_WithoutShards(t *testing.T) {
	mockNet := testnetwork.NewRootMockNetwork()
	rootNode := testutils.NewTestNode(t)
	trustBase := trustbase.NewTrustBaseFromSigners(t, map[string]abcrypto.Signer{
		rootNode.PeerConf.ID.String(): rootNode.Signer,
	})
	observe := testobservability.Default(t)
	dir := t.TempDir()
	orchestration, err := partitions.NewOrchestration(5, filepath.Join(dir, "orchestration.db"), observe.Logger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = orchestration.Close() })
	rootDB, err := storage.NewBoltStorage(filepath.Join(dir, "root.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = rootDB.Close() })

	trustBaseStore, err := tbstore.NewTrustBaseStore(memorydb.New(), observe.Logger())
	require.NoError(t, err)
	require.NoError(t, trustBaseStore.Store(trustBase))

	cm, err := NewConsensusManager(
		rootNode.PeerConf.ID,
		trustBaseStore,
		orchestration,
		mockNet,
		rootNode.Signer,
		rootDB,
		observe,
	)
	require.NoError(t, err)

	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	go func() { require.ErrorIs(t, cm.Run(ctx), context.Canceled) }()

	// request state
	getStateMsg := &abdrc.StateRequestMsg{
		NodeId: rootNode.PeerConf.ID.String(),
	}
	mockNet.WaitReceive(t, getStateMsg)
	stateMsg := testutils.MockAwaitMessage[*abdrc.StateMsg](t, mockNet, network.ProtocolRootStateResp)

	// only genesis block present
	require.Equal(t, 0, len(stateMsg.Pending))
	require.Len(t, stateMsg.CommittedHead.ShardInfo, 0)
	// the hard-coded round 1 is the CommittedHead
	require.Equal(t, uint64(1), stateMsg.CommittedHead.Block.Round)
	require.Equal(t, uint64(1), stateMsg.CommittedHead.CommitQc.GetRound())
	require.Equal(t, uint64(1), stateMsg.CommittedHead.Qc.GetRound())
	// the verification of hard-coded CommittedHead should succeed despite having no signatures
	require.Len(t, stateMsg.CommittedHead.CommitQc.Signatures, 0)
	require.NoError(t, stateMsg.Verify(crypto.SHA256, trustBase))

	// advance to round 2
	lastProposalMsg := testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
	mockNet.WaitReceive(t, lastProposalMsg)
	voteMsg := testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
	mockNet.WaitReceive(t, voteMsg)
	lastProposalMsg = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)

	// request state
	mockNet.WaitReceive(t, getStateMsg)
	stateMsg = testutils.MockAwaitMessage[*abdrc.StateMsg](t, mockNet, network.ProtocolRootStateResp)

	// a new block present now, still no shards
	require.Len(t, stateMsg.Pending, 1)
	require.Equal(t, uint64(2), stateMsg.Pending[0].Round)
	// the hard-coded round 1 is still the CommittedHead
	require.Equal(t, uint64(1), stateMsg.CommittedHead.Block.Round)
	require.Equal(t, uint64(1), stateMsg.CommittedHead.Qc.GetRound())
	// but a new commitQc was produced with signatures
	require.Equal(t, uint64(2), stateMsg.CommittedHead.CommitQc.GetRound())
	require.Len(t, stateMsg.CommittedHead.CommitQc.Signatures, 1)
	require.NoError(t, stateMsg.Verify(crypto.SHA256, trustBase))
}

func TestGetState_WithShards(t *testing.T) {
	mockNet := testnetwork.NewRootMockNetwork()
	cm, _, shardNodes := initConsensusManager(t, mockNet)

	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	go func() { require.ErrorIs(t, cm.Run(ctx), context.Canceled) }()

	getStateMsg := &abdrc.StateRequestMsg{
		NodeId: shardNodes[0].PeerConf.ID.String(),
	}
	// simulate IR change request message
	mockNet.WaitReceive(t, getStateMsg)
	// As the node is the leader, next round will trigger a proposal
	stateMsg := testutils.MockAwaitMessage[*abdrc.StateMsg](t, mockNet, network.ProtocolRootStateResp)
	// at this stage there is only genesis block
	require.Equal(t, uint64(1), stateMsg.CommittedHead.Block.Round)
	require.Equal(t, 0, len(stateMsg.Pending))
	require.Len(t, stateMsg.CommittedHead.ShardInfo, 1)
}

func Test_ConsensusManager_onVoteMsg(t *testing.T) {
	t.Parallel()

	makeVoteMsg := func(t *testing.T, cms []*ConsensusManager, round uint64) *abdrc.VoteMsg {
		t.Helper()
		qcRoundInfo := abdrctu.NewDummyRootRoundInfo(round - 2)
		commitInfo := abdrctu.NewDummyCommitInfo(t, crypto.SHA256, qcRoundInfo)
		highQc := &drctypes.QuorumCert{
			VoteInfo:         qcRoundInfo,
			LedgerCommitInfo: commitInfo,
			Signatures:       map[string]hex.Bytes{},
		}
		cib := testcertificates.UnicitySealBytes(t, commitInfo)
		for _, cm := range cms {
			sig, err := cm.safety.signer.SignBytes(cib)
			require.NoError(t, err)
			highQc.Signatures[cm.id.String()] = sig
		}

		voteRoundInfo := abdrctu.NewDummyRootRoundInfo(round)
		h, err := voteRoundInfo.Hash(crypto.SHA256)
		require.NoError(t, err)
		voteMsg := &abdrc.VoteMsg{
			VoteInfo: voteRoundInfo,
			LedgerCommitInfo: &types.UnicitySeal{
				Version:      1,
				PreviousHash: h,
			},
			HighQc: highQc,
			Author: cms[0].id.String(),
		}
		require.NoError(t, voteMsg.Sign(cms[0].safety.signer))
		return voteMsg
	}

	t.Run("stale vote", func(t *testing.T) {
		cms, _ := createConsensusManagers(t, 1, nil)
		cms[0].pacemaker.Reset(context.Background(), 8, nil, nil)
		defer cms[0].pacemaker.Stop()

		vote := makeVoteMsg(t, cms, 7)
		err := cms[0].onVoteMsg(context.Background(), vote)
		require.EqualError(t, err, `stale vote for round 7 from `+cms[0].id.String())
		require.Empty(t, cms[0].voteBuffer)
	})

	t.Run("invalid vote: verify fails", func(t *testing.T) {
		// here we just test that only verified votes are processed, all the possible
		// vote verification failures should be tested by vote.Verify unit tests...
		const votedRound = 10
		cms, _ := createConsensusManagers(t, 1, nil)
		cms[0].pacemaker.Reset(context.Background(), votedRound-1, nil, nil)
		defer cms[0].pacemaker.Stop()

		vote := makeVoteMsg(t, cms, votedRound)
		vote.Author = "foobar"
		err := cms[0].onVoteMsg(context.Background(), vote)
		require.EqualError(t, err, `invalid vote: vote from 'foobar' signature verification error: author 'foobar' is not part of the trust base`)
		require.Empty(t, cms[0].voteBuffer)
	})

	t.Run("vote for next round should be buffered", func(t *testing.T) {
		const votedRound = 10
		// need at least two CMs so that we do not trigger recovery because of having
		// received enough votes for the quorum
		cms, _ := createConsensusManagers(t, 2, nil)
		cms[0].pacemaker.Reset(context.Background(), votedRound-1, nil, nil)
		defer cms[0].pacemaker.Stop()

		vote := makeVoteMsg(t, cms, votedRound+1)
		err := cms[0].onVoteMsg(context.Background(), vote)
		require.NoError(t, err)
		require.Equal(t, vote, cms[0].voteBuffer[vote.Author])
	})

	t.Run("repeat vote for next round should be ignored (not buffered twice)", func(t *testing.T) {
		const votedRound = 10
		// need at least two CMs so that we do not trigger recovery because of having
		// received enough votes for the quorum
		cms, _ := createConsensusManagers(t, 2, nil)
		cms[0].pacemaker.Reset(context.Background(), votedRound-1, nil, nil)
		defer cms[0].pacemaker.Stop()

		vote := makeVoteMsg(t, cms, votedRound+1)
		err := cms[0].onVoteMsg(context.Background(), vote)
		require.NoError(t, err)
		require.Equal(t, vote, cms[0].voteBuffer[vote.Author])
		// send the vote again - should not trigger recovery ie vote is not counted again
		require.NoError(t, cms[0].onVoteMsg(context.Background(), vote))
		require.Equal(t, vote, cms[0].voteBuffer[vote.Author], "expected original vote still to be in the buffer")
		require.Len(t, cms[0].voteBuffer, 1, "expected only one vote to be buffered")
	})

	t.Run("quorum of votes for next round should trigger recovery", func(t *testing.T) {
		const votedRound = 10
		cms, _ := createConsensusManagers(t, 1, nil)
		cms[0].pacemaker.Reset(context.Background(), votedRound-1, nil, nil)
		defer cms[0].pacemaker.Stop()

		// as we have single CM vote means quorum and recovery should be triggered as CM hasn't
		// seen proposal yet
		vote := makeVoteMsg(t, cms, votedRound+1)
		err := cms[0].onVoteMsg(context.Background(), vote)
		require.EqualError(t, err, `have received 1 votes but no proposal, entering recovery`)
		require.Equal(t, vote, cms[0].voteBuffer[vote.Author], "expected vote to be buffered")
	})
	/* todo - need a way to mock storage
	t.Run("not the leader of the (next) round", func(t *testing.T) {
		const votedRound = 10
		cms, _, _ := createConsensusManagers(t, 2, []*genesis.PartitionRecord{partitionRecord})
		cms[0].leaderSelector = constLeader{leader: cms[1].id, nodes: cms[1].leaderSelector.GetNodes()} // make sure this CM won't be the leader
		cms[0].pacemaker.Reset(context.Background(), votedRound-1, nil, nil)
		defer cms[0].pacemaker.Stop()

		vote := makeVoteMsg(t, cms, votedRound)
		err := cms[0].onVoteMsg(context.Background(), vote)
		require.EqualError(t, err, fmt.Sprintf("validator is not the leader for round %d", votedRound+1))
		require.Empty(t, cms[0].voteBuffer)
	})
	*/
}

func Test_ConsensusManager_handleRootNetMsg(t *testing.T) {
	t.Parallel()

	observe := testobservability.Default(t)
	pm, err := NewPacemaker(time.Minute, 2*time.Minute, observe)
	if err != nil {
		t.Fatalf("creating Pacemaker: %v", err)
	}

	t.Run("untyped nil msg", func(t *testing.T) {
		cm := &ConsensusManager{pacemaker: pm, tracer: observe.Tracer("cm")}
		require.NoError(t, cm.initMetrics(observe))
		err := cm.handleRootNetMsg(context.Background(), nil)
		require.EqualError(t, err, `unknown message type <nil>`)
	})

	t.Run("type not known for the handler", func(t *testing.T) {
		cm := &ConsensusManager{pacemaker: pm, tracer: observe.Tracer("cm")}
		require.NoError(t, cm.initMetrics(observe))
		err := cm.handleRootNetMsg(context.Background(), "foobar")
		require.EqualError(t, err, `unknown message type string`)
	})
}

func Test_ConsensusManager_messages(t *testing.T) {
	t.Parallel()

	waitExit := func(t *testing.T, ctxCancel context.CancelFunc, doneCh chan struct{}) {
		t.Helper()
		ctxCancel()
		// and wait for cm to exit
		select {
		case <-time.After(10 * time.Second):
			_ = pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
			t.Fatal("consensus manager did not exit in time")
		case <-doneCh:
		}
	}

	// partition data used/shared by tests
	shardNodes, shardNodeInfos := testutils.CreateTestNodes(t, 2)

	t.Run("IR change request from shard included in proposal", func(t *testing.T) {
		cms, rootNet := createConsensusManagers(t, 1, shardNodeInfos)

		ctx, stopCM := context.WithCancel(context.Background())
		defer stopCM()
		go func() { require.ErrorIs(t, cms[0].Run(ctx), context.Canceled) }()

		// proposal will be broadcast so eavesdrop the network and make copy of it
		propCh := make(chan *abdrc.ProposalMsg, 1)
		rootNet.SetFirewall(func(from, to peer.ID, msg any) bool {
			if msg, ok := msg.(*abdrc.ProposalMsg); ok {
				propCh <- msg
			}
			return false
		})

		si, err := cms[0].ShardInfo(partitionID, shardID)
		require.NoError(t, err)

		// simulate root validator node sending IRCR to consensus manager
		irCReq := IRChangeRequest{
			Partition: partitionID,
			Reason:    Quorum,
			Requests:  buildBlockCertificationRequest(t, shardNodes, si.LastCR),
		}

		rcCtx, rcCancel := context.WithTimeout(ctx, cms[0].pacemaker.minRoundLen)
		require.NoError(t, cms[0].RequestCertification(rcCtx, irCReq), "CM doesn't consume IR change request")
		rcCancel()

		// IRCR must be included into proposal
		select {
		case <-time.After(cms[0].pacemaker.maxRoundLen):
			t.Fatal("haven't got the proposal before timeout")
		case prop := <-propCh:
			require.NotNil(t, prop)
			require.NotNil(t, prop.Block)
			require.NotNil(t, prop.Block.Payload)
			require.Len(t, prop.Block.Payload.Requests, 1)
			require.EqualValues(t, irCReq.Partition, prop.Block.Payload.Requests[0].Partition)
			require.ElementsMatch(t, irCReq.Requests, prop.Block.Payload.Requests[0].Requests)
		}
	})

	t.Run("IR change request from partition forwarded to leader", func(t *testing.T) {
		// we create two CMs but only non-leader node has to be running as we test
		// that it will forward message to leader by monitoring network
		cms, rootNet := createConsensusManagers(t, 2, shardNodeInfos)
		cmLeader := cms[0]
		nonLeaderNode := cms[1]
		nonLeaderNode.leaderSelector = constLeader{leader: cmLeader.id, nodes: cmLeader.Validators()} // use "const leader" to take leader selection out of test
		// eavesdrop the network and copy IR change message sent by non-leader to leader
		irCh := make(chan *abdrc.IrChangeReqMsg, 1)
		rootNet.SetFirewall(func(from, to peer.ID, msg any) bool {
			if msg, ok := msg.(*abdrc.IrChangeReqMsg); ok && from == nonLeaderNode.id && to == cmLeader.id {
				irCh <- msg
			}
			return false
		})

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); require.ErrorIs(t, nonLeaderNode.Run(ctx), context.Canceled) }()
		defer waitExit(t, cancel, done)

		// simulate partition request sent to non-leader node
		irCReq := IRChangeRequest{
			Partition: partitionID,
			Reason:    Quorum,
			Requests:  buildBlockCertificationRequest(t, shardNodes, nil),
		}
		rcCtx, rcCancel := context.WithTimeout(ctx, nonLeaderNode.pacemaker.minRoundLen)
		require.NoError(t, nonLeaderNode.RequestCertification(rcCtx, irCReq), "CM doesn't consume IR change request")
		rcCancel()

		select {
		case <-time.After(cmLeader.pacemaker.maxRoundLen):
			t.Fatal("haven't got the IR Change message before timeout")
		case irMsg := <-irCh:
			require.NotNil(t, irMsg)
			require.Equal(t, irMsg.Author, nonLeaderNode.id.String())
			require.EqualValues(t, irCReq.Partition, irMsg.IrChangeReq.Partition)
			require.ElementsMatch(t, irCReq.Requests, irMsg.IrChangeReq.Requests)
		}
	})

	t.Run("IR change request forwarded by peer included in proposal", func(t *testing.T) {
		// we create two CMs but only leader is running, the other is just needed for
		// valid peer ID in the genesis so IRCR can be signed and validated
		cms, rootNet := createConsensusManagers(t, 2, shardNodeInfos)

		cmOther := cms[1]
		cmLeader := cms[0]
		cmLeader.leaderSelector = constLeader{leader: cmLeader.id, nodes: cmLeader.Validators()} // use "const leader" to take leader selection out of test

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { require.ErrorIs(t, cmLeader.Run(ctx), context.Canceled) }()

		// leader is expected to broadcast proposal message, snoop for it
		wire := make(chan *abdrc.ProposalMsg, 1)
		rootNet.SetFirewall(ForwardMsgs(cmLeader.id, cmOther.id, wire))

		si, err := cmLeader.ShardInfo(partitionID, shardID)
		require.NoError(t, err)

		// simulate IR change request message, "other root node" forwarding IRCR to leader
		irChReqMsg := &abdrc.IrChangeReqMsg{
			Author: cmOther.id.String(),
			IrChangeReq: &drctypes.IRChangeReq{
				Partition:  partitionID,
				CertReason: drctypes.Quorum,
				Requests:   buildBlockCertificationRequest(t, shardNodes[0:2], si.LastCR),
			},
		}
		require.NoError(t, cmOther.safety.Sign(irChReqMsg))
		require.NoError(t, cmOther.net.Send(ctx, irChReqMsg, cmLeader.id))

		// IRCR must be included into broadcast proposal, either this or next round
		sawIRCR := false
		for cnt := 0; cnt < 2 && !sawIRCR; cnt++ {
			select {
			case <-time.After(cmLeader.pacemaker.maxRoundLen):
				t.Fatal("haven't got the proposal before timeout")
			case prop := <-wire:
				require.NotNil(t, prop)
				require.NotNil(t, prop.Block)
				require.NotNil(t, prop.Block.Payload)
				if len(prop.Block.Payload.Requests) == 1 {
					require.EqualValues(t, irChReqMsg.IrChangeReq.Partition, prop.Block.Payload.Requests[0].Partition)
					require.ElementsMatch(t, irChReqMsg.IrChangeReq.Requests, prop.Block.Payload.Requests[0].Requests)
					sawIRCR = true
				}
			}
		}
		require.True(t, sawIRCR, "expected to see the IRCR in one of the next two proposals")
	})

	t.Run("IR change request arrives late and is forwarded to the next leader", func(t *testing.T) {
		// mimic situation where nonLeaderNode was the leader and IRCR was sent to it. However, by
		// the time msg arrives leader has changed to cmLeader, so we expect nonLeaderNode to
		// forward the message.
		cms, rootNet := createConsensusManagers(t, 2, shardNodeInfos)
		cmLeader := cms[0]
		nonLeaderNode := cms[1]
		nonLeaderNode.leaderSelector = constLeader{leader: cmLeader.id, nodes: cmLeader.Validators()}

		irCh := make(chan *abdrc.IrChangeReqMsg, 1)
		rootNet.SetFirewall(func(from, to peer.ID, msg any) bool {
			if msg, ok := msg.(*abdrc.IrChangeReqMsg); ok && from == nonLeaderNode.id && to == cmLeader.id {
				irCh <- msg
			}
			return false
		})

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); require.ErrorIs(t, nonLeaderNode.Run(ctx), context.Canceled) }()
		defer waitExit(t, cancel, done)

		// send IRCR to non-leader, simulating message arriving late, leader has changed
		irChReqMsg := &abdrc.IrChangeReqMsg{
			Author: cmLeader.id.String(),
			IrChangeReq: &drctypes.IRChangeReq{
				Partition:  partitionID,
				CertReason: drctypes.Quorum,
				Requests:   buildBlockCertificationRequest(t, shardNodes[0:2], nil),
			},
		}
		require.NoError(t, cmLeader.safety.Sign(irChReqMsg))
		rootNet.Send(irChReqMsg, nonLeaderNode.id)

		// non-leader is not the next leader and must forward the request to the leader node
		select {
		case <-time.After(cmLeader.pacemaker.maxRoundLen):
			t.Fatal("haven't seen forwarded proposal before timeout")
		case irMsg := <-irCh:
			require.NotNil(t, irMsg)
			require.Equal(t, irMsg.Author, cmLeader.id.String())
			require.EqualValues(t, irChReqMsg.IrChangeReq.Partition, irMsg.IrChangeReq.Partition)
			require.ElementsMatch(t, irChReqMsg.IrChangeReq.Requests, irMsg.IrChangeReq.Requests)
		}
	})

	t.Run("state request triggers response", func(t *testing.T) {
		cms, _ := createConsensusManagers(t, 2, shardNodeInfos)
		cmA, cmB := cms[0], cms[1]

		// only launch cmA, we manage cmB "manually"
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); require.ErrorIs(t, cmA.Run(ctx), context.Canceled) }()
		defer waitExit(t, cancel, done)

		// cmB sends state request to cmA
		msg := &abdrc.StateRequestMsg{NodeId: cmB.id.String()}
		require.NoError(t, cmB.net.Send(ctx, msg, cmA.id))

		// cmB should receive state response
		select {
		case <-time.After(1000 * time.Millisecond):
			t.Fatal("timeout while waiting for recovery response")
		case msg := <-cmB.net.ReceivedChannel():
			state := msg.(*abdrc.StateMsg)
			require.NotNil(t, state)
			require.EqualValues(t, 1, state.CommittedHead.Block.Round)
			require.Empty(t, state.Pending)
			require.Len(t, state.CommittedHead.ShardInfo, 1)
		}
	})
}

func Test_ConsensusManager_sendCertificates(t *testing.T) {
	t.Parallel()

	// generate UCs for given systems (with random data in QC)
	makeUCs := func(partitionIds ...types.PartitionID) map[types.PartitionShardID]*certification.CertificationResponse {
		rUC := make(map[types.PartitionShardID]*certification.CertificationResponse)
		for _, id := range partitionIds {
			cr := certification.CertificationResponse{
				Partition: id,
				Shard:     shardID,
				UC: types.UnicityCertificate{
					Version:       1,
					ShardConfHash: test.RandomBytes(32),
					UnicityTreeCertificate: &types.UnicityTreeCertificate{
						Version:   1,
						Partition: id,
					},
				},
			}
			rUC[types.PartitionShardID{PartitionID: cr.Partition, ShardID: cr.Shard.Key()}] = &cr
		}
		return rUC
	}

	// consumeUCs reads UCs from "cm"-s output and stores them into map it returns.
	// it reads until "timeout" has passed.
	consumeUCs := func(cm *ConsensusManager, timeout time.Duration) map[types.PartitionShardID]*certification.CertificationResponse {
		to := time.After(timeout)
		rUC := make(map[types.PartitionShardID]*certification.CertificationResponse)
		for {
			select {
			case uc := <-cm.CertificationResult():
				rUC[types.PartitionShardID{PartitionID: uc.Partition, ShardID: uc.Shard.Key()}] = uc
			case <-to:
				return rUC
			}
		}
	}

	outputMustBeEmpty := func(t *testing.T, cm *ConsensusManager) {
		t.Helper()
		select {
		case uc := <-cm.CertificationResult():
			t.Errorf("unexpected data from cert chan: %#v", uc)
		default:
		}
	}

	t.Run("consume before next input is sent", func(t *testing.T) {
		cms, _ := createConsensusManagers(t, 1, nil)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { require.ErrorIs(t, cms[0].sendCertificates(ctx), context.Canceled) }()

		// send some certificates into sink...
		ucs := makeUCs(1, 2)
		select {
		case cms[0].ucSink <- slices.Collect(maps.Values(ucs)):
		default:
			t.Fatal("expected that input would be accepted immediately, sink should be empty")
		}
		//...and consume them
		rUC := consumeUCs(cms[0], 100*time.Millisecond)
		require.Equal(t, ucs, rUC)
		outputMustBeEmpty(t, cms[0])

		// and repeat the exercise with different partition identifiers
		ucs = makeUCs(3, 4)
		select {
		case cms[0].ucSink <- slices.Collect(maps.Values(ucs)):
		default:
			t.Fatal("expected that input would be accepted immediately, sink should be empty")
		}

		rUC = consumeUCs(cms[0], 100*time.Millisecond)
		require.Equal(t, ucs, rUC)
		outputMustBeEmpty(t, cms[0])
	})

	t.Run("overwriting unconsumed QC", func(t *testing.T) {
		cms, _ := createConsensusManagers(t, 1, nil)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { require.ErrorIs(t, cms[0].sendCertificates(ctx), context.Canceled) }()

		// exp - expected result in the end of test, we add/overwrite certs as we send them
		exp := map[types.PartitionShardID]*certification.CertificationResponse{}

		ucs := makeUCs(1, 2)
		for k, v := range ucs {
			exp[k] = v
		}

		select {
		case cms[0].ucSink <- slices.Collect(maps.Values(ucs)):
		default:
			t.Fatal("expected that input would be accepted immediately, sink should be empty")
		}

		// as we haven't consumed anything sending new set of certs into the sink should
		// overwrite {0,0,0,2} and add {0,0,0,3}
		ucs = makeUCs(3, 2)
		for k, v := range ucs {
			exp[k] = v
		}

		select {
		case cms[0].ucSink <- slices.Collect(maps.Values(ucs)):
		case <-time.After(100 * time.Millisecond):
			t.Error("next input hasn't been consumed fast enough")
		}

		rUC := consumeUCs(cms[0], 100*time.Millisecond)
		require.Len(t, rUC, 3, "number of different partition identifiers")
		require.Equal(t, exp, rUC)
		outputMustBeEmpty(t, cms[0])
	})

	t.Run("adding without overwriting", func(t *testing.T) {
		cms, _ := createConsensusManagers(t, 1, nil)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { require.ErrorIs(t, cms[0].sendCertificates(ctx), context.Canceled) }()
		// exp - expected result in the end of test, we add/overwrite certs as we send them
		exp := map[types.PartitionShardID]*certification.CertificationResponse{}

		ucs := makeUCs(1, 2)
		for k, v := range ucs {
			exp[k] = v
		}

		select {
		case cms[0].ucSink <- slices.Collect(maps.Values(ucs)):
		default:
			t.Fatal("expected that input would be accepted immediately, sink should be empty")
		}

		// send another set of certs, unique sysIDs, ie no overwrites, just add (nothing
		// has been consumed yet)
		ucs = makeUCs(3, types.PartitionID(4))
		for k, v := range ucs {
			exp[k] = v
		}

		select {
		case cms[0].ucSink <- slices.Collect(maps.Values(ucs)):
		case <-time.After(100 * time.Millisecond):
			t.Error("next input hasn't been consumed fast enough")
		}

		rUC := consumeUCs(cms[0], 100*time.Millisecond)
		require.Len(t, rUC, 4, "number of different partition identifiers")
		require.Equal(t, exp, rUC)
		outputMustBeEmpty(t, cms[0])
	})

	t.Run("concurrency", func(t *testing.T) {
		// concurrent read and writes to trip race detector
		cms, _ := createConsensusManagers(t, 1, nil)
		done := make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			defer close(done)
			require.ErrorIs(t, cms[0].sendCertificates(ctx), context.Canceled)
		}()

		go func() {
			for {
				select {
				case cms[0].ucSink <- slices.Collect(maps.Values(makeUCs(1, 2, 3))):
				case <-ctx.Done():
					return
				}
			}
		}()

		go func() {
			for {
				select {
				case <-cms[0].CertificationResult():
				case <-ctx.Done():
					return
				}
			}
		}()

		time.Sleep(time.Second)
		cancel()
		<-done
	})
}

func Test_selectRandomNodeIdsFromSignatureMap(t *testing.T) {
	t.Parallel()

	// generate some valid peer IDs for tests to use
	peerIDs := make(peer.IDSlice, 3)
	for i := range peerIDs {
		_, publicKey, err := p2pcrypto.GenerateSecp256k1Key(rand.Reader)
		require.NoError(t, err)
		pubKeyBytes, err := publicKey.Raw()
		require.NoError(t, err)
		peerIDs[i], err = network.NodeIDFromPublicKeyBytes(pubKeyBytes)
		require.NoError(t, err)
	}
	idA, idB, idC := peerIDs[0], peerIDs[1], peerIDs[2]

	t.Run("empty inputs", func(t *testing.T) {
		nodes := selectRandomNodeIdsFromSignatureMap(nil, 2)
		require.Empty(t, nodes)

		nodes = selectRandomNodeIdsFromSignatureMap(map[string]hex.Bytes{}, 2)
		require.Empty(t, nodes)
	})

	t.Run("no duplicates added", func(t *testing.T) {
		nodes := selectRandomNodeIdsFromSignatureMap(map[string]hex.Bytes{idA.String(): nil}, 2)
		require.ElementsMatch(t, []peer.ID{idA}, nodes)

		nodes = selectRandomNodeIdsFromSignatureMap(map[string]hex.Bytes{idA.String(): nil, idB.String(): nil}, 2)
		require.ElementsMatch(t, []peer.ID{idA, idB}, nodes)

		nodes = selectRandomNodeIdsFromSignatureMap(map[string]hex.Bytes{idA.String(): nil, idB.String(): nil}, 3)
		require.ElementsMatch(t, []peer.ID{idA, idB}, nodes)
	})

	t.Run("invalid IDs are ignored", func(t *testing.T) {
		nodes := selectRandomNodeIdsFromSignatureMap(map[string]hex.Bytes{"foo bar": nil}, 1)
		require.Empty(t, nodes)

		nodes = selectRandomNodeIdsFromSignatureMap(map[string]hex.Bytes{"foo bar": nil, idB.String(): nil}, 2)
		require.ElementsMatch(t, []peer.ID{idB}, nodes)
	})

	t.Run("max count items is returned", func(t *testing.T) {
		inp := map[string]hex.Bytes{idA.String(): nil, idB.String(): nil, idC.String(): nil}

		nodes := selectRandomNodeIdsFromSignatureMap(inp, 1)
		require.Len(t, nodes, 1)

		nodes = selectRandomNodeIdsFromSignatureMap(inp, 2)
		require.Len(t, nodes, 2)
		require.NotEqual(t, nodes[0], nodes[1])
	})
}

func Test_rootNetworkRunning(t *testing.T) {
	t.Parallel()
	// this test is mostly useful for debugging - modify conditions in the test,
	// launch the test and observe logs...

	// for quorum, we need 2/3+1 validators (root nodes) to be healthy
	const rootNodeCnt = 4
	// destination round - until which round (minimum) the test should run. test stops as soon as
	// one node is in that round so last round might be "incomplete". System starts with round 2.
	const destRound = 10

	// consumeUC acts as a validator node consuming the UC-s generated by CM (until ctx is cancelled).
	// strictly speaking not needed as current implementation should continue working even when there
	// is no-one consuming UCs.
	consumeUC := func(ctx context.Context, cm *ConsensusManager) {
		for {
			select {
			case <-ctx.Done():
				return
			case uc := <-cm.certResultCh:
				t.Logf("%s UC for round %d sent to validator", cm.id.ShortString(), uc.UC.GetRoundNumber())
			}
		}
	}

	cms, rootNet := createConsensusManagers(t, rootNodeCnt, nil)

	var totalMsgCnt atomic.Uint32
	rootNet.SetFirewall(func(from, to peer.ID, msg any) bool {
		msgCnt := totalMsgCnt.Add(1)
		block := msgCnt%200 == 0 // drop every n-th message from the network
		t.Logf("%t # %s -> %s : %T", block, from.ShortString(), to.ShortString(), msg)
		return block
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	start := time.Now()
	go func() {
		wg := sync.WaitGroup{}
		wg.Add(len(cms))
		for _, v := range cms {
			go func(cm *ConsensusManager) {
				defer wg.Done()
				require.ErrorIs(t, cm.Run(ctx), context.Canceled)
			}(v)
			go func(cm *ConsensusManager) { consumeUC(ctx, cm) }(v)
		}
		wg.Wait()
		close(done)
	}()
	cm := cms[0]
	// assume rounds are successful and each round takes between minRoundLen and roundTimeout on average
	maxTestDuration := destRound * (cm.pacemaker.minRoundLen + (cm.pacemaker.maxRoundLen-cm.pacemaker.minRoundLen)/2)
	require.Eventually(t, func() bool { return cm.pacemaker.GetCurrentRound() >= destRound }, maxTestDuration, 100*time.Millisecond, "waiting for round %d to be achieved", destRound)
	stop := time.Now()
	cancel()
	// when calculating expected message counts keep in mind that last round might not be complete
	// ie the test ended before all nodes had a chance to post their message. so use -1 rounds!
	// and we start from round 2 so that's another -1 completed rounds.
	completeRounds := cm.pacemaker.GetCurrentRound() - 2
	avgRoundLen := time.Duration(int64(stop.Sub(start)) / int64(completeRounds))

	// output some statistics
	t.Logf("total msg count: %d during %s", totalMsgCnt.Load(), stop.Sub(start))

	// check some expectations
	// we expect to see proposal + vote per node per round. when some round timeouts msg count is higher!
	require.GreaterOrEqual(t, totalMsgCnt.Load(), uint32(completeRounds*rootNodeCnt*2), "total number of messages in the network")
	// average round duration should be between minRoundLen and maxRoundLen (aka timeout)
	// potentially flaky as there is delay between starting CMs and starting the clock!
	require.GreaterOrEqual(t, avgRoundLen, cm.pacemaker.minRoundLen, "minimum round duration for %d rounds", completeRounds)
	require.GreaterOrEqual(t, cm.pacemaker.maxRoundLen, avgRoundLen, "maximum round duration for %d rounds", completeRounds)
	// wait for cm routine to exit, otherwise logger may be destructed before last usage
	select {
	case <-time.After(1000 * time.Millisecond):
		t.Fatal("consensus managers did not exit in time")
	case <-done:
	}
}

func Test_ConsensusManager_RestoreVote(t *testing.T) {
	// Make timeout 10x shorter
	consensusParams := NewConsensusParams()
	consensusParams.BlockRate /= 10
	consensusParams.LocalTimeout /= 10

	mockNet := testnetwork.NewRootMockNetwork()
	cm, _, _ := initConsensusManager(t, mockNet, WithConsensusParams(*consensusParams))

	timeoutVote := &abdrc.TimeoutMsg{
		Timeout: &drctypes.Timeout{Round: 2},
		Author:  "test",
		LastTC: &drctypes.TimeoutCert{
			Timeout: &drctypes.Timeout{Round: 1},
		},
	}
	// store timeout vote to DB
	require.NoError(t, cm.blockStore.GetDB().WriteVote(timeoutVote))

	// replace leader selector
	allNodes := cm.Validators()
	leaderId, err := p2ptest.RandPeerID()
	require.NoError(t, err)
	allNodes = append(allNodes, leaderId)
	cm.leaderSelector = constLeader{leader: leaderId, nodes: allNodes}
	require.NoError(t, err)
	require.NotNil(t, cm)
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	go func() { require.ErrorIs(t, cm.Run(ctx), context.Canceled) }()
	lastTimeoutMsg := testutils.MockAwaitMessage[*abdrc.TimeoutMsg](t, mockNet, network.ProtocolRootTimeout)
	require.NotNil(t, lastTimeoutMsg)
	// make sure the stored timeout vote is broadcast
	require.EqualValues(t, 2, lastTimeoutMsg.Timeout.Round)
	require.EqualValues(t, "test", lastTimeoutMsg.Author)
	require.EqualValues(t, 1, lastTimeoutMsg.LastTC.GetRound())
}

/*
Round can get both QC and TC and timeout message can carry both of them (HighQc: QC(N),
LastTC: TC(N)) - the block certified by the high QC must stay in the block tree when the
TC is processed after the QC as the next proposal extends that block.
*/
func Test_ConsensusManager_tcForCertifiedBlock(t *testing.T) {
	cm, _, shardNodes := initConsensusManager(t, testnetwork.NewRootMockNetwork())
	bs := cm.blockStore
	req := &drctypes.IRChangeReq{
		Partition:  partitionID,
		Shard:      shardID,
		CertReason: drctypes.Quorum,
		Requests:   buildBlockCertificationRequest(t, shardNodes[0:2], bs.ShardInfo(partitionID, shardID).LastCR),
	}
	// B1 (root) --> B2 --> B3, B3 changes the shard
	rh2, err := bs.Add(&drctypes.BlockData{Round: 2, Payload: &drctypes.Payload{}, Qc: bs.GetHighQc()}, cm.irReqVerifier)
	require.NoError(t, err)
	qc2 := testQC(2, 1, rh2)
	_, err = bs.ProcessQc(qc2)
	require.NoError(t, err)
	rh3, err := bs.Add(&drctypes.BlockData{Round: 3, Payload: &drctypes.Payload{Requests: []*drctypes.IRChangeReq{req}}, Qc: qc2}, cm.irReqVerifier)
	require.NoError(t, err)
	qc3 := testQC(3, 2, rh3)

	// what onTimeoutMsg does for a round 4 timeout message {HighQc: QC(3), LastTC: TC(3)}
	_, err = bs.ProcessQc(qc3)
	require.NoError(t, err)
	require.NoError(t, bs.ProcessTc(&drctypes.TimeoutCert{Timeout: &drctypes.Timeout{Round: 3, HighQc: qc2}}))

	// B3 is still in the tree, ie the shard has change in progress and peers can recover to the round
	require.EqualValues(t, 3, bs.GetHighQc().GetRound())
	require.NotNil(t, bs.IsChangeInProgress(3, partitionID, shardID))
	state, err := bs.GetState()
	require.NoError(t, err)
	require.NoError(t, state.CanRecoverToRound(3))

	// as leader the node does not propose the change again and the proposal is accepted
	require.NoError(t, cm.irReqBuffer.Add(4, req, cm.irReqVerifier))
	payload := cm.irReqBuffer.GeneratePayload(5, nil, func(partition types.PartitionID, shard types.ShardID) *types.InputRecord {
		return bs.IsChangeInProgress(3, partition, shard)
	})
	require.Empty(t, payload.Requests)
	_, err = bs.Add(&drctypes.BlockData{Round: 5, Payload: payload, Qc: qc3}, cm.irReqVerifier)
	require.NoError(t, err)
}

/*
The block of a round which got TC stays in the block tree but the changes in it must not be
in the way of the chain continuing from the previous round: the same shard can be changed in
the block which extends the previous round.
*/
func Test_ConsensusManager_changeInTimeoutBlock(t *testing.T) {
	cm, _, shardNodes := initConsensusManager(t, testnetwork.NewRootMockNetwork())
	bs := cm.blockStore
	req := &drctypes.IRChangeReq{
		Partition:  partitionID,
		Shard:      shardID,
		CertReason: drctypes.Quorum,
		Requests:   buildBlockCertificationRequest(t, shardNodes[0:2], bs.ShardInfo(partitionID, shardID).LastCR),
	}
	inProgress := func(branch uint64) InProgressFn {
		return func(partition types.PartitionID, shard types.ShardID) *types.InputRecord {
			return bs.IsChangeInProgress(branch, partition, shard)
		}
	}
	// B1 (root) --> B2 --> B3, B3 changes the shard and the round gets TC
	rh2, err := bs.Add(&drctypes.BlockData{Round: 2, Payload: &drctypes.Payload{}, Qc: bs.GetHighQc()}, cm.irReqVerifier)
	require.NoError(t, err)
	qc2 := testQC(2, 1, rh2)
	_, err = bs.ProcessQc(qc2)
	require.NoError(t, err)
	rh3, err := bs.Add(&drctypes.BlockData{Round: 3, Payload: &drctypes.Payload{Requests: []*drctypes.IRChangeReq{req}}, Qc: qc2}, cm.irReqVerifier)
	require.NoError(t, err)
	require.NoError(t, bs.ProcessTc(&drctypes.TimeoutCert{Timeout: &drctypes.Timeout{Round: 3, HighQc: qc2}}))
	require.EqualValues(t, 2, bs.GetHighQc().GetRound())

	// the shard has not timed out yet but the change in B3 is not the reason
	tmo, err := cm.t2Timeouts.GetT2Timeouts(4, 2)
	require.NoError(t, err)
	require.Empty(t, tmo)
	require.Nil(t, bs.IsChangeInProgress(2, partitionID, shardID))

	// leader of the round 4 extends B2 and can propose the change again
	require.NoError(t, cm.irReqBuffer.Add(4, req, cm.irReqVerifier))
	payload := cm.irReqBuffer.GeneratePayload(4, nil, inProgress(2))
	require.Equal(t, []*drctypes.IRChangeReq{req}, payload.Requests)
	// block which extends B3 (ie leader has QC for the round 3) can't contain the change...
	qc3 := testQC(3, 2, rh3)
	_, err = bs.Add(&drctypes.BlockData{Round: 4, Payload: payload, Qc: qc3}, cm.irReqVerifier)
	require.ErrorIs(t, err, ErrDuplicateChangeReq)
	// ...but the one which extends B2 can
	rh4, err := bs.Add(&drctypes.BlockData{Round: 4, Payload: payload, Qc: qc2}, cm.irReqVerifier)
	require.NoError(t, err)
	require.NotNil(t, bs.IsChangeInProgress(4, partitionID, shardID))

	// a peer can recover from the state with both branches (what onStateResponse does with the state message)
	state, err := bs.GetState()
	require.NoError(t, err)
	require.ElementsMatch(t, []uint64{2, 3, 4}, pendingRounds(state))
	slices.SortFunc(state.Pending, func(a, b *drctypes.BlockData) int { return cmp.Compare(a.GetRound(), b.GetRound()) })
	db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "peer.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	peerStore, err := storage.NewFromState(cm.params.HashAlgorithm, state.CommittedHead, db, cm.orchestration, cm.log)
	require.NoError(t, err)
	peerVerifier, err := NewIRChangeReqVerifier(cm.params, peerStore)
	require.NoError(t, err)
	for _, block := range state.Pending {
		_, err = peerStore.ProcessQc(block.Qc)
		require.NoError(t, err)
		_, err = peerStore.Add(block, peerVerifier)
		require.NoError(t, err, "adding block of the round %d", block.GetRound())
	}
	for _, round := range []uint64{3, 4} {
		require.NotNil(t, peerStore.IsChangeInProgress(round, partitionID, shardID))
	}

	// B2 --> B3
	//  ╰--> B4 --> B5: QC for the round 5 commits B4 and the shard gets certificate
	qc4 := testQC(4, 2, rh4)
	_, err = bs.ProcessQc(qc4)
	require.NoError(t, err)
	// late copy of the request is buffered but not proposed again in this branch
	require.NoError(t, cm.irReqBuffer.Add(5, req, cm.irReqVerifier))
	payload = cm.irReqBuffer.GeneratePayload(5, nil, inProgress(4))
	require.Empty(t, payload.Requests)
	rh5, err := bs.Add(&drctypes.BlockData{Round: 5, Payload: payload, Qc: qc4}, cm.irReqVerifier)
	require.NoError(t, err)
	qc5 := testQC(5, 4, rh5)
	qc5.LedgerCommitInfo.RootChainRoundNumber = 4
	qc5.LedgerCommitInfo.Hash = rh4
	crs, err := bs.ProcessQc(qc5)
	require.NoError(t, err)
	require.Len(t, crs, 1)
	require.Equal(t, req.Requests[0].InputRecord, crs[0].UC.InputRecord)
	_, err = bs.Block(3)
	require.Error(t, err, "block of the losing branch should be pruned")
}

/*
A certified block can end up in a losing branch too: QC(3) is known only to a minority, so
TC(4) carries high QC of the round 2 and the leader of the round 5 extends B2.

	B2 --> B3 (changes the shard, certified) --> B4 (timed out)
	 ╰--> B5 --> B6

The change in B3 is not in the way of changing the shard in the branch of B5.
NB! This is where the validity rule differs from the one where all the uncommitted blocks were
checked (B6 was not valid), see docs/upgrade.md.
*/
func Test_ConsensusManager_changeInCertifiedBlockOfOtherBranch(t *testing.T) {
	cm, _, shardNodes := initConsensusManager(t, testnetwork.NewRootMockNetwork())
	bs := cm.blockStore
	req := &drctypes.IRChangeReq{
		Partition:  partitionID,
		Shard:      shardID,
		CertReason: drctypes.Quorum,
		Requests:   buildBlockCertificationRequest(t, shardNodes[0:2], bs.ShardInfo(partitionID, shardID).LastCR),
	}
	rh2, err := bs.Add(&drctypes.BlockData{Round: 2, Payload: &drctypes.Payload{}, Qc: bs.GetHighQc()}, cm.irReqVerifier)
	require.NoError(t, err)
	qc2 := testQC(2, 1, rh2)
	_, err = bs.ProcessQc(qc2)
	require.NoError(t, err)
	rh3, err := bs.Add(&drctypes.BlockData{Round: 3, Payload: &drctypes.Payload{Requests: []*drctypes.IRChangeReq{req}}, Qc: qc2}, cm.irReqVerifier)
	require.NoError(t, err)
	qc3 := testQC(3, 2, rh3)
	_, err = bs.ProcessQc(qc3)
	require.NoError(t, err)
	_, err = bs.Add(&drctypes.BlockData{Round: 4, Payload: &drctypes.Payload{}, Qc: qc3}, cm.irReqVerifier)
	require.NoError(t, err)
	require.NoError(t, bs.ProcessTc(&drctypes.TimeoutCert{Timeout: &drctypes.Timeout{Round: 4, HighQc: qc2}}))

	// the request arrives (again) while the high QC is still QC(3), ie the change is in progress in the
	// branch the next proposal is expected to extend - it is buffered anyway
	require.EqualValues(t, 3, bs.GetHighQc().GetRound())
	require.NoError(t, cm.irReqBuffer.Add(5, req, cm.irReqVerifier))

	rh5, err := bs.Add(&drctypes.BlockData{Round: 5, Payload: &drctypes.Payload{}, Qc: qc2}, cm.irReqVerifier)
	require.NoError(t, err)
	qc5 := testQC(5, 2, rh5)
	_, err = bs.ProcessQc(qc5)
	require.NoError(t, err)

	// leader of the round 6 proposes the buffered request on QC(5) and the block is accepted
	payload := cm.irReqBuffer.GeneratePayload(6, nil, func(p types.PartitionID, s types.ShardID) *types.InputRecord {
		return bs.IsChangeInProgress(bs.GetHighQc().GetRound(), p, s)
	})
	require.Equal(t, []*drctypes.IRChangeReq{req}, payload.Requests)
	_, err = bs.Add(&drctypes.BlockData{Round: 6, Payload: payload, Qc: qc5}, cm.irReqVerifier)
	require.NoError(t, err)
	// state sent to recovering peers carries both branches
	state, err := bs.GetState()
	require.NoError(t, err)
	require.ElementsMatch(t, []uint64{2, 3, 4, 5, 6}, pendingRounds(state))
}

/*
The change request of a shard arrives again to the next leader during the round whose QC commits
the block with the change of the shard:

	B3 (changes the shard) --> B4, QC(4) commits B3

The request is buffered (the change is not committed yet) but it is stale by the time the proposal
is made and there is no change in progress anymore. The leader must not propose it as the block
would be rejected by all the validators and the round would time out.
*/
func Test_ConsensusManager_staleRequestAfterCommit(t *testing.T) {
	mockNet := testnetwork.NewRootMockNetwork()
	cm, rootNode, shardNodes := initConsensusManager(t, mockNet)
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()
	go func() { require.ErrorIs(t, cm.Run(ctx), context.Canceled) }()

	si, err := cm.ShardInfo(partitionID, shardID)
	require.NoError(t, err)
	irChReqMsg := &abdrc.IrChangeReqMsg{
		Author: rootNode.PeerConf.ID.String(),
		IrChangeReq: &drctypes.IRChangeReq{
			Partition:  partitionID,
			CertReason: drctypes.Quorum,
			Requests:   buildBlockCertificationRequest(t, shardNodes[0:2], si.LastCR),
		},
	}
	require.NoError(t, irChReqMsg.Sign(rootNode.Signer))

	// round 2, request is buffered -> proposal 3 changes the shard
	prop := testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
	mockNet.WaitReceive(t, prop)
	mockNet.WaitReceive(t, irChReqMsg)
	vote := testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
	mockNet.WaitReceive(t, vote)
	prop = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
	require.EqualValues(t, 3, prop.Block.Round)
	require.Len(t, prop.Block.Payload.Requests, 1)

	// round 3 -> proposal 4
	mockNet.WaitReceive(t, prop)
	vote = testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
	mockNet.WaitReceive(t, vote)
	prop = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
	require.EqualValues(t, 4, prop.Block.Round)

	// round 4: the block 3 is not committed yet, the same request arrives again
	mockNet.WaitReceive(t, prop)
	vote = testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
	mockNet.WaitReceive(t, irChReqMsg)
	// QC(4) commits the block 3
	mockNet.WaitReceive(t, vote)
	prop = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
	require.EqualValues(t, 5, prop.Block.Round)
	require.EqualValues(t, 3, cm.blockStore.GetHighQc().GetCommitRound())
	require.Empty(t, prop.Block.Payload.Requests, "stale request must not be proposed")

	// the proposal is valid, the node votes for it
	mockNet.WaitReceive(t, prop)
	vote = testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
	require.EqualValues(t, 5, vote.VoteInfo.RoundNumber)
}

/*
The next leader buffers the change request of a shard but doesn't make a proposal (it skipped its
leader round) before a block of another leader with the same change gets committed:

	B2 (changes the shard) --> B3, QC(3) commits B2

The buffered request is stale and must not block the next request of the shard (it used to be
rejected as equivocating until the node made a proposal and the buffer was cleared).
*/
func Test_ConsensusManager_staleRequestInBuffer(t *testing.T) {
	for _, pending := range []bool{false, true} {
		name := "request buffered before the block with the change"
		if pending {
			name = "request buffered while the block with the change is pending"
		}
		t.Run(name, func(t *testing.T) {
			cm, _, shardNodes := initConsensusManager(t, testnetwork.NewRootMockNetwork())
			bs := cm.blockStore
			req := &drctypes.IRChangeReq{
				Partition:  partitionID,
				Shard:      shardID,
				CertReason: drctypes.Quorum,
				Requests:   buildBlockCertificationRequest(t, shardNodes[0:2], bs.ShardInfo(partitionID, shardID).LastCR),
			}
			if !pending {
				require.NoError(t, cm.irReqBuffer.Add(2, req, cm.irReqVerifier))
			}
			rh2, err := bs.Add(&drctypes.BlockData{Round: 2, Payload: &drctypes.Payload{Requests: []*drctypes.IRChangeReq{req}}, Qc: bs.GetHighQc()}, cm.irReqVerifier)
			require.NoError(t, err)
			qc2 := testQC(2, 1, rh2)
			_, err = bs.ProcessQc(qc2)
			require.NoError(t, err)
			rh3, err := bs.Add(&drctypes.BlockData{Round: 3, Payload: &drctypes.Payload{}, Qc: qc2}, cm.irReqVerifier)
			require.NoError(t, err)
			if pending {
				require.NoError(t, cm.irReqBuffer.Add(3, req, cm.irReqVerifier))
			}
			qc3 := testQC(3, 2, rh3)
			qc3.LedgerCommitInfo.RootChainRoundNumber = 2
			qc3.LedgerCommitInfo.Hash = rh2
			qc3.LedgerCommitInfo.Timestamp = types.NewTimestamp()
			ucs, err := bs.ProcessQc(qc3)
			require.NoError(t, err)
			require.Len(t, ucs, 1)

			// next request of the shard, extends the state certified by the commit of B2
			si := bs.ShardInfo(partitionID, shardID)
			ir := &types.InputRecord{
				Version:      1,
				PreviousHash: si.RootHash,
				Hash:         test.RandomBytes(32),
				BlockHash:    test.RandomBytes(32),
				SummaryValue: []byte{2, 3, 4},
				RoundNumber:  si.LastCR.Technical.Round,
				Epoch:        si.LastCR.Technical.Epoch,
				Timestamp:    si.LastCR.UC.UnicitySeal.Timestamp,
			}
			var bcrs []*certification.BlockCertificationRequest
			for _, n := range shardNodes[0:2] {
				bcrs = append(bcrs, testutils.CreateBlockCertificationRequest(t, ir, partitionID, n))
			}
			nextReq := &drctypes.IRChangeReq{Partition: partitionID, Shard: shardID, CertReason: drctypes.Quorum, Requests: bcrs}
			require.NoError(t, cm.irReqBuffer.Add(4, nextReq, cm.irReqVerifier))

			payload := cm.irReqBuffer.GeneratePayload(4, nil, func(p types.PartitionID, s types.ShardID) *types.InputRecord {
				return bs.IsChangeInProgress(bs.GetHighQc().GetRound(), p, s)
			})
			require.Equal(t, []*drctypes.IRChangeReq{nextReq}, payload.Requests)
			_, err = bs.Add(&drctypes.BlockData{Round: 4, Payload: payload, Qc: qc3}, cm.irReqVerifier)
			require.NoError(t, err)
		})
	}
}

/*
Recovery from a state where the block of the high QC has no child yet and its QC doesn't commit
anything (the block doesn't extend the QC of the previous round):

	B2 --> (round 3 times out)
	 ╰--> B4 (extends QC(2) with TC(3)), QC(4)

The state message carries B4 but not QC(4), which is not the commit QC of any block either. The QC
carried by the message which triggered the recovery must be processed after the recovery,
otherwise the high QC of the node stays behind.
*/
func Test_ConsensusManager_recoveryRestoresHighQc(t *testing.T) {
	// returns stopped CM with the tree above, its state and QC(4)
	setup := func(t *testing.T) (*ConsensusManager, *abdrc.StateMsg, *drctypes.QuorumCert, string) {
		mockNet := testnetwork.NewRootMockNetwork()
		cm, rootNode, _ := initConsensusManager(t, mockNet)
		ctx, ctxCancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { require.ErrorIs(t, cm.Run(ctx), context.Canceled); close(done) }()

		prop := testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
		mockNet.WaitReceive(t, prop)
		vote := testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
		mockNet.WaitReceive(t, vote)
		// QC(2), proposal 3 is not delivered and the round times out
		prop = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
		require.EqualValues(t, 3, prop.Block.Round)
		// simulate local timeout by calling the method -> race/hack accessing from different go routines not safe
		cm.onLocalTimeout(ctx)
		tmo := testutils.MockAwaitMessage[*abdrc.TimeoutMsg](t, mockNet, network.ProtocolRootTimeout)
		mockNet.WaitReceive(t, tmo)
		// TC(3) -> proposal 4 extends QC(2)
		prop = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
		require.EqualValues(t, 4, prop.Block.Round)
		require.EqualValues(t, 2, prop.Block.Qc.GetRound())
		mockNet.WaitReceive(t, prop)
		vote = testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
		mockNet.WaitReceive(t, vote)
		// QC(4), proposal 5 is not delivered so B4 has no child
		prop = testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
		require.EqualValues(t, 5, prop.Block.Round)
		ctxCancel()
		<-done

		qc4 := cm.blockStore.GetHighQc()
		require.EqualValues(t, 4, qc4.GetRound())
		require.Zero(t, qc4.LedgerCommitInfo.RootChainRoundNumber, "QC(4) doesn't commit")
		state, err := cm.blockStore.GetState()
		require.NoError(t, err)
		require.Less(t, state.CommittedHead.CommitQc.GetRound(), qc4.GetRound())
		for _, b := range state.Pending {
			require.Less(t, b.Qc.GetRound(), qc4.GetRound(), "state doesn't carry QC(4)")
		}
		return cm, state, qc4, rootNode.PeerConf.ID.String()
	}
	// recover from the state, replaces the block store
	recoverFrom := func(t *testing.T, cm *ConsensusManager, state *abdrc.StateMsg, trigger any) {
		ctx, ctxCancel := context.WithCancel(context.Background())
		defer ctxCancel()
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-cm.ucSink:
				}
			}
		}()
		cm.recovery = &recoveryState{}
		_, err := cm.recovery.Set(trigger)
		require.NoError(t, err)
		require.NoError(t, cm.onStateResponse(ctx, state))
		require.False(t, cm.recovery.InRecovery())
	}

	t.Run("triggered by timeout vote", func(t *testing.T) {
		cm, state, qc4, author := setup(t)
		recoverFrom(t, cm, state, &abdrc.TimeoutMsg{
			Author:  author,
			Timeout: drctypes.NewTimeout(5, cm.trustBase.Load().Epoch, qc4),
		})
		require.EqualValues(t, 4, cm.blockStore.GetHighQc().GetRound())
		require.EqualValues(t, 5, cm.pacemaker.GetCurrentRound())
	})

	t.Run("triggered by QC", func(t *testing.T) {
		cm, state, qc4, _ := setup(t)
		recoverFrom(t, cm, state, qc4)
		require.EqualValues(t, 4, cm.blockStore.GetHighQc().GetRound())
		require.EqualValues(t, 5, cm.pacemaker.GetCurrentRound())
	})

	t.Run("triggered by vote", func(t *testing.T) {
		cm, state, qc4, author := setup(t)
		recoverFrom(t, cm, state, &abdrc.VoteMsg{
			Author:   author,
			VoteInfo: &drctypes.RoundInfo{RoundNumber: 5, ParentRoundNumber: 4, Epoch: qc4.VoteInfo.Epoch},
			HighQc:   qc4,
		})
		require.EqualValues(t, 4, cm.blockStore.GetHighQc().GetRound())
		require.EqualValues(t, 5, cm.pacemaker.GetCurrentRound())
	})
}

func testQC(round, parent uint64, rootHash []byte) *drctypes.QuorumCert {
	return &drctypes.QuorumCert{
		VoteInfo:         &drctypes.RoundInfo{RoundNumber: round, ParentRoundNumber: parent, CurrentRootHash: rootHash},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1},
	}
}
