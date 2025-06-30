package network

import (
	"time"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
)

const (
	ProtocolRootIrChangeReq = "/ab/root-change-req/0.0.1"
	ProtocolRootProposal    = "/ab/root-proposal/0.0.1"
	ProtocolRootVote        = "/ab/root-vote/0.0.1"
	ProtocolRootTimeout     = "/ab/root-timeout/0.0.1"
	ProtocolRootStateReq    = "/ab/root-state-req/0.0.1"
	ProtocolRootStateResp   = "/ab/root-state-resp/0.0.1"
)

func NewLibP2RootConsensusNetwork(self *Peer, capacity uint, sendTimeout time.Duration, obs Observability) (*LibP2PNetwork, error) {
	n, err := NewLibP2PNetwork(self, capacity, obs)
	if err != nil {
		return nil, err
	}
	sendProtocolDescriptions := []SendProtocolDescription{
		{ProtocolID: ProtocolRootIrChangeReq, Timeout: sendTimeout, MsgType: abdrc.IrChangeReqMsg{}},
		{ProtocolID: ProtocolRootProposal, Timeout: sendTimeout, MsgType: abdrc.ProposalMsg{}},
		{ProtocolID: ProtocolRootVote, Timeout: sendTimeout, MsgType: abdrc.VoteMsg{}},
		{ProtocolID: ProtocolRootTimeout, Timeout: sendTimeout, MsgType: abdrc.TimeoutMsg{}},
		{ProtocolID: ProtocolRootStateReq, Timeout: sendTimeout, MsgType: abdrc.StateRequestMsg{}},
		{ProtocolID: ProtocolRootStateResp, Timeout: sendTimeout, MsgType: abdrc.StateMsg{}},
	}
	if err = n.RegisterSendProtocols(sendProtocolDescriptions); err != nil {
		return nil, err
	}
	receiveProtocolDescriptions := []ReceiveProtocolDescription{
		{
			ProtocolID: ProtocolRootIrChangeReq,
			TypeFn:     func() any { return &abdrc.IrChangeReqMsg{} },
		},
		{
			ProtocolID: ProtocolRootProposal,
			TypeFn:     func() any { return &abdrc.ProposalMsg{} },
		},
		{
			ProtocolID: ProtocolRootVote,
			TypeFn:     func() any { return &abdrc.VoteMsg{} },
		},
		{
			ProtocolID: ProtocolRootTimeout,
			TypeFn:     func() any { return &abdrc.TimeoutMsg{} },
		},
		{
			ProtocolID: ProtocolRootStateReq,
			TypeFn:     func() any { return &abdrc.StateRequestMsg{} },
		},
		{
			ProtocolID: ProtocolRootStateResp,
			TypeFn:     func() any { return &abdrc.StateMsg{} },
		},
	}
	if err = n.RegisterReceiveProtocols(receiveProtocolDescriptions); err != nil {
		return nil, err
	}
	return n, nil
}
