package consensus

import (
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	Quorum CertReqReason = iota
	QuorumNotPossible
)

type (
	CertReqReason uint8

	IRChangeRequest struct {
		Partition types.PartitionID
		Shard     types.ShardID
		Reason    CertReqReason
		Requests  []*certification.BlockCertificationRequest
	}
)
