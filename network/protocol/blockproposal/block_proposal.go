package blockproposal

import (
	gocrypto "crypto"
	"errors"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/crypto"
	abhash "github.com/unicitynetwork/bft-go-base/hash"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	ErrBlockProposalIsNil     = errors.New("block proposal is nil")
	ErrTrustBaseIsNil         = errors.New("trust base is nil")
	ErrSignerIsNil            = errors.New("signer is nil")
	ErrNodeVerifierIsNil      = errors.New("node signature verifier is nil")
	ErrInvalidPartitionID     = errors.New("invalid partition identifier")
	errBlockProposerIDMissing = errors.New("block proposer id is missing")
)

type BlockProposal struct {
	_                  struct{} `cbor:",toarray"`
	PartitionID        types.PartitionID
	ShardID            types.ShardID
	NodeID             peer.ID
	UnicityCertificate *types.UnicityCertificate
	Technical          certification.TechnicalRecord
	Transactions       []*types.TransactionRecord
	Signature          []byte
}

func (x *BlockProposal) IsValid(nodeSignatureVerifier crypto.Verifier, tb types.RootTrustBase, algorithm gocrypto.Hash, partitionID types.PartitionID, shardConfHash []byte) error {
	if x == nil {
		return ErrBlockProposalIsNil
	}
	if nodeSignatureVerifier == nil {
		return ErrNodeVerifierIsNil
	}
	if len(x.NodeID) == 0 {
		return errBlockProposerIDMissing
	}
	if tb == nil {
		return ErrTrustBaseIsNil
	}
	if partitionID != x.PartitionID {
		return fmt.Errorf("%w, expected %s, got %s", ErrInvalidPartitionID, partitionID, x.PartitionID)
	}
	if err := x.UnicityCertificate.Verify(tb, algorithm, partitionID, shardConfHash); err != nil {
		return err
	}
	if err := x.Technical.IsValid(); err != nil {
		return fmt.Errorf("invalid TechnicalRecord: %w", err)
	}
	if err := x.Technical.HashMatches(x.UnicityCertificate.TRHash); err != nil {
		return fmt.Errorf("comparing TechnicalRecord hash to UC.TRHash: %w", err)
	}
	return x.Verify(algorithm, nodeSignatureVerifier)
}

func (x *BlockProposal) Hash(algorithm gocrypto.Hash) ([]byte, error) {
	proposal := *x
	hasher := abhash.New(algorithm.New())
	proposal.Signature = nil
	hasher.Write(proposal)
	h, err := hasher.Sum()
	if err != nil {
		return nil, fmt.Errorf("failed to calculate block proposal hash: %w", err)
	}
	return h, nil
}

func (x *BlockProposal) Sign(algorithm gocrypto.Hash, signer crypto.Signer) error {
	if signer == nil {
		return ErrSignerIsNil
	}
	hash, err := x.Hash(algorithm)
	if err != nil {
		return err
	}
	x.Signature, err = signer.SignHash(hash)
	if err != nil {
		return err
	}
	return nil
}

func (x *BlockProposal) Verify(algorithm gocrypto.Hash, nodeSignatureVerifier crypto.Verifier) error {
	if nodeSignatureVerifier == nil {
		return ErrNodeVerifierIsNil
	}
	hash, err := x.Hash(algorithm)
	if err != nil {
		return err
	}
	return nodeSignatureVerifier.VerifyHash(x.Signature, hash)
}
