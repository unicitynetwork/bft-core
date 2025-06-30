package blockproposal

import (
	gocrypto "crypto"
	"errors"
	"fmt"

	"github.com/alphabill-org/alphabill-go-base/crypto"
	abhash "github.com/alphabill-org/alphabill-go-base/hash"
	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/alphabill-org/alphabill/network/protocol/certification"
	"github.com/libp2p/go-libp2p/core/peer"
)

var (
	ErrBlockProposalIsNil     = errors.New("block proposal is nil")
	ErrShardConfIsNil         = errors.New("shard conf is nil")
	ErrTrustBaseIsNil         = errors.New("trust base is nil")
	ErrSignerIsNil            = errors.New("signer is nil")
	ErrNodeVerifierIsNil      = errors.New("node signature verifier is nil")
	ErrInvalidPartitionID     = errors.New("invalid partition identifier")
	ErrInvalidShardID         = errors.New("invalid shard identifier")
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

func (x *BlockProposal) IsValid(trustBase types.RootTrustBase, shardConf *types.PartitionDescriptionRecord, hashAlg gocrypto.Hash) error {
	if x == nil {
		return ErrBlockProposalIsNil
	}
	if shardConf == nil {
		return ErrShardConfIsNil
	}
	if trustBase == nil {
		return ErrTrustBaseIsNil
	}
	if shardConf.PartitionID != x.PartitionID {
		return fmt.Errorf("%w, expected %s, got %s", ErrInvalidPartitionID, shardConf.PartitionID, x.PartitionID)
	}
	if !shardConf.ShardID.Equal(x.ShardID) {
		return fmt.Errorf("%w, expected %s, got %s", ErrInvalidShardID, shardConf.ShardID, x.ShardID)
	}
	if len(x.NodeID) == 0 {
		return errBlockProposerIDMissing
	}
	proposer := shardConf.FindValidator(x.NodeID.String())
	if proposer == nil {
		return fmt.Errorf("block proposal from unknown validator %s", x.NodeID)
	}
	sigVerifier, err := proposer.SigVerifier()
	if err != nil {
		return fmt.Errorf("failed to get block proposer signature verifier: %w", err)
	}
	if err := x.UnicityCertificate.Verify(trustBase, hashAlg, shardConf.PartitionID, shardConf.ShardID, nil); err != nil {
		return err
	}
	if err := x.Technical.IsValid(); err != nil {
		return fmt.Errorf("invalid TechnicalRecord: %w", err)
	}
	if err := x.Technical.HashMatches(x.UnicityCertificate.TRHash); err != nil {
		return fmt.Errorf("comparing TechnicalRecord hash to UC.TRHash: %w", err)
	}
	return x.Verify(hashAlg, sigVerifier)
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
