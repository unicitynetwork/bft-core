package partition

import (
	gocrypto "crypto"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/network/protocol/blockproposal"
	"github.com/unicitynetwork/bft-go-base/types"
)

type (
	// TransactionOrderValidator is used to validate generic transactions (e.g. timeouts, partition identifiers, etc.). This validator
	// should not contain transaction system specific validation logic.
	TransactionOrderValidator interface {
		Validate(tx *types.TransactionOrder, shardConf *types.PartitionDescriptionRecord, currentRoundNumber uint64) error
	}

	// UnicityCertificateValidator is used to validate certificates.UnicityCertificate.
	UnicityCertificateValidator interface {
		// Validate validates the given UC. Returns an error if UC is not valid.
		Validate(uc *types.UnicityCertificate, shardConf *types.PartitionDescriptionRecord, trustBase types.RootTrustBase) error
	}

	// BlockProposalValidator is used to validate block proposals.
	BlockProposalValidator interface {
		// Validate validates the given blockproposal.BlockProposal. Returns an error if given block proposal
		// is not valid.
		Validate(bp *blockproposal.BlockProposal, shardConf *types.PartitionDescriptionRecord, trustBase types.RootTrustBase) error
	}

	// DefaultUnicityCertificateValidator is a default implementation of UnicityCertificateValidator.
	DefaultUnicityCertificateValidator struct {
		hashAlg gocrypto.Hash
	}

	// DefaultBlockProposalValidator is a default implementation of UnicityCertificateValidator.
	DefaultBlockProposalValidator struct {
		hashAlg gocrypto.Hash
	}

	DefaultTransactionOrderValidator struct {
	}
)

var ErrTxTimeout = errors.New("transaction has timed out")
var errInvalidPartitionID = errors.New("invalid partition identifier")

// NewDefaultTransactionOrderValidator creates a new instance of default TxValidator.
func NewDefaultTransactionOrderValidator() TransactionOrderValidator {
	return &DefaultTransactionOrderValidator{}
}

func (v *DefaultTransactionOrderValidator) Validate(tx *types.TransactionOrder, shardConf *types.PartitionDescriptionRecord, currentRoundNumber uint64) error {
	if tx == nil {
		return errors.New("transaction is nil")
	}
	if shardConf.PartitionID != tx.PartitionID {
		// transaction was not sent to correct transaction system
		return fmt.Errorf("expected partitionID %s, got %s: %w", shardConf.PartitionID, tx.PartitionID, errInvalidPartitionID)
	}
	if tx.Timeout() < currentRoundNumber {
		// transaction is expired
		return fmt.Errorf("transaction timeout round is %d, current round is %d: %w", tx.Timeout(), currentRoundNumber, ErrTxTimeout)
	}

	if n := len(tx.ReferenceNumber()); n > 32 {
		return fmt.Errorf("maximum allowed length of the ReferenceNumber is 32 bytes, got %d bytes", n)
	}

	return nil
}

// NewDefaultUnicityCertificateValidator creates a new instance of default UnicityCertificateValidator.
func NewDefaultUnicityCertificateValidator(hashAlg gocrypto.Hash) UnicityCertificateValidator {
	return &DefaultUnicityCertificateValidator{hashAlg: hashAlg}
}

func (ucv *DefaultUnicityCertificateValidator) Validate(uc *types.UnicityCertificate, shardConf *types.PartitionDescriptionRecord, trustBase types.RootTrustBase) error {
	if shardConf == nil {
		return errors.New("shard conf is nil")
	}

	var shardConfHash []byte
	// Only verify shardConfHash if UC epoch matches the current shard epoch.
	if uc != nil && uc.GetShardEpoch() == shardConf.Epoch {
		var err error
		shardConfHash, err = shardConf.Hash(ucv.hashAlg)
		if err != nil {
			return fmt.Errorf("failed to calculate shard conf hash: %w", err)
		}
	}
	return uc.Verify(trustBase, ucv.hashAlg, shardConf.PartitionID, shardConf.ShardID, shardConfHash)
}

// NewDefaultBlockProposalValidator creates a new instance of default BlockProposalValidator.
func NewDefaultBlockProposalValidator(hashAlg gocrypto.Hash) BlockProposalValidator {
	return &DefaultBlockProposalValidator{hashAlg: hashAlg}
}

func (bpv *DefaultBlockProposalValidator) Validate(bp *blockproposal.BlockProposal, shardConf *types.PartitionDescriptionRecord, trustBase types.RootTrustBase) error {
	return bp.IsValid(trustBase, shardConf, bpv.hashAlg)
}
