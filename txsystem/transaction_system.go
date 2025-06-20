package txsystem

import (
	"errors"
	"io"

	"github.com/unicitynetwork/bft-core/state"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	ErrStateContainsUncommittedChanges = errors.New("state contains uncommitted changes")
	ErrTransactionExpired              = errors.New("transaction timeout must be greater than or equal to the current round number")
	ErrInvalidPartitionID              = errors.New("error invalid partition identifier")
)

type (
	// TransactionSystem is a set of rules and logic for defining units and performing transactions with them.
	// The following sequence of methods is executed for each block: BeginBlock,
	// Execute (called once for each transaction in the block), EndBlock, and Commit (consensus round was successful) or
	// Revert (consensus round was unsuccessful).
	TransactionSystem interface {
		TransactionExecutor

		// StateSummary returns the summary of the current state of the transaction system or an ErrStateContainsUncommittedChanges if
		// current state contains uncommitted changes.
		StateSummary() (*StateSummary, error)

		StateSize() (uint64, error)

		// BeginBlock signals the start of a new block and is invoked before any Execute method calls.
		BeginBlock(uint64) error

		// EndBlock signals the end of the block and is called after all transactions have been delivered to the
		// transaction system.
		EndBlock() (*StateSummary, error)

		// Revert signals the unsuccessful consensus round. When called the transaction system must revert all the changes
		// made during the BeginBlock, EndBlock, and Execute method calls.
		Revert()

		// Commit signals the successful consensus round. Called after the block was approved by the root chain. When called
		// the transaction system must commit all the changes made during the BeginBlock,
		// EndBlock, and Execute method calls.
		Commit(uc *types.UnicityCertificate) error

		// CommittedUC returns the unicity certificate of the latest commit.
		CommittedUC() *types.UnicityCertificate

		// State returns clone of transaction system state
		State() StateReader

		// IsPermissionedMode returns true if permissioned mode is enabled and only transactions from approved parties
		// are executed.
		IsPermissionedMode() bool

		// IsFeelessMode returns true if feeless mode is enabled and the cost of executing transactions is 0.
		IsFeelessMode() bool

		// TypeID returns the type identifier of the transaction system.
		TypeID() types.PartitionTypeID

		SerializeState(writer io.Writer) error
	}

	StateReader interface {
		GetUnit(id types.UnitID, committed bool) (state.Unit, error)

		CreateUnitStateProof(id types.UnitID, logIndex int) (*types.UnitStateProof, error)

		CreateIndex(state.KeyExtractor[string]) (state.Index[string], error)

		// Serialize writes the serialized state to the given writer.
		Serialize(writer io.Writer, committed bool, executedTransactions map[string]uint64) error

		GetUnits(unitTypeID *uint32, pdr *types.PartitionDescriptionRecord) ([]types.UnitID, error)
	}

	TransactionExecutor interface {
		// Execute method executes the transaction order. An error must be returned if the transaction order execution
		// was not successful.
		Execute(order *types.TransactionOrder) (*types.TransactionRecord, error)
	}

	// StateSummary represents aggregate state hashes of the transaction system.
	StateSummary struct {
		rootHash []byte
		summary  []byte
		etHash   []byte
	}
)

func NewStateSummary(rootHash []byte, summary []byte, etHash []byte) *StateSummary {
	return &StateSummary{
		rootHash: rootHash,
		summary:  summary,
		etHash:   etHash,
	}
}

func (s StateSummary) Root() []byte {
	return s.rootHash
}

func (s StateSummary) Summary() []byte {
	return s.summary
}

func (s StateSummary) ETHash() []byte {
	return s.etHash
}
