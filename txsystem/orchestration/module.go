package orchestration

import (
	"crypto"
	"errors"

	"github.com/unicitynetwork/bft-core/predicates"
	"github.com/unicitynetwork/bft-core/state"
	txtypes "github.com/unicitynetwork/bft-core/txsystem/types"
	"github.com/unicitynetwork/bft-go-base/txsystem/orchestration"
	"github.com/unicitynetwork/bft-go-base/types"
)

var _ txtypes.Module = (*Module)(nil)

type (
	Module struct {
		state          *state.State
		ownerPredicate types.PredicateBytes
		hashAlgorithm  crypto.Hash
		execPredicate  predicates.PredicateRunner
		pdr            types.PartitionDescriptionRecord
	}
)

func NewModule(pdr types.PartitionDescriptionRecord, options *Options) (*Module, error) {
	if options == nil {
		return nil, errors.New("money module options are missing")
	}
	if options.state == nil {
		return nil, errors.New("state is nil")
	}
	if options.ownerPredicate == nil {
		return nil, errors.New("owner predicate is nil")
	}
	m := &Module{
		pdr:            pdr,
		state:          options.state,
		ownerPredicate: options.ownerPredicate,
		hashAlgorithm:  options.hashAlgorithm,
		execPredicate:  predicates.NewPredicateRunner(options.exec),
	}
	return m, nil
}

func (m *Module) TxHandlers() map[uint16]txtypes.TxExecutor {
	return map[uint16]txtypes.TxExecutor{
		orchestration.TransactionTypeAddVAR: txtypes.NewTxHandler[orchestration.AddVarAttributes, orchestration.AddVarAuthProof](m.validateAddVarTx, m.executeAddVarTx),
	}
}
