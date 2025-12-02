package fc

import (
	"crypto"
	"errors"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/metric"

	"github.com/unicitynetwork/bft-core/predicates"
	"github.com/unicitynetwork/bft-core/predicates/templates"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-core/state"
	txtypes "github.com/unicitynetwork/bft-core/txsystem/types"
	"github.com/unicitynetwork/bft-go-base/txsystem/fc"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	GeneralTxCostGasUnits = 400
	GasUnitsPerTema       = 1000
)

var _ txtypes.FeeCreditModule = (*FeeCreditModule)(nil)

var (
	ErrMoneyPartitionIDMissing = errors.New("money transaction partition identifier is missing")
	ErrStateIsNil              = errors.New("state is nil")
	ErrTrustBaseStoreIsNil     = errors.New("trust base store is nil")
)

type (
	// FeeCreditModule contains fee credit related functionality.
	FeeCreditModule struct {
		moneyPartitionID        types.PartitionID
		state                   *state.State
		hashAlgorithm           crypto.Hash
		trustBaseStore          *trustbase.TrustBaseStore
		execPredicate           predicates.PredicateRunner
		feeBalanceValidator     *FeeBalanceValidator
		feeCreditRecordUnitType uint32
		shardConf               ShardConf
	}

	Observability interface {
		Meter(name string, opts ...metric.MeterOption) metric.Meter
		Logger() *slog.Logger
	}

	ShardConf interface {
		ExtractUnitType(unitID types.UnitID) (uint32, error)
		ComposeUnitID(shardID types.ShardID, unitType uint32, prndSh func([]byte) error) (types.UnitID, error)
	}
)

func NewFeeCreditModule(shardConf ShardConf, moneyPartitionID types.PartitionID, state *state.State, trustBaseStore *trustbase.TrustBaseStore, obs Observability, opts ...Option) (*FeeCreditModule, error) {
	m := &FeeCreditModule{
		shardConf:        shardConf,
		moneyPartitionID: moneyPartitionID,
		state:            state,
		trustBaseStore:   trustBaseStore,
		hashAlgorithm:    crypto.SHA256,
	}
	for _, o := range opts {
		o(m)
	}
	if m.execPredicate == nil {
		templEngine, err := templates.New(obs)
		if err != nil {
			return nil, fmt.Errorf("creating predicate templates executor: %w", err)
		}
		predEng, err := predicates.Dispatcher(templEngine)
		if err != nil {
			return nil, fmt.Errorf("creating predicate executor: %w", err)
		}
		m.execPredicate = predicates.NewPredicateRunner(predEng.Execute)
	}
	if m.feeBalanceValidator == nil {
		m.feeBalanceValidator = NewFeeBalanceValidator(m.shardConf.ExtractUnitType, m.state, m.execPredicate, m.feeCreditRecordUnitType)
	}
	if err := m.IsValid(); err != nil {
		return nil, fmt.Errorf("invalid fee credit module configuration: %w", err)
	}
	return m, nil
}

func (f *FeeCreditModule) CalculateCost(gasUsed uint64) uint64 {
	cost := (gasUsed + GasUnitsPerTema/2) / GasUnitsPerTema
	// all transactions cost at least 1 tema - to be refined
	if cost == 0 {
		cost = 1
	}
	return cost
}

func (f *FeeCreditModule) BuyGas(maxTxCost uint64) uint64 {
	return maxTxCost * GasUnitsPerTema
}

func (f *FeeCreditModule) TxHandlers() map[uint16]txtypes.TxExecutor {
	return map[uint16]txtypes.TxExecutor{
		fc.TransactionTypeAddFeeCredit:   txtypes.NewTxHandler[fc.AddFeeCreditAttributes, fc.AddFeeCreditAuthProof](f.validateAddFC, f.executeAddFC),
		fc.TransactionTypeCloseFeeCredit: txtypes.NewTxHandler[fc.CloseFeeCreditAttributes, fc.CloseFeeCreditAuthProof](f.validateCloseFC, f.executeCloseFC),
	}
}

func (f *FeeCreditModule) IsFeeCreditTx(tx *types.TransactionOrder) bool {
	return fc.IsFeeCreditTx(tx)
}

func (f *FeeCreditModule) IsValid() error {
	if f.moneyPartitionID == 0 {
		return ErrMoneyPartitionIDMissing
	}
	if f.state == nil {
		return ErrStateIsNil
	}
	if f.trustBaseStore == nil {
		return ErrTrustBaseStoreIsNil
	}
	return nil
}

func (f *FeeCreditModule) IsCredible(exeCtx txtypes.ExecutionContext, tx *types.TransactionOrder) error {
	return f.feeBalanceValidator.IsCredible(exeCtx, tx)
}

func (f *FeeCreditModule) IsPermissionedMode() bool {
	return false
}

func (f *FeeCreditModule) IsFeelessMode() bool {
	return false
}

func (f *FeeCreditModule) FeeCreditRecordUnitType() uint32 {
	return f.feeCreditRecordUnitType
}
