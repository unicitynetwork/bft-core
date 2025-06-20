package exec_context

import (
	"errors"

	"github.com/unicitynetwork/bft-core/state"
	"github.com/unicitynetwork/bft-core/tree/avl"
	txtypes "github.com/unicitynetwork/bft-core/txsystem/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

type MockExecContext struct {
	Unit          state.Unit
	RootTrustBase types.RootTrustBase
	RoundNumber   uint64
	GasRemaining  uint64
	mockErr       error
	customData    []byte
	exArgument    func() ([]byte, error)
	exeType       txtypes.ExecutionType
}

func (m *MockExecContext) GetUnit(id types.UnitID, committed bool) (state.Unit, error) {
	if m.mockErr != nil {
		return nil, m.mockErr
	}
	// return avl.ErrNotFound if unit does not exist to be consistent with actual implementation
	if m.Unit == nil {
		return nil, avl.ErrNotFound
	}
	return m.Unit, nil
}

func (m *MockExecContext) CommittedUC() *types.UnicityCertificate { return nil }

func (m *MockExecContext) CurrentRound() uint64 { return m.RoundNumber }

func (m *MockExecContext) TrustBase(epoch uint64) (types.RootTrustBase, error) {
	if m.mockErr != nil {
		return nil, m.mockErr
	}
	return m.RootTrustBase, nil
}

func (m *MockExecContext) ExtraArgument() ([]byte, error) {
	if m.exArgument == nil {
		return nil, errors.New("extra argument callback not assigned")
	}
	return m.exArgument()
}

func (m *MockExecContext) WithExArg(f func() ([]byte, error)) txtypes.ExecutionContext {
	m.exArgument = f
	return m
}

func (m *MockExecContext) GetData() []byte {
	return m.customData
}

func (m *MockExecContext) SetData(data []byte) {
	m.customData = data
}

type TestOption func(*MockExecContext)

func WithCurrentRound(round uint64) TestOption {
	return func(m *MockExecContext) {
		m.RoundNumber = round
	}
}

func WithUnit(unit state.Unit) TestOption {
	return func(m *MockExecContext) {
		m.Unit = unit
	}
}

func WithData(data []byte) TestOption {
	return func(m *MockExecContext) {
		m.customData = data
	}
}

func WithErr(err error) TestOption {
	return func(m *MockExecContext) {
		m.mockErr = err
	}
}

func (m *MockExecContext) GasAvailable() uint64 {
	return m.GasRemaining
}

func (m *MockExecContext) SpendGas(gas uint64) error {
	return m.mockErr
}

func (m *MockExecContext) CalculateCost() uint64 {
	//gasUsed := ec.initialGas - ec.remainingGas
	return 1 // (gasUsed + GasUnitsPerTema/2) / GasUnitsPerTema
}

func (m *MockExecContext) ExecutionType() txtypes.ExecutionType {
	return txtypes.ExecutionTypeUnconditional
}

func (m *MockExecContext) SetExecutionType(exeType txtypes.ExecutionType) {
	m.exeType = exeType
}

func NewMockExecutionContext(options ...TestOption) *MockExecContext {
	execCtx := &MockExecContext{}
	for _, o := range options {
		o(execCtx)
	}
	return execCtx
}
