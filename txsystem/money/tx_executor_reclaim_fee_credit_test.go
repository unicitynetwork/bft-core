package money

import (
	"testing"

	"github.com/stretchr/testify/require"

	testblock "github.com/unicitynetwork/bft-core/internal/testutils/block"
	testsig "github.com/unicitynetwork/bft-core/internal/testutils/sig"
	"github.com/unicitynetwork/bft-core/txsystem/fc/testutils"
	testctx "github.com/unicitynetwork/bft-core/txsystem/testutils/exec_context"
	testtransaction "github.com/unicitynetwork/bft-core/txsystem/testutils/transaction"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/predicates/templates"
	moneyid "github.com/unicitynetwork/bft-go-base/testutils/money"
	fcsdk "github.com/unicitynetwork/bft-go-base/txsystem/fc"
	"github.com/unicitynetwork/bft-go-base/txsystem/money"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"
)

func TestModule_validateReclaimFCTx(t *testing.T) {
	const (
		amount  = uint64(100)
		counter = uint64(4)
	)
	signer, verifier := testsig.CreateSignerAndVerifier(t)
	authProof := &fcsdk.ReclaimFeeCreditAuthProof{OwnerProof: nil}
	pdr := moneyid.PDR()

	t.Run("Ok", func(t *testing.T) {
		tx := testutils.NewReclaimFC(t, &pdr, signer, nil, testtransaction.WithPartition(&pdr))
		attr := &fcsdk.ReclaimFeeCreditAttributes{}
		require.NoError(t, tx.UnmarshalAttributes(attr))
		module := newTestMoneyModule(t, verifier,
			withStateUnit(tx.UnitID, &money.BillData{Value: amount, Counter: counter, OwnerPredicate: templates.AlwaysTrueBytes()}))
		exeCtx := testctx.NewMockExecutionContext()
		require.NoError(t, module.validateReclaimFCTx(tx, attr, authProof, exeCtx))
	})
	t.Run("Bill is missing", func(t *testing.T) {
		tx := testutils.NewReclaimFC(t, &pdr, signer, nil)
		attr := &fcsdk.ReclaimFeeCreditAttributes{}
		require.NoError(t, tx.UnmarshalAttributes(attr))
		module := newTestMoneyModule(t, verifier)
		exeCtx := testctx.NewMockExecutionContext()
		require.EqualError(t, module.validateReclaimFCTx(tx, attr, authProof, exeCtx),
			"get unit error: item 000000000000000000000000000000000000000000000000000000000000000001 does not exist: not found")
	})
	t.Run("unit is not bill data", func(t *testing.T) {
		tx := testutils.NewReclaimFC(t, &pdr, signer, nil)
		attr := &fcsdk.ReclaimFeeCreditAttributes{}
		require.NoError(t, tx.UnmarshalAttributes(attr))
		exeCtx := testctx.NewMockExecutionContext()
		module := newTestMoneyModule(t, verifier, withStateUnit(tx.UnitID, &fcsdk.FeeCreditRecord{Balance: 10, OwnerPredicate: templates.AlwaysTrueBytes()}))
		require.EqualError(t, module.validateReclaimFCTx(tx, attr, authProof, exeCtx), "invalid unit type")
	})
	t.Run("Fee credit record exists in transaction", func(t *testing.T) {
		tx := testutils.NewReclaimFC(t, &pdr, signer, nil,
			testtransaction.WithClientMetadata(&types.ClientMetadata{FeeCreditRecordID: []byte{0}}))
		attr := &fcsdk.ReclaimFeeCreditAttributes{}
		require.NoError(t, tx.UnmarshalAttributes(attr))
		module := newTestMoneyModule(t, verifier,
			withStateUnit(tx.UnitID, &money.BillData{Value: amount, Counter: counter, OwnerPredicate: templates.AlwaysTrueBytes()}))
		exeCtx := testctx.NewMockExecutionContext()
		require.EqualError(t, module.validateReclaimFCTx(tx, attr, authProof, exeCtx), "fee transaction cannot contain fee credit reference")
	})
	t.Run("Fee proof exists", func(t *testing.T) {
		tx := testutils.NewReclaimFC(t, &pdr, signer, nil,
			testtransaction.WithFeeProof([]byte{0, 0, 0, 0}))
		attr := &fcsdk.ReclaimFeeCreditAttributes{}
		require.NoError(t, tx.UnmarshalAttributes(attr))
		module := newTestMoneyModule(t, verifier,
			withStateUnit(tx.UnitID, &money.BillData{Value: amount, Counter: counter, OwnerPredicate: templates.AlwaysTrueBytes()}))
		exeCtx := testctx.NewMockExecutionContext()
		require.EqualError(t, module.validateReclaimFCTx(tx, attr, authProof, exeCtx), "fee transaction cannot contain fee authorization proof")
	})
	t.Run("Invalid target unit", func(t *testing.T) {
		tx := testutils.NewReclaimFC(t, &pdr, signer, nil,
			testtransaction.WithUnitID(moneyid.NewFeeCreditRecordID(t)))
		attr := &fcsdk.ReclaimFeeCreditAttributes{}
		require.NoError(t, tx.UnmarshalAttributes(attr))
		module := newTestMoneyModule(t, verifier,
			withStateUnit(tx.UnitID, &money.BillData{Value: amount, Counter: counter, OwnerPredicate: templates.AlwaysTrueBytes()}))
		exeCtx := testctx.NewMockExecutionContext()
		require.EqualError(t, module.validateReclaimFCTx(tx, attr, authProof, exeCtx), "invalid target unit")
	})
	t.Run("Invalid transaction fee", func(t *testing.T) {
		closeFC := &types.TransactionRecord{
			Version: 1,
			TransactionOrder: testtransaction.TxoToBytes(t, testutils.NewCloseFC(t, signer,
				testutils.NewCloseFCAttr(
					testutils.WithCloseFCAmount(2),
					testutils.WithCloseFCTargetUnitCounter(counter),
				),
				testtransaction.WithPartition(&pdr),
			)),
			ServerMetadata: &types.ServerMetadata{ActualFee: 10},
		}
		tx := testutils.NewReclaimFC(t, &pdr, signer,
			testutils.NewReclaimFCAttr(t, &pdr, signer,
				testutils.WithReclaimFCClosureProof(testblock.CreateTxRecordProof(t, closeFC, signer)),
			),
		)
		attr := &fcsdk.ReclaimFeeCreditAttributes{}
		require.NoError(t, tx.UnmarshalAttributes(attr))
		module := newTestMoneyModule(t, verifier,
			withStateUnit(tx.UnitID, &money.BillData{Value: amount, Counter: counter, OwnerPredicate: templates.AlwaysTrueBytes()}))
		exeCtx := testctx.NewMockExecutionContext()
		require.EqualError(t, module.validateReclaimFCTx(tx, attr, authProof, exeCtx), "the transaction fees cannot exceed the transferred value")
	})
	t.Run("Invalid target unit counter", func(t *testing.T) {
		tx := testutils.NewReclaimFC(t, &pdr, signer, nil)
		attr := &fcsdk.ReclaimFeeCreditAttributes{}
		require.NoError(t, tx.UnmarshalAttributes(attr))
		module := newTestMoneyModule(t, verifier,
			withStateUnit(tx.UnitID, &money.BillData{Value: amount, Counter: counter + 1, OwnerPredicate: templates.AlwaysTrueBytes()}))
		exeCtx := testctx.NewMockExecutionContext()
		require.EqualError(t, module.validateReclaimFCTx(tx, attr, authProof, exeCtx), "invalid target unit counter")
	})
	t.Run("owner error", func(t *testing.T) {
		tx := testutils.NewReclaimFC(t, &pdr, signer, nil)
		attr := &fcsdk.ReclaimFeeCreditAttributes{}
		require.NoError(t, tx.UnmarshalAttributes(attr))
		module := newTestMoneyModule(t, verifier,
			withStateUnit(tx.UnitID, &money.BillData{Value: amount, Counter: counter, OwnerPredicate: templates.AlwaysFalseBytes()}))
		exeCtx := testctx.NewMockExecutionContext()
		require.EqualError(t, module.validateReclaimFCTx(tx, attr, authProof, exeCtx), `predicate evaluated to "false"`)
	})
	t.Run("Invalid proof", func(t *testing.T) {
		tx := testutils.NewReclaimFC(t, &pdr, signer, testutils.NewReclaimFCAttr(t, &pdr, signer,
			testutils.WithReclaimFCClosureProof(newInvalidProof(t, &pdr, signer))))
		attr := &fcsdk.ReclaimFeeCreditAttributes{}
		require.NoError(t, tx.UnmarshalAttributes(attr))
		module := newTestMoneyModule(t, verifier,
			withStateUnit(tx.UnitID, &money.BillData{Value: amount, Counter: counter, OwnerPredicate: templates.AlwaysTrueBytes()}))
		exeCtx := testctx.NewMockExecutionContext()
		tx.NetworkID = module.pdr.NetworkID
		require.EqualError(t, module.validateReclaimFCTx(tx, attr, authProof, exeCtx), "invalid proof: verify tx inclusion: proof block hash does not match to block hash in unicity certificate")
	})
}

func TestModule_executeReclaimFCTx(t *testing.T) {
	const (
		amount  = uint64(100)
		counter = uint64(4)
	)
	pdr := moneyid.PDR()
	signer, verifier := testsig.CreateSignerAndVerifier(t)
	tx := testutils.NewReclaimFC(t, &pdr, signer, nil)
	attr := &fcsdk.ReclaimFeeCreditAttributes{}
	require.NoError(t, tx.UnmarshalAttributes(attr))
	module := newTestMoneyModule(t, verifier,
		withStateUnit(tx.UnitID, &money.BillData{Value: amount, Counter: counter, OwnerPredicate: templates.AlwaysTrueBytes()}))
	reclaimAmount := uint64(40)
	exeCtx := testctx.NewMockExecutionContext(testctx.WithData(util.Uint64ToBytes(reclaimAmount)))
	authProof := &fcsdk.ReclaimFeeCreditAuthProof{OwnerProof: nil}
	sm, err := module.executeReclaimFCTx(tx, attr, authProof, exeCtx)
	require.NoError(t, err)
	require.True(t, sm.ActualFee > 0)
	require.EqualValues(t, types.TxStatusSuccessful, sm.SuccessIndicator)
	require.EqualValues(t, []types.UnitID{tx.UnitID}, sm.TargetUnits)
	// verify changes
	u, err := module.state.GetUnit(tx.UnitID, false)
	require.NoError(t, err)
	bill, ok := u.Data().(*money.BillData)
	require.True(t, ok)
	require.EqualValues(t, bill.Owner(), templates.AlwaysTrueBytes())
	// target bill is credited correct amount (using default values from testutils)
	v := reclaimAmount - sm.ActualFee
	require.EqualValues(t, bill.Value, amount+v)
	// counter is incremented
	require.EqualValues(t, bill.Counter, counter+1)
}

func newInvalidProof(t *testing.T, pdr *types.PartitionDescriptionRecord, signer abcrypto.Signer) *types.TxRecordProof {
	attr := testutils.NewDefaultReclaimFCAttr(t, pdr, signer)
	attr.CloseFeeCreditProof.TxProof.BlockHeaderHash = []byte("invalid hash")
	return attr.CloseFeeCreditProof
}
