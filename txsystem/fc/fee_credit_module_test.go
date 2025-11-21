package fc

import (
	"testing"

	"github.com/stretchr/testify/require"

	moneyid "github.com/unicitynetwork/bft-go-base/testutils/money"
	fcsdk "github.com/unicitynetwork/bft-go-base/txsystem/fc"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/internal/testutils/observability"
	testsig "github.com/unicitynetwork/bft-core/internal/testutils/sig"
	testtb "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-core/state"
)

func TestFC_Validation(t *testing.T) {
	t.Parallel()

	signer, _ := testsig.CreateSignerAndVerifier(t)
	trustBase := testtb.NewTrustBase(t, signer)
	s := state.NewEmptyState()
	const partitionID = 10
	targetPDR := moneyid.PDR()
	observe := observability.Default(t)

	trustBaseStore, err := trustbase.NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)
	require.NoError(t, trustBaseStore.Store(trustBase))

	t.Run("new fc module validation errors", func(t *testing.T) {
		_, err = NewFeeCreditModule(&targetPDR, 0, s, trustBaseStore, observe)
		require.ErrorIs(t, err, ErrMoneyPartitionIDMissing)

		_, err = NewFeeCreditModule(&targetPDR, partitionID, nil, trustBaseStore, observe)
		require.ErrorIs(t, err, ErrStateIsNil)

		_, err = NewFeeCreditModule(&targetPDR, partitionID, s, nil, observe)
		require.ErrorIs(t, err, ErrTrustBaseStoreIsNil)
	})

	t.Run("new fc module validation", func(t *testing.T) {
		fc, err := NewFeeCreditModule(&targetPDR, partitionID, s, trustBaseStore, observe)
		require.NoError(t, err)
		require.NotNil(t, fc)
	})

	t.Run("new fc module executors", func(t *testing.T) {
		fc, err := NewFeeCreditModule(&targetPDR, partitionID, s, trustBaseStore, observe)
		require.NoError(t, err)
		fcExecutors := fc.TxHandlers()
		require.Len(t, fcExecutors, 2)
		require.Contains(t, fcExecutors, fcsdk.TransactionTypeAddFeeCredit)
		require.Contains(t, fcExecutors, fcsdk.TransactionTypeCloseFeeCredit)
	})

}

func TestFC_CalculateCost(t *testing.T) {
	signer, _ := testsig.CreateSignerAndVerifier(t)
	trustBase := testtb.NewTrustBase(t, signer)
	trustBaseStore, err := trustbase.NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)
	require.NoError(t, trustBaseStore.Store(trustBase))

	shardConf := moneyid.PDR()
	fcModule, err := NewFeeCreditModule(&shardConf, 1, state.NewEmptyState(), trustBaseStore, observability.Default(t))
	require.NoError(t, err)
	require.NotNil(t, fcModule)
	gas := fcModule.BuyGas(10)
	require.EqualValues(t, 10*GasUnitsPerTema, gas)
	require.EqualValues(t, 9, fcModule.CalculateCost(9*GasUnitsPerTema))
	// is rounded up
	require.EqualValues(t, 10, fcModule.CalculateCost(9*GasUnitsPerTema+GasUnitsPerTema/2))
	// is rounded down
	require.EqualValues(t, 9, fcModule.CalculateCost(9*GasUnitsPerTema+1))
	// returns always the cost of at least 1 tema
	require.EqualValues(t, 1, fcModule.CalculateCost(0))
	require.EqualValues(t, 1, fcModule.CalculateCost(100))
}
