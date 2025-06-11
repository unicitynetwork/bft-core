package fc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/observability"
	testsig "github.com/unicitynetwork/bft-core/internal/testutils/sig"
	testtb "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/state"
	"github.com/unicitynetwork/bft-core/txsystem/testutils/exec_context"
	testtransaction "github.com/unicitynetwork/bft-core/txsystem/testutils/transaction"
	moneyid "github.com/unicitynetwork/bft-go-base/testutils/money"
	"github.com/unicitynetwork/bft-go-base/txsystem/fc"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestCheckFeeCreditBalance(t *testing.T) {
	_, verifier := testsig.CreateSignerAndVerifier(t)
	trustBase := testtb.NewTrustBase(t, verifier)
	ownerPredicate := []byte{2}

	pdr := moneyid.PDR()
	missingID, err := pdr.ComposeUnitID(types.ShardID{}, 0xFC, moneyid.Random)
	require.NoError(t, err)
	recordID, err := pdr.ComposeUnitID(types.ShardID{}, 0xFC, moneyid.Random)
	require.NoError(t, err)
	existingFCR := &fc.FeeCreditRecord{Balance: 10, Counter: 0, OwnerPredicate: ownerPredicate}

	sharedState := state.NewEmptyState()
	require.NoError(t, sharedState.Apply(state.AddUnit(recordID, existingFCR)))
	require.NoError(t, sharedState.AddUnitLog(recordID, []byte{9}))

	fcModule, err := NewFeeCreditModule(pdr, moneyPartitionID, sharedState, trustBase, observability.Default(t), WithFeeCreditRecordUnitType(0xFC))
	require.NoError(t, err)

	tests := []struct {
		name          string
		tx            *types.TransactionOrder
		expectedError string
	}{
		{
			name:          "fee credit record missing",
			tx:            testtransaction.NewTransactionOrder(t, testtransaction.WithTransactionType(22)),
			expectedError: "fee credit record missing",
		},
		{
			name: "fee credit record unit is nil",
			tx: testtransaction.NewTransactionOrder(t,
				testtransaction.WithTransactionType(22),
				testtransaction.WithClientMetadata(&types.ClientMetadata{FeeCreditRecordID: missingID}),
			),
			expectedError: "fee credit record unit is nil",
		},
		{
			name: "invalid fee proof",
			tx: testtransaction.NewTransactionOrder(t,
				testtransaction.WithTransactionType(22),
				testtransaction.WithClientMetadata(&types.ClientMetadata{FeeCreditRecordID: recordID}),
				testtransaction.WithFeeProof(ownerPredicate),
			),
			expectedError: "decoding predicate",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := fcModule.IsCredible(exec_context.NewMockExecutionContext(), test.tx)
			if test.expectedError != "" {
				assert.ErrorContains(t, err, test.expectedError, "unexpected error")
			} else {
				assert.NoError(t, err, "expected no error")
			}
		})
	}
}
