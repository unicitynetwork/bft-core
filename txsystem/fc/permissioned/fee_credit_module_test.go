package permissioned

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/observability"
	testsig "github.com/unicitynetwork/bft-core/internal/testutils/sig"
	"github.com/unicitynetwork/bft-core/state"
	predtempl "github.com/unicitynetwork/bft-go-base/predicates/templates"
	moneyid "github.com/unicitynetwork/bft-go-base/testutils/money"
)

func TestNewFeeCreditModule(t *testing.T) {
	_, verifier := testsig.CreateSignerAndVerifier(t)
	pubKey, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	stateTree := state.NewEmptyState()
	const feeCreditRecordUnitType = 1
	adminOwnerPredicate := predtempl.NewP2pkh256BytesFromKey(pubKey)
	targetPDR := moneyid.PDR()
	observe := observability.Default(t)

	t.Run("invalid target PDR", func(t *testing.T) {
		invalidPDR := targetPDR
		invalidPDR.NetworkID = 0
		m, err := NewFeeCreditModule(invalidPDR, stateTree, feeCreditRecordUnitType, adminOwnerPredicate, observe)
		require.Nil(t, m)
		require.EqualError(t, err, `invalid target PDR: invalid network identifier: 0`)
	})

	t.Run("state is nil", func(t *testing.T) {
		m, err := NewFeeCreditModule(targetPDR, nil, feeCreditRecordUnitType, adminOwnerPredicate, observe)
		require.Nil(t, m)
		require.ErrorIs(t, err, ErrStateIsNil)
	})

	t.Run("fee credit record unit type is nil", func(t *testing.T) {
		m, err := NewFeeCreditModule(targetPDR, stateTree, 0, adminOwnerPredicate, observe)
		require.Nil(t, m)
		require.ErrorIs(t, err, ErrMissingFeeCreditRecordUnitType)
	})

	t.Run("admin owner predicate is nil", func(t *testing.T) {
		m, err := NewFeeCreditModule(targetPDR, stateTree, feeCreditRecordUnitType, nil, observe)
		require.Nil(t, m)
		require.ErrorIs(t, err, ErrMissingAdminOwnerPredicate)
	})

	t.Run("ok", func(t *testing.T) {
		m, err := NewFeeCreditModule(targetPDR, stateTree, feeCreditRecordUnitType, adminOwnerPredicate, observe)
		require.NoError(t, err)
		require.NotNil(t, m)
		require.NotNil(t, m.execPredicate, "execPredicate should not be nil")
		require.NotNil(t, m.feeBalanceValidator, "feeBalanceValidator should not be nil")
	})
}
