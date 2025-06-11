package testutils

import (
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/predicates/templates"
	moneyid "github.com/unicitynetwork/bft-go-base/testutils/money"
	"github.com/unicitynetwork/bft-go-base/txsystem/money"
	"github.com/unicitynetwork/bft-go-base/types"
)

func NewFeeCreditRecordID(t *testing.T, signer abcrypto.Signer) types.UnitID {
	pdr := moneyid.PDR()
	ownerPredicate := NewP2pkhPredicate(t, signer)
	uid, err := money.NewFeeCreditRecordIDFromOwnerPredicate(&pdr, types.ShardID{}, ownerPredicate, latestAdditionTime)
	require.NoError(t, err)
	return uid
}

func NewFeeCreditRecordIDAlwaysTrue(t *testing.T) types.UnitID {
	pdr := moneyid.PDR()
	uid, err := money.NewFeeCreditRecordIDFromOwnerPredicate(&pdr, types.ShardID{}, templates.AlwaysTrueBytes(), latestAdditionTime)
	require.NoError(t, err)
	return uid
}

func NewP2pkhPredicate(t *testing.T, signer abcrypto.Signer) types.PredicateBytes {
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	publicKey, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	return templates.NewP2pkh256BytesFromKey(publicKey)
}

func DefaultMoneyUnitID() types.UnitID {
	return append(make([]byte, 32), money.BillUnitType)
}
