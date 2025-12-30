package trustbase

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
)

func TestTrustBaseStore(t *testing.T) {
	// create db
	db := memorydb.New()
	trustBaseStore, err := NewTrustBaseStore(db, logger.New(t))
	require.NoError(t, err)
	require.Equal(t, db, trustBaseStore.db)

	// load trust base from empty store
	tb1, err := trustBaseStore.GetByEpoch(1)
	require.Error(t, err, "trust base not found")
	require.Nil(t, tb1)

	// create trust base
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	tb1, err = types.NewTrustBase(
		5,
		[]*types.NodeInfo{trustbase.NewNodeInfoFromVerifier(t, "test", verifier)},
	)
	require.NoError(t, err)
	require.Equal(t, types.Version(1), tb1.GetVersion())
	require.NoError(t, tb1.Sign("test", signer))

	// store trust base
	err = trustBaseStore.Store(tb1)
	require.NoError(t, err)

	// verify trust base can be loaded
	tb1FromDB, err := trustBaseStore.GetByEpoch(1)
	require.NoError(t, err)
	require.NoError(t, tb1FromDB.VerifySignatures(nil)) // loads sigVerifier private field

	require.Equal(t, tb1, tb1FromDB)
	require.Equal(t, types.Version(1), tb1.GetVersion())

	// create a second trust base with a gap in epoch numbers
	previousTrustBaseHash, err := tb1.Hash(crypto.SHA256)
	require.NoError(t, err)
	invalidTrustBase, err := types.NewTrustBase(5, []*types.NodeInfo{trustbase.NewNodeInfoFromVerifier(t, "test", verifier)},
		types.WithEpoch(3),
		types.WithEpochStart(10),
		types.WithPreviousTrustBaseHash(previousTrustBaseHash),
	)
	require.NoError(t, err)

	// attempt to store the second trust base
	err = trustBaseStore.Store(invalidTrustBase)
	require.ErrorContains(t, err, "previous trust base not found for epoch 2")

	// create a second trust base with correct epoch numbers
	tb2, err := types.NewTrustBase(5, []*types.NodeInfo{trustbase.NewNodeInfoFromVerifier(t, "test", verifier)},
		types.WithEpoch(2),
		types.WithEpochStart(10),
		types.WithPreviousTrustBaseHash(previousTrustBaseHash),
	)
	require.NoError(t, err)
	require.NoError(t, tb2.Sign("test", signer))

	// store the valid second trust base
	err = trustBaseStore.Store(tb2)
	require.NoError(t, err)

	// verify the valid second trust base can be loaded
	tb2FromDB, err := trustBaseStore.GetByEpoch(2)
	require.NoError(t, err)
	require.NoError(t, tb2FromDB.VerifySignatures(tb1)) // loads sigVerifier private field
	require.Equal(t, tb2, tb2FromDB)
}

func TestTrustBaseStore_AlreadyExists(t *testing.T) {
	// create db
	db := memorydb.New()
	trustBaseStore, err := NewTrustBaseStore(db, logger.New(t))
	require.NoError(t, err)

	// create and store initial trust base
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	tb1, err := types.NewTrustBase(
		5, []*types.NodeInfo{trustbase.NewNodeInfoFromVerifier(t, "original", verifier)},
	)
	require.NoError(t, err)
	require.NoError(t, tb1.Sign("original", signer))
	require.NoError(t, trustBaseStore.Store(tb1))

	// create another trust base but for same epoch
	tb2, err := types.NewTrustBase(
		5, []*types.NodeInfo{trustbase.NewNodeInfoFromVerifier(t, "original", verifier)},
		types.WithEpochStart(10),
	)
	require.NoError(t, err)

	// attempt to store the modified trust base
	require.ErrorIs(t, trustBaseStore.Store(tb2), ErrAlreadyExists)
}
