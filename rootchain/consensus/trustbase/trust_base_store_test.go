package trustbase

import (
	"testing"

	"github.com/alphabill-org/alphabill-go-base/crypto"
	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/alphabill-org/alphabill/internal/testutils/logger"
	"github.com/alphabill-org/alphabill/internal/testutils/trustbase"
	"github.com/alphabill-org/alphabill/keyvaluedb/memorydb"
	"github.com/stretchr/testify/require"
)

func TestTrustBaseStore(t *testing.T) {
	// create db
	db := memorydb.New()
	trustBaseStore, err := NewTrustBaseStore(db, logger.New(t))
	require.NoError(t, err)
	require.Equal(t, db, trustBaseStore.db)

	// load trust base from empty store
	tb, err := trustBaseStore.GetByEpoch(0)
	require.Error(t, err, "trust base not found")
	require.Nil(t, tb)

	// create trust base
	signer, err := crypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	tb, err = types.NewTrustBaseGenesis(
		5,
		[]*types.NodeInfo{trustbase.NewNodeInfoFromVerifier(t, "test", verifier)},
	)
	require.NoError(t, err)

	// store trust base
	err = trustBaseStore.Store(tb)
	require.NoError(t, err)

	// verify trust base can be loaded
	tbFromDB, err := trustBaseStore.GetByEpoch(0)
	require.NoError(t, err)
	require.Equal(t, tb, tbFromDB)
}
