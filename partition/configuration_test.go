package partition

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"

	testobserve "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	testsig "github.com/unicitynetwork/bft-core/internal/testutils/sig"
	"github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
)

func TestNewNodeConf(t *testing.T) {
	blockDB := memorydb.New()
	shardDB := memorydb.New()
	t1Timeout := 250 * time.Millisecond

	keyConf, nodeInfo := createKeyConf(t)
	shardConf := &types.PartitionDescriptionRecord{
		Version:         1,
		NetworkID:       5,
		PartitionID:     0x01010101,
		ShardID:         types.ShardID{},
		PartitionTypeID: 999,
		TypeIDLen:       8,
		UnitIDLen:       256,
		T2Timeout:       2500 * time.Millisecond,
		Epoch:           0,
		EpochStart:      1,
		Validators:      []*types.NodeInfo{nodeInfo},
	}
	signer, _ := testsig.CreateSignerAndVerifier(t)
	trustBase := trustbase.NewTrustBase(t, signer)
	obs := testobserve.Default(t)

	shardConfStore, err := NewShardConfStore(shardDB, obs.Logger())
	require.NoError(t, err)
	require.NoError(t, shardConfStore.Store(shardConf))

	trustBaseStore, err := tbstore.NewTrustBaseStore(memorydb.New(), obs.Logger())
	require.NoError(t, err)
	require.NoError(t, trustBaseStore.Store(trustBase))

	conf, err := NewNodeConf(keyConf, shardConfStore, trustBaseStore, obs,
		WithTxValidator(&AlwaysValidTransactionValidator{}),
		WithUnicityCertificateValidator(&AlwaysValidCertificateValidator{}),
		WithBlockProposalValidator(&AlwaysValidBlockProposalValidator{}),
		WithBlockDB(blockDB),
		WithT1Timeout(t1Timeout),
		WithReplicationParams(1, 2, 3, 1000),
		WithBlockSubscriptionTimeout(3500))

	require.NoError(t, err)
	require.NotNil(t, conf)
	require.Equal(t, blockDB, conf.blockDB)
	require.Equal(t, shardDB, conf.shardConfStore.db)
	require.NoError(t, conf.txValidator.Validate(nil, shardConf, 0))
	require.NoError(t, conf.bpValidator.Validate(nil, nil, nil))
	require.NoError(t, conf.ucValidator.Validate(nil, nil, nil))
	require.Equal(t, t1Timeout, conf.t1Timeout)
	require.EqualValues(t, 1, conf.replicationConfig.maxFetchBlocks)
	require.EqualValues(t, 2, conf.replicationConfig.maxReturnBlocks)
	require.EqualValues(t, 3, conf.replicationConfig.maxTx)
	require.EqualValues(t, 1000, conf.replicationConfig.timeout)
	require.EqualValues(t, 3500, conf.blockSubscriptionTimeout)
}

func TestNewNodeConf_WithDefaults(t *testing.T) {
	keyConf, nodeInfo := createKeyConf(t)
	shardConf := &types.PartitionDescriptionRecord{
		Version:         1,
		NetworkID:       5,
		PartitionID:     0x01010101,
		ShardID:         types.ShardID{},
		PartitionTypeID: 999,
		TypeIDLen:       8,
		UnitIDLen:       256,
		T2Timeout:       2500 * time.Millisecond,
		Epoch:           0,
		EpochStart:      1,
		Validators:      []*types.NodeInfo{nodeInfo},
	}

	signer, _ := testsig.CreateSignerAndVerifier(t)
	trustBase := trustbase.NewTrustBase(t, signer)

	obs := testobserve.Default(t)

	shardConfStore, err := NewShardConfStore(memorydb.New(), obs.Logger())
	require.NoError(t, err)
	require.NoError(t, shardConfStore.Store(shardConf))

	trustBaseStore, err := tbstore.NewTrustBaseStore(memorydb.New(), obs.Logger())
	require.NoError(t, err)
	require.NoError(t, trustBaseStore.Store(trustBase))

	_, err = NewNodeConf(nil, shardConfStore, trustBaseStore, obs)
	require.ErrorIs(t, err, ErrKeyConfIsNil)

	_, err = NewNodeConf(keyConf, nil, trustBaseStore, obs)
	require.ErrorIs(t, err, ErrShardConfStoreIsNil)

	_, err = NewNodeConf(keyConf, shardConfStore, nil, obs)
	require.ErrorIs(t, err, ErrTrustBaseStoreIsNil)

	conf, err := NewNodeConf(keyConf, shardConfStore, trustBaseStore, obs)
	require.NoError(t, err)
	require.NotNil(t, conf)

	require.NotNil(t, conf.blockDB)
	require.NotNil(t, conf.signer)
	require.NotNil(t, conf.txValidator)
	require.NotNil(t, conf.bpValidator)
	require.NotNil(t, conf.ucValidator)
	require.NotNil(t, conf.shardConf)
	require.NotNil(t, conf.hashAlgorithm)
	require.Equal(t, DefaultT1Timeout*time.Millisecond, conf.t1Timeout)
	require.Equal(t, DefaultReplicationMaxBlocks, conf.replicationConfig.maxFetchBlocks)
	require.Equal(t, DefaultReplicationMaxBlocks, conf.replicationConfig.maxReturnBlocks)
	require.Equal(t, DefaultReplicationMaxTx, conf.replicationConfig.maxTx)
	require.Equal(t, DefaultLedgerReplicationTimeout, conf.replicationConfig.timeout)
	require.Equal(t, DefaultBlockSubscriptionTimeout, conf.blockSubscriptionTimeout)
}
