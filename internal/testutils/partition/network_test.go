package testpartition

import (
	"testing"
	"time"

	test "github.com/unicitynetwork/bft-core/internal/testutils"
	testtxsystem "github.com/unicitynetwork/bft-core/internal/testutils/txsystem"
	"github.com/unicitynetwork/bft-core/txsystem"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/stretchr/testify/require"
	testtransaction "github.com/unicitynetwork/bft-core/txsystem/testutils/transaction"
)

func TestNewNetwork_Ok(t *testing.T) {
	shardConf := &types.PartitionDescriptionRecord{
		Version:         1,
		NetworkID:       networkID,
		PartitionID:     0x01020401,
		PartitionTypeID: 1,
		ShardID:         types.ShardID{},
		TypeIDLen:       8,
		UnitIDLen:       256,
		T2Timeout:       2500 * time.Millisecond,
		Epoch:           0,
		EpochStart:      0,
	}

	abNetwork := NewUnicityNetwork(t, 3)
	require.NoError(t, abNetwork.Start(t))
	t.Cleanup(func() { abNetwork.WaitClose(t) })

	abNetwork.AddShard(t, shardConf, 3, func(tb types.RootTrustBase) txsystem.TransactionSystem {
		return &testtxsystem.CounterTxSystem{FixedState: testtxsystem.MockState{}}
	})

	require.Len(t, abNetwork.RootChain.nodes, 3)
	require.Len(t, abNetwork.Shards, 1)
	cPart, err := abNetwork.GetShard(types.PartitionShardID{PartitionID: shardConf.PartitionID, ShardID: shardConf.ShardID.Key()})
	require.NoError(t, err)
	require.Len(t, cPart.Nodes, 3)

	require.Eventually(t, ShardInitReady(t, cPart), test.WaitDuration*3, test.WaitTick)
	tx := testtransaction.NewTransactionOrder(t, testtransaction.WithPartitionID(shardConf.PartitionID))
	require.NoError(t, cPart.SubmitTx(tx))
	test.TryTilCountIs(t, BlockchainContainsTx(t, cPart, tx), 40, test.WaitTick)

	tx = testtransaction.NewTransactionOrder(t, testtransaction.WithPartitionID(shardConf.PartitionID))
	require.NoError(t, cPart.BroadcastTx(tx))
	test.TryTilCountIs(t, BlockchainContainsTx(t, cPart, tx), 40, test.WaitTick)
}
