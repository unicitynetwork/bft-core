package partition

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	testsig "github.com/unicitynetwork/bft-core/internal/testutils/sig"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestShardConfStore(t *testing.T) {
	db := memorydb.New()
	ss, err := NewShardConfStore(db, logger.New(t))
	require.NoError(t, err)

	_, nodeInfo := createKeyConf(t)

	shardConf0 := &types.PartitionDescriptionRecord{
		Version:         1,
		NetworkID:       5,
		PartitionID:     0x01020401,
		PartitionTypeID: 1,
		ShardID:         types.ShardID{},
		TypeIDLen:       8,
		UnitIDLen:       256,
		T2Timeout:       800 * time.Millisecond,
		Epoch:           0,
		EpochStart:      0,
		Validators:      []*types.NodeInfo{nodeInfo},
	}
	require.NoError(t, ss.Store(shardConf0))
	r1, err := ss.Get(0)
	require.NoError(t, err)
	require.Equal(t, shardConf0, r1)

	r2, err := ss.GetFirst()
	require.NoError(t, err)
	require.Equal(t, shardConf0, r2)

	r3, err := ss.Get(1)
	require.Error(t, err, "shard conf not found")
	require.Nil(t, r3)

	shardConf1 := createShardConfWithNewNode(t, shardConf0)
	require.NoError(t, ss.Store(shardConf1))
	r4, err := ss.Get(1)
	require.Nil(t, err)
	require.Equal(t, shardConf1, r4)

	r5, err := ss.GetFirst()
	require.NoError(t, err)
	require.Equal(t, shardConf0, r5)

	shardConf2 := createShardConfWithRemovedNode(t, shardConf1, nodeInfo.NodeID)
	require.NoError(t, ss.Store(shardConf2))
	r6, err := ss.Get(2)
	require.NoError(t, err)
	require.Equal(t, shardConf2, r6)
}

func createShardConfWithNewNode(t *testing.T, prev *types.PartitionDescriptionRecord) *types.PartitionDescriptionRecord {
	peerConf := testpeer.CreatePeerConfiguration(t)
	_, sigVerifier := testsig.CreateSignerAndVerifier(t)
	sigKey, err := sigVerifier.MarshalPublicKey()
	require.NoError(t, err)

	new := *prev
	new.Epoch += 1
	new.EpochStart += 100
	new.Validators = append(prev.Validators, &types.NodeInfo{
		NodeID: peerConf.ID.String(),
		SigKey: sigKey,
		Stake:  1,
	})
	return &new
}

func createShardConfWithRemovedNode(t *testing.T, prev *types.PartitionDescriptionRecord, nodeID string) *types.PartitionDescriptionRecord {
	removeNodeIdx := -1
	for idx, v := range prev.Validators {
		if v.NodeID == nodeID {
			removeNodeIdx = idx
			break
		}
	}

	validators := make([]*types.NodeInfo, len(prev.Validators)-1)
	copy(validators[0:], prev.Validators[:removeNodeIdx])
	copy(validators[removeNodeIdx:], prev.Validators[removeNodeIdx+1:])

	new := *prev
	new.Epoch += 1
	new.EpochStart += 100
	new.Validators = validators
	return &new
}
