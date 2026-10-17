package storage

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Staggered certification: each round a different shard is certified. Every shard must keep its OWN
// original response (same pointer, same view bytes) no matter how many later rounds certified other shards,
// and the retained distinct views are bounded by the number of shards (<= S views, O(S*W) bytes),
// independent of the number of rounds.
func TestLastCRRetention_EachShardKeepsOwnOriginalSidecar(t *testing.T) {
	const bits = 3 // 8 shards = production cap
	S := 1 << bits
	for _, rounds := range []int{1, 4, 8, 16, 40} {
		b := fxBlock(t, fxScheme(bits), 0)
		own := map[types.PartitionShardID]*certification.CertificationResponse{}
		ownBytes := map[types.PartitionShardID][]byte{}
		order, err := types.CanonicalShardOrder(fxScheme(bits))
		require.NoError(t, err)
		for r := 0; r < rounds; r++ {
			idx := r % S
			b.ShardState.Changed = ShardSet{{PartitionID: fxPartition, ShardID: order[idx].Key()}: {}}
			crs, err := b.GenerateCertificates(fxCommitQc(b), logger.New(t))
			require.NoError(t, err)
			require.Len(t, crs, 1)
			require.NotEmpty(t, crs[0].PartitionView)
			id := types.PartitionShardID{PartitionID: fxPartition, ShardID: crs[0].Shard.Key()}
			own[id], ownBytes[id] = crs[0], bytes.Clone(crs[0].PartitionView)
		}
		views := map[*byte]int{}
		for id, si := range b.ShardState.States {
			if id.PartitionID != fxPartition || si.LastCR == nil {
				continue
			}
			want, certified := own[id]
			if !certified {
				continue
			}
			require.Same(t, want, si.LastCR, "R=%d: shard keeps the response it was certified with", rounds)
			require.Equal(t, ownBytes[id], si.LastCR.PartitionView, "R=%d: original sidecar bytes", rounds)
			views[&si.LastCR.PartitionView[0]]++
		}
		// retained views: one per certified shard, never more than S and not growing with R
		require.Len(t, views, min(rounds, S), "R=%d", rounds)
		require.LessOrEqual(t, len(views), S)
	}
}
