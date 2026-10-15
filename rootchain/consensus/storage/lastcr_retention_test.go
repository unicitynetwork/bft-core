package storage

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// retentionStates builds S shards of one partition, none with a response yet.
func retentionStates(s int) ShardStates {
	ss := ShardStates{States: map[types.PartitionShardID]*ShardInfo{}, Changed: ShardSet{}}
	for i := 0; i < s; i++ {
		id := types.PartitionShardID{PartitionID: 1, ShardID: fmt.Sprintf("s%d", i)}
		ss.States[id] = &ShardInfo{PartitionID: 1}
	}
	return ss
}

func newCR(round uint64, view []byte) *certification.CertificationResponse {
	return &certification.CertificationResponse{
		Partition: 1,
		UC: types.UnicityCertificate{
			Version:     1,
			UnicitySeal: &types.UnicitySeal{RootChainRoundNumber: round},
		},
		PartitionView: view,
	}
}

// retainedViews counts distinct view backing arrays and their total bytes reachable from LastCR.
func retainedViews(ss ShardStates) (distinct int, bytes int) {
	seen := map[*byte]struct{}{}
	for _, si := range ss.States {
		if si.LastCR != nil && len(si.LastCR.PartitionView) > 0 {
			p := &si.LastCR.PartitionView[0]
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				bytes += len(si.LastCR.PartitionView)
			}
		}
	}
	return len(seen), bytes
}

// Rotating one shard per round: the unbounded reference retains min(R,S) distinct full views (slope 1 in R,
// then plateau); with the bound the retained views are constant (<= MaxRetainedViewsPerPartition) for all R.
func TestLastCRRetention_RotatingShardIsBounded(t *testing.T) {
	const W = 1024
	for _, s := range []int{4, 8, 16} {
		for _, rounds := range []int{1, 2, 4, 8, 16, 64} {
			bounded, reference := retentionStates(s), retentionStates(s)
			for r := 1; r <= rounds; r++ {
				view := make([]byte, W) // a new encoded view every round
				id := types.PartitionShardID{PartitionID: 1, ShardID: fmt.Sprintf("s%d", (r-1)%s)}
				cr := newCR(uint64(r), view)
				bounded.States[id].LastCR = cr
				reference.States[id].LastCR = cr
				bounded.pruneRetainedViews([]*certification.CertificationResponse{cr})
			}
			refN, refBytes := retainedViews(reference)
			n, b := retainedViews(bounded)
			require.Equal(t, min(rounds, s), refN, "reference model S=%d R=%d", s, rounds)
			require.Equal(t, refN*W, refBytes)
			require.LessOrEqual(t, n, MaxRetainedViewsPerPartition, "S=%d R=%d", s, rounds)
			require.LessOrEqual(t, b, MaxRetainedViewsPerPartition*W)
			// the newest response always keeps its view; every shard keeps its certificate
			latest := bounded.States[types.PartitionShardID{PartitionID: 1, ShardID: fmt.Sprintf("s%d", (rounds-1)%s)}]
			require.NotEmpty(t, latest.LastCR.PartitionView)
			for _, si := range bounded.States {
				if si.LastCR != nil {
					require.NotZero(t, si.LastCR.UC.GetRootRoundNumber())
				}
			}
		}
	}
}

// Synchronous updates (all shards same round, one shared view) retain a single view; pruning is a no-op.
func TestLastCRRetention_SynchronousUpdatesShareOneView(t *testing.T) {
	ss := retentionStates(8)
	for r := 1; r <= 10; r++ {
		view := make([]byte, 512)
		var crs []*certification.CertificationResponse
		for id, si := range ss.States {
			cr := newCR(uint64(r), view)
			si.LastCR = cr
			_ = id
			crs = append(crs, cr)
		}
		ss.pruneRetainedViews(crs)
		n, b := retainedViews(ss)
		require.Equal(t, 1, n)
		require.Equal(t, 512, b)
	}
}

// Responses are shared between block states: pruning replaces the pointer of the pruned state and never
// edits the response another state (an older, pending block) still holds.
func TestLastCRRetention_DoesNotMutateSharedResponses(t *testing.T) {
	older := retentionStates(2)
	id0 := types.PartitionShardID{PartitionID: 1, ShardID: "s0"}
	id1 := types.PartitionShardID{PartitionID: 1, ShardID: "s1"}
	old := newCR(1, []byte{1, 2, 3})
	older.States[id0].LastCR = old

	next := retentionStates(2)
	next.States[id0].LastCR = old // inherited pointer
	fresh := newCR(2, []byte{9, 9})
	next.States[id1].LastCR = fresh
	next.pruneRetainedViews([]*certification.CertificationResponse{fresh})

	require.Equal(t, []byte{1, 2, 3}, old.PartitionView, "shared response must be untouched")
	require.Same(t, old, older.States[id0].LastCR)
	require.Nil(t, next.States[id0].LastCR.PartitionView)
	require.Equal(t, old.UC.GetRootRoundNumber(), next.States[id0].LastCR.UC.GetRootRoundNumber())
	require.Equal(t, []byte{9, 9}, next.States[id1].LastCR.PartitionView)
}

// Work is one pass over the shard states per generation: it does not depend on the number of rounds.
func TestLastCRRetention_NoPartitionViewMeansNoWork(t *testing.T) {
	ss := retentionStates(4)
	cr := newCR(1, nil)
	ss.States[types.PartitionShardID{PartitionID: 1, ShardID: "s0"}].LastCR = cr
	ss.pruneRetainedViews([]*certification.CertificationResponse{cr})
	require.Same(t, cr, ss.States[types.PartitionShardID{PartitionID: 1, ShardID: "s0"}].LastCR)
}
