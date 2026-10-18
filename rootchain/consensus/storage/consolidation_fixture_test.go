package storage

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

const fxPartition types.PartitionID = 7 // the aggregation partition, as in the vendored corpus

func fxHash(label string) []byte {
	h := sha256.Sum256([]byte(label))
	return h[:]
}

func fxScheme(bits int) types.ShardingScheme {
	if bits == 0 {
		return types.ShardingScheme{}
	}
	ids := []types.ShardID{{}}
	for ; bits > 0; bits-- {
		var next []types.ShardID
		for _, id := range ids {
			a, b := id.Split()
			next = append(next, a, b)
		}
		ids = next
	}
	return types.ShardingScheme(ids)
}

// fxBlock builds deterministic executed block of two partitions (so the unicity tree
// partition path is not empty); the partition "fxPartition" has the given scheme and
// the shards with indexes in "changed" (in canonical order) changed. Fully deterministic.
func fxBlock(t testing.TB, scheme types.ShardingScheme, changed ...int) *ExecutedBlock {
	order := fxOrder(scheme)
	ss := ShardStates{States: map[types.PartitionShardID]*ShardInfo{}, Changed: ShardSet{}}
	mk := func(p types.PartitionID, id types.ShardID, n int) *ShardInfo {
		return &ShardInfo{
			PartitionID: p, ShardID: id,
			IR: &types.InputRecord{
				Version: 1, RoundNumber: uint64(10 + n), Epoch: uint64(n % 2),
				PreviousHash: fxHash(fmt.Sprint("prev", p, id, n)), Hash: fxHash(fmt.Sprint("state", p, id, n)),
				BlockHash: fxHash(fmt.Sprint("block", p, id, n)), SummaryValue: []byte{},
				Timestamp: 1731504540 + uint64(n), SumOfEarnedFees: 1<<53 + uint64(n),
			},
			TR:            certification.TechnicalRecord{Round: uint64(n + 1), Epoch: uint64(n % 2), Leader: "node", FeeHash: fxHash("fee"), StatHash: fxHash("stat")},
			ShardConfHash: fxHash(fmt.Sprint("conf", p, id)),
		}
	}
	for i, id := range order {
		ss.States[types.PartitionShardID{PartitionID: fxPartition, ShardID: id.Key()}] = mk(fxPartition, id, i)
	}
	other := types.PartitionID(0x01010101)
	ss.States[types.PartitionShardID{PartitionID: other, ShardID: types.ShardID{}.Key()}] = mk(other, types.ShardID{}, 0)
	for _, i := range changed {
		ss.Changed[types.PartitionShardID{PartitionID: fxPartition, ShardID: order[i].Key()}] = struct{}{}
	}
	ut, _, err := ss.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	return &ExecutedBlock{
		BlockData: &drctypes.BlockData{Author: "test", Round: 2, Payload: &drctypes.Payload{}},
		HashAlgo:  crypto.SHA256, RootHash: ut.RootHash(), ShardState: ss,
	}
}

func fxCommitQc(b *ExecutedBlock) *drctypes.QuorumCert {
	return &drctypes.QuorumCert{
		VoteInfo: &drctypes.RoundInfo{RoundNumber: 3, ParentRoundNumber: 2, CurrentRootHash: make([]byte, 32)},
		LedgerCommitInfo: &types.UnicitySeal{
			Version: 1, NetworkID: 5, RootChainRoundNumber: 3, Epoch: 1, Timestamp: 1731504600,
			PreviousHash: fxHash("previous root"), Hash: b.RootHash,
		},
		// fixed placeholder, the producer subset is about the tree (real signing is covered by the full corpus)
		Signatures: types.SignatureMap{"root1": fxHash("signature")},
	}
}

type fxCase struct {
	name    string
	bits    int
	changed []int
}

var fxCases = []fxCase{
	{"shards-1", 0, []int{0}},
	{"shards-4", 2, []int{0, 3}},
	{"shards-8", 3, []int{1, 2, 6}},
	{"shards-8-all", 3, []int{0, 1, 2, 3, 4, 5, 6, 7}},
}

// fxOrder is the left-to-right order of the scheme, also for schemes over the view limit.
func fxOrder(scheme types.ShardingScheme) []types.ShardID {
	ids := slices.Collect(scheme.All())
	slices.SortFunc(ids, func(a, b types.ShardID) int { return slices.Compare([]byte(a.String()), []byte(b.String())) })
	return ids
}
