package ucfixture

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"
)

func h(label string) []byte { x := sha256.Sum256([]byte(label)); return x[:] }

func topology(p *Producer) types.PartitionViewTopology {
	t := types.PartitionViewTopology{ShardConfHashes: map[string][]byte{}}
	for _, s := range p.Shards() {
		if s.ID.Length() > 0 {
			t.Scheme = append(t.Scheme, s.ID)
		}
		t.ShardConfHashes[s.ID.Key()] = s.ConfigHash
	}
	return t
}

// scenario: genesis, all shards write, then a timeout, an empty block record and a partial change
func run(t *testing.T, bits int) []*Block {
	p, err := New(Config{Partition: 0x0a0b0c0d, ShardBits: bits})
	require.NoError(t, err)
	n := len(p.Shards())
	var all []Change
	for i := 0; i < n; i++ {
		all = append(all, Change{Shard: i, Hash: h(fmt.Sprint("s1-", i)), Fees: 1<<53 + uint64(i)})
	}
	b1, err := p.Next(BlockSpec{Round: 5, Timestamp: 1731504100, Changes: all})
	require.NoError(t, err)
	changes2 := []Change{{Shard: 0, Timeout: true}}
	if n > 1 {
		changes2 = append(changes2, Change{Shard: n - 1, Hash: h(fmt.Sprint("s1-", n-1))}) // empty block record
	}
	b2, err := p.Next(BlockSpec{Round: 9, Timestamp: 1731504200, Changes: changes2})
	require.NoError(t, err)
	b3, err := p.Next(BlockSpec{Round: 12, Timestamp: 1731504300, Changes: []Change{{Shard: 0, Hash: h("s3-0"), SummaryValue: []byte{1}}}, Signers: []int{1, 2, 3}})
	require.NoError(t, err)
	return []*Block{b1, b2, b3}
}

func TestProducerEquivalence(t *testing.T) {
	for _, bits := range []int{0, 1, 2, 3} {
		t.Run(fmt.Sprintf("%d shards", 1<<bits), func(t *testing.T) {
			p, err := New(Config{Partition: 0x0a0b0c0d, ShardBits: bits})
			require.NoError(t, err)
			topo := topology(p)
			blocks := run(t, bits)
			for bi, b := range blocks {
				require.NotEmpty(t, b.View, "block %d", bi)
				view, err := types.DecodePartitionViewV1(b.View)
				require.NoError(t, err)
				require.Len(t, view.Leaves, 1<<bits)
				for _, cr := range b.Responses {
					require.Equal(t, b.View, cr.PartitionView)
				}
				// the changed shard's real response UC reconstructs every shard's UC
				var enclosing *types.UnicityCertificate
				changed := 0
				for _, so := range b.Shards {
					if so.Changed {
						changed++
						if enclosing == nil {
							enclosing = so.UC
						}
						require.NotEmpty(t, so.ResponseV1)
						require.NotEmpty(t, so.ResponseV2)
					}
				}
				require.Equal(t, changed, len(b.Responses))
				ucs, err := view.AssembleCertificates(enclosing, 0x0a0b0c0d, topo, types.TrustBaseSealVerifier(p.TrustBase()), crypto.SHA256)
				require.NoError(t, err, "block %d", bi)
				for i, uc := range ucs {
					got, err := uc.MarshalCBOR()
					require.NoError(t, err)
					require.Equal(t, b.Shards[i].UCBytes, got, "block %d shard %d", bi, i)
					require.NoError(t, b.Shards[i].UC.Verify(p.TrustBase(), crypto.SHA256, 0x0a0b0c0d, b.Shards[i].Shard, p.Shards()[i].ConfigHash))
				}
			}
		})
	}
}

func TestProducerScenarioDetails(t *testing.T) {
	blocks := run(t, 2)
	b1, b2, b3 := blocks[0], blocks[1], blocks[2]
	// timeout: record preserved, technical record (TRHash) moved on
	require.Equal(t, b1.Shards[0].Record.Hash, b2.Shards[0].Record.Hash)
	require.True(t, b2.Shards[0].Changed)
	require.NotEqual(t, b1.Shards[0].UC.TRHash, b2.Shards[0].UC.TRHash)
	// empty block record on the last shard: hash unchanged, no block hash
	last := b2.Shards[3].Record
	require.Equal(t, last.Hash, last.PreviousHash)
	require.Empty(t, last.BlockHash)
	// unchanged leaves keep their previous record and technical record
	require.False(t, b2.Shards[1].Changed)
	require.Equal(t, b1.Shards[1].Record, b2.Shards[1].Record)
	require.Equal(t, b1.Shards[1].UC.TRHash, b2.Shards[1].UC.TRHash)
	require.Greater(t, b1.Shards[1].Record.SumOfEarnedFees, uint64(1<<53))
	// reference time of a record is the previous seal timestamp
	require.Equal(t, b1.Seal.Timestamp, b2.Shards[3].Record.Timestamp)
	// alternate signers: different witnesses
	require.Len(t, b3.Seal.Signatures, 3)
	require.Contains(t, b3.Seal.Signatures, "root-4")
	require.NotContains(t, b3.Seal.Signatures, "root-1")
}

func TestProducerIsDeterministic(t *testing.T) {
	a, b := run(t, 2), run(t, 2)
	for i := range a {
		require.Equal(t, a[i].View, b[i].View)
		for j := range a[i].Shards {
			require.Equal(t, a[i].Shards[j].UCBytes, b[i].Shards[j].UCBytes)
			require.Equal(t, a[i].Shards[j].ResponseV2, b[i].Shards[j].ResponseV2)
		}
	}
	p1, _ := New(Config{Partition: 0x0a0b0c0d, ShardBits: 1})
	p2, _ := New(Config{Partition: 0x0a0b0c0d, ShardBits: 1})
	t1, _ := p1.TrustBaseCBOR()
	t2, _ := p2.TrustBaseCBOR()
	require.Equal(t, t1, t2)
}

// Several timeouts in one block: each shard repeats its own record.
func TestProducerMultipleTimeoutsKeepPerShardRecords(t *testing.T) {
	p, err := New(Config{Partition: 0x0a0b0c0d, ShardBits: 2})
	require.NoError(t, err)
	b1, err := p.Next(BlockSpec{Round: 5, Timestamp: 1731504100, Changes: []Change{
		{Shard: 0, Hash: h("a"), Fees: 1}, {Shard: 1, Hash: h("b"), Fees: 2}, {Shard: 2, Hash: h("c"), Fees: 3},
	}})
	require.NoError(t, err)
	b2, err := p.Next(BlockSpec{Round: 9, Timestamp: 1731504200, Changes: []Change{
		{Shard: 0, Timeout: true}, {Shard: 1, Timeout: true}, {Shard: 2, Timeout: true},
	}})
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		want, got := b1.Shards[i].Record, b2.Shards[i].Record
		require.Equal(t, want.Hash, got.Hash, "shard %d", i)
		require.Equal(t, want.BlockHash, got.BlockHash, "shard %d", i)
		require.Equal(t, want.SumOfEarnedFees, got.SumOfEarnedFees, "shard %d", i)
		require.True(t, b2.Shards[i].Changed)
	}
	require.NotEqual(t, b2.Shards[0].Record.Hash, b2.Shards[1].Record.Hash)
}
