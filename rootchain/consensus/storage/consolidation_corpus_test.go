package storage_test

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/testutils/ucfixture"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The producer subset of the portable UC consolidation corpus (testdata/uc-consolidation/v1)
// is copied verbatim from the aggregator-go corpus, which is its canonical home. These tests
// prove producer equivalence: the real block executor, driven with the recorded blocks, yields
// the committed responses, partition views and unicity certificates byte for byte, and the
// committed bytes are consumable (view -> every shard's UC, native verification).

const corpusDir = "testdata/uc-consolidation/v1"

type corpusManifest struct {
	SourceManifestSHA256 string            `json:"sourceManifestSha256"`
	Commits              map[string]string `json:"generatorCommits"`
	SHA256               map[string]string `json:"sha256"`
}

type corpusContext struct {
	NetworkID    uint32   `json:"networkId"`
	PartitionID  uint32   `json:"partitionId"`
	Shards       []string `json:"shards"`
	ShardConfigs []struct {
		Shard string `json:"shard"`
		File  string `json:"file"`
		Hash  string `json:"hash"`
	} `json:"shardConfigs"`
	Master    string `json:"master"`
	TrustBase string `json:"trustBase"`
}

type producerSpec struct {
	Partition uint32 `json:"partitionId"`
	ShardBits int    `json:"shardBits"`
	Blocks    []struct {
		Name      string `json:"name"`
		Round     uint64 `json:"round,string"`
		Timestamp uint64 `json:"timestamp,string"`
		Signers   []int  `json:"signers"`
		Changes   []struct {
			Shard   int     `json:"shard"`
			Timeout bool    `json:"timeout"`
			Hash    string  `json:"hash"`
			Fees    uint64  `json:"fees,string"`
			Summary string  `json:"summary"`
			ETHash  *string `json:"etHash"`
		} `json:"changes"`
	} `json:"blocks"`
}

func readAll(t *testing.T) map[string][]byte {
	files := map[string][]byte{}
	require.NoError(t, filepath.WalkDir(corpusDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		rel, _ := filepath.Rel(corpusDir, p)
		files[filepath.ToSlash(rel)] = b
		return err
	}))
	return files
}

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestCorpusSubsetChecksums(t *testing.T) {
	files := readAll(t)
	var m corpusManifest
	require.NoError(t, json.Unmarshal(files["manifest.json"], &m))
	require.Len(t, m.SourceManifestSHA256, 64)
	for _, k := range []string{"aggregator-go", "bft-core", "bft-go-base"} {
		require.NotEmpty(t, m.Commits[k], k)
	}
	for name, want := range m.SHA256 {
		sum := sha256.Sum256(files[name])
		require.Equal(t, want, hex.EncodeToString(sum[:]), name)
	}
	for name := range files {
		if name != "manifest.json" {
			require.Contains(t, m.SHA256, name, "unpinned file %s", name)
		}
	}
}

func TestCorpusProducerEquivalence(t *testing.T) {
	files := readAll(t)
	cases := map[string]bool{}
	for name := range files {
		if i := strings.Index(name, "/"); i > 0 {
			cases[name[:i]] = true
		}
	}
	require.GreaterOrEqual(t, len(cases), 7)
	for name := range cases {
		t.Run(name, func(t *testing.T) {
			get := func(f string) []byte {
				b, ok := files[name+"/"+f]
				require.True(t, ok, f)
				return b
			}
			var ctx corpusContext
			require.NoError(t, json.Unmarshal(get("context.json"), &ctx))
			var spec producerSpec
			require.NoError(t, json.Unmarshal(get("producer.json"), &spec))
			require.Equal(t, ctx.PartitionID, spec.Partition)

			// replay the recorded blocks through the production block executor
			p, err := ucfixture.New(ucfixture.Config{Partition: types.PartitionID(spec.Partition), ShardBits: spec.ShardBits})
			require.NoError(t, err)
			tb, err := p.TrustBaseCBOR()
			require.NoError(t, err)
			require.Equal(t, get(ctx.TrustBase), tb)
			for i, s := range p.Shards() {
				require.Equal(t, ctx.Shards[i], s.ID.String())
				require.Equal(t, get(ctx.ShardConfigs[i].File), s.ConfigBytes)
				require.Equal(t, ctx.ShardConfigs[i].Hash, hex.EncodeToString(s.ConfigHash))
			}
			var final *ucfixture.Block
			for _, b := range spec.Blocks {
				bs := ucfixture.BlockSpec{Round: b.Round, Timestamp: b.Timestamp, Signers: b.Signers}
				for _, c := range b.Changes {
					ch := ucfixture.Change{Shard: c.Shard, Timeout: c.Timeout, Fees: c.Fees, SummaryValue: unhex(t, c.Summary)}
					if !c.Timeout {
						ch.Hash = unhex(t, c.Hash)
					}
					if c.ETHash != nil {
						ch.ETHash = unhex(t, *c.ETHash)
					}
					bs.Changes = append(bs.Changes, ch)
				}
				blk, err := p.Next(bs)
				require.NoError(t, err)
				if b.Name == "F" {
					final = blk
				}
			}
			require.NotNil(t, final)

			// the committed bytes are what the executor produced
			require.Equal(t, get("partition-view.cbor"), final.View)
			masterIdx := slices.Index(ctx.Shards, ctx.Master)
			require.GreaterOrEqual(t, masterIdx, 0)
			require.Equal(t, get("response-v1.cbor"), final.Shards[masterIdx].ResponseV1)
			require.Equal(t, get("response-v2.cbor"), final.Shards[masterIdx].ResponseV2)
			for i, s := range ctx.Shards {
				f := s
				if f == "" {
					f = "root"
				}
				require.Equal(t, get("ucs/"+f+".cbor"), final.Shards[i].UCBytes, "shard %q", s)
			}

			// ... and they are consumable without the producer: legacy and v2 responses
			// decode, the view rebuilds every shard's UC and each passes native verification
			var legacy certification.CertificationResponse
			require.NoError(t, types.Cbor.Unmarshal(get("response-v1.cbor"), &legacy))
			require.Empty(t, legacy.PartitionView, "legacy wire carries no view")
			var v2 certification.CertificationResponseV2
			require.NoError(t, v2.UnmarshalCBOR(get("response-v2.cbor")))
			require.Equal(t, get("partition-view.cbor"), v2.PartitionView)
			wireLegacy, err := types.Cbor.Marshal(&legacy)
			require.NoError(t, err)
			require.Equal(t, get("response-v1.cbor"), wireLegacy)

			trust := &types.RootTrustBaseV1{}
			require.NoError(t, trust.UnmarshalCBOR(get(ctx.TrustBase)))
			view, err := types.DecodePartitionViewV1(v2.PartitionView)
			require.NoError(t, err)
			topo := types.PartitionViewTopology{ShardConfHashes: map[string][]byte{}}
			for i, c := range ctx.ShardConfigs {
				id := p.Shards()[i].ID
				if id.Length() > 0 {
					topo.Scheme = append(topo.Scheme, id)
				}
				topo.ShardConfHashes[id.Key()] = unhex(t, c.Hash)
			}
			uc := legacy.UC
			ucs, err := view.AssembleCertificates(&uc, legacy.Partition, topo, types.TrustBaseSealVerifier(trust), crypto.SHA256)
			require.NoError(t, err)
			for i, u := range ucs {
				b, err := u.MarshalCBOR()
				require.NoError(t, err)
				require.Equal(t, final.Shards[i].UCBytes, b)
				require.NoError(t, u.Verify(trust, crypto.SHA256, legacy.Partition, p.Shards()[i].ID, topo.ShardConfHashes[p.Shards()[i].ID.Key()]))
			}
		})
	}
}
