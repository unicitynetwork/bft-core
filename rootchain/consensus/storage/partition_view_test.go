package storage

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

func fxTopology(t *testing.T, b *ExecutedBlock, scheme types.ShardingScheme) types.PartitionViewTopology {
	topo := types.PartitionViewTopology{Scheme: scheme, ShardConfHashes: map[string][]byte{}}
	for k, si := range b.ShardState.States {
		if k.PartitionID == fxPartition {
			topo.ShardConfHashes[k.ShardID] = si.ShardConfHash
		}
	}
	return topo
}

func Test_PartitionView_Producer(t *testing.T) {
	for _, c := range fxCases {
		t.Run(c.name, func(t *testing.T) {
			scheme := fxScheme(c.bits)
			b := fxBlock(t, scheme, c.changed...)
			// snapshot of the tree inputs before certification
			wantTree, _, err := b.ShardState.UnicityTree(crypto.SHA256)
			require.NoError(t, err)

			crs, err := b.GenerateCertificates(fxCommitQc(b), logger.New(t))
			require.NoError(t, err)
			require.Len(t, crs, len(c.changed))

			topo := fxTopology(t, b, scheme)
			var first []byte
			for _, cr := range crs {
				require.NotEmpty(t, cr.PartitionView)
				if first == nil {
					first = cr.PartitionView
				}
				// encoded once and shared by the responses of the partition
				require.Same(t, &first[0], &cr.PartitionView[0])

				view, err := types.DecodePartitionViewV1(cr.PartitionView)
				require.NoError(t, err)
				require.Len(t, view.Leaves, 1<<c.bits, "view must have unchanged leaves too")
				// the view hashes into the seal and reproduces the response's UC
				enclosing := cr.UC
				ucs, err := view.AssembleCertificates(&enclosing, fxPartition, topo, acceptSeal{}, crypto.SHA256)
				require.NoError(t, err)
				want, err := cr.UC.MarshalCBOR()
				require.NoError(t, err)
				var got []byte
				for _, uc := range ucs {
					if uc.ShardTreeCertificate.Shard.Equal(cr.Shard) {
						got, err = uc.MarshalCBOR()
						require.NoError(t, err)
					}
				}
				require.Equal(t, want, got)
				require.True(t, bytes.Equal(wantTree.RootHash(), cr.UC.UnicitySeal.Hash))
			}

			// unchanged shards are not responded to and their LastCR is not touched
			for k, si := range b.ShardState.States {
				if _, ok := b.ShardState.Changed[k]; !ok {
					require.Nil(t, si.LastCR)
				} else {
					require.Equal(t, first, si.LastCR.PartitionView)
				}
			}
		})
	}
}

// acceptSeal stands in for seal authentication, the tests are about the tree.
type acceptSeal struct{}

func (acceptSeal) VerifySeal(*types.UnicitySeal) error { return nil }

func Test_PartitionView_OnlyChangedPartitions(t *testing.T) {
	b := fxBlock(t, fxScheme(1), 0)
	// the other partition has no changes: no response, no view work
	_, _, viewErrs, err := b.ShardState.certificationResponsesWithViews(crypto.SHA256)
	require.NoError(t, err)
	require.Empty(t, viewErrs)
	_, _, in, err := b.ShardState.unicityTree(crypto.SHA256)
	require.NoError(t, err)
	views, errs := b.ShardState.partitionViews(in)
	require.Empty(t, errs)
	require.Len(t, views, 1)
	require.Contains(t, views, fxPartition)
}

func Test_PartitionView_Immutable(t *testing.T) {
	b := fxBlock(t, fxScheme(2), 1)
	crs, err := b.GenerateCertificates(fxCommitQc(b), logger.New(t))
	require.NoError(t, err)
	before := bytes.Clone(crs[0].PartitionView)

	// the shard state moves on after the response was produced
	for _, si := range b.ShardState.States {
		si.IR.Hash[0] ^= 0xff
		si.IR.PreviousHash[0] ^= 0xff
		si.TR.Round++
		si.ShardConfHash[0] ^= 0xff
	}
	require.Equal(t, before, crs[0].PartitionView)
	_, err = types.DecodePartitionViewV1(crs[0].PartitionView)
	require.NoError(t, err)
}

func Test_PartitionView_ErrorsAreNotFatal(t *testing.T) {
	// existing tests use configuration hashes which are not valid for a view
	b := fxBlock(t, fxScheme(1), 0, 1)
	for k, si := range b.ShardState.States {
		if k.PartitionID == fxPartition {
			si.ShardConfHash = []byte{1, 2, 3, 4}
		}
	}
	ut, _, err := b.ShardState.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	b.RootHash = ut.RootHash()

	crs, err := b.GenerateCertificates(fxCommitQc(b), logger.New(t))
	require.NoError(t, err, "sidecar failure must not fail certification")
	require.Len(t, crs, 2)
	for _, cr := range crs {
		require.Nil(t, cr.PartitionView)
		require.NoError(t, cr.IsValid())
	}
	_, _, viewErrs, err := b.ShardState.certificationResponsesWithViews(crypto.SHA256)
	require.NoError(t, err)
	require.ErrorContains(t, viewErrs[fxPartition], "ShardConfHash")
}

func Test_PartitionView_OverLimitTopologyOmitted(t *testing.T) {
	// 16 shards is a valid partition but outside of the view limits
	b := fxBlock(t, fxScheme(4), 0)
	crs, err := b.GenerateCertificates(fxCommitQc(b), logger.New(t))
	require.NoError(t, err)
	require.Len(t, crs, 1)
	require.Nil(t, crs[0].PartitionView)
}

func Test_PartitionView_NotInLegacyFormat(t *testing.T) {
	b := fxBlock(t, fxScheme(1), 0)
	crs, err := b.GenerateCertificates(fxCommitQc(b), logger.New(t))
	require.NoError(t, err)
	cr := crs[0]
	require.NotEmpty(t, cr.PartitionView)

	with, err := types.Cbor.Marshal(cr)
	require.NoError(t, err)
	cp := *cr
	cp.PartitionView = nil
	without, err := types.Cbor.Marshal(&cp)
	require.NoError(t, err)
	require.Equal(t, without, with, "carrier must not change the legacy encoding")
	require.EqualValues(t, 0x84, with[0], "legacy response is four element array")

	// hashing / persistence formats: ShardInfo round trip drops the carrier
	si := b.ShardState.States[types.PartitionShardID{PartitionID: fxPartition, ShardID: cr.Shard.Key()}]
	require.Equal(t, cr.PartitionView, si.LastCR.PartitionView)
	data, err := types.Cbor.Marshal(si)
	require.NoError(t, err)
	var dec ShardInfo
	require.NoError(t, types.Cbor.Unmarshal(data, &dec))
	require.NotNil(t, dec.LastCR)
	require.Nil(t, dec.LastCR.PartitionView)
	var back certification.CertificationResponse
	require.NoError(t, types.Cbor.Unmarshal(with, &back))
	require.Nil(t, back.PartitionView)
}

// fxShardKey is the key of the idx-th shard of the scheme.
func fxShardKey(bits, idx int) string {
	return fxOrder(fxScheme(bits))[idx].Key()
}
