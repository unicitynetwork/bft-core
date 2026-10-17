package storage

import (
	"crypto"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Measurement support for the UC consolidation acceptance criteria: encoded sizes of
// the partition view and of the response frames, and the cost the sidecar adds to a
// round. See docs/uc-consolidation-measurements.md for commands and results.

type msShape struct {
	name    string
	bits    int
	changed []int
}

var msShapes = []msShape{
	{"1 shard", 0, []int{0}},
	{"4 shards", 2, []int{0, 3}},
	{"4 shards, all changed", 2, []int{0, 1, 2, 3}},
	{"8 shards", 3, []int{1, 2, 6}},
	{"8 shards, all changed", 3, []int{0, 1, 2, 3, 4, 5, 6, 7}},
}

// msIR describes an aggregation input record. Typical is what a shard aggregator
// certifies: 32 byte state/previous/block hashes, empty (non-nil) summary value,
// no fees, no ETHash. Max sets every optional field to its consolidation admission
// limit: 256 byte summary value, 32 byte ETHash and maximal uint64 round, epoch,
// timestamp and fee fields (the longest CBOR encodings).
type msIR struct {
	name    string
	summary int
	fees    uint64
	max     bool // every field at its admitted maximum (see Test_MeasurementMaximumIRIsAdmitted)
}

var msIRs = []msIR{
	{name: "typical aggregation IR"},
	{name: "maximum admitted IR (256 B summary, 32 B ETHash, all uint64 fields 2^64-1)", summary: 256, fees: math.MaxUint64, max: true},
}

func msBlock(t testing.TB, ir msIR, bits int, changed ...int) *ExecutedBlock {
	scheme := fxScheme(bits)
	order := fxOrder(scheme)
	ss := ShardStates{States: map[types.PartitionShardID]*ShardInfo{}, Changed: ShardSet{}}
	mk := func(p types.PartitionID, id types.ShardID, n int) *ShardInfo {
		return &ShardInfo{
			PartitionID: p, ShardID: id,
			IR: &types.InputRecord{
				Version: 1, RoundNumber: uint64(1_000_000 + n), Epoch: 1,
				PreviousHash: fxHash(fmt.Sprint("prev", p, id, n)), Hash: fxHash(fmt.Sprint("state", p, id, n)),
				BlockHash: fxHash(fmt.Sprint("block", p, id, n)), SummaryValue: make([]byte, ir.summary),
				Timestamp: 1731504540 + uint64(n), SumOfEarnedFees: ir.fees,
			},
			TR:            certification.TechnicalRecord{Round: uint64(n + 1), Epoch: 1, Leader: "16Uiu2HAmLeaderPeerIDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", FeeHash: fxHash("fee"), StatHash: fxHash("stat")},
			ShardConfHash: fxHash(fmt.Sprint("conf", p, id)),
		}
	}
	mkMax := mk
	mk = func(p types.PartitionID, id types.ShardID, n int) *ShardInfo {
		si := mkMax(p, id, n)
		if ir.max {
			si.IR.RoundNumber, si.IR.Epoch, si.IR.Timestamp = math.MaxUint64-uint64(n), math.MaxUint64, math.MaxUint64
			si.IR.ETHash = fxHash(fmt.Sprint("eth", p, id, n))
			si.TR.Round, si.TR.Epoch = math.MaxUint64-uint64(n), math.MaxUint64
		}
		return si
	}
	for i, id := range order {
		ss.States[types.PartitionShardID{PartitionID: fxPartition, ShardID: id.Key()}] = mk(fxPartition, id, i)
	}
	// further single shard partitions, the root chain certifies all of them every round
	for i := 0; i < 3; i++ {
		other := types.PartitionID(0x01010101 + i)
		ss.States[types.PartitionShardID{PartitionID: other, ShardID: types.ShardID{}.Key()}] = mk(other, types.ShardID{}, 0)
	}
	for _, i := range changed {
		ss.Changed[types.PartitionShardID{PartitionID: fxPartition, ShardID: order[i].Key()}] = struct{}{}
	}
	ut, _, err := ss.UnicityTree(crypto.SHA256)
	require.NoError(t, err)
	return &ExecutedBlock{HashAlgo: crypto.SHA256, RootHash: ut.RootHash(), ShardState: ss}
}

// msSeal builds a seal signed by n root validators (65 byte secp256k1 signatures).
func msSeal(rootHash []byte, signers int) *types.UnicitySeal {
	sigs := types.SignatureMap{}
	for i := 0; i < signers; i++ {
		sigs[fmt.Sprintf("16Uiu2HAmRootValidatorPeerID%02dxxxxxxxxxxxxxxxxxxxxxxxx", i)] = make([]byte, 65)
	}
	return &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: 1_000_003, Epoch: 1, Timestamp: 1731504600,
		PreviousHash: fxHash("previous root"), Hash: rootHash, Signatures: sigs}
}

// msCertify runs the producer on blk with a seal signed by the given number of
// 65 byte signatures, and checks that witness is what the response carries.
func msCertify(t testing.TB, blk *ExecutedBlock, signers int) []*certification.CertificationResponse {
	qc := fxCommitQc(blk)
	qc.LedgerCommitInfo = msSeal(blk.RootHash, signers)
	qc.Signatures = qc.LedgerCommitInfo.Signatures // GenerateCertificates copies the QC's signatures
	crs, err := blk.GenerateCertificates(qc, logger.New(t))
	require.NoError(t, err)
	for _, cr := range crs {
		require.Len(t, cr.UC.UnicitySeal.Signatures, signers)
		for _, sig := range cr.UC.UnicitySeal.Signatures {
			require.Len(t, sig, 65)
		}
	}
	return crs
}

func msFrame(data []byte) int {
	var buf [binary.MaxVarintLen64]byte
	return binary.PutUvarint(buf[:], uint64(len(data))) + len(data)
}

// baselineCertificationResponses is certificationResponses as it was before the
// partition view producer: the same tree build and response loop, no sidecar.
func baselineCertificationResponses(ss ShardStates, algo crypto.Hash) ([]*certification.CertificationResponse, []byte, error) {
	ut, shardTrees, err := ss.UnicityTree(algo)
	if err != nil {
		return nil, nil, err
	}
	crs := make([]*certification.CertificationResponse, 0, len(ss.Changed))
	for psID, si := range ss.changedShards() {
		stCert, err := shardTrees[psID.PartitionID].Certificate(si.ShardID)
		if err != nil {
			return nil, nil, err
		}
		utCert, err := ut.Certificate(si.PartitionID)
		if err != nil {
			return nil, nil, err
		}
		trHash, err := si.TR.Hash()
		if err != nil {
			return nil, nil, err
		}
		crs = append(crs, &certification.CertificationResponse{
			Partition: si.PartitionID, Shard: si.ShardID, Technical: si.TR,
			UC: types.UnicityCertificate{Version: 1, InputRecord: si.IR, TRHash: trHash, ShardConfHash: si.ShardConfHash,
				UnicityTreeCertificate: utCert, ShardTreeCertificate: stCert},
		})
	}
	return crs, ut.RootHash(), nil
}

// Test_MeasurementMaximumIRIsAdmitted checks the "maximum admitted IR" workload really
// is the largest the producer admits: every optional IR field is populated at its
// limit, generation succeeds and the strict decoder accepts the result, and one more
// byte of summary value is rejected.
func Test_MeasurementMaximumIRIsAdmitted(t *testing.T) {
	ir := msIRs[1]
	b := msBlock(t, ir, 3, 0, 1)
	crs := msCertify(t, b, 4)
	cr := crs[0]
	view, err := types.DecodePartitionViewV1(cr.PartitionView)
	require.NoError(t, err)
	require.Len(t, view.Leaves, 8)
	for _, l := range view.Leaves {
		require.Len(t, l.InputRecord.SummaryValue, types.MaxPartitionViewSummaryValueBytes)
		require.Len(t, l.InputRecord.ETHash, 32)
		require.Equal(t, uint64(math.MaxUint64), l.InputRecord.Epoch)
		require.Equal(t, uint64(math.MaxUint64), l.InputRecord.Timestamp)
		require.Equal(t, uint64(math.MaxUint64), l.InputRecord.SumOfEarnedFees)
		enc, err := types.Cbor.Marshal(l.InputRecord)
		require.NoError(t, err)
		require.LessOrEqual(t, len(enc), types.MaxPartitionViewIRBytes)
	}
	over := view.Clone()
	over.Leaves[0].InputRecord.SummaryValue = make([]byte, types.MaxPartitionViewSummaryValueBytes+1)
	_, err = over.MarshalCBOR()
	require.Error(t, err)
}

// Test_MeasurementReport prints (go test -v) the exact encoded sizes as a markdown
// table and enforces the consolidation limits on them.
func Test_MeasurementReport(t *testing.T) {
	const signers = 4
	var sb strings.Builder
	sb.WriteString("| IR | shape | view (B) | V1 frame (B) | V2 frame with view (B) | added per response (B) | V2 frame, null view (B) | UC (B) |\n|---|---|---|---|---|---|---|---|\n")
	for _, ir := range msIRs {
		for _, sh := range msShapes {
			b := msBlock(t, ir, sh.bits, sh.changed...)
			crs := msCertify(t, b, signers)
			require.NotEmpty(t, crs)
			cr := crs[0]
			require.NotEmpty(t, cr.PartitionView)

			v1, err := types.Cbor.Marshal(cr)
			require.NoError(t, err)
			withView, err := types.Cbor.Marshal(certification.NewCertificationResponseV2(cr))
			require.NoError(t, err)
			nullCR := *cr
			nullCR.PartitionView = nil
			nullView, err := types.Cbor.Marshal(certification.NewCertificationResponseV2(&nullCR))
			require.NoError(t, err)
			uc, err := cr.UC.MarshalCBOR()
			require.NoError(t, err)

			require.LessOrEqual(t, len(cr.PartitionView), certification.MaxPartitionViewSize)
			require.LessOrEqual(t, len(withView), certification.MaxCertificationResponseV2Frame)
			fmt.Fprintf(&sb, "| %s | %s | %d | %d | %d | %d | %d | %d |\n", ir.name, sh.name, len(cr.PartitionView),
				msFrame(v1), msFrame(withView), msFrame(withView)-msFrame(v1), msFrame(nullView), len(uc))
		}
	}
	t.Logf("seal signatures: %d x 65 B\n%s", signers, sb.String())
}

func BenchmarkUnicityTree(b *testing.B) {
	for _, sh := range msShapes {
		blk := msBlock(b, msIRs[0], sh.bits, sh.changed...)
		b.Run(sh.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, _, err := blk.ShardState.UnicityTree(crypto.SHA256); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkCertificationResponses compares the response builder before (baseline)
// and after (withView) the partition view producer on the same shard states.
func BenchmarkCertificationResponses(b *testing.B) {
	for _, ir := range msIRs {
		for _, sh := range msShapes {
			blk := msBlock(b, ir, sh.bits, sh.changed...)
			b.Run(ir.name+"/"+sh.name+"/baseline", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, _, err := baselineCertificationResponses(blk.ShardState, crypto.SHA256); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run(ir.name+"/"+sh.name+"/withView", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, _, _, err := blk.ShardState.certificationResponsesWithViews(crypto.SHA256); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkEncodePartitionView isolates the producer's added work: clone + encode
// of the complete leaf vector, once per changed partition per round.
func BenchmarkEncodePartitionView(b *testing.B) {
	for _, ir := range msIRs {
		for _, sh := range msShapes[:4] {
			blk := msBlock(b, ir, sh.bits, sh.changed...)
			_, _, inputs, err := blk.ShardState.unicityTree(crypto.SHA256)
			require.NoError(b, err)
			b.Run(ir.name+"/"+sh.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := encodePartitionView(fxPartition, inputs[fxPartition], nil); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkGenerateCertificates is the complete per round certification step as
// executed by the root chain (tree, responses, partition views, seal attach).
func BenchmarkGenerateCertificates(b *testing.B) {
	for _, sh := range msShapes {
		blk := msBlock(b, msIRs[0], sh.bits, sh.changed...)
		qc := fxCommitQc(blk)
		qc.LedgerCommitInfo = msSeal(blk.RootHash, 4)
		qc.Signatures = qc.LedgerCommitInfo.Signatures
		msCertify(b, blk, 4) // validates the witness shape before timing
		b.Run(sh.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := blk.GenerateCertificates(qc, logger.New(b)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkResponseSerialization compares serializing one response in the legacy
// four element form and in the V2 envelope (the root chain does each once per
// dispatch and shares the framed bytes between recipients); also receive side decode.
func BenchmarkResponseSerialization(b *testing.B) {
	for _, sh := range msShapes[:4] {
		blk := msBlock(b, msIRs[0], sh.bits, sh.changed...)
		crs := msCertify(b, blk, 4)
		cr := crs[0]
		v2 := certification.NewCertificationResponseV2(cr)
		v1Bytes, err := types.Cbor.Marshal(cr)
		require.NoError(b, err)
		v2Bytes, err := types.Cbor.Marshal(v2)
		require.NoError(b, err)
		b.Run(sh.name+"/marshal-v1", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := types.Cbor.Marshal(cr); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(sh.name+"/marshal-v2", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := types.Cbor.Marshal(v2); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(sh.name+"/unmarshal-v1", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var out certification.CertificationResponse
				if err := types.Cbor.Unmarshal(v1Bytes, &out); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(sh.name+"/unmarshal-v2", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var out certification.CertificationResponseV2
				if err := types.Cbor.Unmarshal(v2Bytes, &out); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(sh.name+"/decode-partition-view", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := types.DecodePartitionViewV1(cr.PartitionView); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
