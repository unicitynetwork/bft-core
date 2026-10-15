package storage

import (
	"crypto"
	"fmt"
	"math"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Scaling-curve measurements for the partition view producer (see
// docs/uc-consolidation-measurements.md). Each sweep varies one parameter and
// reports hardware independent counters (bytes, allocations, retained arrays)
// next to relative time, with the log-log slope against the expected bound.
// Opt in with UC_MEASURE=1.

type opCost struct {
	allocs, bytes, nanos float64
}

// costOf runs fn repeatedly (at least minTime) and returns per-call allocation
// count, allocated bytes and wall time. The counters are deterministic for
// deterministic code; time is relative only.
func costOf(fn func()) opCost {
	fn() // warm up
	var before, after runtime.MemStats
	n := 1
	for {
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		for i := 0; i < n; i++ {
			fn()
		}
		elapsed := time.Since(start)
		runtime.ReadMemStats(&after)
		if elapsed >= 80*time.Millisecond || n >= 1<<20 {
			return opCost{
				allocs: float64(after.Mallocs-before.Mallocs) / float64(n),
				bytes:  float64(after.TotalAlloc-before.TotalAlloc) / float64(n),
				nanos:  float64(elapsed.Nanoseconds()) / float64(n),
			}
		}
		n *= 4
	}
}

// slope is the least-squares slope of log y against log x (a power law x^a has slope a).
// Zero-valued series (a counter that never moves) have slope 0.
func slope(xs, ys []float64) float64 {
	var sx, sy, sxx, sxy float64
	n := 0.0
	for i := range xs {
		if xs[i] <= 0 || ys[i] <= 0 {
			continue
		}
		lx, ly := math.Log(xs[i]), math.Log(ys[i])
		sx, sy, sxx, sxy, n = sx+lx, sy+ly, sxx+lx*lx, sxy+lx*ly, n+1
	}
	if n < 2 || n*sxx-sx*sx == 0 {
		return 0
	}
	return (n*sxy - sx*sy) / (n*sxx - sx*sx)
}

func fmtSlope(xs, ys []float64) string { return fmt.Sprintf("%.2f", slope(xs, ys)) }

func requireMeasure(t *testing.T) {
	if os.Getenv("UC_MEASURE") == "" {
		t.Skip("set UC_MEASURE=1 to run the scaling measurements")
	}
}

// msViewRaw encodes exactly like PartitionViewV1 (untagged [1, partition, leaves]) but
// without the production admission caps, so the algorithm can be measured beyond 8 shards.
type msViewRaw struct {
	_           struct{} `cbor:",toarray"`
	Version     types.Version
	PartitionID types.PartitionID
	Leaves      []types.PartitionViewLeafV1
}

func msHarnessView(t testing.TB, blk *ExecutedBlock) []byte {
	_, _, inputs, err := blk.ShardState.unicityTree(crypto.SHA256)
	require.NoError(t, err)
	var scheme types.ShardingScheme
	for _, in := range inputs[fxPartition] {
		scheme = append(scheme, in.Shard)
	}
	if len(scheme) == 1 {
		scheme = types.ShardingScheme{} // a single shard partition has the empty scheme
	}
	// canonical order: left-to-right prefix order (the production helper caps the scheme at 8 shards)
	order := fxOrder(scheme)
	if len(scheme) <= types.MaxPartitionViewLeaves {
		prod, err := types.CanonicalShardOrder(scheme)
		require.NoError(t, err)
		require.Equal(t, prod, order)
	}
	byShard := map[string]types.ShardTreeInput{}
	for _, in := range inputs[fxPartition] {
		byShard[in.Shard.Key()] = in
	}
	raw := msViewRaw{Version: types.PartitionViewVersionV1, PartitionID: fxPartition}
	for _, id := range order {
		in := byShard[id.Key()]
		raw.Leaves = append(raw.Leaves, types.PartitionViewLeafV1{ShardID: in.Shard, InputRecord: in.IR, TRHash: in.TRHash, ShardConfHash: in.ShardConfHash})
	}
	data, err := types.Cbor.Marshal(raw)
	require.NoError(t, err)
	return data
}

// Sweep 1: shard count S. Validation, tree build, view encode, dispatch bytes.
// S <= 8 is the production range; larger S uses the uncapped harness encoding
// and measures algorithm scaling only (the producer would omit such a view).
func Test_ScalingShardCount(t *testing.T) {
	requireMeasure(t)
	var sb strings.Builder
	sb.WriteString("| S | view B | IsValid allocs | IsValid ns | CanonicalShardOrder allocs | UnicityTree allocs | UnicityTree B | UnicityTree ns | view encode allocs | view encode ns | V2 frame B | dispatch B, k=1 | dispatch B, k=S |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	var xs, view, validNs, treeAllocs, treeBytes, treeNs, encAllocs, encNs, k1, kS []float64
	var validAllocs, orderAllocs []float64
	for bits := 0; bits <= 8; bits++ {
		S := 1 << bits
		blk := msBlock(t, msIRs[0], bits, 0)
		scheme := fxScheme(bits)
		viewBytes := msHarnessView(t, blk)
		if S <= 8 { // the harness encoding is the production encoding where both exist
			_, _, inputs, err := blk.ShardState.unicityTree(crypto.SHA256)
			require.NoError(t, err)
			prod, err := encodePartitionView(fxPartition, inputs[fxPartition])
			require.NoError(t, err)
			require.Equal(t, prod, viewBytes)
		}
		// one response (the UC is produced without a view beyond the production cap)
		crs, _, _, err := blk.ShardState.certificationResponsesWithViews(crypto.SHA256)
		require.NoError(t, err)
		cr := crs[0]
		cr.UC.UnicitySeal = msSeal(blk.RootHash, 4)
		cr.PartitionView = viewBytes
		env, err := types.Cbor.Marshal(certification.NewCertificationResponseV2(cr))
		require.NoError(t, err)
		frame := msFrame(env)

		valid := costOf(func() { _ = scheme.IsValid() })
		order := opCost{}
		if S <= types.MaxPartitionViewLeaves {
			order = costOf(func() { _, _ = types.CanonicalShardOrder(scheme) })
		}
		tree := costOf(func() { _, _, _ = blk.ShardState.UnicityTree(crypto.SHA256) })
		enc := costOf(func() { _ = msHarnessView(t, blk) })

		fmt.Fprintf(&sb, "| %d | %d | %.0f | %.0f | %.0f | %.0f | %.0f | %.0f | %.0f | %.0f | %d | %d | %d |\n",
			S, len(viewBytes), valid.allocs, valid.nanos, order.allocs, tree.allocs, tree.bytes, tree.nanos, enc.allocs, enc.nanos, frame, frame, S*frame)
		xs = append(xs, float64(S))
		view = append(view, float64(len(viewBytes)))
		validAllocs = append(validAllocs, valid.allocs)
		validNs = append(validNs, valid.nanos)
		orderAllocs = append(orderAllocs, order.allocs)
		treeAllocs = append(treeAllocs, tree.allocs)
		treeBytes = append(treeBytes, tree.bytes)
		treeNs = append(treeNs, tree.nanos)
		encAllocs = append(encAllocs, enc.allocs)
		encNs = append(encNs, enc.nanos)
		k1 = append(k1, float64(frame))
		kS = append(kS, float64(S*frame))
	}
	fmt.Fprintf(&sb, "\n(CanonicalShardOrder is capped at 8 shards by the production helper, its column is 0 beyond.)\nLog-log slopes over S = 1..256 (whole range): view bytes %s (expect 1), IsValid allocs %s, IsValid time %s (pair checks expect 2), "+
		"CanonicalShardOrder allocs (S<=8 only) %s, UnicityTree allocs %s / bytes %s / time %s (expect 1 once validation is linear), view encode allocs %s / time %s (expect 1), "+
		"dispatch bytes k=1 %s (expect 1: one frame carries the view), k=S %s (expect 2: S frames each carry the view)\n",
		fmtSlope(xs, view), fmtSlope(xs, validAllocs), fmtSlope(xs, validNs), fmtSlope(xs[:4], orderAllocs[:4]), fmtSlope(xs, treeAllocs), fmtSlope(xs, treeBytes), fmtSlope(xs, treeNs),
		fmtSlope(xs, encAllocs), fmtSlope(xs, encNs), fmtSlope(xs, k1), fmtSlope(xs, kS))
	// the small-S range is dominated by fixed per-round costs (three further partitions, hashing setup),
	// so the asymptotic slopes are read over the upper range S = 16..256
	u := func(ys []float64) string { return fmtSlope(xs[4:], ys[4:]) }
	fmt.Fprintf(&sb, "Slopes over the upper range S = 16..256: view bytes %s, IsValid allocs %s / time %s, UnicityTree allocs %s / bytes %s / time %s, view encode allocs %s / time %s, dispatch bytes k=1 %s / k=S %s\n",
		u(view), u(validAllocs), u(validNs), u(treeAllocs), u(treeBytes), u(treeNs), u(encAllocs), u(encNs), u(k1), u(kS))
	t.Logf("shard count sweep (one changed shard; UnicityTree includes 3 further single-shard partitions)\n%s", sb.String())
}

// Sweep 2: responses per round k at fixed S. The inner view is encoded once per
// partition (all responses share one backing array); allocation grows only by the
// per-response certificate work.
func Test_ScalingChangedShards(t *testing.T) {
	requireMeasure(t)
	var sb strings.Builder
	for _, bits := range []int{2, 3} {
		S := 1 << bits
		sb.WriteString(fmt.Sprintf("\nS = %d\n| k (changed) | responses | distinct view arrays | build allocs | build B | build ns | V2 dispatch B (k frames) | view B in dispatch |\n|---|---|---|---|---|---|---|---|\n", S))
		var ks, allocs, bytesCol, dispatch []float64
		for k := 1; k <= S; k *= 2 {
			changed := make([]int, k)
			for i := range changed {
				changed[i] = i
			}
			blk := msBlock(t, msIRs[0], bits, changed...)
			crs, _, viewErrs, err := blk.ShardState.certificationResponsesWithViews(crypto.SHA256)
			require.NoError(t, err)
			require.Empty(t, viewErrs)
			require.Len(t, crs, k)
			distinct := map[*byte]bool{}
			total := 0
			for _, cr := range crs {
				distinct[&cr.PartitionView[0]] = true
				cr.UC.UnicitySeal = msSeal(blk.RootHash, 4)
				env, err := types.Cbor.Marshal(certification.NewCertificationResponseV2(cr))
				require.NoError(t, err)
				total += msFrame(env)
			}
			require.Len(t, distinct, 1, "one inner view encode per partition, shared by all k responses")
			c := costOf(func() { _, _, _, _ = blk.ShardState.certificationResponsesWithViews(crypto.SHA256) })
			fmt.Fprintf(&sb, "| %d | %d | %d | %.0f | %.0f | %.0f | %d | %d |\n", k, len(crs), len(distinct), c.allocs, c.bytes, c.nanos, total, k*len(crs[0].PartitionView))
			ks = append(ks, float64(k))
			allocs = append(allocs, c.allocs)
			bytesCol = append(bytesCol, c.bytes)
			dispatch = append(dispatch, float64(total))
		}
		fmt.Fprintf(&sb, "\nS=%d slopes over k: build allocs %s, build bytes %s (both < 1: a fixed per-round cost plus a per-response term), dispatch bytes %s (expect 1)\n",
			S, fmtSlope(ks, allocs), fmtSlope(ks, bytesCol), fmtSlope(ks, dispatch))
	}
	t.Logf("changed-shard sweep\n%s", sb.String())
}

// Sweep 3: LastCR retention over R rounds. Rotating updates leave each shard's LastCR
// pointing at the view of the round in which it last changed, so up to min(R, S)
// distinct vectors are retained; synchronous updates keep exactly one.
func Test_ScalingLastCRRetention(t *testing.T) {
	requireMeasure(t)
	var sb strings.Builder
	for _, bits := range []int{2, 3} {
		S := 1 << bits
		sb.WriteString(fmt.Sprintf("\nS = %d\n| R rounds | rotating: distinct views | rotating: retained view B | synchronous: distinct views | synchronous: retained view B |\n|---|---|---|---|---|\n", S))
		retained := func(blk *ExecutedBlock) (int, int) {
			distinct := map[*byte]int{}
			for _, si := range blk.ShardState.States {
				if si.LastCR != nil && len(si.LastCR.PartitionView) > 0 {
					distinct[&si.LastCR.PartitionView[0]] = len(si.LastCR.PartitionView)
				}
			}
			total := 0
			for _, n := range distinct {
				total += n
			}
			return len(distinct), total
		}
		round := func(blk *ExecutedBlock, changed []int, r int) {
			order := fxOrder(fxScheme(bits))
			blk.ShardState.Changed = ShardSet{}
			for _, i := range changed {
				si := blk.ShardState.States[types.PartitionShardID{PartitionID: fxPartition, ShardID: order[i].Key()}]
				ir := *si.IR
				si.IR = &ir
				si.IR.RoundNumber += uint64(r)
				si.TR.Round++
				blk.ShardState.Changed[types.PartitionShardID{PartitionID: fxPartition, ShardID: order[i].Key()}] = struct{}{}
			}
			ut, _, err := blk.ShardState.UnicityTree(crypto.SHA256)
			require.NoError(t, err)
			blk.RootHash = ut.RootHash()
			msCertify(t, blk, 4)
		}
		rot := msBlock(t, msIRs[0], bits, 0)
		syn := msBlock(t, msIRs[0], bits, 0)
		all := make([]int, S)
		for i := range all {
			all[i] = i
		}
		var rs, rotViews []float64
		for r := 1; r <= 64; r++ {
			round(rot, []int{(r - 1) % S}, r)
			round(syn, all, r)
			if r&(r-1) == 0 {
				rd, rb := retained(rot)
				sd, sb2 := retained(syn)
				fmt.Fprintf(&sb, "| %d | %d | %d | %d | %d |\n", r, rd, rb, sd, sb2)
				rs = append(rs, float64(r))
				rotViews = append(rotViews, float64(rd))
				require.Equal(t, 1, sd)
				require.Equal(t, min(r, S), rd)
			}
		}
		fmt.Fprintf(&sb, "\nS=%d: rotating retention grows linearly in R until it plateaus at S views (slope over R=1..S: %s), synchronous stays at one.\n", S, fmtSlope(rs[:bits+1], rotViews[:bits+1]))
	}
	t.Logf("LastCR retention sweep\n%s", sb.String())
}
