package storage

import (
	"crypto"
	"fmt"
	"math"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
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

// msHarnessLeaves prepares the canonical leaf vector once (outside any timed region).
func msHarnessLeaves(t testing.TB, inputs []types.ShardTreeInput) msViewRaw {
	var scheme types.ShardingScheme
	for _, in := range inputs {
		scheme = append(scheme, in.Shard)
	}
	if len(scheme) == 1 {
		scheme = types.ShardingScheme{} // a single shard partition has the empty scheme
	}
	order := fxOrder(scheme) // left-to-right prefix order (the production helper caps the scheme at 8 shards)
	byShard := map[string]types.ShardTreeInput{}
	for _, in := range inputs {
		byShard[in.Shard.Key()] = in
	}
	raw := msViewRaw{Version: types.PartitionViewVersionV1, PartitionID: fxPartition}
	for _, id := range order {
		in := byShard[id.Key()]
		raw.Leaves = append(raw.Leaves, types.PartitionViewLeafV1{ShardID: in.Shard, InputRecord: in.IR, TRHash: in.TRHash, ShardConfHash: in.ShardConfHash})
	}
	return raw
}

func msEncode(t testing.TB, raw msViewRaw) []byte {
	data, err := types.Cbor.Marshal(raw)
	require.NoError(t, err)
	return data
}

// timeSpread runs fn in samples independent timing batches and returns the median, min and max
// per-call nanoseconds. Times are relative information only (shared, loaded host).
func timeSpread(samples int, fn func()) (median, lo, hi float64) {
	ns := make([]float64, samples)
	for i := range ns {
		ns[i] = costOf(fn).nanos
	}
	slices.Sort(ns)
	return ns[len(ns)/2], ns[0], ns[len(ns)-1]
}

// dispatchBytes marshals every response as the V2 frame the sender would write and returns the total
// and the size of one frame: measured over real responses, not computed from one frame.
func dispatchBytes(t testing.TB, blk *ExecutedBlock, view []byte) (total, first int) {
	crs, _, _, err := blk.ShardState.certificationResponsesWithViews(crypto.SHA256)
	require.NoError(t, err)
	for i, cr := range crs {
		cr.UC.UnicitySeal = msSeal(blk.RootHash, 4)
		if len(cr.PartitionView) == 0 {
			cr.PartitionView = view // above the production cap the producer omits the view; attach the harness view
		}
		env, err := types.Cbor.Marshal(certification.NewCertificationResponseV2(cr))
		require.NoError(t, err)
		total += msFrame(env)
		if i == 0 {
			first = msFrame(env)
		}
	}
	return total, first
}

// Sweep 1: shard count S. Counters: tree hash nodes, allocations, encoded bytes, real dispatch bytes
// for one response (k=1) and for every shard responding (k=S). S <= 8 is the production range; larger S
// uses the uncapped but byte-identical encoding and measures algorithms only. Validation comparisons
// are counted by bft-go-base's own test (TestShardingSchemeValidation_CountedWork), which this sweep
// does not repeat; the IsValid time columns are relative information with their spread.
func Test_ScalingShardCount(t *testing.T) {
	requireMeasure(t)
	var sb strings.Builder
	sb.WriteString("| S | view B | tree hash nodes (2S-1) | UnicityTree allocs | UnicityTree B | view encode allocs (marshal only) | V2 frame B | dispatch B, k=1 | dispatch B, k=S (all responses summed) | IsValid time ns (median, min-max of 5) | UnicityTree time ns (median, min-max) |\n|---|---|---|---|---|---|---|---|---|---|---|\n")
	var xs, view, nodes, treeAllocs, treeBytes, encAllocs, k1, kS []float64
	var validT, treeT []float64
	for bits := 0; bits <= 8; bits++ {
		S := 1 << bits
		one := msBlock(t, msIRs[0], bits, 0)
		all := make([]int, S)
		for i := range all {
			all[i] = i
		}
		full := msBlock(t, msIRs[0], bits, all...)
		scheme := fxScheme(bits)

		_, trees, inputs, err := one.ShardState.unicityTree(crypto.SHA256)
		require.NoError(t, err)
		hashNodes := len(trees[fxPartition])
		require.Equal(t, 2*S-1, hashNodes, "a shard tree over S shards hashes 2S-1 nodes")
		raw := msHarnessLeaves(t, inputs[fxPartition])
		viewBytes := msEncode(t, raw)
		if S <= types.MaxPartitionViewLeaves { // the harness encoding is the production encoding where both exist
			prod, err := encodePartitionView(fxPartition, inputs[fxPartition], nil)
			require.NoError(t, err)
			require.Equal(t, prod, viewBytes)
		}
		total, first := dispatchBytes(t, full, viewBytes)

		tree := costOf(func() { _, _, _ = one.ShardState.UnicityTree(crypto.SHA256) })
		enc := costOf(func() { _ = msEncode(t, raw) })
		vMed, vLo, vHi := timeSpread(5, func() { _ = scheme.IsValid() })
		tMed, tLo, tHi := timeSpread(5, func() { _, _, _ = one.ShardState.UnicityTree(crypto.SHA256) })

		fmt.Fprintf(&sb, "| %d | %d | %d | %.0f | %.0f | %.0f | %d | %d | %d | %.0f (%.0f-%.0f) | %.0f (%.0f-%.0f) |\n",
			S, len(viewBytes), hashNodes, tree.allocs, tree.bytes, enc.allocs, first, first, total, vMed, vLo, vHi, tMed, tLo, tHi)
		xs = append(xs, float64(S))
		view = append(view, float64(len(viewBytes)))
		nodes = append(nodes, float64(hashNodes))
		treeAllocs = append(treeAllocs, tree.allocs)
		treeBytes = append(treeBytes, tree.bytes)
		encAllocs = append(encAllocs, enc.allocs)
		k1 = append(k1, float64(first))
		kS = append(kS, float64(total))
		validT = append(validT, vMed)
		treeT = append(treeT, tMed)
	}
	u := func(ys []float64) string { return fmtSlope(xs[4:], ys[4:]) }
	fmt.Fprintf(&sb, "\nCounter slopes over S = 1..256 (whole range): view bytes %s, tree hash nodes %s, view encode allocations %s.\n", fmtSlope(xs, view), fmtSlope(xs, nodes), fmtSlope(xs, encAllocs))
	fmt.Fprintf(&sb, "Counter slopes over the upper range S = 16..256 (the small-S range is dominated by fixed per-round costs): view bytes %s (expect 1), tree hash nodes %s (expect 1), UnicityTree allocations %s / bytes %s (expect 1), "+
		"view encode allocations %s (expect 1), dispatch bytes for one response (k=1) %s (expect 1: one frame carries the view) and for all S responses (k=S) %s (expect 2: S frames each carry the S-leaf view).\n",
		u(view), u(nodes), u(treeAllocs), u(treeBytes), u(encAllocs), u(k1), u(kS))
	fmt.Fprintf(&sb, "Relative-time slopes, upper range (medians of 5, loaded host, indicative only): IsValid %s, UnicityTree %s.\n", u(validT), u(treeT))
	t.Logf("shard count sweep (one changed shard for the tree and view; every shard changed for k=S; UnicityTree includes 3 further single-shard partitions)\n%s", sb.String())
}

// Sweep 2: responses per round k at fixed S. The inner view is encoded exactly once per changed
// partition (counted, not inferred) whatever k, and all responses share the encoded bytes.
func Test_ScalingChangedShards(t *testing.T) {
	requireMeasure(t)
	var sb strings.Builder
	for _, bits := range []int{2, 3} {
		S := 1 << bits
		sb.WriteString(fmt.Sprintf("\nS = %d\n| k (changed) | responses | inner view encodes (counted) | distinct view arrays | build allocs | build B | V2 dispatch B (measured over the k frames) |\n|---|---|---|---|---|---|---|\n", S))
		var ks, allocs, bytesCol, dispatch []float64
		for k := 1; k <= S; k *= 2 {
			changed := make([]int, k)
			for i := range changed {
				changed[i] = i
			}
			blk := msBlock(t, msIRs[0], bits, changed...)
			var encodes atomic.Int64
			blk.ShardState.viewEncodeHook = func(types.PartitionID) { encodes.Add(1) }
			crs, _, viewErrs, err := blk.ShardState.certificationResponsesWithViews(crypto.SHA256)
			require.NoError(t, err)
			require.Empty(t, viewErrs)
			require.Len(t, crs, k)
			blk.ShardState.viewEncodeHook = nil
			require.EqualValues(t, 1, encodes.Load(), "k=%d: the view is encoded once per changed partition, not once per response", k)
			distinct := map[*byte]bool{}
			for _, cr := range crs {
				distinct[&cr.PartitionView[0]] = true
			}
			require.Len(t, distinct, 1)
			total, _ := dispatchBytes(t, blk, nil)
			c := costOf(func() { _, _, _, _ = blk.ShardState.certificationResponsesWithViews(crypto.SHA256) })
			fmt.Fprintf(&sb, "| %d | %d | %d | %d | %.0f | %.0f | %d |\n", k, len(crs), encodes.Load(), len(distinct), c.allocs, c.bytes, total)
			ks = append(ks, float64(k))
			allocs = append(allocs, c.allocs)
			bytesCol = append(bytesCol, c.bytes)
			dispatch = append(dispatch, float64(total))
		}
		fmt.Fprintf(&sb, "\nS=%d slopes over k: inner view encodes 0 (always 1), build allocs %s, build bytes %s (both < 1: a fixed per-round cost plus a small per-response term), dispatch bytes %s (expect 1)\n",
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
