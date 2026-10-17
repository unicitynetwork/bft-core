package network

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// marshalCounts counts the CBOR encodings of one dispatch. The hook is per network (nil in production) and
// the counters are atomic: the encodings may be requested concurrently by the sends to the recipients.
type marshalCounts struct{ v1, v2 atomic.Int64 }

// countMarshals counts the encodings of the next dispatch of nw.
func countMarshals(nw *LibP2PNetwork) *marshalCounts {
	c := &marshalCounts{}
	nw.framesHook = func(f *certificationFrames) {
		f.marshalHook = func(v2 bool) {
			if v2 {
				c.v2.Add(1)
			} else {
				c.v1.Add(1)
			}
		}
	}
	return c
}

// Serialization counts are independent of the recipient fan-out: one v2 encoding per dispatch, and the
// legacy (v1) encoding happens lazily - never when every recipient negotiates v2, once when any does not.
func Test_SendCertificationResponse_EncodeCountsIndependentOfFanout(t *testing.T) {
	view := bytesOf(0xAB, 2048)
	for _, fanout := range []int{1, 2, 4} {
		for _, withLegacy := range []bool{false, true} {
			senderPeer, senderNw := newCertSender(t)
			frames := countMarshals(senderNw)
			var nws []*LibP2PNetwork
			var ids []peer.ID
			for i := 0; i < fanout; i++ {
				kind := recvV2Only
				if withLegacy && i == 0 {
					kind = recvLegacy
				}
				p, nw := newCertReceiver(t, senderPeer, kind)
				nws, ids = append(nws, nw), append(ids, p.ID())
			}
			require.NoError(t, senderNw.SendCertificationResponse(context.Background(), testCertResponse(t, view), ids...))
			for _, nw := range nws {
				recv(t, nw)
			}
			require.EqualValues(t, 1, frames.v2.Load(), "fanout=%d", fanout)
			if withLegacy {
				require.EqualValues(t, 1, frames.v1.Load(), "fanout=%d", fanout)
			} else {
				require.Zero(t, frames.v1.Load(), "legacy frame must not be built when nobody needs it, fanout=%d", fanout)
			}
		}
	}
}

// When v2 cannot be used the legacy frame is the only one: built (once) and any error is synchronous.
func Test_SendCertificationResponse_LegacyBuiltEagerlyWhenV2Unusable(t *testing.T) {
	senderPeer, senderNw := newCertSender(t)
	frames := countMarshals(senderNw)
	p, nw := newCertReceiver(t, senderPeer, recvLegacy)
	require.NoError(t, senderNw.SendCertificationResponse(context.Background(), testCertResponse(t, nil), p.ID()))
	recv(t, nw)
	require.EqualValues(t, 1, frames.v1.Load())
}

// The V2 envelope shares the sidecar bytes of the carrier instead of copying them: the bytes allocated per
// built v2 frame are smaller than the copying reference by about one view, for every view size. Measured
// with testing.Benchmark (B/op averaged over many iterations, so it is not a single noisy process-wide delta).
func Test_CertificationFrames_SidecarBytesAreShared(t *testing.T) {
	bytesPerOp := func(f func()) int64 {
		return testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				f()
			}
		}).AllocedBytesPerOp()
	}
	for _, w := range []int{4 << 10, 8 << 10, 16 << 10} {
		cr := testCertResponse(t, bytesOf(0x5A, w))
		shared := bytesPerOp(func() {
			f := &certificationFrames{cr: cr}
			if _, err := f.v2Frame(); err != nil {
				panic(err)
			}
		})
		copying := bytesPerOp(func() { // the previous behavior: copy the view into the envelope
			env := certification.NewCertificationResponseV2(cr)
			data, err := types.Cbor.Marshal(env)
			if err != nil {
				panic(err)
			}
			_ = frameMsg(data)
		})
		require.GreaterOrEqual(t, copying-shared, int64(w)*8/10, "W=%d shared=%d B/op copying=%d B/op", w, shared, copying)
		// the carrier backing array is shared with the envelope
		env := certification.NewCertificationResponseV2Shared(cr)
		require.Same(t, &cr.PartitionView[0], &env.PartitionView[0])
		// and the copy constructor stays independent
		require.NotSame(t, &cr.PartitionView[0], &certification.NewCertificationResponseV2(cr).PartitionView[0])
	}
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
