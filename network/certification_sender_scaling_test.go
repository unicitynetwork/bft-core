package network

import (
	"context"
	"runtime"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Serialization counts are independent of the recipient fan-out: one v2 encoding per dispatch, and the
// legacy (v1) encoding happens lazily - never when every recipient negotiates v2, once when any does not.
func Test_SendCertificationResponse_EncodeCountsIndependentOfFanout(t *testing.T) {
	view := bytesOf(0xAB, 2048)
	for _, fanout := range []int{1, 2, 4} {
		for _, withLegacy := range []bool{false, true} {
			senderPeer, senderNw := newCertSender(t)
			var frames *certificationFrames
			senderNw.framesHook = func(f *certificationFrames) { frames = f }
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
			require.EqualValues(t, 1, frames.v2Marshals.Load(), "fanout=%d", fanout)
			if withLegacy {
				require.EqualValues(t, 1, frames.v1Marshals.Load(), "fanout=%d", fanout)
			} else {
				require.Zero(t, frames.v1Marshals.Load(), "legacy frame must not be built when nobody needs it, fanout=%d", fanout)
			}
		}
	}
}

// When v2 cannot be used the legacy frame is the only one: built (once) and any error is synchronous.
func Test_SendCertificationResponse_LegacyBuiltEagerlyWhenV2Unusable(t *testing.T) {
	senderPeer, senderNw := newCertSender(t)
	var frames *certificationFrames
	senderNw.framesHook = func(f *certificationFrames) { frames = f }
	p, nw := newCertReceiver(t, senderPeer, recvLegacy)
	require.NoError(t, senderNw.SendCertificationResponse(context.Background(), testCertResponse(t, nil), p.ID()))
	recv(t, nw)
	require.EqualValues(t, 1, frames.v1Marshals.Load())
}

// The V2 envelope shares the sidecar bytes of the carrier instead of copying them: the allocation of
// building the v2 frame is smaller than the copying reference by about one view, for every view size.
func Test_CertificationFrames_SidecarBytesAreShared(t *testing.T) {
	measure := func(f func()) uint64 {
		var a, b runtime.MemStats
		runtime.ReadMemStats(&a)
		f()
		runtime.ReadMemStats(&b)
		return b.TotalAlloc - a.TotalAlloc
	}
	sharedPath := func(cr *certification.CertificationResponse) func() {
		return func() {
			f := &certificationFrames{cr: cr}
			_, err := f.v2Frame()
			require.NoError(t, err)
		}
	}
	copyingPath := func(cr *certification.CertificationResponse) func() { // the previous behavior: copy the view into the envelope
		return func() {
			env := certification.NewCertificationResponseV2(cr)
			data, err := types.Cbor.Marshal(env)
			require.NoError(t, err)
			_ = frameMsg(data)
		}
	}
	for _, w := range []int{4 << 10, 8 << 10, 16 << 10} {
		cr := testCertResponse(t, bytesOf(0x5A, w))
		// warm up (encoder caches, lazy initialization) before counting bytes
		sharedPath(cr)()
		copyingPath(cr)()
		shared, copying := measure(sharedPath(cr)), measure(copyingPath(cr))
		require.GreaterOrEqual(t, int64(copying)-int64(shared), int64(w)*8/10, "W=%d shared=%d copying=%d", w, shared, copying)
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
