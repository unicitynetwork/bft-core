package network

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	libp2pNetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
)

// Receiver fan-out of one certification response, measured by actually sending it to f
// recipients (see docs/uc-consolidation-measurements.md). Opt in with UC_MEASURE=1.
//
// Each recipient is a real libp2p peer with a raw stream handler for the V2 protocol that
// counts the bytes the sender writes into its stream (varint length prefix plus payload).
// The marshal counters are the sender's own (countMarshals, a hook on the dispatch).
func Test_ScalingRecipientFanout(t *testing.T) {
	if os.Getenv("UC_MEASURE") == "" {
		t.Skip("set UC_MEASURE=1 to run the scaling measurements")
	}
	view := make([]byte, 1544) // typical 8-shard view
	var sb strings.Builder
	sb.WriteString("| recipients f | V2 marshals (counted) | V1 marshals (counted) | streams that received a frame | bytes written to the f streams | bytes per stream |\n|---|---|---|---|---|---|\n")
	var firstPer int64
	for _, f := range []int{1, 2, 4, 8, 16, 32} {
		senderPeer, senderNw := newCertSender(t)
		frames := countMarshals(senderNw)

		var total, streams atomic.Int64
		var wg sync.WaitGroup
		wg.Add(f)
		ids := make([]peer.ID, 0, f)
		for i := 0; i < f; i++ {
			p := createPeer(t)
			senderPeer.Network().Peerstore().AddAddrs(p.ID(), p.MultiAddresses(), peerstore.PermanentAddrTTL)
			var once sync.Once
			p.RegisterProtocolHandler(ProtocolUnicityCertificatesV2, func(s libp2pNetwork.Stream) {
				defer once.Do(wg.Done)
				defer s.Close()
				r := bufio.NewReader(s)
				length, err := binary.ReadUvarint(r)
				if err != nil {
					return
				}
				var prefix [binary.MaxVarintLen64]byte
				n, err := io.CopyN(io.Discard, r, int64(length))
				if err != nil {
					return
				}
				total.Add(int64(binary.PutUvarint(prefix[:], length)) + n)
				streams.Add(1)
			})
			ids = append(ids, p.ID())
		}
		require.NoError(t, senderNw.SendCertificationResponse(context.Background(), testCertResponse(t, view), ids...))
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Fatalf("f=%d: only %d of %d streams completed", f, streams.Load(), f)
		}
		require.EqualValues(t, f, streams.Load())
		require.EqualValues(t, 1, frames.v2.Load(), "f=%d: one V2 encoding per dispatch", f)
		require.Zero(t, frames.v1.Load(), "f=%d: the legacy frame is not built when every recipient negotiates V2", f)
		per := total.Load() / streams.Load()
		if firstPer == 0 {
			firstPer = per
		}
		require.Equal(t, firstPer, per)
		fmt.Fprintf(&sb, "| %d | %d | %d | %d | %d | %d |\n", f, frames.v2.Load(), frames.v1.Load(), streams.Load(), total.Load(), per)
	}
	t.Logf("recipient fan-out: real sends over libp2p\n%s", sb.String())
}
