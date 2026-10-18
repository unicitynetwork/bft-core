package network

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	libp2pprotocol "github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	msmux "github.com/multiformats/go-multistream"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// streamStats describes one outbound certificate stream as seen by the stream muxer, the
// message counts do not depend on timing.
type streamStats struct {
	writes int // Write calls (the multistream header is flushed together with the payload when lazy)
	// bytes of the first write, and whether it opens with the multistream header
	firstWriteLen    int
	firstWriteHeader bool
	// reads which completed before the first write began: the listener greets a new stream with its multistream header
	// at once, and the lazy handshake reader, which starts inside the first Write, may consume it before the Write
	// reaches the muxer. It answers nothing the sender sent, so it is not a round trip.
	readsBeforeFirstWrite int
	// reads which completed before the last write began, other than that greeting: replies the sender waited for
	// before it wrote again, ie negotiation round trips
	repliesBeforeLastWrite int
	reads                  int
}

// countingMuxer wraps yamux and records the outbound streams carrying certificates.
type countingMuxer struct {
	delay   time.Duration // one way latency injected on certificate streams
	mu      sync.Mutex
	streams []*countingStream
}

func (m *countingMuxer) NewConn(c net.Conn, isServer bool, scope network.PeerScope) (network.MuxedConn, error) {
	mc, err := yamux.DefaultTransport.NewConn(c, isServer, scope)
	if err != nil {
		return nil, err
	}
	return &countingConn{MuxedConn: mc, m: m}, nil
}

// stats returns the certificate streams opened since the last call to reset.
func (m *countingMuxer) stats() (res []streamStats) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.streams {
		s.mu.Lock()
		if s.cert {
			res = append(res, s.streamStats)
		}
		s.mu.Unlock()
	}
	return res
}

func (m *countingMuxer) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streams = nil
}

type countingConn struct {
	network.MuxedConn
	m *countingMuxer
}

func (c *countingConn) OpenStream(ctx context.Context) (network.MuxedStream, error) {
	s, err := c.MuxedConn.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	cs := &countingStream{MuxedStream: s, delay: c.m.delay}
	c.m.mu.Lock()
	c.m.streams = append(c.m.streams, cs)
	c.m.mu.Unlock()
	return cs, nil
}

type countingStream struct {
	network.MuxedStream
	delay time.Duration
	mu    sync.Mutex
	cert  bool
	streamStats
}

func (s *countingStream) Write(b []byte) (int, error) {
	s.mu.Lock()
	if s.writes == 0 {
		if bytes.Contains(b, []byte("/ab/certificates/")) {
			s.cert = true
		}
		s.firstWriteLen = len(b)
		s.firstWriteHeader = bytes.HasPrefix(b, []byte("\x13/multistream/1.0.0\n"))
		s.readsBeforeFirstWrite = s.reads
	}
	s.writes++
	s.repliesBeforeLastWrite = s.reads - s.readsBeforeFirstWrite
	cert := s.cert
	s.mu.Unlock()
	if cert {
		time.Sleep(s.delay)
	}
	return s.MuxedStream.Write(b)
}

func (s *countingStream) Read(b []byte) (int, error) {
	n, err := s.MuxedStream.Read(b)
	if n > 0 {
		s.mu.Lock()
		s.reads++
		cert := s.cert
		s.mu.Unlock()
		if cert {
			time.Sleep(s.delay)
		}
	}
	return n, err
}

func newCountingCertSender(t *testing.T) (*Peer, *LibP2PNetwork, *countingMuxer) {
	cm := &countingMuxer{}
	conf, err := NewPeerConfiguration(randomTestAddressStr, nil, generateKeyPair(t), nil, nil)
	require.NoError(t, err)
	p, err := newPeer(context.Background(), conf, logger.New(t), nil, libp2p.Muxer("/yamux/1.0.0", cm))
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	nw, err := NewLibP2PRootChainNetwork(p, 10, time.Second, observability.Default(t))
	require.NoError(t, err)
	return p, nw, cm
}

func Test_SendCertificationResponse_NoNegotiationRoundTripOnWarmConnection(t *testing.T) {
	senderPeer, senderNw, cm := newCountingCertSender(t)
	kinds := map[string]recvKind{"v1 only": recvLegacy, "v2 and v1": recvBoth, "v2 only": recvV2Only}
	for name, kind := range kinds {
		t.Run(name, func(t *testing.T) {
			p, nw := newCertReceiver(t, senderPeer, kind)
			// first send establishes the connection (and runs identify), the following ones are steady state
			require.NoError(t, senderNw.SendCertificationResponse(context.Background(), testCertResponse(t, []byte{1}), p.ID()))
			recv(t, nw)
			cm.reset()
			const sends = 5
			for i := 0; i < sends; i++ {
				require.NoError(t, senderNw.SendCertificationResponse(context.Background(), testCertResponse(t, []byte{1}), p.ID()))
				got := recv(t, nw)
				if kind == recvLegacy {
					require.IsType(t, &certification.CertificationResponse{}, got)
				} else {
					require.IsType(t, &certification.CertificationResponseV2{}, got)
				}
			}
			requireNoMore(t, nw) // exactly one handler invocation per send
			st := cm.stats()
			require.Len(t, st, sends)
			for _, s := range st {
				require.Equal(t, 1, s.writes, "header and payload must be a single write")
				require.True(t, s.firstWriteHeader, "the single write opens with the multistream header")
				require.Greater(t, s.firstWriteLen, 64, "the single write carries the payload after the header and protocol")
				require.Zero(t, s.repliesBeforeLastWrite, "no negotiation exchange before the payload")
			}
		})
	}
}

// Positive control of the counters above: when the sender does not know the receiver's protocols it negotiates
// explicitly, and the counters see it: more than one write, with replies read before the last one.
func Test_SendCertificationResponse_ExplicitNegotiationIsCounted(t *testing.T) {
	senderPeer, senderNw, cm := newCountingCertSender(t)
	p, nw := newCertReceiver(t, senderPeer, recvLegacy)
	require.NoError(t, senderNw.SendCertificationResponse(context.Background(), testCertResponse(t, []byte{1}), p.ID()))
	recv(t, nw)
	cm.reset()
	// forget what identify said: the next send has to ask (the receiver is v1 only, so v2 is refused first)
	require.NoError(t, senderPeer.host.Peerstore().SetProtocols(p.ID()))
	require.NoError(t, senderNw.SendCertificationResponse(context.Background(), testCertResponse(t, []byte{1}), p.ID()))
	recv(t, nw)
	require.Eventually(t, func() bool { return len(cm.stats()) == 1 }, 3*time.Second, 10*time.Millisecond)
	st := cm.stats()[0]
	require.Greater(t, st.writes, 1, "explicit negotiation writes more than once")
	require.Positive(t, st.repliesBeforeLastWrite, "and waits for a reply before the last write")
}

// When the receiver advertises none of the protocols libp2p negotiates explicitly, which is
// the positive control of the counter above (this is not the steady state).
func Test_SendCertificationResponse_AdvertisesNeither(t *testing.T) {
	senderPeer, senderNw, cm := newCountingCertSender(t)
	p := createPeer(t)
	senderPeer.host.Peerstore().AddAddrs(p.ID(), p.MultiAddresses(), peerstore.PermanentAddrTTL)
	// no handlers for certificates at all: nothing to deliver but the explicit negotiation is observable
	err := senderNw.SendCertificationResponse(context.Background(), testCertResponse(t, nil), p.ID())
	require.NoError(t, err)
	require.Eventually(t, func() bool { return len(cm.stats()) == 1 }, 3*time.Second, 10*time.Millisecond)
	// let the sender goroutine finish
	time.Sleep(100 * time.Millisecond)
	st := cm.stats()[0]
	require.Positive(t, st.reads, "explicit negotiation waits for the reply")
}

func newKeyedReceiver(t *testing.T, sender *Peer, kind recvKind, keys *PeerKeyPair) (*Peer, *LibP2PNetwork) {
	conf, err := NewPeerConfiguration(randomTestAddressStr, nil, keys, nil, nil)
	require.NoError(t, err)
	p, err := NewPeer(context.Background(), conf, logger.New(t), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return registerReceiver(t, sender, p, kind)
}

// A receiver which restarts (reconnects) with another protocol set is served with the protocol
// it announced on the new connection.
func Test_SendCertificationResponse_ReceiverRestartedWithOtherProtocols(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before, after recvKind
	}{
		{"v1 only restarts as v2", recvLegacy, recvBoth},
		{"v2 restarts as v1 only", recvBoth, recvLegacy},
		{"v2 only restarts as v1 only", recvV2Only, recvLegacy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			senderPeer, senderNw, _ := newCountingCertSender(t)
			keys := generateKeyPair(t)
			p, nw := newKeyedReceiver(t, senderPeer, tc.before, keys)
			send := func(id peer.ID, want recvKind, nw *LibP2PNetwork) {
				require.NoError(t, senderNw.SendCertificationResponse(context.Background(), testCertResponse(t, []byte{1}), id))
				if want == recvLegacy {
					require.IsType(t, &certification.CertificationResponse{}, recv(t, nw))
				} else {
					require.IsType(t, &certification.CertificationResponseV2{}, recv(t, nw))
				}
				requireNoMore(t, nw)
			}
			send(p.ID(), tc.before, nw)
			send(p.ID(), tc.before, nw) // warm

			require.NoError(t, p.Close())
			p2, nw2 := newKeyedReceiver(t, senderPeer, tc.after, keys)
			require.Equal(t, p.ID(), p2.ID())
			send(p2.ID(), tc.after, nw2)
		})
	}
}

// Capabilities cached in the peerstore cannot outlive the connection: they are replaced by
// what the peer announces on the next connection.
func Test_SendCertificationResponse_StaleCachedCapabilityDoesNotSurviveReconnect(t *testing.T) {
	senderPeer, senderNw, _ := newCountingCertSender(t)
	p, nw := newCertReceiver(t, senderPeer, recvLegacy)
	send := func() {
		require.NoError(t, senderNw.SendCertificationResponse(context.Background(), testCertResponse(t, []byte{1, 2, 3}), p.ID()))
		got, ok := recv(t, nw).(*certification.CertificationResponse)
		require.True(t, ok, "v1 only receiver gets v1")
		require.Equal(t, uint64(7), got.Technical.Round)
		requireNoMore(t, nw)
	}
	send() // connects
	// stale knowledge (e.g. from before a downgrade), then the connection is re-established
	require.NoError(t, senderPeer.host.Peerstore().SetProtocols(p.ID(), ProtocolUnicityCertificatesV2, ProtocolUnicityCertificates))
	require.NoError(t, senderPeer.host.Network().ClosePeer(p.ID()))
	require.Eventually(t, func() bool { return len(senderPeer.host.Network().ConnsToPeer(p.ID())) == 0 }, 3*time.Second, 10*time.Millisecond)
	send()
	protos, err := senderPeer.host.Peerstore().GetProtocols(p.ID())
	require.NoError(t, err)
	require.NotContains(t, protos, ProtocolUnicityCertificatesV2)
}

// A receiver which announces V2 but does not handle it (any more) on the established connection:
// the refusal is reported and nothing is resent, no handler is invoked twice.
func Test_SendCertificationResponse_RefusalIsNotRetried(t *testing.T) {
	senderPeer, senderNw, _ := newCountingCertSender(t)
	p, nw := newCertReceiver(t, senderPeer, recvBoth)
	require.NoError(t, senderNw.SendCertificationResponse(context.Background(), testCertResponse(t, nil), p.ID()))
	recv(t, nw)
	// removed from the mux directly: unlike RemoveStreamHandler this emits no EvtLocalProtocolsUpdated,
	// so identify does not push and the sender deterministically still believes V2 is served
	p.host.Mux().RemoveHandler(ProtocolUnicityCertificatesV2)
	sendCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := senderNw.sendCertificationFrame(sendCtx, p.ID(), []string{ProtocolUnicityCertificatesV2, ProtocolUnicityCertificates}, ProtocolUnicityCertificates, &certificationFrames{cr: testCertResponse(t, nil)})
	require.Error(t, err)
	// the refusal is reported as "refused" if the reply arrives before the receiver's reset of the
	// stream, in both cases the error names the protocol and the certificate is not resent
	require.Contains(t, err.Error(), ProtocolUnicityCertificatesV2)
	requireNoMore(t, nw)
	require.True(t, lazyHandshakeRefused(msmux.ErrNotSupported[libp2pprotocol.ID]{}))
	require.False(t, lazyHandshakeRefused(io.EOF))
}

// Optional: with 120 ms one way latency and a 300 ms send timeout the certificate is delivered
// on the lazy path (header and payload are sent at once). Explicit negotiation would need 3 one
// way trips (360 ms) for the payload to arrive.
func Test_SendCertificationResponse_DeliveredWithLatencyWithinTimeout(t *testing.T) {
	cm := &countingMuxer{delay: 120 * time.Millisecond}
	conf, err := NewPeerConfiguration(randomTestAddressStr, nil, generateKeyPair(t), nil, nil)
	require.NoError(t, err)
	senderPeer, err := newPeer(context.Background(), conf, logger.New(t), nil, libp2p.Muxer("/yamux/1.0.0", cm))
	require.NoError(t, err)
	t.Cleanup(func() { _ = senderPeer.Close() })
	senderNw, err := NewLibP2PRootChainNetwork(senderPeer, 10, 300*time.Millisecond, observability.Default(t))
	require.NoError(t, err)

	for _, kind := range []recvKind{recvLegacy, recvBoth} {
		p, nw := newCertReceiver(t, senderPeer, kind)
		// connection setup and identify are not subject to the send timeout
		require.NoError(t, senderPeer.host.Connect(context.Background(), peer.AddrInfo{ID: p.ID()}))
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		err := senderNw.sendCertificationFrame(ctx, p.ID(), []string{ProtocolUnicityCertificatesV2, ProtocolUnicityCertificates},
			ProtocolUnicityCertificates, &certificationFrames{cr: testCertResponse(t, nil)})
		cancel()
		require.NoError(t, err)
		recv(t, nw)
		requireNoMore(t, nw)
	}
}

// A receiver which is connected and identified but no longer services new streams: the send is
// bounded by the context (both lazy handshake directions), returns the error and is not resent.
func Test_SendCertificationResponse_StalledReceiverIsBounded(t *testing.T) {
	senderPeer, senderNw, cm := newCountingCertSender(t)
	p, nw := newCertReceiver(t, senderPeer, recvBoth)
	require.NoError(t, senderNw.SendCertificationResponse(context.Background(), testCertResponse(t, nil), p.ID()))
	recv(t, nw)
	cm.reset()
	// the swarm hands new streams to a handler which never reads or negotiates
	p.host.Network().SetStreamHandler(func(network.Stream) {})

	frames := &certificationFrames{cr: testCertResponse(t, nil)}
	frames.v2Once.Do(func() { frames.v2 = frameMsg(bytes.Repeat([]byte{1}, 1<<20)) })

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- senderNw.sendCertificationFrame(ctx, p.ID(), []string{ProtocolUnicityCertificatesV2, ProtocolUnicityCertificates}, ProtocolUnicityCertificates, frames)
	}()
	select {
	case err := <-done:
		require.Error(t, err)
		require.Contains(t, err.Error(), ProtocolUnicityCertificatesV2)
	case <-time.After(2 * time.Second):
		t.Fatal("send not bounded by its deadline")
	}
	requireNoMore(t, nw)
	require.Len(t, cm.stats(), 1, "one stream, nothing resent")
}
