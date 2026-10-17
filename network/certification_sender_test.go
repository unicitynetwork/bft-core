package network

import (
	"bufio"
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

func testCertResponse(t *testing.T, view []byte) *certification.CertificationResponse {
	cr := &certification.CertificationResponse{
		Partition: 1,
		UC: types.UnicityCertificate{
			Version:                1,
			UnicityTreeCertificate: &types.UnicityTreeCertificate{Version: 1, Partition: 1},
		},
		PartitionView: view,
	}
	require.NoError(t, cr.SetTechnicalRecord(certification.TechnicalRecord{Round: 7, Epoch: 1, Leader: "1", StatHash: []byte{1}, FeeHash: []byte{2}}))
	return cr
}

type recvKind int

const (
	recvLegacy recvKind = iota // old recipient, v1 only
	recvBoth                   // updated recipient, v2 and v1
	recvV2Only
)

func newCertReceiver(t *testing.T, sender *Peer, kind recvKind) (*Peer, *LibP2PNetwork) {
	return registerReceiver(t, sender, createPeer(t), kind)
}

func registerReceiver(t *testing.T, sender *Peer, p *Peer, kind recvKind) (*Peer, *LibP2PNetwork) {
	nw, err := NewLibP2PNetwork(p, 10, observability.Default(t))
	require.NoError(t, err)
	sender.Network().Peerstore().AddAddrs(p.ID(), p.MultiAddresses(), peerstore.PermanentAddrTTL)
	var descs []ReceiveProtocolDescription
	if kind != recvV2Only {
		descs = append(descs, ReceiveProtocolDescription{ProtocolID: ProtocolUnicityCertificates, TypeFn: func() any { return &certification.CertificationResponse{} }})
	}
	if kind != recvLegacy {
		descs = append(descs, ReceiveProtocolDescription{ProtocolID: ProtocolUnicityCertificatesV2, MaxFrameSize: certification.MaxCertificationResponseV2Frame,
			TypeFn: func() any { return &certification.CertificationResponseV2{} }})
	}
	require.NoError(t, nw.RegisterReceiveProtocols(descs))
	return p, nw
}

func newCertSender(t *testing.T) (*Peer, *LibP2PNetwork) {
	p := createPeer(t)
	nw, err := NewLibP2PRootChainNetwork(p, 10, time.Second, observability.Default(t))
	require.NoError(t, err)
	return p, nw
}

func recv(t *testing.T, nw *LibP2PNetwork) any {
	select {
	case m := <-nw.ReceivedChannel():
		return m
	case <-time.After(3 * time.Second):
		t.Fatal("no message before timeout")
		return nil
	}
}

func requireNoMore(t *testing.T, nw *LibP2PNetwork) {
	select {
	case m := <-nw.ReceivedChannel():
		t.Fatalf("unexpected extra message %T", m)
	case <-time.After(300 * time.Millisecond):
	}
}

func Test_SendCertificationResponse_Negotiation(t *testing.T) {
	view := []byte{0x83, 0x01, 0x01, 0x80}
	cr := testCertResponse(t, view)

	senderPeer, senderNw := newCertSender(t)
	_, oldNw := newCertReceiver(t, senderPeer, recvLegacy)
	_, newNw := newCertReceiver(t, senderPeer, recvBoth)
	_, v2Nw := newCertReceiver(t, senderPeer, recvV2Only)

	oldID, newID, v2ID := oldNw.self.ID(), newNw.self.ID(), v2Nw.self.ID()
	require.NoError(t, senderNw.SendCertificationResponse(context.Background(), cr, oldID, newID, v2ID))

	// new root -> old recipient: legacy four element response, no view
	got := recv(t, oldNw)
	legacy, ok := got.(*certification.CertificationResponse)
	require.True(t, ok, "got %T", got)
	require.Nil(t, legacy.PartitionView)
	wantLegacy, _ := types.Cbor.Marshal(cr)
	gotLegacy, _ := types.Cbor.Marshal(legacy)
	require.Equal(t, wantLegacy, gotLegacy)

	// new -> new, and v2 only: V2 with the view as carrier
	for _, nw := range []*LibP2PNetwork{newNw, v2Nw} {
		v2, ok := recv(t, nw).(*certification.CertificationResponseV2)
		require.True(t, ok)
		require.Equal(t, view, v2.PartitionView)
		require.NoError(t, v2.Legacy().IsValid())
	}
	// exactly one certificate per recipient
	requireNoMore(t, oldNw)
	requireNoMore(t, newNw)
	requireNoMore(t, v2Nw)
}

func Test_SendCertificationResponse_NullView(t *testing.T) {
	senderPeer, senderNw := newCertSender(t)
	p, nw := newCertReceiver(t, senderPeer, recvBoth)
	require.NoError(t, senderNw.SendCertificationResponse(context.Background(), testCertResponse(t, nil), p.ID()))
	v2, ok := recv(t, nw).(*certification.CertificationResponseV2)
	require.True(t, ok)
	require.Nil(t, v2.PartitionView)
	requireNoMore(t, nw)
}

func Test_SendCertificationResponse_OversizeViewIsOmitted(t *testing.T) {
	senderPeer, senderNw := newCertSender(t)
	p, nw := newCertReceiver(t, senderPeer, recvBoth)
	big := bytes.Repeat([]byte{1}, certification.MaxPartitionViewSize+1)
	require.NoError(t, senderNw.SendCertificationResponse(context.Background(), testCertResponse(t, big), p.ID()))
	v2, ok := recv(t, nw).(*certification.CertificationResponseV2)
	require.True(t, ok, "ordinary response must still be sent as v2 with null view")
	require.Nil(t, v2.PartitionView)
	require.NoError(t, v2.Legacy().IsValid())
}

func Test_SendCertificationResponse_FrameTooLargeUsesLegacy(t *testing.T) {
	senderPeer, senderNw := newCertSender(t)
	p, nw := newCertReceiver(t, senderPeer, recvBoth)
	cr := testCertResponse(t, nil)
	cr.Technical.Leader = string(bytes.Repeat([]byte{'a'}, certification.MaxCertificationResponseV2Frame))
	require.NoError(t, senderNw.SendCertificationResponse(context.Background(), cr, p.ID()))
	// selected before sending: legacy path, no v2 attempt
	legacy, ok := recv(t, nw).(*certification.CertificationResponse)
	require.True(t, ok)
	require.Equal(t, cr.Technical.Leader, legacy.Technical.Leader)
	requireNoMore(t, nw)
}

func Test_SendCertificationResponse_Self(t *testing.T) {
	_, nw := newCertSender(t)
	cr := testCertResponse(t, []byte{1})
	require.NoError(t, nw.SendCertificationResponse(context.Background(), cr, nw.self.ID()))
	require.Equal(t, cr, recv(t, nw))
}

func Test_SendCertificationResponse_Errors(t *testing.T) {
	_, nw := newCertSender(t)
	require.NoError(t, nw.SendCertificationResponse(context.Background(), testCertResponse(t, nil)), "no receivers")
	require.EqualError(t, nw.SendCertificationResponse(context.Background(), nil, nw.self.ID()), "nil certification response")

	bare, err := NewLibP2PNetwork(createPeer(t), 1, observability.Default(t))
	require.NoError(t, err)
	err = bare.SendCertificationResponse(context.Background(), testCertResponse(t, nil), nw.self.ID())
	require.ErrorContains(t, err, "no protocol registered")
}

func Test_deserializeMsgLimited(t *testing.T) {
	v2 := certification.NewCertificationResponseV2(testCertResponse(t, []byte{1, 2}))
	data, err := types.Cbor.Marshal(v2)
	require.NoError(t, err)

	t.Run("ok", func(t *testing.T) {
		var dec certification.CertificationResponseV2
		require.NoError(t, deserializeMsgLimited(bufio.NewReader(bytes.NewReader(frameMsg(data))), &dec, uint64(len(data))))
		require.Equal(t, []byte{1, 2}, dec.PartitionView)
	})
	t.Run("over limit rejected before reading payload", func(t *testing.T) {
		// declared length only, no payload following: must fail on the limit, not allocate/read
		hdr := frameMsg(nil)[:0]
		hdr = append(hdr, 0x80, 0x80, 0x80, 0x80, 0x10) // huge uvarint
		var dec certification.CertificationResponseV2
		err := deserializeMsgLimited(bufio.NewReader(bytes.NewReader(hdr)), &dec, certification.MaxCertificationResponseV2Frame)
		require.ErrorContains(t, err, "exceeds the limit")
	})
	t.Run("uvarint overflow", func(t *testing.T) {
		var dec certification.CertificationResponseV2
		over := bytes.Repeat([]byte{0xff}, 11)
		require.Error(t, deserializeMsgLimited(bufio.NewReader(bytes.NewReader(over)), &dec, 1<<20))
	})
	t.Run("zero length", func(t *testing.T) {
		var dec certification.CertificationResponseV2
		require.ErrorContains(t, deserializeMsgLimited(bufio.NewReader(bytes.NewReader([]byte{0})), &dec, 10), "zero")
	})
	t.Run("trailing bytes inside frame", func(t *testing.T) {
		var dec certification.CertificationResponseV2
		fr := frameMsg(append(bytes.Clone(data), 0x00))
		require.Error(t, deserializeMsgLimited(bufio.NewReader(bytes.NewReader(fr)), &dec, 1<<20))
	})
	t.Run("truncated payload", func(t *testing.T) {
		var dec certification.CertificationResponseV2
		fr := frameMsg(data)
		require.Error(t, deserializeMsgLimited(bufio.NewReader(bytes.NewReader(fr[:len(fr)-3])), &dec, 1<<20))
	})
	t.Run("unsupported version", func(t *testing.T) {
		bad := certification.NewCertificationResponseV2(testCertResponse(t, nil))
		bad.Version = 3
		d, err := types.Cbor.Marshal(bad)
		require.NoError(t, err)
		var dec certification.CertificationResponseV2
		require.ErrorContains(t, deserializeMsgLimited(bufio.NewReader(bytes.NewReader(frameMsg(d))), &dec, 1<<20), "unsupported")
	})
}
