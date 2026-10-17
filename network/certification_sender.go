package network

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
	"go.opentelemetry.io/otel/trace"

	"github.com/unicitynetwork/bft-core/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// certificationFrames lazily serializes and caches the framed v1 and v2 payloads of
// a single dispatch so they are shared between all recipients.
type certificationFrames struct {
	cr *certification.CertificationResponse

	v1Once sync.Once
	v1     []byte
	v1Err  error

	v2Once sync.Once
	v2     []byte // nil when v2 must not be used for this response
	v2Err  error

	// marshalHook, when set (tests), is called for every CBOR encoding performed: v2 tells
	// the V2 envelope from the legacy response. It must be set before the frames are used.
	marshalHook func(v2 bool)
}

func (f *certificationFrames) observe(v2 bool) {
	if f.marshalHook != nil {
		f.marshalHook(v2)
	}
}

func (f *certificationFrames) legacy() ([]byte, error) {
	f.v1Once.Do(func() {
		// the carrier field is tagged cbor:"-", legacy bytes are independent of the view
		f.observe(false)
		data, err := types.Cbor.Marshal(f.cr)
		if err != nil {
			f.v1Err = fmt.Errorf("marshaling %T as CBOR: %w", f.cr, err)
			return
		}
		f.v1 = frameMsg(data)
	})
	return f.v1, f.v1Err
}

// v2Frame returns nil frame (and no error) when the v2 envelope is not usable for this
// response, ie the frame would exceed the limit even without the partition view.
func (f *certificationFrames) v2Frame() ([]byte, error) {
	f.v2Once.Do(func() {
		// the carrier bytes are immutable (encoded once per partition), share them instead of copying
		env := certification.NewCertificationResponseV2Shared(f.cr)
		if len(env.PartitionView) > certification.MaxPartitionViewSize {
			env.PartitionView = nil
		}
		f.observe(true)
		data, err := types.Cbor.Marshal(env)
		if err != nil {
			f.v2Err = fmt.Errorf("marshaling %T as CBOR: %w", env, err)
			return
		}
		if len(data) > certification.MaxCertificationResponseV2Frame && env.PartitionView != nil {
			// oversize sidecar: send ordinary response with null view
			env.PartitionView = nil
			f.observe(true)
			if data, err = types.Cbor.Marshal(env); err != nil {
				f.v2Err = fmt.Errorf("marshaling %T as CBOR: %w", env, err)
				return
			}
		}
		if len(data) > certification.MaxCertificationResponseV2Frame {
			return // use legacy path
		}
		f.v2 = frameMsg(data)
	})
	return f.v2, f.v2Err
}

/*
SendCertificationResponse sends the response asynchronously to the receivers, offering
"/ab/certificates/0.0.2" and "/ab/certificates/0.0.1" to each. The serialization is chosen
from the negotiated stream protocol before any payload is written; exactly one certificate
is sent per receiver and a failure is never followed by a second send in another format.
*/
func (n *LibP2PNetwork) SendCertificationResponse(ctx context.Context, cr *certification.CertificationResponse, receivers ...peer.ID) error {
	if len(receivers) == 0 {
		return nil
	}
	if cr == nil {
		return errors.New("nil certification response")
	}
	p, ok := n.sendProtocols[reflect.TypeOf(*cr)]
	if !ok {
		return fmt.Errorf("no protocol registered for messages of type %T", *cr)
	}
	ctx, span := n.tracer.Start(ctx, "LibP2PNetwork.SendCertificationResponse")
	defer span.End()

	frames := &certificationFrames{cr: cr}
	if n.framesHook != nil {
		n.framesHook(frames)
	}
	// choose up front whether v2 can be offered at all (size based selection)
	v2, err := frames.v2Frame()
	if err != nil {
		// sidecar serialization problems must not prevent the ordinary response
		n.log.WarnContext(ctx, "serializing CertificationResponseV2, falling back to legacy", logger.Error(err))
		v2 = nil
	}
	if v2 == nil {
		// the legacy frame is the only one which can be sent: fail synchronously. Otherwise it is
		// serialized lazily, only if some receiver negotiates the legacy protocol.
		if _, err := frames.legacy(); err != nil {
			return fmt.Errorf("serializing message: %w", err)
		}
	}
	protocols := []string{ProtocolUnicityCertificatesV2, p.protocolID}
	if v2 == nil {
		protocols = protocols[1:]
	}

	for _, receiver := range receivers {
		if receiver == n.self.ID() {
			if err := n.receivedMsg(n.self.ID(), p.protocolID, cr); err != nil {
				n.log.WarnContext(ctx, "message loop-back failed", logger.Error(err))
			}
			continue
		}
		go func(receiverID peer.ID) {
			ctx, span := n.tracer.Start(ctx, "LibP2PNetwork.SendCertificationResponse.func", trace.WithNewRoot(), trace.WithLinks(trace.LinkFromContext(ctx)))
			defer span.End()
			sendCtx, cancel := context.WithTimeout(ctx, p.timeout)
			defer cancel()
			if err := n.sendCertificationFrame(sendCtx, receiverID, protocols, p.protocolID, frames); err != nil {
				n.log.WarnContext(sendCtx, fmt.Sprintf("sending certification response to %v", receiverID), logger.Error(err),
					logger.Shard(cr.Partition, cr.Shard))
			}
		}(receiver)
	}
	return nil
}

func (n *LibP2PNetwork) sendCertificationFrame(ctx context.Context, receiver peer.ID, protocols []string, legacyID string, frames *certificationFrames) (err error) {
	s, err := n.self.CreateStreamProtocols(ctx, receiver, protocols...)
	if err != nil {
		return fmt.Errorf("open p2p stream: %w", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("closing p2p stream: %w", closeErr))
		}
	}()
	var data []byte
	switch negotiated := string(s.Protocol()); negotiated {
	case ProtocolUnicityCertificatesV2:
		data, err = frames.v2Frame()
	case legacyID:
		data, err = frames.legacy()
	default:
		err = fmt.Errorf("unexpected negotiated protocol %q", negotiated)
	}
	if err != nil {
		_ = s.Reset()
		return err
	}
	if data == nil { // cannot happen: v2 is only offered when its frame exists
		_ = s.Reset()
		return errors.New("negotiated protocol has no serialized payload")
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err = s.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("error setting write deadline: %w", err)
		}
	}
	if _, err = s.Write(data); err != nil {
		return fmt.Errorf("writing data to p2p stream: %w", err)
	}
	return nil
}
