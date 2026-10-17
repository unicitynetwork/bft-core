package certification

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	// CertificationResponseV2Version is the only version accepted in the V2 envelope.
	CertificationResponseV2Version uint32 = 2

	// MaxPartitionViewSize is the consolidation admission limit for the encoded
	// partition view carried in the sidecar. Larger views are omitted (null) by producers.
	// It is the limit of the view encoder, types.MaxPartitionViewBytes.
	MaxPartitionViewSize = types.MaxPartitionViewBytes

	// MaxCertificationResponseV2Frame is the limit for the CBOR payload (excluding the
	// varint length prefix) of a V2 frame.
	MaxCertificationResponseV2Frame = 1 << 20
)

/*
CertificationResponseV2 is the transport envelope of CertificationResponse sent over
the "/ab/certificates/0.0.2" protocol:

	[2, [partition, shard, technical, uc], bstr(partitionView) | null]

The partition view is opaque canonical bytes at this layer, its decoding is isolated
from the operational response. Omitted view is encoded as null, not as an empty bstr.
*/
type CertificationResponseV2 struct {
	_             struct{} `cbor:",toarray"`
	Version       uint32
	Response      CertificationResponse
	PartitionView []byte
}

// NewCertificationResponseV2 wraps the response and its in-process partition view
// carrier into the V2 envelope. The view bytes are copied.
func NewCertificationResponseV2(cr *CertificationResponse) *CertificationResponseV2 {
	v2 := &CertificationResponseV2{Version: CertificationResponseV2Version, Response: *cr}
	v2.Response.PartitionView = nil
	if len(cr.PartitionView) > 0 {
		v2.PartitionView = append([]byte(nil), cr.PartitionView...)
	}
	return v2
}

// NewCertificationResponseV2Shared is NewCertificationResponseV2 without the copy of the view
// bytes: the envelope shares the backing array of cr.PartitionView. The caller guarantees that the
// view bytes are immutable for the lifetime of the envelope (certificate generation encodes them once
// per partition and never changes them), which makes the O(W) copy per dispatch unnecessary.
func NewCertificationResponseV2Shared(cr *CertificationResponse) *CertificationResponseV2 {
	v2 := &CertificationResponseV2{Version: CertificationResponseV2Version, Response: *cr}
	v2.Response.PartitionView = nil
	if len(cr.PartitionView) > 0 {
		v2.PartitionView = cr.PartitionView
	}
	return v2
}

// Legacy returns the operational response with the partition view copied into the
// in-process carrier field.
func (v2 *CertificationResponseV2) Legacy() *CertificationResponse {
	cr := v2.Response
	cr.PartitionView = nil
	if len(v2.PartitionView) > 0 {
		cr.PartitionView = append([]byte(nil), v2.PartitionView...)
	}
	return &cr
}

// IsValid checks the envelope only (version and an explicit null/non-empty view);
// the operational response is validated with CertificationResponse.IsValid and the
// view bytes are validated by their owner.
func (v2 *CertificationResponseV2) IsValid() error {
	if v2 == nil {
		return errors.New("nil CertificationResponseV2")
	}
	if v2.Version != CertificationResponseV2Version {
		return fmt.Errorf("unsupported CertificationResponseV2 version %d", v2.Version)
	}
	if v2.PartitionView != nil && len(v2.PartitionView) == 0 {
		return errors.New("partition view must be null or non-empty")
	}
	return nil
}

func (v2 CertificationResponseV2) MarshalCBOR() ([]byte, error) {
	if v2.PartitionView != nil && len(v2.PartitionView) == 0 {
		return nil, errors.New("partition view must be null or non-empty")
	}
	type alias CertificationResponseV2
	return types.Cbor.Marshal(alias(v2))
}

// UnmarshalCBOR rejects unknown envelope versions, an empty (non-null) view and any
// view CBOR type other than byte string or null (eg an integer array or undefined).
// The inner view bytes are not interpreted.
func (v2 *CertificationResponseV2) UnmarshalCBOR(data []byte) error {
	type rawEnvelope struct {
		_             struct{} `cbor:",toarray"`
		Version       uint32
		Response      CertificationResponse
		PartitionView cbor.RawMessage
	}
	var r rawEnvelope
	if err := cbor.Unmarshal(data, &r); err != nil {
		return err
	}
	if len(r.PartitionView) == 0 {
		return errors.New("partition view is missing")
	}
	var view []byte
	switch major := r.PartitionView[0] >> 5; {
	case r.PartitionView[0] == 0xf6: // null
	case major == 2 && r.PartitionView[0] != 0x5f: // definite-length byte string
		if err := cbor.Unmarshal(r.PartitionView, &view); err != nil {
			return fmt.Errorf("decoding partition view: %w", err)
		}
	default:
		return fmt.Errorf("partition view must be a byte string or null, got CBOR major type %d", major)
	}
	out := CertificationResponseV2{Version: r.Version, Response: r.Response, PartitionView: view}
	if err := out.IsValid(); err != nil {
		return err
	}
	*v2 = out
	return nil
}
