package certification

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"
)

const legacyGolden = "8401418085186308613141014102d998598701f65820c3c91bb3d460d12c220885d7bf628cabb9e872ee234b176040462396ee03da01f6d9985b83014180f6d9985c830101f6f6"

func testResponse(t *testing.T) *CertificationResponse {
	cr := &CertificationResponse{
		Partition: 1,
		Shard:     types.ShardID{},
		UC: types.UnicityCertificate{
			Version:                1,
			UnicityTreeCertificate: &types.UnicityTreeCertificate{Version: 1, Partition: 1},
		},
	}
	require.NoError(t, cr.SetTechnicalRecord(TechnicalRecord{Round: 99, Epoch: 8, Leader: "1", StatHash: []byte{1}, FeeHash: []byte{2}}))
	return cr
}

// The in-process carrier must not influence the legacy (v1) serialization in any way.
func Test_CertificationResponse_LegacyWireUnchangedByCarrier(t *testing.T) {
	cr := testResponse(t)
	plain, err := types.Cbor.Marshal(cr)
	require.NoError(t, err)
	require.Equal(t, byte(0x84), plain[0], "legacy response must be an untagged four-element array")

	withView := *cr
	withView.PartitionView = []byte{1, 2, 3}
	got, err := types.Cbor.Marshal(&withView)
	require.NoError(t, err)
	require.Equal(t, plain, got)

	// decoding the legacy bytes leaves the carrier empty
	var dec CertificationResponse
	require.NoError(t, types.Cbor.Unmarshal(got, &dec))
	require.Nil(t, dec.PartitionView)

	// pinned legacy bytes
	require.Equal(t, legacyGolden, fmt.Sprintf("%x", plain))
	var again CertificationResponse
	require.NoError(t, types.Cbor.Unmarshal(plain, &again))
	re, err := types.Cbor.Marshal(&again)
	require.NoError(t, err)
	require.Equal(t, plain, re)
}

func Test_CertificationResponseV2_Wire(t *testing.T) {
	cr := testResponse(t)
	legacy, err := types.Cbor.Marshal(cr)
	require.NoError(t, err)

	t.Run("null view", func(t *testing.T) {
		data, err := types.Cbor.Marshal(NewCertificationResponseV2(cr))
		require.NoError(t, err)
		want := append(append([]byte{0x83, 0x02}, legacy...), 0xf6)
		require.Equal(t, want, data)

		var dec CertificationResponseV2
		require.NoError(t, types.Cbor.Unmarshal(data, &dec))
		require.Nil(t, dec.PartitionView)
		back, err := types.Cbor.Marshal(dec.Legacy())
		require.NoError(t, err)
		require.Equal(t, legacy, back)
	})

	t.Run("view as bstr, copied into carrier", func(t *testing.T) {
		withView := *cr
		withView.PartitionView = []byte{0x83, 0x01, 0x02, 0x80}
		v2 := NewCertificationResponseV2(&withView)
		require.Nil(t, v2.Response.PartitionView, "view is not duplicated inside the legacy array")
		data, err := types.Cbor.Marshal(v2)
		require.NoError(t, err)
		want := append(append([]byte{0x83, 0x02}, legacy...), 0x44, 0x83, 0x01, 0x02, 0x80)
		require.Equal(t, want, data)

		var dec CertificationResponseV2
		require.NoError(t, types.Cbor.Unmarshal(data, &dec))
		require.Equal(t, withView.PartitionView, dec.PartitionView)
		got := dec.Legacy()
		require.Equal(t, withView.PartitionView, got.PartitionView)
		// copy, not alias
		got.PartitionView[0] = 0
		require.Equal(t, byte(0x83), dec.PartitionView[0])
	})

	t.Run("empty bstr is rejected both ways", func(t *testing.T) {
		v2 := NewCertificationResponseV2(cr)
		v2.PartitionView = []byte{}
		_, err := types.Cbor.Marshal(v2)
		require.ErrorContains(t, err, "null or non-empty")
		data := append(append([]byte{0x83, 0x02}, legacy...), 0x40)
		var dec CertificationResponseV2
		require.ErrorContains(t, types.Cbor.Unmarshal(data, &dec), "null or non-empty")
	})

	t.Run("version must be exactly 2", func(t *testing.T) {
		for _, v := range []byte{0x00, 0x01, 0x03} {
			data := append(append([]byte{0x83, v}, legacy...), 0xf6)
			var dec CertificationResponseV2
			require.ErrorContains(t, types.Cbor.Unmarshal(data, &dec), "unsupported CertificationResponseV2 version")
		}
	})

	t.Run("view must be bstr or null", func(t *testing.T) {
		for name, tail := range map[string][]byte{
			"integer array":   {0x81, 0x01},
			"undefined":       {0xf7},
			"text string":     {0x61, 'a'},
			"integer":         {0x01},
			"indefinite bstr": {0x5f, 0x41, 0x01, 0xff},
			"false":           {0xf4},
		} {
			data := append(append([]byte{0x83, 0x02}, legacy...), tail...)
			var dec CertificationResponseV2
			require.Error(t, types.Cbor.Unmarshal(data, &dec), name)
		}
		// arbitrary nonempty bstr contents (opaque inner view) are accepted
		data := append(append([]byte{0x83, 0x02}, legacy...), 0x43, 0xff, 0x00, 0xf7)
		var dec CertificationResponseV2
		require.NoError(t, types.Cbor.Unmarshal(data, &dec))
		require.Equal(t, []byte{0xff, 0x00, 0xf7}, dec.PartitionView)
	})

	t.Run("malformed envelopes", func(t *testing.T) {
		good, err := types.Cbor.Marshal(NewCertificationResponseV2(cr))
		require.NoError(t, err)
		for name, data := range map[string][]byte{
			"legacy four element array": legacy,
			"two elements":              append([]byte{0x82, 0x02}, legacy...),
			"four elements":             append(bytes.Clone(good[:len(good)-1]), 0xf6, 0xf6),
			"trailing data":             append(bytes.Clone(good), 0x00),
		} {
			if name == "four elements" {
				data[0] = 0x84
			}
			var dec CertificationResponseV2
			require.Error(t, types.Cbor.Unmarshal(data, &dec), name)
		}
	})
}
