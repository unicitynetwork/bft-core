package network

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/unicitynetwork/bft-go-base/types"
)

func serializeMsg(msg any) ([]byte, error) {
	data, err := types.Cbor.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshaling %T as CBOR: %w", msg, err)
	}
	return frameMsg(data), nil
}

func deserializeMsg(r io.Reader, msg any) error {
	src := bufio.NewReader(r)
	// read data length
	length64, err := binary.ReadUvarint(src)
	if err != nil {
		return fmt.Errorf("reading data length: %w", err)
	}
	if length64 == 0 {
		return fmt.Errorf("unexpected data length zero")
	}

	lengthInt64 := int64(length64) /* #nosec G115 its unlikely that value of length64 exceeds int64 max value */
	if err := types.Cbor.Decode(io.LimitReader(src, lengthInt64), msg); err != nil {
		return fmt.Errorf("decoding message data: %w", err)
	}

	return nil
}

// frameMsg prefixes the CBOR payload with its unsigned-varint length.
func frameMsg(data []byte) []byte {
	buf := make([]byte, binary.MaxVarintLen64, binary.MaxVarintLen64+len(data))
	n := binary.PutUvarint(buf, uint64(len(data)))
	return append(buf[:n], data...)
}

// deserializeMsgLimited reads one frame whose CBOR payload must not exceed maxLen bytes.
// The declared length is checked before any allocation and the payload must be consumed
// exactly by the decoder (no trailing bytes).
func deserializeMsgLimited(src *bufio.Reader, msg any, maxLen uint64) error {
	length, err := binary.ReadUvarint(src)
	if err != nil {
		return fmt.Errorf("reading data length: %w", err)
	}
	if length == 0 {
		return fmt.Errorf("unexpected data length zero")
	}
	if length > maxLen {
		return fmt.Errorf("data length %d exceeds the limit %d", length, maxLen)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(src, data); err != nil {
		return fmt.Errorf("reading message data: %w", err)
	}
	if err := types.Cbor.Unmarshal(data, msg); err != nil {
		return fmt.Errorf("decoding message data: %w", err)
	}
	return nil
}
