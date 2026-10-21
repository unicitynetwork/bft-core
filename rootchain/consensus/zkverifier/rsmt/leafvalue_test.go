package rsmt

import (
	"encoding/hex"
	"testing"
)

// Shared with the Rust, Go aggregator, Java and TypeScript implementations.
const (
	sharedTransactionHash = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	sharedReferenceTime   = uint64(1755000000)
	sharedLeafValue       = "0235bd52cfa10c9785dfa01942bc396f201fe715dbc3896ee117a97e895e1e36"
)

func TestLeafValueMatchesTheSharedTestVector(t *testing.T) {
	txHash, err := hex.DecodeString(sharedTransactionHash)
	if err != nil {
		t.Fatalf("decoding transaction hash: %v", err)
	}

	got := LeafValue(txHash, sharedReferenceTime)
	if hex.EncodeToString(got[:]) != sharedLeafValue {
		t.Fatalf("leaf value mismatch: got %s, want %s", hex.EncodeToString(got[:]), sharedLeafValue)
	}
}

func TestLeafValueChangesWithTheReferenceTime(t *testing.T) {
	txHash, _ := hex.DecodeString(sharedTransactionHash)

	got := LeafValue(txHash, sharedReferenceTime+1)
	if hex.EncodeToString(got[:]) == sharedLeafValue {
		t.Fatal("leaf value did not change with the reference time")
	}
}

func TestCborUintUsesShortestForm(t *testing.T) {
	for _, tc := range []struct {
		value uint64
		want  string
	}{
		{0, "00"},
		{23, "17"},
		{24, "1818"},
		{256, "190100"},
		{1755000000, "1a689b2cc0"},
		{^uint64(0), "1bffffffffffffffff"},
	} {
		if got := hex.EncodeToString(cborUint(tc.value)); got != tc.want {
			t.Errorf("cborUint(%d) = %s, want %s", tc.value, got, tc.want)
		}
	}
}

func TestCborByteStringHeaderUsesShortestForm(t *testing.T) {
	for _, tc := range []struct {
		length int
		want   string
	}{
		{0, "40"},
		{23, "57"},
		{24, "5818"},
		{255, "58ff"},
		{256, "590100"},
		{65535, "59ffff"},
		{65536, "5a00010000"},
	} {
		if got := hex.EncodeToString(cborByteStringHeader(make([]byte, tc.length))); got != tc.want {
			t.Errorf("cborByteStringHeader(length %d) = %s, want %s", tc.length, got, tc.want)
		}
	}
}
