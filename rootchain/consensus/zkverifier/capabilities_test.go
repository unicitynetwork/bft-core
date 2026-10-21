package zkverifier

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsProofTypeAvailable(t *testing.T) {
	// These types should always be available
	require.True(t, IsProofTypeAvailable(ProofTypeExec))
	require.True(t, IsProofTypeAvailable(ProofTypeNone))
	require.True(t, IsProofTypeAvailable(""))

	// Unknown types should not be available
	require.False(t, IsProofTypeAvailable(ProofType("unknown")))

	// SP1 and LightClient availability depends on build tags
	// The stub version returns false for these
	if !IsFFIAvailable() {
		require.False(t, IsProofTypeAvailable(ProofTypeSP1))
		require.False(t, IsProofTypeAvailable(ProofTypeLightClient))
	}
}

func TestAvailableProofTypes(t *testing.T) {
	types := AvailableProofTypes()
	require.NotEmpty(t, types)
	require.Contains(t, types, ProofTypeExec)
}

func TestParseProofTypeFromParams(t *testing.T) {
	testCases := []struct {
		name     string
		params   map[string]string
		expected ProofType
	}{
		{
			name:     "nil params",
			params:   nil,
			expected: ProofTypeNone,
		},
		{
			name:     "empty params",
			params:   map[string]string{},
			expected: ProofTypeNone,
		},
		{
			name:     "empty proof_type",
			params:   map[string]string{ParamProofType: ""},
			expected: ProofTypeNone,
		},
		{
			name:     "sp1",
			params:   map[string]string{ParamProofType: "sp1"},
			expected: ProofTypeSP1,
		},
		{
			name:     "light_client",
			params:   map[string]string{ParamProofType: "light_client"},
			expected: ProofTypeLightClient,
		},
		{
			name:     "exec",
			params:   map[string]string{ParamProofType: "exec"},
			expected: ProofTypeExec,
		},
		{
			name:     "none",
			params:   map[string]string{ParamProofType: "none"},
			expected: ProofTypeNone,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseProofTypeFromParams(tc.params)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestParseVKeyPathFromParams(t *testing.T) {
	testCases := []struct {
		name     string
		params   map[string]string
		expected string
	}{
		{
			name:     "nil params",
			params:   nil,
			expected: "",
		},
		{
			name:     "empty params",
			params:   map[string]string{},
			expected: "",
		},
		{
			name:     "no vkey_path",
			params:   map[string]string{ParamProofType: "sp1"},
			expected: "",
		},
		{
			name:     "with vkey_path",
			params:   map[string]string{ParamProofType: "sp1", ParamVerificationKeyPath: "/path/to/vkey"},
			expected: "/path/to/vkey",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ParseVKeyPathFromParams(tc.params)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestParseChainIDFromParams(t *testing.T) {
	testCases := []struct {
		name       string
		params     map[string]string
		expectedID uint64
		expectedOK bool
	}{
		{
			name:       "nil params",
			params:     nil,
			expectedID: 0,
			expectedOK: false,
		},
		{
			name:       "empty params",
			params:     map[string]string{},
			expectedID: 0,
			expectedOK: false,
		},
		{
			name:       "no chain_id",
			params:     map[string]string{ParamProofType: "sp1"},
			expectedID: 0,
			expectedOK: false,
		},
		{
			name:       "empty chain_id",
			params:     map[string]string{ParamChainID: ""},
			expectedID: 0,
			expectedOK: false,
		},
		{
			name:       "invalid chain_id",
			params:     map[string]string{ParamChainID: "invalid"},
			expectedID: 0,
			expectedOK: false,
		},
		{
			name:       "negative chain_id",
			params:     map[string]string{ParamChainID: "-1"},
			expectedID: 0,
			expectedOK: false,
		},
		{
			name:       "valid chain_id 1",
			params:     map[string]string{ParamChainID: "1"},
			expectedID: 1,
			expectedOK: true,
		},
		{
			name:       "valid chain_id mainnet",
			params:     map[string]string{ParamChainID: "1337"},
			expectedID: 1337,
			expectedOK: true,
		},
		{
			name:       "valid large chain_id",
			params:     map[string]string{ParamChainID: "999999999"},
			expectedID: 999999999,
			expectedOK: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, ok := ParseChainIDFromParams(tc.params)
			require.Equal(t, tc.expectedOK, ok)
			require.Equal(t, tc.expectedID, result)
		})
	}
}
