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
