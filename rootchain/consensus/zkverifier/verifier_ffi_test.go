//go:build zkverifier_ffi

package zkverifier

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewVerifier_SP1_WithFFI(t *testing.T) {
	// Create temporary verification key file
	tmpDir := t.TempDir()
	vkeyPath := filepath.Join(tmpDir, "test.vkey")

	// Create a fake but valid-sized vkey file
	err := os.WriteFile(vkeyPath, make([]byte, 64), 0644)
	require.NoError(t, err)

	cfg := &Config{
		Enabled:             true,
		ProofType:           ProofTypeSP1,
		VerificationKeyPath: vkeyPath,
	}

	verifier, err := NewVerifier(cfg)
	require.NoError(t, err)
	require.NotNil(t, verifier)
	require.True(t, verifier.IsEnabled())
	require.Equal(t, ProofTypeSP1, verifier.ProofType())
}

func TestNewVerifier_SP1_MissingVKey_WithFFI(t *testing.T) {
	cfg := &Config{
		Enabled:             true,
		ProofType:           ProofTypeSP1,
		VerificationKeyPath: "/nonexistent/path/test.vkey",
	}

	verifier, err := NewVerifier(cfg)
	require.Error(t, err)
	require.Nil(t, verifier)
	require.Contains(t, err.Error(), "failed to")
}

func TestSP1Verifier_InvalidInputs_WithFFI(t *testing.T) {
	// Create temporary verification key file
	tmpDir := t.TempDir()
	vkeyPath := filepath.Join(tmpDir, "test.vkey")
	err := os.WriteFile(vkeyPath, make([]byte, 64), 0644)
	require.NoError(t, err)

	verifier, err := NewSP1Verifier(vkeyPath)
	require.NoError(t, err)

	testCases := []struct {
		name              string
		proof             []byte
		previousStateRoot []byte
		newStateRoot      []byte
		blockHash         []byte
		wantErr           bool
		errContains       string
	}{
		{
			name:              "empty proof",
			proof:             []byte{},
			previousStateRoot: make([]byte, 32),
			newStateRoot:      make([]byte, 32),
			blockHash:         make([]byte, 32),
			wantErr:           true,
			errContains:       "proof is empty",
		},
		{
			name:              "invalid previous state root length",
			proof:             make([]byte, 100),
			previousStateRoot: make([]byte, 16),
			newStateRoot:      make([]byte, 32),
			blockHash:         make([]byte, 32),
			wantErr:           true,
			errContains:       "previousStateRoot must be 32 bytes",
		},
		{
			name:              "invalid new state root length",
			proof:             make([]byte, 100),
			previousStateRoot: make([]byte, 32),
			newStateRoot:      make([]byte, 16),
			blockHash:         make([]byte, 32),
			wantErr:           true,
			errContains:       "newStateRoot must be 32 bytes",
		},
		{
			name:              "invalid block hash length",
			proof:             make([]byte, 100),
			previousStateRoot: make([]byte, 32),
			newStateRoot:      make([]byte, 32),
			blockHash:         make([]byte, 16),
			wantErr:           true,
			errContains:       "blockHash must be 32 bytes",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifier.VerifyProof(tc.proof, tc.previousStateRoot, tc.newStateRoot, tc.blockHash)
			if tc.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSP1Verifier_EmptyVKey_WithFFI(t *testing.T) {
	tmpDir := t.TempDir()
	vkeyPath := filepath.Join(tmpDir, "empty.vkey")
	err := os.WriteFile(vkeyPath, []byte{}, 0644)
	require.NoError(t, err)

	verifier, err := NewSP1Verifier(vkeyPath)
	require.Error(t, err)
	require.Nil(t, verifier)
	// FFI will detect empty vkey
}
