package zkverifier

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	require.False(t, cfg.Enabled)
	require.Equal(t, ProofTypeNone, cfg.ProofType)
	require.Empty(t, cfg.VerificationKeyPath)
}

func TestNewVerifier_Disabled(t *testing.T) {
	cfg := &Config{
		Enabled:   false,
		ProofType: ProofTypeSP1,
	}

	verifier, err := NewVerifier(cfg)
	require.NoError(t, err)
	require.NotNil(t, verifier)
	require.False(t, verifier.IsEnabled())
	require.Equal(t, ProofTypeNone, verifier.ProofType())
}

func TestNewVerifier_NoOpForExec(t *testing.T) {
	cfg := &Config{
		Enabled:   true,
		ProofType: ProofTypeExec,
	}

	verifier, err := NewVerifier(cfg)
	require.NoError(t, err)
	require.NotNil(t, verifier)
	require.False(t, verifier.IsEnabled())

	// Should accept any proof
	err = verifier.VerifyProof([]byte("not a real proof"), make([]byte, 32), make([]byte, 32))
	require.NoError(t, err)
}

func TestNewVerifier_SP1(t *testing.T) {
	// Create temporary verification key file
	tmpDir := t.TempDir()
	vkeyPath := filepath.Join(tmpDir, "test.vkey")
	err := os.WriteFile(vkeyPath, []byte("fake_verification_key_data"), 0644)
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

func TestNewVerifier_SP1_MissingVKey(t *testing.T) {
	cfg := &Config{
		Enabled:             true,
		ProofType:           ProofTypeSP1,
		VerificationKeyPath: "/nonexistent/path/test.vkey",
	}

	verifier, err := NewVerifier(cfg)
	require.Error(t, err)
	require.Nil(t, verifier)
	require.Contains(t, err.Error(), "failed to read verification key")
}

func TestNewVerifier_UnknownProofType(t *testing.T) {
	cfg := &Config{
		Enabled:   true,
		ProofType: "unknown",
	}

	verifier, err := NewVerifier(cfg)
	require.Error(t, err)
	require.Nil(t, verifier)
	require.Contains(t, err.Error(), "unknown proof type")
}

func TestNoOpVerifier(t *testing.T) {
	v := &NoOpVerifier{}

	require.False(t, v.IsEnabled())
	require.Equal(t, ProofTypeNone, v.ProofType())

	// Should accept any input
	err := v.VerifyProof(nil, nil, nil)
	require.NoError(t, err)

	err = v.VerifyProof([]byte("test"), []byte("prev"), []byte("new"))
	require.NoError(t, err)
}

func TestSP1Verifier_InvalidInputs(t *testing.T) {
	// Create temporary verification key file
	tmpDir := t.TempDir()
	vkeyPath := filepath.Join(tmpDir, "test.vkey")
	err := os.WriteFile(vkeyPath, []byte("fake_verification_key_data"), 0644)
	require.NoError(t, err)

	verifier, err := NewSP1Verifier(vkeyPath)
	require.NoError(t, err)

	testCases := []struct {
		name              string
		proof             []byte
		previousStateRoot []byte
		newStateRoot      []byte
		wantErr           bool
		errContains       string
	}{
		{
			name:              "empty proof",
			proof:             []byte{},
			previousStateRoot: make([]byte, 32),
			newStateRoot:      make([]byte, 32),
			wantErr:           true,
			errContains:       "proof is empty",
		},
		{
			name:              "invalid previous state root length",
			proof:             make([]byte, 100),
			previousStateRoot: make([]byte, 16),
			newStateRoot:      make([]byte, 32),
			wantErr:           true,
			errContains:       "previousStateRoot must be 32 bytes",
		},
		{
			name:              "invalid new state root length",
			proof:             make([]byte, 100),
			previousStateRoot: make([]byte, 32),
			newStateRoot:      make([]byte, 16),
			wantErr:           true,
			errContains:       "newStateRoot must be 32 bytes",
		},
		{
			name:              "proof too small",
			proof:             make([]byte, 32), // Less than 64 bytes
			previousStateRoot: make([]byte, 32),
			newStateRoot:      make([]byte, 32),
			wantErr:           true,
			errContains:       "SP1 proof too small",
		},
		{
			name:              "valid format (placeholder accepts)",
			proof:             make([]byte, 128),
			previousStateRoot: make([]byte, 32),
			newStateRoot:      make([]byte, 32),
			wantErr:           false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifier.VerifyProof(tc.proof, tc.previousStateRoot, tc.newStateRoot)
			if tc.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSP1Verifier_EmptyVKey(t *testing.T) {
	tmpDir := t.TempDir()
	vkeyPath := filepath.Join(tmpDir, "empty.vkey")
	err := os.WriteFile(vkeyPath, []byte{}, 0644)
	require.NoError(t, err)

	verifier, err := NewSP1Verifier(vkeyPath)
	require.Error(t, err)
	require.Nil(t, verifier)
	require.Contains(t, err.Error(), "verification key is empty")
}
