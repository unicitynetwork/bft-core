//go:build !zkverifier_ffi

package zkverifier

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewVerifier_SP1_WithoutFFI(t *testing.T) {
	// Create temporary verification key file
	tmpDir := t.TempDir()
	vkeyPath := filepath.Join(tmpDir, "test.vkey")
	err := os.WriteFile(vkeyPath, []byte("fake_verification_key_data"), 0644)
	require.NoError(t, err)

	cfg := &Config{
		Enabled:             true,
		ProofType:           ProofTypeSP1,
		VerificationKeyPath: vkeyPath,
		ChainID:             1,
	}

	verifier, err := NewVerifier(cfg)
	require.Error(t, err)
	require.Nil(t, verifier)
	require.Contains(t, err.Error(), "build with -tags zkverifier_ffi")
}

func TestNewVerifier_SP1_MissingVKey_WithoutFFI(t *testing.T) {
	cfg := &Config{
		Enabled:             true,
		ProofType:           ProofTypeSP1,
		VerificationKeyPath: "/nonexistent/path/test.vkey",
		ChainID:             1,
	}

	verifier, err := NewVerifier(cfg)
	require.Error(t, err)
	require.Nil(t, verifier)
	require.Contains(t, err.Error(), "build with -tags zkverifier_ffi")
}

func TestSP1Verifier_InvalidInputs_WithoutFFI(t *testing.T) {
	// Create temporary verification key file
	tmpDir := t.TempDir()
	vkeyPath := filepath.Join(tmpDir, "test.vkey")
	err := os.WriteFile(vkeyPath, []byte("fake_verification_key_data"), 0644)
	require.NoError(t, err)

	verifier, err := NewSP1Verifier(vkeyPath, 1)
	require.Error(t, err)
	require.Nil(t, verifier)
	require.Contains(t, err.Error(), "build with -tags zkverifier_ffi")
}

func TestSP1Verifier_EmptyVKey_WithoutFFI(t *testing.T) {
	tmpDir := t.TempDir()
	vkeyPath := filepath.Join(tmpDir, "empty.vkey")
	err := os.WriteFile(vkeyPath, []byte{}, 0644)
	require.NoError(t, err)

	verifier, err := NewSP1Verifier(vkeyPath, 1)
	require.Error(t, err)
	require.Nil(t, verifier)
	require.Contains(t, err.Error(), "build with -tags zkverifier_ffi")
}
