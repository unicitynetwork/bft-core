package zkverifier

import (
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
	err = verifier.VerifyProof([]byte("not a real proof"), make([]byte, 32), make([]byte, 32), make([]byte, 32))
	require.NoError(t, err)
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
	err := v.VerifyProof(nil, nil, nil, nil)
	require.NoError(t, err)

	err = v.VerifyProof([]byte("test"), []byte("prev"), []byte("new"), []byte("block"))
	require.NoError(t, err)
}
