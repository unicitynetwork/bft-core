package zkverifier

import (
	"errors"
	"fmt"
)

var (
	// ErrProofVerificationFailed is returned when proof verification fails
	ErrProofVerificationFailed = errors.New("proof verification failed")
	// ErrInvalidProofFormat is returned when proof data is malformed
	ErrInvalidProofFormat = errors.New("invalid proof format")
	// ErrVerifierNotConfigured is returned when no verifier is configured
	ErrVerifierNotConfigured = errors.New("zk verifier not configured")
)

// ProofType identifies the proving system used
type ProofType string

const (
	// ProofTypeSP1 indicates SP1 zkVM proof
	ProofTypeSP1 ProofType = "sp1"
	// ProofTypeRISC0 indicates RISC0 zkVM proof
	ProofTypeRISC0 ProofType = "risc0"
	// ProofTypeExec indicates execution without proving (testing only)
	ProofTypeExec ProofType = "exec"
	// ProofTypeNone indicates no proof verification (disabled)
	ProofTypeNone ProofType = "none"
)

// ZKVerifier validates zero-knowledge proofs of state transitions
type ZKVerifier interface {
	// VerifyProof verifies a ZK proof of state transition
	// proof: The ZK proof bytes
	// previousStateRoot: Hash of the previous state
	// newStateRoot: Hash of the new state (claimed)
	// Returns nil if proof is valid, error otherwise
	VerifyProof(proof []byte, previousStateRoot []byte, newStateRoot []byte) error

	// ProofType returns the type of proofs this verifier handles
	ProofType() ProofType

	// IsEnabled returns true if verification is enabled
	IsEnabled() bool
}

// Config holds ZK verifier configuration
type Config struct {
	// Enabled controls whether ZK verification is performed
	Enabled bool

	// ProofType specifies which proof system to use
	ProofType ProofType

	// VerificationKeyPath is the path to the verification key file
	// For SP1: path to the .vkey file
	// For RISC0: path to the verification key
	VerificationKeyPath string

	// AdditionalConfig holds prover-specific configuration
	AdditionalConfig map[string]interface{}
}

// DefaultConfig returns a default configuration with verification disabled
func DefaultConfig() *Config {
	return &Config{
		Enabled:             false,
		ProofType:           ProofTypeNone,
		VerificationKeyPath: "",
		AdditionalConfig:    make(map[string]interface{}),
	}
}

// NewVerifier creates a new ZK verifier based on configuration
func NewVerifier(cfg *Config) (ZKVerifier, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if !cfg.Enabled {
		return &NoOpVerifier{}, nil
	}

	switch cfg.ProofType {
	case ProofTypeSP1:
		return NewSP1Verifier(cfg.VerificationKeyPath)
	case ProofTypeRISC0:
		return nil, fmt.Errorf("RISC0 verifier not implemented")
	case ProofTypeExec, ProofTypeNone:
		return &NoOpVerifier{}, nil
	default:
		return nil, fmt.Errorf("unknown proof type: %s", cfg.ProofType)
	}
}

// NoOpVerifier is a verifier that always returns success (for testing/disabled mode)
type NoOpVerifier struct{}

func (v *NoOpVerifier) VerifyProof(proof []byte, previousStateRoot []byte, newStateRoot []byte) error {
	// No verification performed
	return nil
}

func (v *NoOpVerifier) ProofType() ProofType {
	return ProofTypeNone
}

func (v *NoOpVerifier) IsEnabled() bool {
	return false
}
