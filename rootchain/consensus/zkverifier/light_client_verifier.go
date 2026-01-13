package zkverifier

import (
	"encoding/hex"
	"fmt"
	"log/slog"
)

// LightClientVerifier verifies light client proofs by executing validation logic directly
type LightClientVerifier struct {
	enabled     bool
	ffiVerifier *LightClientVerifierFFI
}

// NewLightClientVerifier creates a new light client verifier
func NewLightClientVerifier() (*LightClientVerifier, error) {
	// Try to create FFI verifier
	if ffiVerifier, err := NewLightClientVerifierFFI(); err == nil {
		slog.Info("Using Light Client FFI verifier", "version", GetLightClientFFIVersion())
		return &LightClientVerifier{
			enabled:     true,
			ffiVerifier: ffiVerifier,
		}, nil
	} else {
		return nil, fmt.Errorf("Light Client FFI verifier not available: %w", err)
	}
}

// VerifyProof verifies a light client proof payload
//
// The proof payload should contain:
// - Magic header: "LCPROOF\0" (8 bytes)
// - Serialized ProgramInput (rkyv format)
//
// This function:
// 1. Validates the magic header
// 2. Deserializes the ProgramInput
// 3. Executes stateless_validation_l1()
// 4. Verifies the state roots and block hash match
func (v *LightClientVerifier) VerifyProof(proof []byte, previousStateRoot []byte, newStateRoot []byte, blockHash []byte) error {
	if !v.enabled {
		return ErrVerifierNotConfigured
	}

	if len(proof) == 0 {
		return fmt.Errorf("%w: proof is empty", ErrInvalidProofFormat)
	}

	if len(previousStateRoot) != 32 {
		return fmt.Errorf("%w: previousStateRoot must be 32 bytes, got %d", ErrInvalidProofFormat, len(previousStateRoot))
	}

	if len(newStateRoot) != 32 {
		return fmt.Errorf("%w: newStateRoot must be 32 bytes, got %d", ErrInvalidProofFormat, len(newStateRoot))
	}

	if len(blockHash) != 32 {
		return fmt.Errorf("%w: blockHash must be 32 bytes, got %d", ErrInvalidProofFormat, len(blockHash))
	}

	// Check magic header
	if len(proof) < 8 {
		return fmt.Errorf("%w: payload too short for magic header", ErrInvalidProofFormat)
	}

	magic := proof[0:8]
	expectedMagic := []byte("LCPROOF\x00")
	if string(magic) != string(expectedMagic) {
		return fmt.Errorf("%w: invalid magic header: expected %v, got %v",
			ErrInvalidProofFormat, expectedMagic, magic)
	}

	slog.Debug("Verifying light client proof",
		"payload_size", len(proof),
		"witness_size", len(proof)-8,
		"prev_root", hex.EncodeToString(previousStateRoot[:8]),
		"new_root", hex.EncodeToString(newStateRoot[:8]),
		"block_hash", hex.EncodeToString(blockHash[:8]))

	return v.ffiVerifier.VerifyProof(proof, previousStateRoot, newStateRoot, blockHash)
}

func (v *LightClientVerifier) ProofType() ProofType {
	return ProofTypeLightClient
}

func (v *LightClientVerifier) IsEnabled() bool {
	return v.enabled
}
