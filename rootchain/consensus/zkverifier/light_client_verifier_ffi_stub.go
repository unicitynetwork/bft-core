//go:build !zkverifier_ffi

package zkverifier

import "fmt"

// LightClientVerifierFFI is a stub when FFI is not available
type LightClientVerifierFFI struct {
	chainID uint64
}

// NewLightClientVerifierFFI returns an error when FFI is not available
// chainID: chain identifier of EVM partition from the partition config (invariant)
func NewLightClientVerifierFFI(chainID uint64) (*LightClientVerifierFFI, error) {
	return nil, fmt.Errorf("Light Client FFI verifier not available: build with -tags zkverifier_ffi to enable")
}

// VerifyProof returns an error when FFI is not available
func (v *LightClientVerifierFFI) VerifyProof(proof []byte, previousStateRoot []byte, newStateRoot []byte, blockHash []byte) error {
	return fmt.Errorf("Light Client FFI verifier not available")
}

// ProofType returns the proof type
func (v *LightClientVerifierFFI) ProofType() ProofType {
	return ProofTypeLightClient
}

// IsEnabled returns false when FFI is not available
func (v *LightClientVerifierFFI) IsEnabled() bool {
	return false
}

// GetLightClientFFIVersion returns "unavailable" when FFI is not built
func GetLightClientFFIVersion() string {
	return "unavailable"
}
