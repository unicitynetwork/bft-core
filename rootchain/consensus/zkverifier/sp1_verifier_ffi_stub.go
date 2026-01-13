//go:build !zkverifier_ffi

package zkverifier

import "fmt"

// SP1VerifierFFI is a stub when FFI is not available
type SP1VerifierFFI struct {
	vkey []byte
}

// NewSP1VerifierFFI returns an error when FFI is not available
func NewSP1VerifierFFI(vkeyPath string) (*SP1VerifierFFI, error) {
	return nil, fmt.Errorf("SP1 FFI verifier not available: build with -tags zkverifier_ffi to enable")
}

// VerifyProof returns an error when FFI is not available
func (v *SP1VerifierFFI) VerifyProof(proof []byte, previousStateRoot []byte, newStateRoot []byte, blockHash []byte) error {
	return fmt.Errorf("SP1 FFI verifier not available")
}

// ProofType returns the proof type
func (v *SP1VerifierFFI) ProofType() ProofType {
	return ProofTypeSP1
}

// IsEnabled returns false when FFI is not available
func (v *SP1VerifierFFI) IsEnabled() bool {
	return false
}

// GetFFIVersion returns "unavailable" when FFI is not built
func GetFFIVersion() string {
	return "unavailable"
}
