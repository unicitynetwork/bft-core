//go:build zkverifier_ffi

package zkverifier

// #cgo LDFLAGS: -L${SRCDIR}/light-client-verifier-ffi/target/release -llight_client_verifier_ffi -ldl -lm
// #include "light-client-verifier-ffi/light_client_verifier.h"
// #include <stdlib.h>
import "C"
import (
	"fmt"
	"unsafe"
)

// LightClientVerifierFFI wraps the Rust FFI library for light client proof verification
type LightClientVerifierFFI struct {
	enabled bool
}

// NewLightClientVerifierFFI creates a new FFI-based light client verifier
func NewLightClientVerifierFFI() (*LightClientVerifierFFI, error) {
	// Verify FFI library is available
	version := C.light_client_ffi_version()
	if version == nil {
		return nil, fmt.Errorf("FFI library not available")
	}

	return &LightClientVerifierFFI{
		enabled: true,
	}, nil
}

// VerifyProof verifies a light client proof using the Rust FFI library
func (v *LightClientVerifierFFI) VerifyProof(proof []byte, previousStateRoot []byte, newStateRoot []byte, blockHash []byte) error {
	// Validate inputs
	if len(proof) == 0 {
		return fmt.Errorf("%w: proof is empty", ErrInvalidProofFormat)
	}
	if len(previousStateRoot) != 32 {
		return fmt.Errorf("%w: previousStateRoot must be 32 bytes", ErrInvalidProofFormat)
	}
	if len(newStateRoot) != 32 {
		return fmt.Errorf("%w: newStateRoot must be 32 bytes", ErrInvalidProofFormat)
	}
	if len(blockHash) != 32 {
		return fmt.Errorf("%w: blockHash must be 32 bytes", ErrInvalidProofFormat)
	}

	// Prepare C pointers
	var errorOut *C.char
	defer func() {
		if errorOut != nil {
			C.light_client_free_string(errorOut)
		}
	}()

	// Call FFI verification function
	result := C.light_client_verify_proof(
		(*C.uint8_t)(unsafe.Pointer(&proof[0])),
		C.size_t(len(proof)),
		(*C.uint8_t)(unsafe.Pointer(&previousStateRoot[0])),
		(*C.uint8_t)(unsafe.Pointer(&newStateRoot[0])),
		(*C.uint8_t)(unsafe.Pointer(&blockHash[0])),
		&errorOut,
	)

	// Check result
	switch result {
	case C.LIGHT_CLIENT_VERIFY_SUCCESS:
		return nil
	case C.LIGHT_CLIENT_VERIFY_INVALID_PROOF:
		if errorOut != nil {
			return fmt.Errorf("%w: %s", ErrInvalidProofFormat, C.GoString(errorOut))
		}
		return ErrInvalidProofFormat
	case C.LIGHT_CLIENT_VERIFY_INVALID_MAGIC_HEADER:
		if errorOut != nil {
			return fmt.Errorf("invalid magic header: %s", C.GoString(errorOut))
		}
		return fmt.Errorf("invalid magic header")
	case C.LIGHT_CLIENT_VERIFY_INVALID_PUBLIC_INPUTS:
		if errorOut != nil {
			return fmt.Errorf("invalid public inputs: %s", C.GoString(errorOut))
		}
		return fmt.Errorf("invalid public inputs")
	case C.LIGHT_CLIENT_VERIFY_VERIFICATION_FAILED:
		if errorOut != nil {
			return fmt.Errorf("%w: %s", ErrProofVerificationFailed, C.GoString(errorOut))
		}
		return ErrProofVerificationFailed
	default:
		if errorOut != nil {
			return fmt.Errorf("internal error: %s", C.GoString(errorOut))
		}
		return fmt.Errorf("internal error")
	}
}

// ProofType returns the proof type
func (v *LightClientVerifierFFI) ProofType() ProofType {
	return ProofTypeLightClient
}

// IsEnabled returns true if the verifier is enabled
func (v *LightClientVerifierFFI) IsEnabled() bool {
	return v.enabled
}

// GetLightClientFFIVersion returns the version of the FFI library
func GetLightClientFFIVersion() string {
	version := C.light_client_ffi_version()
	if version == nil {
		return "unknown"
	}
	return C.GoString(version)
}
