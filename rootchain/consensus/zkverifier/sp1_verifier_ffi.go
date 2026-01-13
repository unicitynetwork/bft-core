//go:build zkverifier_ffi

package zkverifier

// #cgo LDFLAGS: -L${SRCDIR}/sp1-verifier-ffi/target/release -lsp1_verifier_ffi -ldl -lm
// #include "sp1-verifier-ffi/sp1_verifier.h"
// #include <stdlib.h>
import "C"
import (
	"fmt"
	"unsafe"
)

// SP1VerifierFFI wraps the Rust FFI library for SP1 proof verification
type SP1VerifierFFI struct {
	vkey []byte
}

// NewSP1VerifierFFI creates a new FFI-based SP1 verifier
func NewSP1VerifierFFI(vkeyPath string) (*SP1VerifierFFI, error) {
	// Load verification key
	vkey, err := loadVerificationKey(vkeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load verification key: %w", err)
	}

	// Verify FFI library is available
	version := C.sp1_ffi_version()
	if version == nil {
		return nil, fmt.Errorf("FFI library not available")
	}

	// Validate verification key
	if len(vkey) == 0 {
		return nil, fmt.Errorf("verification key is empty")
	}

	var errorOut *C.char
	defer func() {
		if errorOut != nil {
			C.sp1_free_string(errorOut)
		}
	}()

	result := C.sp1_validate_vkey(
		(*C.uint8_t)(unsafe.Pointer(&vkey[0])),
		C.size_t(len(vkey)),
		&errorOut,
	)

	if result != C.SP1_VERIFY_SUCCESS {
		if errorOut != nil {
			return nil, fmt.Errorf("invalid verification key: %s", C.GoString(errorOut))
		}
		return nil, fmt.Errorf("invalid verification key")
	}

	return &SP1VerifierFFI{
		vkey: vkey,
	}, nil
}

// VerifyProof verifies an SP1 proof using the Rust FFI library
func (v *SP1VerifierFFI) VerifyProof(proof []byte, previousStateRoot []byte, newStateRoot []byte, blockHash []byte) error {
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
			C.sp1_free_string(errorOut)
		}
	}()

	// Call FFI verification function
	result := C.sp1_verify_proof(
		(*C.uint8_t)(unsafe.Pointer(&v.vkey[0])),
		C.size_t(len(v.vkey)),
		(*C.uint8_t)(unsafe.Pointer(&proof[0])),
		C.size_t(len(proof)),
		(*C.uint8_t)(unsafe.Pointer(&previousStateRoot[0])),
		(*C.uint8_t)(unsafe.Pointer(&newStateRoot[0])),
		(*C.uint8_t)(unsafe.Pointer(&blockHash[0])),
		&errorOut,
	)

	// Check result
	switch result {
	case C.SP1_VERIFY_SUCCESS:
		return nil
	case C.SP1_VERIFY_INVALID_PROOF:
		if errorOut != nil {
			return fmt.Errorf("%w: %s", ErrInvalidProofFormat, C.GoString(errorOut))
		}
		return ErrInvalidProofFormat
	case C.SP1_VERIFY_INVALID_VKEY:
		if errorOut != nil {
			return fmt.Errorf("invalid verification key: %s", C.GoString(errorOut))
		}
		return fmt.Errorf("invalid verification key")
	case C.SP1_VERIFY_INVALID_PUBLIC_INPUTS:
		if errorOut != nil {
			return fmt.Errorf("invalid public inputs: %s", C.GoString(errorOut))
		}
		return fmt.Errorf("invalid public inputs")
	case C.SP1_VERIFY_VERIFICATION_FAILED:
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
func (v *SP1VerifierFFI) ProofType() ProofType {
	return ProofTypeSP1
}

// IsEnabled returns true if the verifier is enabled
func (v *SP1VerifierFFI) IsEnabled() bool {
	return len(v.vkey) > 0
}

// GetFFIVersion returns the version of the FFI library
func GetFFIVersion() string {
	version := C.sp1_ffi_version()
	if version == nil {
		return "unknown"
	}
	return C.GoString(version)
}

// Helper function to load verification key from file
func loadVerificationKey(path string) ([]byte, error) {
	// This is implemented in sp1_verifier.go as readFile
	// We reuse that function
	return readFile(path)
}
