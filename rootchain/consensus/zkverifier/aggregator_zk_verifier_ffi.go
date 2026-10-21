//go:build zkverifier_aggregator_zk_ffi

package zkverifier

// #cgo LDFLAGS: -L${SRCDIR}/aggregator-zk-verifier-ffi/target/release -laggregator_zk_verifier_ffi -ldl -lm
// #include "aggregator-zk-verifier-ffi/aggregator_zk_verifier.h"
// #include <stdlib.h>
import "C"
import (
	"fmt"
	"unsafe"
)

// AggregatorZKVerifierFFI wraps the Rust FFI library for aggregator ZK proof verification.
type AggregatorZKVerifierFFI struct {
	vkey []byte
}

// NewAggregatorZKVerifierFFI creates a new FFI-based aggregator ZK verifier.
func NewAggregatorZKVerifierFFI(vkeyPath string) (*AggregatorZKVerifierFFI, error) {
	vkey, err := readFile(vkeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load vkey: %w", err)
	}
	if len(vkey) == 0 {
		return nil, fmt.Errorf("vkey file is empty")
	}

	var errorOut *C.char
	defer func() {
		if errorOut != nil {
			C.aggzk_free_string(errorOut)
		}
	}()

	result := C.aggzk_validate_vkey(
		(*C.uint8_t)(unsafe.Pointer(&vkey[0])),
		C.size_t(len(vkey)),
		&errorOut,
	)
	if result != C.AGGZK_VERIFY_SUCCESS {
		if errorOut != nil {
			return nil, fmt.Errorf("invalid vkey: %s", C.GoString(errorOut))
		}
		return nil, fmt.Errorf("invalid vkey")
	}

	return &AggregatorZKVerifierFFI{vkey: vkey}, nil
}

// VerifyProof verifies an aggregator ZK proof via the Rust FFI library.
// blockHash is unused by aggregator ZK proofs and not passed to the FFI.
//
// referenceTime is CR.IR.t. The circuit derives the round's leaf values from
// it and commits it as the third public value, so the check below is what ties
// the ZK instantiation to the same reference time the hash-based one enforces.
func (v *AggregatorZKVerifierFFI) VerifyProof(proof []byte, prevRoot []byte, newRoot []byte, referenceTime uint64) error {
	if len(proof) == 0 {
		return fmt.Errorf("%w: proof is empty", ErrInvalidProofFormat)
	}
	if len(prevRoot) != 32 {
		return fmt.Errorf("%w: prevRoot must be 32 bytes", ErrInvalidProofFormat)
	}
	if len(newRoot) != 32 {
		return fmt.Errorf("%w: newRoot must be 32 bytes", ErrInvalidProofFormat)
	}

	var errorOut *C.char
	defer func() {
		if errorOut != nil {
			C.aggzk_free_string(errorOut)
		}
	}()

	result := C.aggzk_verify_proof(
		(*C.uint8_t)(unsafe.Pointer(&v.vkey[0])),
		C.size_t(len(v.vkey)),
		(*C.uint8_t)(unsafe.Pointer(&proof[0])),
		C.size_t(len(proof)),
		(*C.uint8_t)(unsafe.Pointer(&prevRoot[0])),
		(*C.uint8_t)(unsafe.Pointer(&newRoot[0])),
		C.uint64_t(referenceTime),
		&errorOut,
	)

	switch result {
	case C.AGGZK_VERIFY_SUCCESS:
		return nil
	case C.AGGZK_VERIFY_INVALID_PROOF:
		if errorOut != nil {
			return fmt.Errorf("%w: %s", ErrInvalidProofFormat, C.GoString(errorOut))
		}
		return ErrInvalidProofFormat
	case C.AGGZK_VERIFY_INVALID_VKEY:
		if errorOut != nil {
			return fmt.Errorf("invalid vkey: %s", C.GoString(errorOut))
		}
		return fmt.Errorf("invalid vkey")
	case C.AGGZK_VERIFY_INVALID_PUBLIC_INPUTS:
		if errorOut != nil {
			return fmt.Errorf("invalid public inputs: %s", C.GoString(errorOut))
		}
		return fmt.Errorf("invalid public inputs")
	case C.AGGZK_VERIFY_VERIFICATION_FAILED:
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

// GetAggregatorZKFFIVersion returns the version of the Rust FFI library.
func GetAggregatorZKFFIVersion() string {
	v := C.aggzk_ffi_version()
	if v == nil {
		return "unknown"
	}
	return C.GoString(v)
}
