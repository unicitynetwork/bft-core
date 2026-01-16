//go:build !zkverifier_ffi

package zkverifier

// IsProofTypeAvailable returns whether the given proof type is available
// in the current build. Without FFI, only Exec (no-op) is available.
func IsProofTypeAvailable(pt ProofType) bool {
	switch pt {
	case ProofTypeExec, ProofTypeNone, "":
		return true
	default:
		return false
	}
}

// AvailableProofTypes returns the list of proof types available in the current build.
// Without FFI, only Exec is available (besides m-of-n signature mode).
func AvailableProofTypes() []ProofType {
	return []ProofType{ProofTypeExec}
}

// IsFFIAvailable returns whether FFI support is built in.
func IsFFIAvailable() bool {
	return false
}
