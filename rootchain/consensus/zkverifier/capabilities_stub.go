//go:build !zkverifier_ffi

package zkverifier

// IsProofTypeAvailable returns whether the given proof type is available
// in the current build. Without FFI, the pure-Go aggregator RSMT verifier
// is available alongside the m-of-n "exec" mode.
func IsProofTypeAvailable(pt ProofType) bool {
	switch pt {
	case ProofTypeAggregatorRSMTv1, ProofTypeExec, ProofTypeNone, "":
		return true
	default:
		return false
	}
}

// AvailableProofTypes returns the list of proof types available in the current build.
// Without FFI, the pure-Go aggregator RSMT verifier and Exec (m-of-n) are available.
func AvailableProofTypes() []ProofType {
	return []ProofType{ProofTypeAggregatorRSMTv1, ProofTypeExec}
}

// IsFFIAvailable returns whether FFI support is built in.
func IsFFIAvailable() bool {
	return false
}
