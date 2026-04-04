//go:build zkverifier_ffi

package zkverifier

// IsProofTypeAvailable returns whether the given proof type is available
// in the current build. With FFI, SP1 and LightClient are available.
func IsProofTypeAvailable(pt ProofType) bool {
	switch pt {
	case ProofTypeSP1, ProofTypeLightClient, ProofTypeAggregatorRSMTv1, ProofTypeExec, ProofTypeNone, "":
		return true
	default:
		return false
	}
}

// AvailableProofTypes returns the list of proof types available in the current build.
// With FFI, SP1 and LightClient are available (besides m-of-n signature mode
// and the pure-Go aggregator RSMT verifier).
func AvailableProofTypes() []ProofType {
	return []ProofType{ProofTypeSP1, ProofTypeLightClient, ProofTypeAggregatorRSMTv1, ProofTypeExec}
}

// IsFFIAvailable returns whether FFI support is built in.
func IsFFIAvailable() bool {
	return true
}
