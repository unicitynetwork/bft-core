package zkverifier

// IsProofTypeAvailable reports whether pt can be used in the current binary.
// Each FFI verifier is independently toggled by its own build tag:
//   - SP1, LightClient:    -tags zkverifier_ffi
//   - AggregatorZKv1:      -tags zkverifier_aggregator_zk_ffi
//
// Pure-Go verifiers (AggregatorRSMTv1, Exec, None) are always available.
func IsProofTypeAvailable(pt ProofType) bool {
	switch pt {
	case ProofTypeAggregatorRSMTv1, ProofTypeExec, ProofTypeNone, "":
		return true
	case ProofTypeSP1:
		return isSP1Available()
	case ProofTypeLightClient:
		return isLightClientAvailable()
	case ProofTypeAggregatorZKv1:
		return isAggregatorZKv1Available()
	default:
		return false
	}
}

// AvailableProofTypes returns the proof types that can be instantiated in the
// current binary.
func AvailableProofTypes() []ProofType {
	types := []ProofType{ProofTypeAggregatorRSMTv1, ProofTypeExec}
	if isSP1Available() {
		types = append(types, ProofTypeSP1)
	}
	if isLightClientAvailable() {
		types = append(types, ProofTypeLightClient)
	}
	if isAggregatorZKv1Available() {
		types = append(types, ProofTypeAggregatorZKv1)
	}
	return types
}

// IsFFIAvailable reports whether any FFI-backed verifier is available.
func IsFFIAvailable() bool {
	return isSP1Available() || isLightClientAvailable() || isAggregatorZKv1Available()
}
