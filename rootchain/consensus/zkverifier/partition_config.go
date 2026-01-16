package zkverifier

// Partition params keys for proof verification configuration.
// These are stored in PartitionDescriptionRecord.PartitionParams.
const (
	// ParamProofType specifies the proof type for the partition.
	// Valid values: "sp1", "light_client", "exec"
	// If empty or not set, m-of-n signature verification only (no ZK proof required).
	ParamProofType = "proof_type"

	// ParamVerificationKeyPath specifies the path to the verification key file.
	// Required for SP1 proof type.
	ParamVerificationKeyPath = "vkey_path"
)

// ParseProofTypeFromParams extracts the ProofType from partition params.
// Returns ProofTypeNone if proof_type is not set or empty.
func ParseProofTypeFromParams(params map[string]string) ProofType {
	if params == nil {
		return ProofTypeNone
	}
	pt, ok := params[ParamProofType]
	if !ok || pt == "" {
		return ProofTypeNone
	}
	return ProofType(pt)
}

// ParseVKeyPathFromParams extracts the verification key path from partition params.
// Returns empty string if not set.
func ParseVKeyPathFromParams(params map[string]string) string {
	if params == nil {
		return ""
	}
	return params[ParamVerificationKeyPath]
}
