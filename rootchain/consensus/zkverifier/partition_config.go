package zkverifier

import "strconv"

// Partition params keys for proof verification configuration.
// These are stored in PartitionDescriptionRecord.PartitionParams.
const (
	// ParamProofType specifies the proof type for the partition.
	// Valid values: "sp1", "light_client", "aggregator_rsmt_v1", "exec"
	// If empty or not set, m-of-n signature verification only (no ZK proof required).
	ParamProofType = "proof_type"

	// ParamVerificationKeyPath specifies the path to the verification key file.
	// Required for SP1 proof type.
	ParamVerificationKeyPath = "vkey_path"

	// ParamChainID specifies the EVM chain ID for the partition.
	// Required for SP1 and light_client proof types.
	// This is different from the BFT Core network ID - each EVM partition has its own chain ID.
	ParamChainID = "chain_id"
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

// ParseChainIDFromParams extracts the EVM chain ID from partition params.
// Returns 0 and false if not set or invalid.
// The chain_id is specific to the EVM partition and verified against ZK proof public values.
func ParseChainIDFromParams(params map[string]string) (uint64, bool) {
	if params == nil {
		return 0, false
	}
	cidStr, ok := params[ParamChainID]
	if !ok || cidStr == "" {
		return 0, false
	}
	cid, err := strconv.ParseUint(cidStr, 10, 64)
	if err != nil {
		return 0, false
	}
	return cid, true
}
