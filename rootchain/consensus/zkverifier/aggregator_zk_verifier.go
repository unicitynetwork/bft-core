package zkverifier

import (
	"encoding/hex"
	"fmt"
	"log/slog"
)

// AggregatorZKVerifier verifies SP1 ZK consistency proofs produced by the
// rugregator aggregator (SP1 6.0.2).
//
// The proof commits exactly 72 public-value bytes:
//
//	bytes  0–31: previous SMT root (must match previousStateRoot arg)
//	bytes 32–63: new SMT root      (must match newStateRoot arg)
//	bytes 64–71: reference time, big-endian u64 (must match CR.IR.t)
//
// The reference time is public because the batch is not. In the hash-based
// instantiation the Core derives each leaf value as H(txhash, tau) from the
// batch it receives; here it receives no batch, so the circuit performs that
// derivation internally and exposes tau for the Core to check. Changing the
// proof instantiation therefore does not change the certified relation.
//
// blockHash is accepted by the ZKVerifier interface but ignored — aggregator
// ZK proofs do not commit a block hash.
type AggregatorZKVerifier struct {
	enabled     bool
	ffiVerifier *AggregatorZKVerifierFFI
}

// NewAggregatorZKVerifier creates a new aggregator ZK verifier.
// vkeyPath must point to a bincode-serialized SP1VerifyingKey (see extract-vkey).
func NewAggregatorZKVerifier(vkeyPath string) (*AggregatorZKVerifier, error) {
	if vkeyPath == "" {
		return nil, fmt.Errorf("vkey_path is required for aggregator_zk_v1 proof type")
	}
	ffi, err := NewAggregatorZKVerifierFFI(vkeyPath)
	if err != nil {
		return nil, fmt.Errorf("aggregator ZK FFI verifier not available: %w", err)
	}
	slog.Info("Using aggregator ZK verifier", "path", vkeyPath, "version", GetAggregatorZKFFIVersion())
	return &AggregatorZKVerifier{enabled: true, ffiVerifier: ffi}, nil
}

// VerifyProof verifies an aggregator SP1 ZK consistency proof.
func (v *AggregatorZKVerifier) VerifyProof(proof []byte, previousStateRoot []byte, newStateRoot []byte, blockHash []byte, referenceTime uint64) error {
	if !v.enabled {
		return ErrVerifierNotConfigured
	}
	if len(proof) == 0 {
		return fmt.Errorf("%w: proof is empty", ErrInvalidProofFormat)
	}
	if len(previousStateRoot) != 32 {
		return fmt.Errorf("%w: previousStateRoot must be 32 bytes, got %d", ErrInvalidProofFormat, len(previousStateRoot))
	}
	if len(newStateRoot) != 32 {
		return fmt.Errorf("%w: newStateRoot must be 32 bytes, got %d", ErrInvalidProofFormat, len(newStateRoot))
	}

	slog.Debug("Verifying aggregator ZK proof",
		"proof_size", len(proof),
		"prev_root", hex.EncodeToString(previousStateRoot[:8]),
		"new_root", hex.EncodeToString(newStateRoot[:8]),
		"reference_time", referenceTime)

	return v.ffiVerifier.VerifyProof(proof, previousStateRoot, newStateRoot, referenceTime)
}

// ProofType returns ProofTypeAggregatorZKv1.
func (v *AggregatorZKVerifier) ProofType() ProofType { return ProofTypeAggregatorZKv1 }

// IsEnabled returns true if the verifier is configured and the FFI library is available.
func (v *AggregatorZKVerifier) IsEnabled() bool { return v.enabled }
