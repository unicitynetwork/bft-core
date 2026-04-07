//go:build !zkverifier_aggregator_zk_ffi

package zkverifier

import "fmt"

// AggregatorZKVerifierFFI is a stub when the FFI library is not compiled in.
type AggregatorZKVerifierFFI struct {
	vkey []byte
}

// NewAggregatorZKVerifierFFI returns an error when the FFI library is not available.
func NewAggregatorZKVerifierFFI(_ string) (*AggregatorZKVerifierFFI, error) {
	return nil, fmt.Errorf("aggregator ZK FFI verifier not available: build with -tags zkverifier_aggregator_zk_ffi to enable")
}

// VerifyProof always returns an error in the stub.
func (v *AggregatorZKVerifierFFI) VerifyProof(_ []byte, _ []byte, _ []byte) error {
	return fmt.Errorf("aggregator ZK FFI verifier not available")
}

// GetAggregatorZKFFIVersion returns "unavailable" in the stub.
func GetAggregatorZKFFIVersion() string { return "unavailable" }
