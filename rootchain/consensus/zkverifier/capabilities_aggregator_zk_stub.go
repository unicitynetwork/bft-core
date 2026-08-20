//go:build !zkverifier_aggregator_zk_ffi

package zkverifier

// isAggregatorZKv1Available returns false when the aggregator ZK FFI verifier was not compiled in.
func isAggregatorZKv1Available() bool { return false }
