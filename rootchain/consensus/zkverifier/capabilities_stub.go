//go:build !zkverifier_ffi

package zkverifier

// isSP1Available returns false when the SP1 FFI verifier was not compiled in.
func isSP1Available() bool { return false }

// isLightClientAvailable returns false when the LightClient FFI verifier was not compiled in.
func isLightClientAvailable() bool { return false }
