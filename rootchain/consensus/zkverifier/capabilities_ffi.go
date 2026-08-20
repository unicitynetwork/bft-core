//go:build zkverifier_ffi

package zkverifier

// isSP1Available returns true when the SP1 FFI verifier was compiled in.
func isSP1Available() bool { return true }

// isLightClientAvailable returns true when the LightClient FFI verifier was compiled in.
func isLightClientAvailable() bool { return true }
