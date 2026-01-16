package zkverifier

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	require.NotNil(t, r)
	require.NotNil(t, r.cache)
	require.Empty(t, r.cache)
}

func TestRegistry_GetVerifier_NoProofType(t *testing.T) {
	r := NewRegistry()

	// Empty params should return NoOpVerifier
	v, err := r.GetVerifier(1, types.ShardID{}, 0, nil)
	require.NoError(t, err)
	require.NotNil(t, v)
	require.IsType(t, &NoOpVerifier{}, v)
	require.False(t, v.IsEnabled())

	// Empty proof_type should return NoOpVerifier
	v, err = r.GetVerifier(1, types.ShardID{}, 0, map[string]string{})
	require.NoError(t, err)
	require.NotNil(t, v)
	require.IsType(t, &NoOpVerifier{}, v)

	// proof_type = "none" should return NoOpVerifier
	v, err = r.GetVerifier(1, types.ShardID{}, 0, map[string]string{ParamProofType: string(ProofTypeNone)})
	require.NoError(t, err)
	require.NotNil(t, v)
	require.IsType(t, &NoOpVerifier{}, v)

	// proof_type = "exec" should return NoOpVerifier
	v, err = r.GetVerifier(1, types.ShardID{}, 0, map[string]string{ParamProofType: string(ProofTypeExec)})
	require.NoError(t, err)
	require.NotNil(t, v)
	require.IsType(t, &NoOpVerifier{}, v)
}

func TestRegistry_GetVerifier_Caching(t *testing.T) {
	r := NewRegistry()

	// Get verifier twice - should be cached
	params := map[string]string{ParamProofType: string(ProofTypeExec)}
	v1, err := r.GetVerifier(1, types.ShardID{}, 0, params)
	require.NoError(t, err)

	v2, err := r.GetVerifier(1, types.ShardID{}, 0, params)
	require.NoError(t, err)

	// Same verifier should be returned from cache (type check is sufficient for NoOpVerifier)
	require.IsType(t, v1, v2)

	// Check that cache has entry
	require.Len(t, r.cache, 1)

	// Different epoch should create new cache entry
	_, err = r.GetVerifier(1, types.ShardID{}, 1, params)
	require.NoError(t, err)
	require.Len(t, r.cache, 2)

	// Different partition should create new cache entry
	_, err = r.GetVerifier(2, types.ShardID{}, 0, params)
	require.NoError(t, err)
	require.Len(t, r.cache, 3)
}

func TestRegistry_InvalidateCache(t *testing.T) {
	r := NewRegistry()

	params := map[string]string{ParamProofType: string(ProofTypeExec)}
	_, err := r.GetVerifier(1, types.ShardID{}, 0, params)
	require.NoError(t, err)
	require.Len(t, r.cache, 1)

	// Invalidate cache
	r.InvalidateCache(1, types.ShardID{}, 0)
	require.Len(t, r.cache, 0)

	// Getting verifier again should recreate cache entry
	_, err = r.GetVerifier(1, types.ShardID{}, 0, params)
	require.NoError(t, err)
	require.Len(t, r.cache, 1)
}

func TestRegistry_ClearCache(t *testing.T) {
	r := NewRegistry()

	params := map[string]string{ParamProofType: string(ProofTypeExec)}
	_, err := r.GetVerifier(1, types.ShardID{}, 0, params)
	require.NoError(t, err)
	_, err = r.GetVerifier(2, types.ShardID{}, 0, params)
	require.NoError(t, err)

	require.Len(t, r.cache, 2)

	r.ClearCache()
	require.Empty(t, r.cache)
}

func TestRegistry_GetVerifier_SP1MissingVKey(t *testing.T) {
	r := NewRegistry()

	// SP1 without vkey_path should fail
	params := map[string]string{ParamProofType: string(ProofTypeSP1)}
	_, err := r.GetVerifier(1, types.ShardID{}, 0, params)
	require.Error(t, err)

	// In stub mode (without FFI), error is "not available"
	// In FFI mode, error is "vkey_path required"
	if IsFFIAvailable() {
		require.Contains(t, err.Error(), "vkey_path required")
	} else {
		require.Contains(t, err.Error(), "not available")
	}
}

func TestRegistry_GetVerifier_UnavailableProofType(t *testing.T) {
	r := NewRegistry()

	// Test with an unknown proof type
	params := map[string]string{ParamProofType: "unknown_type"}
	_, err := r.GetVerifier(1, types.ShardID{}, 0, params)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not available")
}
