package zkverifier

import (
	"fmt"
	"sync"

	"github.com/unicitynetwork/bft-go-base/types"
)

// registryCacheKey uniquely identifies a verifier configuration for a partition/shard/epoch.
type registryCacheKey struct {
	PartitionID types.PartitionID
	ShardID     string // ShardID.Key()
	Epoch       uint64
}

// Registry manages ZK verifiers for partitions, caching them by partition+shard+epoch.
type Registry struct {
	cache map[registryCacheKey]ZKVerifier
	mu    sync.RWMutex
}

// NewRegistry creates a new ZK verifier registry.
func NewRegistry() *Registry {
	return &Registry{
		cache: make(map[registryCacheKey]ZKVerifier),
	}
}

// GetVerifier returns a ZK verifier for the given partition configuration.
// It caches verifiers by partition+shard+epoch to avoid recreating them.
//
// Returns:
//   - NoOpVerifier when proof_type is empty, "none", or "exec" (m-of-n mode)
//   - The appropriate verifier for sp1/light_client
//   - Error if the requested proof type is unavailable (FFI not built) or misconfigured
func (r *Registry) GetVerifier(partitionID types.PartitionID, shardID types.ShardID, epoch uint64, params map[string]string) (ZKVerifier, error) {
	key := registryCacheKey{
		PartitionID: partitionID,
		ShardID:     shardID.Key(),
		Epoch:       epoch,
	}

	// Check cache first
	r.mu.RLock()
	if v, ok := r.cache[key]; ok {
		r.mu.RUnlock()
		return v, nil
	}
	r.mu.RUnlock()

	// Create new verifier
	verifier, err := r.createVerifier(params)
	if err != nil {
		return nil, err
	}

	// Cache the verifier
	r.mu.Lock()
	// Double-check in case another goroutine created it
	if v, ok := r.cache[key]; ok {
		r.mu.Unlock()
		return v, nil
	}
	r.cache[key] = verifier
	r.mu.Unlock()

	return verifier, nil
}

// createVerifier creates a new verifier based on partition params.
func (r *Registry) createVerifier(params map[string]string) (ZKVerifier, error) {
	proofType := ParseProofTypeFromParams(params)

	// Check availability before attempting to create
	if !IsProofTypeAvailable(proofType) {
		return nil, fmt.Errorf("proof type %q not available (build with -tags zkverifier_ffi to enable)", proofType)
	}

	switch proofType {
	case ProofTypeNone, ProofTypeExec, "":
		// m-of-n mode - no ZK proof verification
		return &NoOpVerifier{}, nil

	case ProofTypeSP1:
		vkeyPath := ParseVKeyPathFromParams(params)
		if vkeyPath == "" {
			return nil, fmt.Errorf("vkey_path required for SP1 proof type")
		}
		chainID, ok := ParseChainIDFromParams(params)
		if !ok {
			return nil, fmt.Errorf("chain_id required for SP1 proof type")
		}
		return NewSP1Verifier(vkeyPath, chainID)

	case ProofTypeLightClient:
		chainID, ok := ParseChainIDFromParams(params)
		if !ok {
			return nil, fmt.Errorf("chain_id required for light_client proof type")
		}
		return NewLightClientVerifier(chainID)

	case ProofTypeAggregatorRSMTv1:
		// Pure-Go verifier: no vkey, no chain_id. Consistency proof is
		// self-contained and recomputes roots from the envelope.
		return NewAggregatorRSMTVerifier(), nil

	default:
		return nil, fmt.Errorf("unknown proof type: %s", proofType)
	}
}

// InvalidateCache removes the cached verifier for the given partition+shard+epoch.
// Call this when partition configuration changes.
func (r *Registry) InvalidateCache(partitionID types.PartitionID, shardID types.ShardID, epoch uint64) {
	key := registryCacheKey{
		PartitionID: partitionID,
		ShardID:     shardID.Key(),
		Epoch:       epoch,
	}

	r.mu.Lock()
	delete(r.cache, key)
	r.mu.Unlock()
}

// ClearCache removes all cached verifiers.
func (r *Registry) ClearCache() {
	r.mu.Lock()
	r.cache = make(map[registryCacheKey]ZKVerifier)
	r.mu.Unlock()
}
