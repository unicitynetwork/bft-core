package zkverifier

import (
	"fmt"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier/rsmt"
)

// AggregatorRSMTVerifier verifies Radix SMT consistency proofs produced by
// the Rust aggregator's `rsmt` crate (proof type "aggregator_rsmt_v1").
//
// The verifier is pure Go, always compiled in (no build tag, no FFI). It
// recomputes both the pre- and post-insertion SMT roots from the envelope
// and checks them against the claimed InputRecord.PreviousHash / Hash.
//
// See rootchain/consensus/zkverifier/rsmt for the canonical wire format.
type AggregatorRSMTVerifier struct{}

// NewAggregatorRSMTVerifier constructs a stateless RSMT consistency verifier.
// No configuration or verification key is required — the consistency proof
// is self-contained and verified against root hashes from the InputRecord.
func NewAggregatorRSMTVerifier() *AggregatorRSMTVerifier {
	return &AggregatorRSMTVerifier{}
}

// VerifyProof decodes the zk_proof envelope and verifies the
// previousStateRoot → newStateRoot transition. The blockHash argument is
// unused: the aggregator's state transition is validated independently of
// the block header hash, which is covered by the normal InputRecord rules.
//
// An empty previousStateRoot (len == 0) is reserved for genesis / sync UCs
// and is filtered out earlier in Node.verifyZKProof, so both roots are
// expected to be 32 bytes here in practice.
func (v *AggregatorRSMTVerifier) VerifyProof(proof []byte, previousStateRoot []byte, newStateRoot []byte, _ []byte) error {
	env, err := rsmt.DecodeEnvelope(proof)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProofFormat, err)
	}
	oldRoot, err := rsmt.RootFromBytes(previousStateRoot)
	if err != nil {
		return fmt.Errorf("%w: previous state root: %v", ErrInvalidProofFormat, err)
	}
	newRoot, err := rsmt.RootFromBytes(newStateRoot)
	if err != nil {
		return fmt.Errorf("%w: new state root: %v", ErrInvalidProofFormat, err)
	}
	if err := rsmt.Verify(env, oldRoot, newRoot); err != nil {
		return fmt.Errorf("%w: %v", ErrProofVerificationFailed, err)
	}
	return nil
}

// ProofType returns ProofTypeAggregatorRSMTv1.
func (*AggregatorRSMTVerifier) ProofType() ProofType {
	return ProofTypeAggregatorRSMTv1
}

// IsEnabled reports that aggregator RSMT verification is active.
func (*AggregatorRSMTVerifier) IsEnabled() bool {
	return true
}
