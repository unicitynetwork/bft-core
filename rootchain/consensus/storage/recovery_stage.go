package storage

import (
	"bytes"
	"cmp"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

/*
ValidateRecoveryState checks a recovery state message completely, in memory, before the node writes, installs or
advances anything. It stages the recovery the way the consensus manager performs it (the committed head, then each
pending block in round order: process the QC it carries, execute the block) on a throw-away store and requires that

  - the committed head is bound to its authenticated root, configuration and last responses (NewRootBlock);
  - every pending block extends a block of the recovered tree (ancestry) and carries a QC of that parent whose round,
    parent round, epoch, timestamp and state root are the ones of the recovered parent, ie of what executing the
    blocks really gives - also when the QC is one the store would treat as already known;
  - the block certified by the head's commit QC (the round after the head) has the state root, epoch, timestamp and
    parent that QC certifies;
  - all blocks execute under the ordinary rules (verifier), and the block of the target round is there.

A block without a QC (the tip) is not certified by anything in the message: it is only executed under the ordinary
rules; when the proposal of the tip's round arrives after the recovery the consensus manager compares the whole
blocks (BlockStore.Add) and does not vote on a mismatch.

The Author of a recovered block is not authenticated: RoundInfo commits to round, epoch, time, parent and state root
but not to the block hash or the author, and the state message carries no proposer signature. Leader selection excludes
recent authors, so a recovering node can temporarily elect a different leader than its peers, reject an honest proposal
or send its vote elsewhere (a liveness limitation, safety rules and the state root binding are not affected). The
election is deliberately not changed for recovered authors only, nodes which saw the original proposal would not agree
with it.

"local" is read only (the trusted local genesis comes from it).
*/
func ValidateRecoveryState(hashAlg crypto.Hash, state *abdrc.StateMsg, toRound uint64, orchestration Orchestration, local PersistentStore,
	newVerifier func(*BlockStore) (IRChangeReqVerifier, error), log *slog.Logger) error {
	if state == nil || state.CommittedHead == nil {
		return errors.New("recovery state without a committed head")
	}
	// the staging must not touch the message the real recovery uses
	raw, err := types.Cbor.Marshal(state)
	if err != nil {
		return fmt.Errorf("copying the state: %w", err)
	}
	var sm abdrc.StateMsg
	if err := types.Cbor.Unmarshal(raw, &sm); err != nil {
		return fmt.Errorf("copying the state: %w", err)
	}

	mem := newMemoryStore()
	if local != nil {
		genesis, err := trustedGenesis(local, hashAlg, orchestration)
		if err != nil {
			return err
		}
		if err := mem.WriteBlock(genesis, false); err != nil {
			return err
		}
	}
	staged, err := NewFromState(hashAlg, sm.CommittedHead, mem, orchestration, log)
	if err != nil {
		return fmt.Errorf("committed head: %w", err)
	}
	verifier, err := newVerifier(staged)
	if err != nil {
		return fmt.Errorf("verifier construction failed: %w", err)
	}
	head := sm.CommittedHead
	pending := slices.Clone(sm.Pending)
	slices.SortFunc(pending, func(a, b *rctypes.BlockData) int { return cmp.Compare(a.GetRound(), b.GetRound()) })
	for i, b := range pending {
		if b == nil || b.Qc == nil || b.Qc.VoteInfo == nil {
			return fmt.Errorf("pending block %d has no QC", i)
		}
		// ancestry and the QC of the parent against what the recovered parent really is
		parentRound := b.GetParentRound()
		parent, err := staged.Block(parentRound)
		if err != nil || parent == nil {
			return fmt.Errorf("pending block of round %d: parent round %d is not part of the recovered state", b.GetRound(), parentRound)
		}
		if err := checkQcOfBlock(b.Qc, parent); err != nil {
			return fmt.Errorf("pending block of round %d: its QC does not certify the recovered block of round %d: %w", b.GetRound(), parentRound, err)
		}
		if _, err := staged.ProcessQc(b.Qc); err != nil {
			if i != 0 || !errors.Is(err, ErrCommitFailed) {
				return fmt.Errorf("pending block %d of round %d: processing its QC: %w", i, b.GetRound(), err)
			}
		}
		if _, err := staged.Add(b, verifier); err != nil {
			return fmt.Errorf("pending block %d of round %d: %w", i, b.GetRound(), err)
		}
		// the block which the commit QC of the head certifies
		if head.CommitQc != nil && b.GetRound() == head.CommitQc.GetRound() {
			added, err := staged.Block(b.GetRound())
			if err != nil || added == nil {
				return fmt.Errorf("pending block of round %d is not in the recovered tree", b.GetRound())
			}
			if err := checkQcOfBlock(head.CommitQc, added); err != nil {
				return fmt.Errorf("pending block of round %d does not match the commit QC of the head: %w", b.GetRound(), err)
			}
		}
	}
	if toRound > head.GetRound() {
		if b, err := staged.Block(toRound); err != nil || b == nil {
			return fmt.Errorf("the recovered state has no block for the target round %d", toRound)
		}
	}
	return nil
}

// checkQcOfBlock requires that the QC certifies the block: its round, parent round, epoch, timestamp and state root
// are the ones of the block (the root being the one computed by executing it).
func checkQcOfBlock(qc *rctypes.QuorumCert, b *ExecutedBlock) error {
	if qc == nil || qc.VoteInfo == nil || b == nil || b.BlockData == nil {
		return errors.New("QC or block missing")
	}
	vi := qc.VoteInfo
	switch {
	case vi.RoundNumber != b.GetRound():
		return fmt.Errorf("QC is of round %d", vi.RoundNumber)
	case vi.ParentRoundNumber != b.GetParentRound():
		return fmt.Errorf("QC parent round %d, block parent round %d", vi.ParentRoundNumber, b.GetParentRound())
	case vi.Epoch != b.BlockData.Epoch || vi.Timestamp != b.BlockData.Timestamp:
		return errors.New("QC epoch or timestamp differ from the block's")
	case !bytes.Equal(vi.CurrentRootHash, b.RootHash):
		return fmt.Errorf("QC state root %X differs from the root %X of the block", []byte(vi.CurrentRootHash), []byte(b.RootHash))
	}
	return nil
}

// memoryStore is a PersistentStore which keeps everything in memory: the staging area of ValidateRecoveryState.
type memoryStore struct {
	m      sync.Mutex
	blocks map[uint64]*ExecutedBlock
	vote   any
	tc     *rctypes.TimeoutCert
}

func newMemoryStore() *memoryStore { return &memoryStore{blocks: map[uint64]*ExecutedBlock{}} }

func (s *memoryStore) LoadBlocks() ([]*ExecutedBlock, error) {
	s.m.Lock()
	defer s.m.Unlock()
	out := make([]*ExecutedBlock, 0, len(s.blocks))
	for _, b := range s.blocks {
		out = append(out, b)
	}
	slices.SortFunc(out, func(a, b *ExecutedBlock) int { return cmp.Compare(b.GetRound(), a.GetRound()) })
	return out, nil
}

func (s *memoryStore) WriteBlock(block *ExecutedBlock, root bool) error {
	s.m.Lock()
	defer s.m.Unlock()
	if root {
		for r := range s.blocks {
			if r < block.GetRound() {
				delete(s.blocks, r)
			}
		}
	}
	s.blocks[block.GetRound()] = block
	return nil
}

func (s *memoryStore) WriteVote(vote any) error { s.vote = vote; return nil }
func (s *memoryStore) ReadLastVote() (any, error) {
	return s.vote, nil
}
func (s *memoryStore) WriteTC(tc *rctypes.TimeoutCert) error { s.tc = tc; return nil }
func (s *memoryStore) ReadLastTC() (*rctypes.TimeoutCert, error) {
	return s.tc, nil
}
