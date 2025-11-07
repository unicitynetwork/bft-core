package leader

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	abtypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

/*
NewReputationBased creates "leader election based on reputation" strategy implementation.

  - the "windowSize" is number of committed blocks to use to determine list of active
    validators (ie those which voted). It must not be larger than the "block history"
    available to the blockLoader, IOW the "blockLoader" must be able to return blocks
    at least inside the window.
  - "excludeSize" is the number of most recent block authors to exclude form candidate
    list when electing leader for the next round. Generally should be between f and 2f
    (where f is max allowed number of faulty nodes).
*/
func NewReputationBased(windowSize, excludeSize int, trustBaseStore *trustbase.TrustBaseStore) (*ReputationBased, error) {
	if windowSize == 0 {
		return nil, fmt.Errorf("window size must be greater than zero")
	}

	return &ReputationBased{
		windowSize:     windowSize,
		excludeSize:    excludeSize,
		trustBaseStore: trustBaseStore,
	}, nil
}

type roundLeader struct {
	round  uint64
	leader peer.ID
}

/*
ReputationBased implements reputation based leader election strategy.
Zero value is not usable, use constructor!

Remarks:
  - same leader might be elected for up to three consecutive rounds - leader of
    the round R is not eligible to be leader for rounds [R+3 .. R+3+excludeSize-1];
*/
type ReputationBased struct {
	windowSize     int // number of latest commits to take into account when determining which validators are active
	excludeSize    int // number of excluded authors of last committed blocks (should be between f and 2f)
	trustBaseStore *trustbase.TrustBaseStore

	// Elected leaders.
	// We do not (need to) keep history and we can only elect leader for the next
	// round so we need two slots - current round and next round.
	// One additional slot as a buffer for cases where election happens while some
	// other part of the manager still needs to know (now committed) round leader?
	leaders [3]roundLeader
	curIdx  int        // index of the latest election round data in the "leaders" slice
	m       sync.Mutex // this lock must be held while operating on "curIdx" and/or "leaders"
}

/*
GetLeaderForRound returns either elected leader or (in case the round doesn't have
elected leader) falls back to round-robin of all epoch validators.
Undefined behavior for round==0.
*/
func (rb *ReputationBased) GetLeaderForRound(round uint64) (peer.ID, error) {
	rb.m.Lock()
	defer rb.m.Unlock()

	for _, l := range rb.leaders {
		if l.round == round {
			return l.leader, nil
		}
	}

	tb, err := rb.trustBaseStore.GetByRound(round)
	if err != nil {
		return UnknownLeader, fmt.Errorf("failed to get trust base for round %d: %w", round, err)
	}
	leader := pickLeader(tb.GetRootNodes(), round)
	leaderID, err := peer.Decode(leader.NodeID)
	if err != nil {
		return UnknownLeader, fmt.Errorf("failed to decode leader ID %q: %w", leader.NodeID, err)
	}
	return leaderID, nil
}

func (rb *ReputationBased) UpdateWithTrustBase(trustBase types.RootTrustBase, currentRound uint64) error {
	// NB! leader selector algorithm makes the assumption that the validators slice is sorted
	rb.m.Lock()
	defer rb.m.Unlock()

	currentRoundLeader := pickLeader(trustBase.GetRootNodes(), currentRound)
	currentLeaderID, err := peer.Decode(currentRoundLeader.NodeID)
	if err != nil {
		return fmt.Errorf("invalid peer id %q: %w", currentRoundLeader.NodeID, err)
	}
	idx := rb.slotIndex(currentRound)
	rb.leaders[idx].round = currentRound
	rb.leaders[idx].leader = currentLeaderID

	nextRoundLeader := pickLeader(trustBase.GetRootNodes(), currentRound+1)
	nextLeaderID, err := peer.Decode(nextRoundLeader.NodeID)
	if err != nil {
		return fmt.Errorf("invalid peer id %q: %w", nextRoundLeader.NodeID, err)
	}
	idx = rb.slotIndex(currentRound + 1)
	rb.leaders[idx].round = currentRound + 1
	rb.leaders[idx].leader = nextLeaderID

	return nil
}

/*
Update triggers leader election for the next round.
Returns error when election fails or QC and currentRound combination does not trigger election.
"currentRound" - what PaceMaker considers to be the current round at the time QC is processed.
"blockLoader" - a callback into block store which allows to load block data of given
round, it is expected to return either valid block or error.
*/
func (rb *ReputationBased) Update(qc *abtypes.QuorumCert, currentRound uint64, blockLoader BlockLoader) error {
	exR := qc.GetParentRound()
	qcR := qc.GetRound()
	if exR+1 != qcR || qcR+1 != currentRound {
		return fmt.Errorf("not updating leaders because rounds are not consecutive {parent: %d, QC: %d, current: %d}", exR, qcR, currentRound)
	}

	nextTrustBase, err := rb.trustBaseStore.GetByEpoch(qc.VoteInfo.Epoch + 1)
	if err != nil && !errors.Is(err, trustbase.ErrNotFound) {
		return fmt.Errorf("failed to load trustBase for epoch %d: %w", qc.VoteInfo.Epoch+1, err)
	}

	// If we elect leader for next epoch, pick a leader from the set of all validators.
	var leader peer.ID
	if nextTrustBase != nil && nextTrustBase.EpochStart <= currentRound+1 {
		// NB! leader selector algorithm makes the assumption that the validators slice is sorted
		// validators, err := toPeerIDs(trustBase.GetRootNodes())
		// if err != nil {
		// 	return nil, fmt.Errorf("failed to get root validator peerIDs: %w", err)
		// }

		leaderNode := pickLeader(nextTrustBase.RootNodes, leaderSeed(qc))
		leader, err = peer.Decode(leaderNode.NodeID)
		if err != nil {
			return fmt.Errorf("invalid peer id %q: %w", leaderNode, err)
		}
	} else {
		leader, err = rb.electLeader(qc, blockLoader)
		if err != nil {
			return fmt.Errorf("failed to elect leader for round %d: %w", currentRound+1, err)
		}
	}

	rb.m.Lock()
	idx := rb.slotIndex(currentRound + 1)
	rb.leaders[idx].round = currentRound + 1
	rb.leaders[idx].leader = leader
	rb.m.Unlock()

	return nil
}

/*
slotIndex returns "leaders" index into which election result for the "round" should be stored.
Same index is returned when calling with the same "round" value multiple times in a row.
*/
func (rb *ReputationBased) slotIndex(round uint64) int {
	if round == rb.leaders[rb.curIdx].round {
		return rb.curIdx
	}

	if rb.curIdx++; rb.curIdx == len(rb.leaders) {
		rb.curIdx = 0
	}
	return rb.curIdx
}

func (rb *ReputationBased) electLeader(qc *abtypes.QuorumCert, blockLoader BlockLoader) (peer.ID, error) {
	qcRound := qc.GetRound()
	leaderSeed := leaderSeed(qc)
	authors := make(map[string]struct{}) // block authors of the recent rounds
	active := make(map[string]struct{})  // validators that signed the committed blocks
	round := qc.GetParentRound()
	for i := 0; i < rb.windowSize || len(authors) < rb.excludeSize; i++ {
		block, err := blockLoader(round)
		if err != nil {
			return UnknownLeader, fmt.Errorf("failed to load round %d block data (starting QC round %d, iteration %d): %w", round, qcRound, i, err)
		}

		if len(authors) < rb.excludeSize {
			authors[block.BlockData.Author] = struct{}{}
		}
		if i < rb.windowSize {
			for signerID := range qc.Signatures {
				active[signerID] = struct{}{}
			}
		}

		qc = block.BlockData.Qc
		round = qc.GetRound()
	}

	if len(authors) < len(active) {
		// Only remove recent authros if we have enough active validators
		for id := range authors {
			delete(active, id)
		}
	}

	leader := pickLeader(toSortedSlice(active), leaderSeed)
	id, err := peer.Decode(leader)
	if err != nil {
		return UnknownLeader, fmt.Errorf("invalid peer id %q: %w", leader, err)
	}
	return id, nil
}

/*
pickLeader picks a leader from validators based on seed. The validators slice must be sorted and not empty.
*/
func pickLeader[T any](validators []T, seed uint64) T {
	return validators[seed%uint64(len(validators))]
}

func leaderSeed(qc *abtypes.QuorumCert) uint64 {
	extra := qc.LedgerCommitInfo.PreviousHash
	return qc.GetRound() + (uint64(extra[0]) | uint64(extra[1])<<8 | uint64(extra[2])<<16 | uint64(extra[3])<<24)
}

/*
toSortedSlice returns keys of the "leaders" map as a sorted slice of strings.
*/
func toSortedSlice(leaders map[string]struct{}) []string {
	s := make([]string, len(leaders))
	i := 0
	for id := range leaders {
		s[i] = id
		i++
	}
	sort.Strings(s)
	return s
}

func toPeerIDs(nodes []*types.NodeInfo) ([]peer.ID, error) {
	peerIDs := make([]peer.ID, len(nodes))
	for n, v := range nodes {
		peerID, err := peer.Decode(v.NodeID)
		if err != nil {
			return nil, fmt.Errorf("failed to convert node ID %q: %w", v.NodeID, err)
		}
		peerIDs[n] = peerID
	}
	return peerIDs, nil
}
