package storage

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"maps"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

/*
Validation of the committed head of a recovery state message.

StateMsg.Verify authenticates the QCs and each UC on their own, but nothing ties the shard infos of the message to
the root the QCs commit to. A recovering node must therefore, before anything is written or installed:

 1. cross-check the round, parent and state root relationships of the block, its QC and the commit QC (the
    genesis head only if it is the trusted local genesis), rebuild the complete shard tree from the supplied
    input records, technical records and configuration hashes and require it to equal the authenticated
    committed root; reject duplicate, missing and unexpected shards against the local configuration;
 2. recompute the fee and statistics commitments of the technical record from the supplied accounting data
    (using the epoch transition representation where the head is the block which triggered the transition) and
    derive timeouts and validator lists from the local configuration; and
 3. bind each retained last response (UC and technical record) to the shard and to the head state; a shard
    without one is accepted only when its whole state is the initial state derived from the configuration.

No information beyond the state message and the local orchestration is used.
*/

// shardConfPair is the configuration of a shard active in the round of the head and, if the shard's epoch changes
// in that round, the configuration of the previous epoch.
type shardConfPair struct {
	current  *types.PartitionDescriptionRecord
	previous *types.PartitionDescriptionRecord
}

// recoveredShardConfs resolves for every shard with validators the configurations relevant for the head.
func recoveredShardConfs(round uint64, shardConfs map[types.PartitionShardID]*types.PartitionDescriptionRecord, orchestration Orchestration) (map[types.PartitionShardID]shardConfPair, error) {
	out := make(map[types.PartitionShardID]shardConfPair, len(shardConfs))
	// every shard's previous epoch configuration is looked up at the round before ITS epoch started; the shards
	// of a head do not switch epochs at the same round, so the lookups are cached by round, not shared
	olderAt := map[uint64]map[types.PartitionShardID]*types.PartitionDescriptionRecord{}
	for k, pdr := range shardConfs {
		if len(pdr.Validators) == 0 {
			continue // the shard is deleted
		}
		pair := shardConfPair{current: pdr}
		if pdr.Epoch > 0 && pdr.EpochStart > 1 {
			lookup := pdr.EpochStart - 1
			older, ok := olderAt[lookup]
			if !ok {
				var err error
				if older, err = orchestration.ShardConfigs(lookup); err != nil {
					return nil, fmt.Errorf("loading shard configurations for round %d: %w", lookup, err)
				}
				olderAt[lookup] = older
			}
			if prev, ok := older[k]; ok && prev.Epoch+1 == pdr.Epoch && len(prev.Validators) > 0 {
				pair.previous = prev
			}
		}
		out[k] = pair
	}
	return out, nil
}

// validateRecoveredShard checks one shard info and returns the configuration the info is of.
func validateRecoveredShard(d *abdrc.ShardInfo, pair shardConfPair, hashAlg crypto.Hash) (*types.PartitionDescriptionRecord, error) {
	if d.IR == nil {
		return nil, errors.New("input record is missing")
	}
	// The info is of the active configuration, except while the shard has not switched to the epoch which the active
	// configuration starts: then it is still of the previous epoch (the switch is made by the first change request
	// of the shard in the new epoch). In the block of that request the technical record is already of the new epoch
	// but the info is switched only when the next block starts ("transition").
	conf, transition := pair.current, false
	confHash, err := pair.current.Hash(hashAlg)
	if err != nil {
		return nil, fmt.Errorf("calculating PDR hash: %w", err)
	}
	if !bytes.Equal(d.ShardConfHash, confHash) {
		if pair.previous == nil {
			return nil, errors.New("calculated shard conf hash doesn't match the value in block data")
		}
		prevHash, err := pair.previous.Hash(hashAlg)
		if err != nil {
			return nil, fmt.Errorf("calculating PDR hash: %w", err)
		}
		if !bytes.Equal(d.ShardConfHash, prevHash) {
			return nil, errors.New("calculated shard conf hash doesn't match the value in block data")
		}
		switch d.IRTR.Epoch {
		case pair.current.Epoch:
			transition = true
		case pair.previous.Epoch:
			// not switched yet
		default:
			return nil, fmt.Errorf("technical record of epoch %d with the info of epoch %d", d.IRTR.Epoch, pair.previous.Epoch)
		}
		conf = pair.previous
	}

	// operational values are derived from the configuration, never taken from the message
	if d.T2Timeout != conf.T2Timeout {
		return nil, fmt.Errorf("T2 timeout %s differs from the configured %s", d.T2Timeout, conf.T2Timeout)
	}
	if len(d.Fees) != len(conf.Validators) {
		return nil, fmt.Errorf("fee list has %d entries but the shard has %d validators", len(d.Fees), len(conf.Validators))
	}
	for _, v := range conf.Validators {
		if _, ok := d.Fees[v.NodeID]; !ok {
			return nil, fmt.Errorf("fee list lacks validator %q", v.NodeID)
		}
	}
	if !bytes.Equal(d.RootHash, d.IR.Hash) {
		return nil, errors.New("last certified root hash differs from the state hash of the input record")
	}

	// fee and statistics commitments of the technical record
	si := &ShardInfo{
		PartitionID: d.Partition, ShardID: d.Shard, T2Timeout: d.T2Timeout, ShardConfHash: d.ShardConfHash, RootHash: d.RootHash,
		PrevEpochStat: d.PrevEpochStat, Stat: d.Stat, PrevEpochFees: d.PrevEpochFees, Fees: maps.Clone(d.Fees),
		IR: d.IR, TR: d.IRTR,
	}
	accounting := si
	if transition {
		if accounting, err = si.nextEpoch(pair.current, hashAlg); err != nil {
			return nil, fmt.Errorf("deriving the next epoch accounting: %w", err)
		}
	}
	feeHash, err := accounting.feeHash(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("hashing fees: %w", err)
	}
	statHash, err := accounting.statHash(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("hashing statistics: %w", err)
	}
	initial, err := isInitialShardState(d, conf, hashAlg)
	if err != nil {
		return nil, err
	}
	// While the shard has not certified in its new epoch (the IR is still of the old one) every block starts the
	// next epoch of the info again (ShardStates.nextBlock): from the second block on its accounting is the
	// deterministic one of a new epoch (nothing but the configured validators with zero fees) and the technical
	// record still carries the hashes computed in the transition block. That state has no free value.
	repeatedSwitch := !transition && conf == pair.current && d.IR.Epoch != d.IRTR.Epoch && isNewEpochAccounting(d, conf)
	// the initial technical record carries precomputed hashes of the empty accounting
	if !initial && !repeatedSwitch && (!bytes.Equal(feeHash, d.IRTR.FeeHash) || !bytes.Equal(statHash, d.IRTR.StatHash)) {
		return nil, errors.New("fees or statistics do not match the commitments of the technical record")
	}

	// the last certification response: every shard of a committed head has one - a newly activated shard gets its
	// first response when the block of the activation is committed - so it can not be left out (a peer could
	// otherwise strip it from a certified shard and have the node refuse the shard's requests)
	if d.UC == nil || d.TR == nil {
		return nil, errors.New("last response (UC and technical record) is required")
	}
	if d.UC.UnicityTreeCertificate == nil || d.UC.UnicityTreeCertificate.Partition != d.Partition || !d.UC.ShardTreeCertificate.Shard.Equal(d.Shard) {
		return nil, errors.New("last response UC is of another shard")
	}
	// the UC was issued while the info was of the current or of the previous epoch of the shard
	ucConf := bytes.Equal(d.UC.ShardConfHash, confHash)
	if !ucConf && pair.previous != nil {
		prevHash, err := pair.previous.Hash(hashAlg)
		if err != nil {
			return nil, fmt.Errorf("calculating PDR hash: %w", err)
		}
		ucConf = bytes.Equal(d.UC.ShardConfHash, prevHash)
	}
	if !ucConf {
		return nil, errors.New("last response UC carries a shard configuration hash which is not one of the shard's")
	}
	trHash, err := d.TR.Hash()
	if err != nil {
		return nil, fmt.Errorf("hashing the technical record of the last response: %w", err)
	}
	if !bytes.Equal(trHash, d.UC.TRHash) {
		return nil, errors.New("technical record of the last response does not match the UC")
	}
	// the last response is the one generated when the head (or the block which last changed the shard) was
	// committed, hence it certifies exactly the state the info holds; an older genuine UC of the shard is not it
	if eq, err := types.EqualIR(d.UC.InputRecord, d.IR); err != nil || !eq {
		return nil, errors.New("last response UC certifies another input record than the shard info holds")
	}
	if !technicalRecordsEqual(d.TR, &d.IRTR) {
		return nil, errors.New("technical record of the last response differs from the one of the shard info")
	}
	return conf, nil
}

// isNewEpochAccounting tells whether the accounting of the info has the form ShardInfo.nextEpoch gives it when the
// switch to the next epoch is made again by a following block: zero fees of exactly the configured validators and
// zero statistics, after the serialized accounting of the epoch it follows. The serialized previous accounting
// itself is what the first switch took from the then current info (a fee map of the configured validators, a
// statistical record), and nothing the message carries commits to it any more: the technical record holds the
// hashes of the accounting from before the repeated switch, which is gone. So its form is checked, its values can
// not be (changing the next-epoch step to keep them changes the state root: a coordinated upgrade).
func isNewEpochAccounting(d *abdrc.ShardInfo, conf *types.PartitionDescriptionRecord) bool {
	if d.Stat != (certification.StatisticalRecord{}) || len(d.Fees) != len(conf.Validators) {
		return false
	}
	for _, v := range conf.Validators {
		if fee, ok := d.Fees[v.NodeID]; !ok || fee != 0 {
			return false
		}
	}
	var prevFees map[string]uint64
	if types.Cbor.Unmarshal(d.PrevEpochFees, &prevFees) != nil || len(prevFees) != len(conf.Validators) {
		return false
	}
	for _, v := range conf.Validators {
		if _, ok := prevFees[v.NodeID]; !ok {
			return false
		}
	}
	var prevStat certification.StatisticalRecord
	if types.Cbor.Unmarshal(d.PrevEpochStat, &prevStat) != nil {
		return false
	}
	// canonical encodings: what is hashed later is exactly these bytes
	reFees, err1 := types.Cbor.Marshal(prevFees)
	reStat, err2 := types.Cbor.Marshal(prevStat)
	return err1 == nil && err2 == nil && bytes.Equal(reFees, d.PrevEpochFees) && bytes.Equal(reStat, d.PrevEpochStat)
}

func technicalRecordsEqual(a, b *certification.TechnicalRecord) bool {
	return a.Round == b.Round && a.Epoch == b.Epoch && a.Leader == b.Leader &&
		bytes.Equal(a.StatHash, b.StatHash) && bytes.Equal(a.FeeHash, b.FeeHash)
}

// isInitialShardState tells whether the shard info is exactly what NewShardInfo derives from the configuration,
// ie the shard has never been certified.
func isInitialShardState(d *abdrc.ShardInfo, conf *types.PartitionDescriptionRecord, hashAlg crypto.Hash) (bool, error) {
	ref, err := NewShardInfo(conf, hashAlg)
	if err != nil {
		return false, fmt.Errorf("deriving the initial shard state: %w", err)
	}
	eq, err := types.EqualIR(d.IR, ref.IR)
	if err != nil || !eq {
		return false, nil
	}
	return technicalRecordsEqual(&d.IRTR, &ref.TR) && bytes.Equal(d.ShardConfHash, ref.ShardConfHash) && len(d.RootHash) == 0 &&
		bytes.Equal(d.PrevEpochStat, ref.PrevEpochStat) && bytes.Equal(d.PrevEpochFees, ref.PrevEpochFees) &&
		d.Stat == ref.Stat && maps.Equal(d.Fees, ref.Fees), nil
}

// validateRecoveredHead cross-checks the block, QC and commit QC of the head with each other and with the
// reconstructed state root, which is the root the commit QC authenticates.
func validateRecoveredHead(block *abdrc.CommittedBlock, rootHash []byte, hashAlg crypto.Hash, localGenesis *ExecutedBlock) error {
	if block == nil || block.Block == nil || block.Qc == nil || block.CommitQc == nil {
		return errors.New("committed block, its QC and its commit QC are required")
	}
	if block.Qc.VoteInfo == nil || block.CommitQc.VoteInfo == nil || block.CommitQc.LedgerCommitInfo == nil {
		return errors.New("QCs without vote info or ledger commit info")
	}
	round := block.Block.Round
	if round == rctypes.GenesisRootRound {
		return validateGenesisHead(block, rootHash, hashAlg, localGenesis)
	}
	qc, cqc, info := block.Qc.VoteInfo, block.CommitQc.VoteInfo, block.CommitQc.LedgerCommitInfo
	// the QC of the block
	if qc.RoundNumber != round {
		return fmt.Errorf("QC is of round %d but the block is of round %d", qc.RoundNumber, round)
	}
	if qc.ParentRoundNumber != block.Block.GetParentRound() {
		return fmt.Errorf("QC parent round %d differs from the parent round %d of the block", qc.ParentRoundNumber, block.Block.GetParentRound())
	}
	if qc.Epoch != block.Block.Epoch || qc.Timestamp != block.Block.Timestamp {
		return errors.New("QC epoch or timestamp differ from the block's")
	}
	// the commit QC is the QC of the consecutive round which commits the block
	if cqc.ParentRoundNumber != round || cqc.RoundNumber != round+1 {
		return fmt.Errorf("commit QC is of round %d (parent %d), expected round %d committing round %d", cqc.RoundNumber, cqc.ParentRoundNumber, round+1, round)
	}
	if info.RootChainRoundNumber != round || info.Epoch != block.Block.Epoch || info.Timestamp != block.Block.Timestamp {
		return errors.New("commit info is not of the committed block")
	}
	// the state: the shard tree rebuilt from the supplied records is the authenticated one
	if !bytes.Equal(info.Hash, rootHash) {
		return fmt.Errorf("shard state root %X differs from the root %X committed by the commit QC", rootHash, info.Hash)
	}
	if !bytes.Equal(qc.CurrentRootHash, rootHash) {
		return fmt.Errorf("shard state root %X differs from the root %X of the block's QC", rootHash, qc.CurrentRootHash)
	}
	return nil
}

// trustedGenesis is the genesis block the node trusts: the one in its own storage while it is still there,
// otherwise the one every node of the network derives (NewGenesisBlock).
func trustedGenesis(db PersistentStore, hashAlg crypto.Hash, orchestration Orchestration) (*ExecutedBlock, error) {
	if db != nil {
		blocks, err := db.LoadBlocks()
		if err != nil {
			return nil, fmt.Errorf("reading local blocks: %w", err)
		}
		for _, b := range blocks {
			if b != nil && b.BlockData != nil && b.GetRound() == rctypes.GenesisRootRound {
				return b, nil
			}
		}
	}
	return NewGenesisBlock(orchestration.NetworkID(), hashAlg)
}

// validateGenesisHead: the genesis block is the same on every node and unsigned, so a genesis head is accepted
// only if it is the trusted local genesis: same block, same state root, same commit QC. Its commit QC is either the
// self-committing genesis QC, or (once the next round has been voted) the QC of round 2 which commits it, which
// the generic commit relationships describe.
func validateGenesisHead(block *abdrc.CommittedBlock, rootHash []byte, hashAlg crypto.Hash, local *ExecutedBlock) error {
	if local == nil || local.BlockData == nil || local.CommitQc == nil || local.CommitQc.VoteInfo == nil || local.CommitQc.LedgerCommitInfo == nil {
		return errors.New("no trusted local genesis")
	}
	if !bytes.Equal(rootHash, local.RootHash) || len(block.ShardInfo) != len(local.ShardState.States) {
		return errors.New("genesis state differs from the local genesis")
	}
	want, err := local.BlockData.Hash(hashAlg)
	if err != nil {
		return err
	}
	got, err := block.Block.Hash(hashAlg)
	if err != nil {
		return fmt.Errorf("hashing the genesis block: %w", err)
	}
	if !bytes.Equal(want, got) {
		return errors.New("genesis block differs from the local genesis")
	}
	// the QC of the genesis block is unsigned: it must be the local one in full
	if local.Qc == nil || local.Qc.VoteInfo == nil || local.Qc.LedgerCommitInfo == nil {
		return errors.New("no trusted local genesis QC")
	}
	wantVi, err := local.Qc.VoteInfo.Hash(hashAlg)
	if err != nil {
		return err
	}
	gotVi, err := block.Qc.VoteInfo.Hash(hashAlg)
	if err != nil {
		return err
	}
	if !bytes.Equal(wantVi, gotVi) || block.Qc.LedgerCommitInfo == nil ||
		!bytes.Equal(block.Qc.LedgerCommitInfo.PreviousHash, local.Qc.LedgerCommitInfo.PreviousHash) ||
		!bytes.Equal(block.Qc.LedgerCommitInfo.Hash, local.Qc.LedgerCommitInfo.Hash) ||
		block.Qc.LedgerCommitInfo.RootChainRoundNumber != local.Qc.LedgerCommitInfo.RootChainRoundNumber ||
		block.Qc.LedgerCommitInfo.Epoch != local.Qc.LedgerCommitInfo.Epoch || block.Qc.LedgerCommitInfo.Timestamp != local.Qc.LedgerCommitInfo.Timestamp {
		return errors.New("genesis QC differs from the local genesis")
	}
	cqc, info := block.CommitQc.VoteInfo, block.CommitQc.LedgerCommitInfo
	if cqc.RoundNumber == rctypes.GenesisRootRound {
		// the self-committing genesis QC is a constant of the network
		wantQc, err := local.CommitQc.VoteInfo.Hash(hashAlg)
		if err != nil {
			return err
		}
		gotQc, err := cqc.Hash(hashAlg)
		if err != nil {
			return err
		}
		if !bytes.Equal(wantQc, gotQc) || !bytes.Equal(info.PreviousHash, local.CommitQc.LedgerCommitInfo.PreviousHash) || !bytes.Equal(info.Hash, rootHash) {
			return errors.New("genesis commit QC differs from the local genesis")
		}
		return nil
	}
	if cqc.ParentRoundNumber != rctypes.GenesisRootRound || cqc.RoundNumber != rctypes.GenesisRootRound+1 {
		return fmt.Errorf("commit QC of round %d (parent %d) does not commit the genesis block", cqc.RoundNumber, cqc.ParentRoundNumber)
	}
	if info.RootChainRoundNumber != rctypes.GenesisRootRound || info.Epoch != block.Block.Epoch || info.Timestamp != block.Block.Timestamp || !bytes.Equal(info.Hash, rootHash) {
		return errors.New("commit info is not of the genesis block")
	}
	return nil
}
