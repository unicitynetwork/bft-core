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
	var older map[types.PartitionShardID]*types.PartitionDescriptionRecord
	for k, pdr := range shardConfs {
		if len(pdr.Validators) == 0 {
			continue // the shard is deleted
		}
		pair := shardConfPair{current: pdr}
		if pdr.Epoch > 0 && pdr.EpochStart > 1 {
			if older == nil {
				var err error
				if older, err = orchestration.ShardConfigs(pdr.EpochStart - 1); err != nil {
					return nil, fmt.Errorf("loading shard configurations for round %d: %w", pdr.EpochStart-1, err)
				}
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
	// The info is of the active configuration, except in the block which triggered an epoch change of the shard:
	// the technical record has already moved to the new epoch but the info (fees, validators) is switched to it
	// only when the next block starts.
	conf, transition := pair.current, false
	confHash, err := pair.current.Hash(hashAlg)
	if err != nil {
		return nil, fmt.Errorf("calculating PDR hash: %w", err)
	}
	if !bytes.Equal(d.ShardConfHash, confHash) {
		if pair.previous == nil || d.IRTR.Epoch != pair.current.Epoch {
			return nil, errors.New("calculated shard conf hash doesn't match the value in block data")
		}
		prevHash, err := pair.previous.Hash(hashAlg)
		if err != nil {
			return nil, fmt.Errorf("calculating PDR hash: %w", err)
		}
		if !bytes.Equal(d.ShardConfHash, prevHash) {
			return nil, errors.New("calculated shard conf hash doesn't match the value in block data")
		}
		conf, transition = pair.previous, true
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
	// the initial technical record carries precomputed hashes of the empty accounting
	if !initial && (!bytes.Equal(feeHash, d.IRTR.FeeHash) || !bytes.Equal(statHash, d.IRTR.StatHash)) {
		return nil, errors.New("fees or statistics do not match the commitments of the technical record")
	}

	// the last certification response
	if (d.UC == nil) != (d.TR == nil) {
		return nil, errors.New("last response must have both the UC and the technical record, or neither")
	}
	if d.UC == nil {
		if !initial {
			return nil, errors.New("a shard without a last response must be in its initial state")
		}
		return conf, nil
	}
	if d.UC.UnicityTreeCertificate == nil || d.UC.UnicityTreeCertificate.Partition != d.Partition || !d.UC.ShardTreeCertificate.Shard.Equal(d.Shard) {
		return nil, errors.New("last response UC is of another shard")
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
	if block.Qc.VoteInfo.RoundNumber != rctypes.GenesisRootRound {
		return errors.New("genesis QC is of another round")
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
