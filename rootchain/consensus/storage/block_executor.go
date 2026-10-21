package storage

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"log/slog"

	"github.com/unicitynetwork/bft-core/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

type (
	ExecutedBlock struct {
		_          struct{}            `cbor:",toarray"`
		BlockData  *rctypes.BlockData  // proposed block
		HashAlgo   crypto.Hash         // hash algorithm for the block
		RootHash   hex.Bytes           // resulting root hash
		Qc         *rctypes.QuorumCert // block's quorum certificate (from next view)
		CommitQc   *rctypes.QuorumCert // block's commit certificate
		ShardState ShardStates
	}

	IRChangeReqVerifier interface {
		// VerifyIRChangeReq verifies the change request for the block of the "round" which
		// extends the block of the "parentRound".
		VerifyIRChangeReq(round, parentRound uint64, irChReq *rctypes.IRChangeReq) (*types.InputRecord, error)
	}
)

func NewRootBlock(block *abdrc.CommittedBlock, hash crypto.Hash, orchestration Orchestration) (*ExecutedBlock, error) {
	return newRootBlock(block, hash, orchestration, nil)
}

// newRootBlock creates the root block of a recovery state. The state is validated completely before the block is
// returned, ie before anything is persisted or installed. localGenesis is the genesis the node trusts (nil: the
// one derived by NewGenesisBlock).
func newRootBlock(block *abdrc.CommittedBlock, hash crypto.Hash, orchestration Orchestration, localGenesis *ExecutedBlock) (*ExecutedBlock, error) {
	if block == nil {
		return nil, errors.New("committed block is nil")
	}
	shardConfs, err := orchestration.ShardConfigs(block.GetRound())
	if err != nil {
		return nil, fmt.Errorf("loading shard configurations for round %d: %w", block.GetRound(), err)
	}
	confPairs, err := recoveredShardConfs(block.GetRound(), shardConfs, orchestration)
	if err != nil {
		return nil, err
	}

	shardState := ShardStates{
		States:  make(map[types.PartitionShardID]*ShardInfo, len(shardConfs)),
		Changed: ShardSet{},
	}
	for i := range block.ShardInfo {
		d := &block.ShardInfo[i]
		shardKey := types.PartitionShardID{PartitionID: d.Partition, ShardID: d.Shard.Key()}
		if _, dup := shardState.States[shardKey]; dup {
			return nil, fmt.Errorf("block contains shard %s - %s more than once", d.Partition, d.Shard)
		}
		pair, ok := confPairs[shardKey]
		if !ok {
			return nil, fmt.Errorf("block contains shard %s - %s which is not active in the local orchestration", d.Partition, d.Shard)
		}
		shardConf, err := validateRecoveredShard(d, pair, hash)
		if err != nil {
			return nil, fmt.Errorf("shard %s - %s: %w", d.Partition, d.Shard, err)
		}

		si := &ShardInfo{
			PartitionID:   d.Partition,
			ShardID:       d.Shard,
			T2Timeout:     d.T2Timeout,
			ShardConfHash: d.ShardConfHash,
			RootHash:      d.RootHash,
			PrevEpochStat: d.PrevEpochStat,
			Stat:          d.Stat,
			PrevEpochFees: d.PrevEpochFees,
			Fees:          d.Fees,
			IR:            d.IR,
			TR:            d.IRTR,
		}
		if d.UC != nil {
			si.LastCR = &certification.CertificationResponse{
				Partition: d.Partition,
				Shard:     d.Shard,
				Technical: *d.TR,
				UC:        *d.UC,
			}
		}
		if err := si.resetTrustBase(shardConf); err != nil {
			return nil, fmt.Errorf("initializing shard trustbase: %w", err)
		}
		shardState.States[shardKey] = si
	}
	for k := range confPairs {
		// the genesis block has no shards (they are activated by the first block, see ShardStates.nextBlock)
		if _, ok := shardState.States[k]; !ok && block.GetRound() != rctypes.GenesisRootRound {
			return nil, fmt.Errorf("block lacks the active shard %s - %s", k.PartitionID, k.ShardID)
		}
	}

	ut, _, err := shardState.UnicityTree(hash)
	if err != nil {
		return nil, err
	}
	// before anything is written: the head is consistent with the authenticated root and with itself
	if block.GetRound() == rctypes.GenesisRootRound && localGenesis == nil {
		if localGenesis, err = NewGenesisBlock(orchestration.NetworkID(), hash); err != nil {
			return nil, fmt.Errorf("local genesis: %w", err)
		}
	}
	if err := validateRecoveredHead(block, ut.RootHash(), hash, localGenesis); err != nil {
		return nil, fmt.Errorf("invalid recovery state: %w", err)
	}
	return &ExecutedBlock{
		BlockData:  block.Block,
		HashAlgo:   hash,
		RootHash:   ut.RootHash(),
		Qc:         block.Qc,
		CommitQc:   block.CommitQc,
		ShardState: shardState,
	}, nil
}

func (x *ExecutedBlock) Extend(newBlock *rctypes.BlockData, verifier IRChangeReqVerifier, orchestration Orchestration, hash crypto.Hash, log *slog.Logger) (*ExecutedBlock, error) {
	// clone parent state
	shardConfs, err := orchestration.ShardConfigs(newBlock.Round)
	if err != nil {
		return nil, fmt.Errorf("loading shard configurations for round %d: %w", newBlock.Round, err)
	}

	nextShardState, err := x.ShardState.nextBlock(shardConfs, hash)
	if err != nil {
		return nil, fmt.Errorf("creating shard info for the block: %w", err)
	}

	for _, irChReq := range newBlock.Payload.Requests {
		shardKey := types.PartitionShardID{PartitionID: irChReq.Partition, ShardID: irChReq.Shard.Key()}
		si, ok := nextShardState.States[shardKey]
		if !ok {
			log.Info(fmt.Sprintf("no validators in shard config (shard has been removed?) %s", shardKey))
			continue
		}

		if si.IR, err = verifier.VerifyIRChangeReq(newBlock.Round, x.GetRound(), irChReq); err != nil {
			return nil, fmt.Errorf("verifying change request: %w", err)
		}

		// timeout IR change request do not have BCR
		var req *certification.BlockCertificationRequest
		if len(irChReq.Requests) > 0 {
			req = irChReq.Requests[0]
		}
		if err = si.nextRound(req, shardConfs[shardKey], hash); err != nil {
			return nil, fmt.Errorf("updating shard info for the next round: %w", err)
		}

		nextShardState.Changed[shardKey] = struct{}{}
	}

	ut, _, err := nextShardState.UnicityTree(hash)
	if err != nil {
		return nil, fmt.Errorf("creating UnicityTree: %w", err)
	}
	return &ExecutedBlock{
		BlockData:  newBlock,
		HashAlgo:   hash,
		RootHash:   ut.RootHash(),
		ShardState: nextShardState,
	}, nil
}

func (x *ExecutedBlock) GenerateCertificates(commitQc *rctypes.QuorumCert, log *slog.Logger) ([]*certification.CertificationResponse, error) {
	crs, rootHash, viewErrs, err := x.ShardState.certificationResponsesWithViews(x.HashAlgo)
	if err != nil {
		return nil, fmt.Errorf("failed to generate root hash: %w", err)
	}
	// sanity check, data must not have changed, hence the root hash must still be the same
	if !bytes.Equal(rootHash, x.RootHash) {
		return nil, fmt.Errorf("root hash does not match previously calculated root hash")
	}
	// sanity check, if root hashes do not match then fall back to recovery
	if !bytes.Equal(rootHash, commitQc.LedgerCommitInfo.Hash) {
		return nil, fmt.Errorf("root hash does not match hash in commit QC")
	}
	if len(crs) == 0 {
		return nil, nil
	}
	// the partition view is optional proof material, never a reason to fail the certification
	for partition, err := range viewErrs {
		log.Warn("certification responses are sent without partition view",
			slog.Uint64("partition", uint64(partition)), slog.Uint64("round", x.GetRound()), logger.Error(err))
	}

	// create UnicitySeal for pending certificates
	uSeal := &types.UnicitySeal{
		Version:              1,
		NetworkID:            commitQc.LedgerCommitInfo.NetworkID,
		RootChainRoundNumber: commitQc.LedgerCommitInfo.RootChainRoundNumber,
		Epoch:                commitQc.LedgerCommitInfo.Epoch,
		Hash:                 commitQc.LedgerCommitInfo.Hash,
		Timestamp:            commitQc.LedgerCommitInfo.Timestamp,
		PreviousHash:         commitQc.LedgerCommitInfo.PreviousHash,
		Signatures:           commitQc.Signatures,
	}
	for _, cr := range crs {
		cr.UC.UnicitySeal = uSeal
		x.ShardState.States[types.PartitionShardID{PartitionID: cr.Partition, ShardID: cr.Shard.Key()}].LastCR = cr
	}
	return crs, nil
}

func (x *ExecutedBlock) GetRound() uint64 {
	if x != nil {
		return x.BlockData.GetRound()
	}
	return 0
}

func (x *ExecutedBlock) GetParentRound() uint64 {
	if x != nil {
		return x.BlockData.GetParentRound()
	}
	return 0
}
