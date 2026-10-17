// Package ucfixture is a deterministic, test-only producer of real root chain
// certification material for the UC consolidation fixture corpus. It drives the
// production block executor (Extend, GenerateCertificates) with fixed keys,
// network, times and rounds, so that other repositories can feed it their own
// shard state roots (for example real RSMT roots) and obtain signed
// certification responses, partition views and the independently derived
// ordinary unicity certificate of every shard.
//
// It must only be used by tests and fixture generators; the keys are public.
package ucfixture

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"slices"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	// NetworkID of the fixture network.
	NetworkID = types.NetworkTestNet
	// RootNodes is the number of root authority nodes; the quorum is 3 of 4.
	RootNodes = 4
	// OtherPartition is a second, single shard partition present in the root
	// tree so that the partition authentication path is never empty.
	OtherPartition types.PartitionID = 0x01010101
	// GenesisTimestamp is the seal timestamp of the genesis block.
	GenesisTimestamp uint64 = 1731504000

	shardValidators = 3
)

// Config of a fixture producer.
type Config struct {
	// Partition is the ID of the fixture partition.
	Partition types.PartitionID
	// ShardBits is the shard ID length: 0, 1, 2, 3 give 1, 2, 4, 8 shards.
	ShardBits int
}

// Shard is a shard of the fixture partition.
type Shard struct {
	ID types.ShardID
	// Config is the shard configuration, ConfigBytes its native encoding and
	// ConfigHash the hash committed in the shard tree.
	Config      *types.PartitionDescriptionRecord
	ConfigBytes []byte
	ConfigHash  []byte
}

// Producer holds the evolving root chain state.
type Producer struct {
	cfg    Config
	shards []Shard // canonical order
	other  *types.PartitionDescriptionRecord
	tb     *types.RootTrustBaseV1
	roots  []abcrypto.Signer
	cur    *storage.ExecutedBlock
	seal   *types.UnicitySeal
	orc    orchestration
}

// New creates the producer and its genesis state (round 1): every shard has its
// initial empty state record.
func New(cfg Config) (*Producer, error) {
	if cfg.Partition == 0 || cfg.Partition == OtherPartition {
		return nil, errors.New("invalid fixture partition")
	}
	if cfg.ShardBits < 0 || cfg.ShardBits > 3 {
		return nil, errors.New("shard bits must be 0..3")
	}
	p := &Producer{cfg: cfg}

	// root authority
	var rootInfos []*types.NodeInfo
	for i := 0; i < RootNodes; i++ {
		s, err := signer("root", i)
		if err != nil {
			return nil, err
		}
		p.roots = append(p.roots, s)
		v, err := s.Verifier()
		if err != nil {
			return nil, err
		}
		key, err := v.MarshalPublicKey()
		if err != nil {
			return nil, err
		}
		rootInfos = append(rootInfos, &types.NodeInfo{NodeID: RootNodeID(i), SigKey: key, Stake: 1})
	}
	tb, err := types.NewTrustBase(NetworkID, rootInfos, types.WithEpochStart(1))
	if err != nil {
		return nil, err
	}
	p.tb = tb

	// shard validators and configurations
	var validators []*types.NodeInfo
	for i := 0; i < shardValidators; i++ {
		s, err := signer("validator", i)
		if err != nil {
			return nil, err
		}
		v, err := s.Verifier()
		if err != nil {
			return nil, err
		}
		key, err := v.MarshalPublicKey()
		if err != nil {
			return nil, err
		}
		validators = append(validators, &types.NodeInfo{NodeID: fmt.Sprintf("validator-%d", i), SigKey: key, Stake: 1})
	}
	mk := func(partition types.PartitionID, id types.ShardID) (*types.PartitionDescriptionRecord, error) {
		return &types.PartitionDescriptionRecord{
			Version: 1, NetworkID: NetworkID, PartitionID: partition, ShardID: id,
			TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 2500000000, EpochStart: 1, Validators: validators,
		}, nil
	}
	scheme := schemeOf(cfg.ShardBits)
	order, err := types.CanonicalShardOrder(scheme)
	if err != nil {
		return nil, err
	}
	for _, id := range order {
		pdr, _ := mk(cfg.Partition, id)
		b, err := types.Cbor.Marshal(pdr)
		if err != nil {
			return nil, err
		}
		h, err := pdr.Hash(crypto.SHA256)
		if err != nil {
			return nil, err
		}
		p.shards = append(p.shards, Shard{ID: id, Config: pdr, ConfigBytes: b, ConfigHash: h})
	}
	p.other, _ = mk(OtherPartition, types.ShardID{})
	p.orc = orchestration{configs: map[types.PartitionShardID]*types.PartitionDescriptionRecord{}}
	for _, s := range p.shards {
		p.orc.configs[key(cfg.Partition, s.ID)] = s.Config
	}
	p.orc.configs[key(OtherPartition, types.ShardID{})] = p.other

	// genesis block
	ss := storage.ShardStates{States: map[types.PartitionShardID]*storage.ShardInfo{}, Changed: storage.ShardSet{}}
	for k, pdr := range p.orc.configs {
		si, err := storage.NewShardInfo(pdr, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("shard info: %w", err)
		}
		ss.States[k] = si
		ss.Changed[k] = struct{}{}
	}
	ut, _, err := ss.UnicityTree(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	p.cur = &storage.ExecutedBlock{
		BlockData: &rctypes.BlockData{Author: "fixture", Round: rctypes.GenesisRootRound, Timestamp: GenesisTimestamp, Payload: &rctypes.Payload{}},
		HashAlgo:  crypto.SHA256, RootHash: ut.RootHash(), ShardState: ss,
	}
	if _, err := p.commit(p.cur, GenesisTimestamp, nil); err != nil {
		return nil, err
	}
	return p, nil
}

// RootNodeID is the node ID of the i-th root authority node.
func RootNodeID(i int) string { return fmt.Sprintf("root-%d", i+1) }

// Shards returns the shards of the partition in canonical (left-to-right) order.
func (p *Producer) Shards() []Shard { return slices.Clone(p.shards) }

// TrustBase is the (unsigned) trust base of the fixture authority.
func (p *Producer) TrustBase() *types.RootTrustBaseV1 { return p.tb }

// TrustBaseCBOR is the native encoding of the trust base.
func (p *Producer) TrustBaseCBOR() ([]byte, error) { return p.tb.MarshalCBOR() }

// Quorum is the number of root signatures a seal needs.
func (p *Producer) Quorum() int {
	q := p.tb.GetQuorumThreshold()
	if q > uint64(math.MaxInt) {
		panic(fmt.Sprintf("ucfixture: quorum threshold %d does not fit in int", q))
	}
	return int(q)
}

// Change is a new state record of a shard in a block.
type Change struct {
	// Shard index in canonical order.
	Shard int
	// Timeout makes the shard's record a timeout repeat of the previous one:
	// the input record is preserved while the technical record moves on.
	Timeout bool
	// Hash is the new state hash (the shard's state tree root). Ignored for
	// Timeout. When equal to the previous hash it is an empty block record.
	Hash []byte
	// Fees, SummaryValue, ETHash complete the record; ETHash may stay nil.
	Fees         uint64
	SummaryValue []byte
	ETHash       []byte
}

// BlockSpec describes one root chain block.
type BlockSpec struct {
	// Round is the root chain round of the block and its seal, greater than the previous.
	Round uint64
	// Timestamp is the seal timestamp. The records of the shards use the
	// timestamp of the previous seal as their reference time, as in production.
	Timestamp uint64
	// Changes are the shards which change in this block.
	Changes []Change
	// Signers are the indexes of the root nodes signing the seal; nil means
	// the first Quorum() nodes.
	Signers []int
}

// ShardOutput is the certification material of one shard of a block.
type ShardOutput struct {
	Shard types.ShardID
	// Changed is true if the shard has a certification response in the block.
	Changed bool
	// ResponseV1 is the legacy four element response, ResponseV2 the version 2
	// envelope (with the partition view). Both only if Changed.
	ResponseV1, ResponseV2 []byte
	// UC is the ordinary unicity certificate of the shard in this block, derived
	// independently from the shard and unicity trees (not from the partition
	// view): for changed shards it is equal to the response's UC.
	UC      *types.UnicityCertificate
	UCBytes []byte
	// Record is the shard's input record in the block.
	Record *types.InputRecord
}

// Block is the output of one block.
type Block struct {
	Round  uint64
	Seal   *types.UnicitySeal
	Root   []byte
	Shards []ShardOutput // canonical order
	// View is the encoded partition view shared by the responses; nil if none
	// of the shards changed or the view was omitted.
	View []byte
	// Responses are the in-process responses of the changed shards.
	Responses []*certification.CertificationResponse
}

// Next executes and commits the next block with the production block executor.
func (p *Producer) Next(spec BlockSpec) (*Block, error) {
	if spec.Round <= p.cur.GetRound() {
		return nil, fmt.Errorf("round %d does not follow round %d", spec.Round, p.cur.GetRound())
	}
	prevTimestamp := p.seal.Timestamp
	payload := &rctypes.Payload{}
	repeat := map[types.PartitionShardID]*types.InputRecord{}
	for _, c := range spec.Changes {
		if c.Shard < 0 || c.Shard >= len(p.shards) {
			return nil, fmt.Errorf("no shard %d", c.Shard)
		}
		sh := p.shards[c.Shard]
		k := key(p.cfg.Partition, sh.ID)
		si := p.cur.ShardState.States[k]
		req := &rctypes.IRChangeReq{Partition: p.cfg.Partition, Shard: sh.ID}
		if c.Timeout {
			req.CertReason = rctypes.T2Timeout
			repeat[k] = si.IR.NewRepeatIR()
		} else {
			if len(c.Hash) != sha256.Size {
				return nil, errors.New("state hash must be 32 bytes")
			}
			ir := &types.InputRecord{
				Version: 1, RoundNumber: si.IR.RoundNumber + 1, Epoch: si.IR.Epoch,
				PreviousHash: bytes.Clone(si.IR.Hash), Hash: bytes.Clone(c.Hash),
				SummaryValue: nonNil(c.SummaryValue), Timestamp: prevTimestamp,
				SumOfEarnedFees: c.Fees, ETHash: bytes.Clone(c.ETHash),
			}
			if !bytes.Equal(ir.Hash, ir.PreviousHash) {
				h := sha256.Sum256(append([]byte("block"), c.Hash...))
				ir.BlockHash = h[:]
			}
			req.CertReason = rctypes.Quorum
			req.Requests = []*certification.BlockCertificationRequest{{
				PartitionID: p.cfg.Partition, ShardID: sh.ID, NodeID: "validator-0", InputRecord: ir,
			}}
		}
		payload.Requests = append(payload.Requests, req)
	}
	verifier := verifierFunc(func(round, _ uint64, ch *rctypes.IRChangeReq) (*types.InputRecord, error) {
		if len(ch.Requests) > 0 {
			return ch.Requests[0].InputRecord, nil
		}
		return repeat[key(ch.Partition, ch.Shard)], nil
	})
	bd := &rctypes.BlockData{Author: "fixture", Round: spec.Round, Timestamp: spec.Timestamp, Payload: payload}
	next, err := p.cur.Extend(bd, verifier, p.orc, crypto.SHA256, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return nil, fmt.Errorf("extending block: %w", err)
	}
	return p.commit(next, spec.Timestamp, spec.Signers)
}

// commit signs the seal of the block, generates the certificates and derives the output.
func (p *Producer) commit(b *storage.ExecutedBlock, timestamp uint64, signers []int) (*Block, error) {
	if signers == nil {
		for i := 0; i < p.Quorum(); i++ {
			signers = append(signers, i)
		}
	}
	seal := &types.UnicitySeal{
		Version: 1, NetworkID: NetworkID, RootChainRoundNumber: b.GetRound(), Epoch: p.tb.GetEpoch(),
		Timestamp: timestamp, PreviousHash: previousRoot(p.cur, b), Hash: b.RootHash,
	}
	for _, i := range signers {
		if err := seal.Sign(RootNodeID(i), p.roots[i]); err != nil {
			return nil, err
		}
	}
	qc := &rctypes.QuorumCert{
		VoteInfo:         &rctypes.RoundInfo{RoundNumber: b.GetRound() + 1, ParentRoundNumber: b.GetRound(), CurrentRootHash: make([]byte, 32)},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, NetworkID: seal.NetworkID, RootChainRoundNumber: seal.RootChainRoundNumber, Epoch: seal.Epoch, Timestamp: seal.Timestamp, PreviousHash: seal.PreviousHash, Hash: seal.Hash},
		Signatures:       seal.Signatures,
	}
	crs, err := b.GenerateCertificates(qc)
	if err != nil {
		return nil, fmt.Errorf("generating certificates: %w", err)
	}
	b.CommitQc = qc

	ut, trees, err := b.ShardState.UnicityTree(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	utc, err := ut.Certificate(p.cfg.Partition)
	if err != nil {
		return nil, err
	}
	out := &Block{Round: b.GetRound(), Seal: seal, Root: bytes.Clone(b.RootHash), Responses: nil}
	for _, sh := range p.shards {
		si := b.ShardState.States[key(p.cfg.Partition, sh.ID)]
		trHash, err := si.TR.Hash()
		if err != nil {
			return nil, err
		}
		stc, err := trees[p.cfg.Partition].Certificate(sh.ID)
		if err != nil {
			return nil, err
		}
		// the UC of the shard in this block, built from the trees only
		uc := &types.UnicityCertificate{
			Version: 1, InputRecord: si.IR, TRHash: trHash, ShardConfHash: si.ShardConfHash,
			ShardTreeCertificate: stc, UnicityTreeCertificate: utc, UnicitySeal: seal,
		}
		ucBytes, err := uc.MarshalCBOR()
		if err != nil {
			return nil, err
		}
		so := ShardOutput{Shard: sh.ID, UC: uc, UCBytes: ucBytes, Record: si.IR}
		if _, ok := b.ShardState.Changed[key(p.cfg.Partition, sh.ID)]; ok {
			so.Changed = true
		}
		out.Shards = append(out.Shards, so)
	}
	for _, cr := range crs {
		if cr.Partition != p.cfg.Partition {
			continue
		}
		idx := slices.IndexFunc(p.shards, func(s Shard) bool { return s.ID.Equal(cr.Shard) })
		so := &out.Shards[idx]
		own, err := cr.UC.MarshalCBOR()
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(own, so.UCBytes) {
			return nil, fmt.Errorf("response UC of shard %q differs from the tree derived UC", cr.Shard)
		}
		if v1, err := types.Cbor.Marshal(cr); err != nil {
			return nil, err
		} else {
			so.ResponseV1 = v1
		}
		if v2, err := certification.NewCertificationResponseV2(cr).MarshalCBOR(); err != nil {
			return nil, err
		} else {
			so.ResponseV2 = v2
		}
		out.Responses = append(out.Responses, cr)
		if out.View == nil && len(cr.PartitionView) > 0 {
			out.View = bytes.Clone(cr.PartitionView)
		}
	}
	p.cur, p.seal = b, seal
	return out, nil
}

func previousRoot(prev, cur *storage.ExecutedBlock) []byte {
	if prev == nil || prev == cur || len(prev.RootHash) == 0 {
		return bytes.Repeat([]byte{0}, 32)
	}
	return bytes.Clone(prev.RootHash)
}

func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return bytes.Clone(b)
}

func key(p types.PartitionID, id types.ShardID) types.PartitionShardID {
	return types.PartitionShardID{PartitionID: p, ShardID: id.Key()}
}

func schemeOf(bits int) types.ShardingScheme {
	if bits == 0 {
		return types.ShardingScheme{}
	}
	ids := []types.ShardID{{}}
	for ; bits > 0; bits-- {
		var next []types.ShardID
		for _, id := range ids {
			a, b := id.Split()
			next = append(next, a, b)
		}
		ids = next
	}
	return types.ShardingScheme(ids)
}

// signer returns the public, deterministic test key of the role and index.
func signer(role string, i int) (abcrypto.Signer, error) {
	k := sha256.Sum256([]byte(fmt.Sprintf("uc-consolidation fixture key %s %d", role, i)))
	return abcrypto.NewInMemorySecp256K1SignerFromKey(k[:])
}

type orchestration struct {
	configs map[types.PartitionShardID]*types.PartitionDescriptionRecord
}

func (o orchestration) NetworkID() types.NetworkID { return NetworkID }
func (o orchestration) ShardConfig(p types.PartitionID, s types.ShardID, _ uint64) (*types.PartitionDescriptionRecord, error) {
	if c, ok := o.configs[key(p, s)]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("no configuration for %d-%s", p, s)
}
func (o orchestration) ShardConfigs(uint64) (map[types.PartitionShardID]*types.PartitionDescriptionRecord, error) {
	return o.configs, nil
}

type verifierFunc func(round, parentRound uint64, ch *rctypes.IRChangeReq) (*types.InputRecord, error)

func (f verifierFunc) VerifyIRChangeReq(round, parentRound uint64, ch *rctypes.IRChangeReq) (*types.InputRecord, error) {
	return f(round, parentRound, ch)
}
