package blockproposal

import (
	gocrypto "crypto"
	"testing"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	test "github.com/unicitynetwork/bft-core/internal/testutils"
	testcerts "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testsig "github.com/unicitynetwork/bft-core/internal/testutils/sig"
	"github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

const partitionID types.PartitionID = 1

func newNodeInfo(t *testing.T) (*types.NodeInfo, crypto.Signer) {
	t.Helper()
	signer, verifier := testsig.CreateSignerAndVerifier(t)

	sigKey, err := verifier.MarshalPublicKey()
	require.NoError(t, err)

	publicKey, err := verifier.MarshalPublicKey()
	require.NoError(t, err)

	libp2pPublicKey, err := libp2pcrypto.UnmarshalSecp256k1PublicKey(publicKey)
	require.NoError(t, err)
	nodeID, err := peer.IDFromPublicKey(libp2pPublicKey)
	require.NoError(t, err)

	return &types.NodeInfo{
		NodeID: nodeID.String(),
		SigKey: sigKey,
		Stake:  1,
	}, signer
}

func TestBlockProposal_IsValid_NotOk(t *testing.T) {
	shardNode, _ := newNodeInfo(t)
	_, rootNodeSigner := newNodeInfo(t)

	type fields struct {
		PartitionID        types.PartitionID
		NodeID             peer.ID
		UnicityCertificate *types.UnicityCertificate
		TechnicalRecord    certification.TechnicalRecord
		Transactions       []*types.TransactionRecord
	}
	type args struct {
		trustBase types.RootTrustBase
		shardConf *types.PartitionDescriptionRecord
		algorithm gocrypto.Hash
	}

	trustBase := trustbase.NewTrustBase(t, rootNodeSigner)

	shardConf := &types.PartitionDescriptionRecord{
		PartitionID: partitionID,
		Validators:  []*types.NodeInfo{shardNode},
	}
	tr := certification.TechnicalRecord{
		Round:    1,
		Epoch:    1,
		Leader:   "anyone",
		StatHash: []byte{0},
		FeeHash:  []byte{0},
	}

	proposerID, err := peer.Decode(shardNode.NodeID)
	require.NoError(t, err)

	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr string
	}{
		{
			name: "trust base is nil",
			fields: fields{
				PartitionID:  partitionID,
				NodeID:       proposerID,
				Transactions: []*types.TransactionRecord{},
			},
			args: args{
				trustBase: nil,
				shardConf: shardConf,
				algorithm: gocrypto.SHA256,
			},
			wantErr: ErrTrustBaseIsNil.Error(),
		},
		{
			name: "shard conf is nil",
			fields: fields{
				PartitionID:  partitionID,
				NodeID:       proposerID,
				Transactions: []*types.TransactionRecord{},
			},
			args: args{
				trustBase: trustBase,
				shardConf: nil,
				algorithm: gocrypto.SHA256,
			},
			wantErr: ErrShardConfIsNil.Error(),
		},
		{
			name: "invalid partition identifier",
			fields: fields{
				PartitionID:  partitionID,
				NodeID:       proposerID,
				Transactions: []*types.TransactionRecord{},
			},
			args: args{
				trustBase: trustBase,
				shardConf: &types.PartitionDescriptionRecord{PartitionID: 2},
				algorithm: gocrypto.SHA256,
			},
			wantErr: ErrInvalidPartitionID.Error(),
		},
		{
			name: "block proposer id is missing",
			fields: fields{
				PartitionID:  partitionID,
				Transactions: []*types.TransactionRecord{},
			},
			args: args{
				trustBase: trustBase,
				shardConf: shardConf,
				algorithm: gocrypto.SHA256,
			},
			wantErr: errBlockProposerIDMissing.Error(),
		},
		{
			name: "uc is nil",
			fields: fields{
				PartitionID:        partitionID,
				NodeID:             proposerID,
				UnicityCertificate: nil,
				Transactions:       []*types.TransactionRecord{},
			},
			args: args{
				trustBase: trustBase,
				shardConf: shardConf,
				algorithm: gocrypto.SHA256,
			},
			wantErr: types.ErrUnicityCertificateIsNil.Error(),
		},
		{
			name: "tr hash mismatch",
			fields: fields{
				PartitionID: partitionID,
				NodeID:      proposerID,
				UnicityCertificate: testcerts.CreateUnicityCertificate(
					t, rootNodeSigner, &types.InputRecord{
						Version:      1,
						PreviousHash: test.RandomBytes(32),
						Hash:         test.RandomBytes(32),
						BlockHash:    test.RandomBytes(32),
						SummaryValue: test.RandomBytes(32),
						Timestamp:    1,
					}, shardConf, 1, []byte{0}, make([]byte, 32)),
				TechnicalRecord: tr,
				Transactions:    []*types.TransactionRecord{},
			},
			args: args{
				trustBase: trustBase,
				shardConf: shardConf,
				algorithm: gocrypto.SHA256,
			},
			wantErr: "hash mismatch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bp := &BlockProposal{
				PartitionID:        tt.fields.PartitionID,
				NodeID:             tt.fields.NodeID,
				UnicityCertificate: tt.fields.UnicityCertificate,
				Technical:          tt.fields.TechnicalRecord,
				Transactions:       tt.fields.Transactions,
			}
			err := bp.IsValid(tt.args.trustBase, tt.args.shardConf, tt.args.algorithm)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestBlockProposal_IsValid_BlockProposalIsNil(t *testing.T) {
	var bp *BlockProposal
	signer, _ := testsig.CreateSignerAndVerifier(t)
	shardConf := &types.PartitionDescriptionRecord{
		PartitionID: partitionID,
	}

	trustBase := trustbase.NewTrustBaseFromSigners(t, map[string]crypto.Signer{"1": signer})
	err := bp.IsValid(trustBase, shardConf, gocrypto.SHA256)
	require.ErrorIs(t, err, ErrBlockProposalIsNil)
}

func TestBlockProposal_SignAndVerify(t *testing.T) {
	signer, verifier := testsig.CreateSignerAndVerifier(t)
	sdrHash := test.RandomBytes(32)
	seal := &types.UnicitySeal{
		Version:              1,
		RootChainRoundNumber: 1,
		Timestamp:            10000,
		PreviousHash:         test.RandomBytes(32),
		Hash:                 test.RandomBytes(32),
		Signatures:           map[string]hex.Bytes{"1": test.RandomBytes(32)},
	}
	tx, err := (&types.TransactionOrder{
		Version: 1,
		Payload: types.Payload{
			PartitionID:    0,
			Type:           22,
			UnitID:         nil,
			Attributes:     nil,
			ClientMetadata: nil,
		},
		AuthProof: nil,
		FeeProof:  nil,
	}).MarshalCBOR()
	require.NoError(t, err)
	bp := &BlockProposal{
		PartitionID: partitionID,
		NodeID:      "1",
		UnicityCertificate: &types.UnicityCertificate{
			Version: 1,
			InputRecord: &types.InputRecord{
				Version:      1,
				PreviousHash: test.RandomBytes(32),
				Hash:         test.RandomBytes(32),
				BlockHash:    test.RandomBytes(32),
				SummaryValue: test.RandomBytes(32),
			},
			ShardConfHash: sdrHash,
			UnicityTreeCertificate: &types.UnicityTreeCertificate{
				Version:   1,
				Partition: partitionID,
				HashSteps: []*types.PathItem{{Key: types.PartitionID(test.RandomUint32()), Hash: test.RandomBytes(32)}},
			},
			UnicitySeal: seal,
		},
		Transactions: []*types.TransactionRecord{{
			TransactionOrder: tx,
			ServerMetadata: &types.ServerMetadata{
				ActualFee: 10,
			},
		}},
	}
	require.NoError(t, bp.Sign(gocrypto.SHA256, signer))

	require.NoError(t, bp.Verify(gocrypto.SHA256, verifier))
}

func TestBlockProposal_InvalidSignature(t *testing.T) {
	signer, verifier := testsig.CreateSignerAndVerifier(t)
	sdrHash := test.RandomBytes(32)
	seal := &types.UnicitySeal{
		Version:              1,
		RootChainRoundNumber: 1,
		PreviousHash:         test.RandomBytes(32),
		Hash:                 test.RandomBytes(32),
		Timestamp:            10000,
		Signatures:           map[string]hex.Bytes{"1": test.RandomBytes(32)},
	}
	tx, err := (&types.TransactionOrder{
		Version: 1,
		Payload: types.Payload{
			PartitionID:    0,
			Type:           22,
			UnitID:         nil,
			Attributes:     nil,
			ClientMetadata: nil,
		},
		AuthProof: nil,
		FeeProof:  nil,
	}).MarshalCBOR()
	require.NoError(t, err)
	bp := &BlockProposal{
		PartitionID: partitionID,
		NodeID:      "1",
		UnicityCertificate: &types.UnicityCertificate{
			Version: 1,
			InputRecord: &types.InputRecord{
				Version:      1,
				PreviousHash: test.RandomBytes(32),
				Hash:         test.RandomBytes(32),
				BlockHash:    test.RandomBytes(32),
				SummaryValue: test.RandomBytes(32),
			},
			ShardConfHash: sdrHash,
			UnicityTreeCertificate: &types.UnicityTreeCertificate{
				Version:   1,
				Partition: partitionID,
				HashSteps: []*types.PathItem{{Key: types.PartitionID(test.RandomUint32()), Hash: test.RandomBytes(32)}},
			},
			UnicitySeal: seal,
		},
		Transactions: []*types.TransactionRecord{{
			TransactionOrder: tx,
			ServerMetadata: &types.ServerMetadata{
				ActualFee: 10,
			}}},
	}
	err = bp.Sign(gocrypto.SHA256, signer)
	require.NoError(t, err)
	bp.Signature = test.RandomBytes(64)

	err = bp.Verify(gocrypto.SHA256, verifier)
	require.ErrorContains(t, err, "verification failed")
}
