package partition

import (
	gocrypto "crypto"
	"testing"
	"time"

	"github.com/alphabill-org/alphabill-go-base/types"
	testcertificates "github.com/alphabill-org/alphabill/internal/testutils/certificates"
	testsig "github.com/alphabill-org/alphabill/internal/testutils/sig"
	"github.com/alphabill-org/alphabill/internal/testutils/trustbase"
	"github.com/alphabill-org/alphabill/network/protocol/blockproposal"
	"github.com/alphabill-org/alphabill/network/protocol/certification"
	testtransaction "github.com/alphabill-org/alphabill/txsystem/testutils/transaction"
	"github.com/stretchr/testify/require"
)

var shardConf = &types.PartitionDescriptionRecord{
	Version:         1,
	NetworkID:       5,
	PartitionID:     1,
	PartitionTypeID: 1,
	TypeIDLen:       8,
	UnitIDLen:       256,
	T2Timeout:       2500 * time.Millisecond,
}

func TestDefaultUnicityCertificateValidator_ValidateNotOk(t *testing.T) {
	v := NewDefaultUnicityCertificateValidator(gocrypto.SHA256)
	require.ErrorIs(t, v.Validate(nil, shardConf, nil), types.ErrUnicityCertificateIsNil)
}

func TestDefaultUnicityCertificateValidator_ValidateOk(t *testing.T) {
	signer, verifier := testsig.CreateSignerAndVerifier(t)
	trustBase := trustbase.NewTrustBase(t, verifier)
	v := NewDefaultUnicityCertificateValidator(gocrypto.SHA256)
	ir := &types.InputRecord{
		Version:      1,
		PreviousHash: make([]byte, 32),
		Hash:         make([]byte, 32),
		BlockHash:    nil,
		SummaryValue: make([]byte, 32),
		RoundNumber:  1,
		Timestamp:    types.NewTimestamp(),
	}
	uc := testcertificates.CreateUnicityCertificate(
		t,
		signer,
		ir,
		shardConf,
		1,
		make([]byte, 32),
		make([]byte, 32),
	)
	require.NoError(t, v.Validate(uc, shardConf, trustBase))
}

func TestDefaultNewDefaultBlockProposalValidator_ValidateNotOk(t *testing.T) {
	v := NewDefaultBlockProposalValidator(gocrypto.SHA256)
	require.ErrorIs(t, v.Validate(nil, nil, nil), blockproposal.ErrBlockProposalIsNil)
}

func TestDefaultNewDefaultBlockProposalValidator_ValidateOk(t *testing.T) {
	shardConf := *shardConf
	keyConf, nodeInfo := createKeyConf(t)
	shardConf.Validators = []*types.NodeInfo{nodeInfo}
	signer, err := keyConf.Signer()
	require.NoError(t, err)

	rootSigner, rootVerifier := testsig.CreateSignerAndVerifier(t)
	trustBase := trustbase.NewTrustBase(t, rootVerifier)
	v := NewDefaultBlockProposalValidator(gocrypto.SHA256)
	ir := &types.InputRecord{
		Version:      1,
		PreviousHash: make([]byte, 32),
		Hash:         make([]byte, 32),
		BlockHash:    nil,
		SummaryValue: make([]byte, 32),
		RoundNumber:  1,
		Timestamp:    types.NewTimestamp(),
	}
	tr := certification.TechnicalRecord{
		Round:    1,
		Epoch:    1,
		Leader:   "anyone",
		StatHash: []byte{0},
		FeeHash:  []byte{0},
	}
	trHash, err := tr.Hash()
	require.NoError(t, err)
	uc := testcertificates.CreateUnicityCertificate(
		t,
		rootSigner,
		ir,
		&shardConf,
		1,
		make([]byte, 32),
		trHash,
	)

	peerID, err := keyConf.NodeID()
	require.NoError(t, err)

	bp := &blockproposal.BlockProposal{
		PartitionID:        uc.UnicityTreeCertificate.Partition,
		NodeID:             peerID,
		UnicityCertificate: uc,
		Technical:          tr,
		Transactions: []*types.TransactionRecord{
			{
				TransactionOrder: testtransaction.NewTransactionOrderBytes(t),
				ServerMetadata: &types.ServerMetadata{
					ActualFee: 10,
				},
			},
		},
	}
	err = bp.Sign(gocrypto.SHA256, signer)
	require.NoError(t, err)
	require.NoError(t, v.Validate(bp, &shardConf, trustBase))

	bp.NodeID = "1"
	require.ErrorContains(t, v.Validate(bp, &shardConf, trustBase), "block proposal from unknown validator")
}

func TestDefaultTxValidator_ValidateNotOk(t *testing.T) {
	tests := []struct {
		name                string
		tx                  *types.TransactionOrder
		latestBlockNumber   uint64
		expectedPartitionID types.PartitionID
		errStr              string
	}{
		{
			name:                "tx is nil",
			tx:                  nil,
			latestBlockNumber:   10,
			expectedPartitionID: 0x01020304,
			errStr:              "transaction is nil",
		},
		{
			name:                "invalid partition identifier",
			tx:                  testtransaction.NewTransactionOrder(t), // default partitionID is 0x00000001
			latestBlockNumber:   10,
			expectedPartitionID: 0x01020304,
			errStr:              "expected partitionID 01020304, got 00000001: invalid partition identifier",
		},
		{
			name:                "expired transaction",
			tx:                  testtransaction.NewTransactionOrder(t), // default timeout is 10
			latestBlockNumber:   11,
			expectedPartitionID: 0x00000001,
			errStr:              "transaction timeout round is 10, current round is 11: transaction has timed out",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dtv := &DefaultTransactionOrderValidator{}
			
			shardConf := &types.PartitionDescriptionRecord{
				PartitionID: tt.expectedPartitionID,
			}
			err := dtv.Validate(tt.tx, shardConf, tt.latestBlockNumber)
			require.ErrorContains(t, err, tt.errStr)
		})
	}
}
