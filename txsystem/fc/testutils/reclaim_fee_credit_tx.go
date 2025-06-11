package testutils

import (
	"testing"

	"github.com/stretchr/testify/require"
	testblock "github.com/unicitynetwork/bft-core/internal/testutils/block"
	testtransaction "github.com/unicitynetwork/bft-core/txsystem/testutils/transaction"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/txsystem/fc"
	"github.com/unicitynetwork/bft-go-base/types"
)

func NewReclaimFC(t *testing.T, pdr *types.PartitionDescriptionRecord, signer abcrypto.Signer, reclaimFCAttr *fc.ReclaimFeeCreditAttributes, opts ...testtransaction.Option) *types.TransactionOrder {
	if reclaimFCAttr == nil {
		reclaimFCAttr = NewReclaimFCAttr(t, pdr, signer)
	}
	tx := testtransaction.NewTransactionOrder(t,
		testtransaction.WithUnitID(DefaultMoneyUnitID()),
		testtransaction.WithAttributes(reclaimFCAttr),
		testtransaction.WithTransactionType(fc.TransactionTypeReclaimFeeCredit),
		testtransaction.WithAuthProof(fc.ReclaimFeeCreditAuthProof{}),
	)
	for _, opt := range opts {
		require.NoError(t, opt(tx))
	}
	return tx
}

func NewReclaimFCAttr(t *testing.T, pdr *types.PartitionDescriptionRecord, signer abcrypto.Signer, opts ...ReclaimFCOption) *fc.ReclaimFeeCreditAttributes {
	defaultReclaimFC := NewDefaultReclaimFCAttr(t, pdr, signer)
	for _, opt := range opts {
		opt(defaultReclaimFC)
	}
	return defaultReclaimFC
}

func NewDefaultReclaimFCAttr(t *testing.T, pdr *types.PartitionDescriptionRecord, signer abcrypto.Signer) *fc.ReclaimFeeCreditAttributes {
	tx, err := (newCloseFC(t, pdr)).MarshalCBOR()
	require.NoError(t, err)
	txr := &types.TransactionRecord{
		Version:          1,
		TransactionOrder: tx,
		ServerMetadata: &types.ServerMetadata{
			ActualFee:        10,
			SuccessIndicator: types.TxStatusSuccessful,
		},
	}
	return &fc.ReclaimFeeCreditAttributes{CloseFeeCreditProof: testblock.CreateTxRecordProof(t, txr, signer)}
}

type ReclaimFCOption func(*fc.ReclaimFeeCreditAttributes) ReclaimFCOption

func WithReclaimFCClosureProof(proof *types.TxRecordProof) ReclaimFCOption {
	return func(tx *fc.ReclaimFeeCreditAttributes) ReclaimFCOption {
		tx.CloseFeeCreditProof = proof
		return nil
	}
}

func newCloseFC(t *testing.T, pdr *types.PartitionDescriptionRecord) *types.TransactionOrder {
	attr := &fc.CloseFeeCreditAttributes{
		Amount:            amount,
		TargetUnitID:      DefaultMoneyUnitID(),
		TargetUnitCounter: targetCounter,
	}
	return testtransaction.NewTransactionOrder(t,
		testtransaction.WithUnitID(DefaultMoneyUnitID()),
		testtransaction.WithAttributes(attr),
		testtransaction.WithTransactionType(fc.TransactionTypeCloseFeeCredit),
		testtransaction.WithPartition(pdr),
	)
}
