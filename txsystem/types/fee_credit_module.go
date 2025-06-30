package types

import (
	"github.com/unicitynetwork/bft-go-base/types"
)

type (
	FeeCreditModule interface {
		Module
		FeeCalculation
		FeeBalanceValidator
		FeeTxVerifier

		IsPermissionedMode() bool
		IsFeelessMode() bool
		FeeCreditRecordUnitType() uint32
	}

	FeeBalanceValidator interface {
		IsCredible(exeCtx ExecutionContext, tx *types.TransactionOrder) error
	}

	FeeTxVerifier interface {
		IsFeeCreditTx(tx *types.TransactionOrder) bool
	}
)
