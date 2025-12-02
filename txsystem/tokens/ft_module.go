package tokens

import (
	"crypto"

	"github.com/unicitynetwork/bft-core/predicates"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-core/state"
	"github.com/unicitynetwork/bft-core/txsystem"
	txtypes "github.com/unicitynetwork/bft-core/txsystem/types"
	"github.com/unicitynetwork/bft-go-base/txsystem/tokens"
)

var _ txtypes.Module = &FungibleTokensModule{}

type FungibleTokensModule struct {
	state          *state.State
	hashAlgorithm  crypto.Hash
	trustBaseStore *trustbase.TrustBaseStore
	execPredicate  predicates.PredicateRunner
	shardConf      txsystem.ShardConf
}

func NewFungibleTokensModule(shardConf txsystem.ShardConf, options *Options) (*FungibleTokensModule, error) {
	return &FungibleTokensModule{
		state:          options.state,
		hashAlgorithm:  options.hashAlgorithm,
		trustBaseStore: options.trustBaseStore,
		execPredicate:  predicates.NewPredicateRunner(options.exec),
		shardConf:      shardConf,
	}, nil
}

func (m *FungibleTokensModule) TxHandlers() map[uint16]txtypes.TxExecutor {
	return map[uint16]txtypes.TxExecutor{
		tokens.TransactionTypeDefineFT:   txtypes.NewTxHandler[tokens.DefineFungibleTokenAttributes, tokens.DefineFungibleTokenAuthProof](m.validateDefineFT, m.executeDefineFT),
		tokens.TransactionTypeMintFT:     txtypes.NewTxHandler[tokens.MintFungibleTokenAttributes, tokens.MintFungibleTokenAuthProof](m.validateMintFT, m.executeMintFT),
		tokens.TransactionTypeTransferFT: txtypes.NewTxHandler[tokens.TransferFungibleTokenAttributes, tokens.TransferFungibleTokenAuthProof](m.validateTransferFT, m.executeTransferFT),
		tokens.TransactionTypeSplitFT:    txtypes.NewTxHandler[tokens.SplitFungibleTokenAttributes, tokens.SplitFungibleTokenAuthProof](m.validateSplitFT, m.executeSplitFT, txtypes.WithTargetUnitsFn(m.splitFTTargetUnits)),
		tokens.TransactionTypeBurnFT:     txtypes.NewTxHandler[tokens.BurnFungibleTokenAttributes, tokens.BurnFungibleTokenAuthProof](m.validateBurnFT, m.executeBurnFT),
		tokens.TransactionTypeJoinFT:     txtypes.NewTxHandler[tokens.JoinFungibleTokenAttributes, tokens.JoinFungibleTokenAuthProof](m.validateJoinFT, m.executeJoinFT),
	}
}
