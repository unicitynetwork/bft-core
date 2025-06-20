package txsystem

import (
	"crypto"
	"fmt"

	"github.com/unicitynetwork/bft-core/predicates"
	"github.com/unicitynetwork/bft-core/predicates/templates"
	"github.com/unicitynetwork/bft-core/state"
	abfc "github.com/unicitynetwork/bft-core/txsystem/fc"
	txtypes "github.com/unicitynetwork/bft-core/txsystem/types"
)

type Options struct {
	hashAlgorithm        crypto.Hash
	state                *state.State
	executedTransactions map[string]uint64
	beginBlockFunctions  []func(blockNumber uint64) error
	endBlockFunctions    []func(blockNumber uint64) error
	predicateRunner      predicates.PredicateRunner
	feeCredit            txtypes.FeeCreditModule
	observe              Observability
}

type Option func(*Options) error

func DefaultOptions(observe Observability) (*Options, error) {
	return (&Options{
		hashAlgorithm: crypto.SHA256,
		state:         state.NewEmptyState(),
		feeCredit:     abfc.NewNoFeeCreditModule(),
		observe:       observe,
	}).initPredicateRunner(observe)
}

func WithBeginBlockFunctions(funcs ...func(blockNumber uint64) error) Option {
	return func(g *Options) error {
		g.beginBlockFunctions = append(g.beginBlockFunctions, funcs...)
		return nil
	}
}

func WithEndBlockFunctions(funcs ...func(blockNumber uint64) error) Option {
	return func(g *Options) error {
		g.endBlockFunctions = append(g.endBlockFunctions, funcs...)
		return nil
	}
}

func WithHashAlgorithm(hashAlgorithm crypto.Hash) Option {
	return func(g *Options) error {
		g.hashAlgorithm = hashAlgorithm
		return nil
	}
}

func WithState(s *state.State) Option {
	return func(g *Options) error {
		g.state = s
		// re-init predicate runner
		_, err := g.initPredicateRunner(g.observe)
		return err
	}
}

func WithExecutedTransactions(executedTransactions map[string]uint64) Option {
	return func(g *Options) error {
		g.executedTransactions = executedTransactions
		return nil
	}
}

func WithFeeCredits(f txtypes.FeeCreditModule) Option {
	return func(g *Options) error {
		g.feeCredit = f
		return nil
	}
}

func (o *Options) initPredicateRunner(observe Observability) (*Options, error) {
	templEng, err := templates.New(observe)
	if err != nil {
		return nil, fmt.Errorf("creating predicate template executor: %w", err)
	}
	engines, err := predicates.Dispatcher(templEng)
	if err != nil {
		return nil, fmt.Errorf("creating predicate executor: %w", err)
	}
	o.predicateRunner = predicates.NewPredicateRunner(engines.Execute)
	return o, nil
}
