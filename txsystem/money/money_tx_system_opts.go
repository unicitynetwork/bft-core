package money

import (
	"crypto"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/predicates"
	"github.com/unicitynetwork/bft-core/predicates/templates"
	"github.com/unicitynetwork/bft-core/state"
	"github.com/unicitynetwork/bft-core/txsystem"
)

type (
	Options struct {
		state                *state.State
		executedTransactions map[string]uint64
		hashAlgorithm        crypto.Hash
		trustBase            types.RootTrustBase
		exec                 predicates.PredicateExecutor
	}

	Option func(*Options)
)

func defaultOptions(observe txsystem.Observability) (*Options, error) {
	templEng, err := templates.New(observe)
	if err != nil {
		return nil, fmt.Errorf("creating predicate template executor: %w", err)
	}
	predEng, err := predicates.Dispatcher(templEng)
	if err != nil {
		return nil, fmt.Errorf("creating predicate executor: %w", err)
	}

	return &Options{
		hashAlgorithm: crypto.SHA256,
		exec:          predEng.Execute,
	}, nil
}

func WithState(s *state.State) Option {
	return func(g *Options) {
		g.state = s
	}
}

func WithExecutedTransactions(executedTransactions map[string]uint64) Option {
	return func(g *Options) {
		g.executedTransactions = executedTransactions
	}
}

func WithTrustBase(trust types.RootTrustBase) Option {
	return func(options *Options) {
		options.trustBase = trust
	}
}

func WithHashAlgorithm(hashAlgorithm crypto.Hash) Option {
	return func(g *Options) {
		g.hashAlgorithm = hashAlgorithm
	}
}

/*
WithPredicateExecutor allows to replace the default predicate executor function.
Should be used by tests only.
*/
func WithPredicateExecutor(exec predicates.PredicateExecutor) Option {
	return func(g *Options) {
		if exec != nil {
			g.exec = exec
		}
	}
}
