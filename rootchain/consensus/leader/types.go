package leader

import (
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

type BlockLoader func(round uint64) (*storage.ExecutedBlock, error)
