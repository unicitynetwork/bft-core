package leader

import (
	"github.com/alphabill-org/alphabill/rootchain/consensus/storage"
)

const UnknownLeader = ""

type BlockLoader func(round uint64) (*storage.ExecutedBlock, error)
