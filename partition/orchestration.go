package partition

import (
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
)

/*
static orchestration until real thing is implemented.
*/
type Orchestration struct {
	trustBaseStore *trustbase.TrustBaseStore
}

func (orc Orchestration) TrustBase(epoch uint64) (types.RootTrustBase, error) {
	return orc.trustBaseStore.GetByEpoch(epoch)
}
