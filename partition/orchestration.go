package partition

import (
	"github.com/alphabill-org/alphabill-go-base/types"
	"github.com/alphabill-org/alphabill/rootchain/consensus/trustbase"
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
