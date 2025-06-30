package testutils

import (
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
)

func NewOrchestration(t *testing.T, log *slog.Logger) *partitions.Orchestration {
	orchestration, err := partitions.NewOrchestration(5, filepath.Join(t.TempDir(), "orchestration.db"), log)
	require.NoError(t, err)
	t.Cleanup(func() { _ = orchestration.Close() })
	return orchestration
}
