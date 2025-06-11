package txsystem

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils"
)

func TestNewStateSummary(t *testing.T) {
	root := test.RandomBytes(32)
	value := test.RandomBytes(8)
	etHash := test.RandomBytes(8)
	summary := NewStateSummary(root, value, etHash)
	require.Equal(t, root, summary.Root())
	require.Equal(t, value, summary.Summary())
	require.Equal(t, etHash, summary.ETHash())
}
