package cmd

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"

	testobserve "github.com/unicitynetwork/bft-core/internal/testutils/observability"
)

func TestTrustBaseGenerateAndSign(t *testing.T) {
	ctx := context.Background()
	logF := testobserve.NewFactory(t)

	// root node 1
	homeDir1 := t.TempDir()
	cmd := New(logF)
	cmd.baseCmd.SetArgs([]string{
		"root-node", "init", "--home", homeDir1, "--generate",
	})
	require.NoError(t, cmd.Execute(ctx))
	nodeInfoFile1 := filepath.Join(homeDir1, nodeInfoFileName)

	// root node 2
	homeDir2 := t.TempDir()
	cmd = New(logF)
	cmd.baseCmd.SetArgs([]string{
		"root-node", "init", "--home", homeDir2, "--generate",
	})
	require.NoError(t, cmd.Execute(ctx))
	nodeInfoFile2 := filepath.Join(homeDir2, nodeInfoFileName)

	cmd = New(logF)
	cmd.baseCmd.SetArgs([]string{
		"trust-base", "generate",
		"--home", homeDir1,
		"--node-info", nodeInfoFile1,
		"--node-info", nodeInfoFile2,
		"--network-id", "5",
		"--quorum-threshold", "2",
	})
	require.NoError(t, cmd.Execute(ctx))

	// verify the resulting file
	trustBasePath := filepath.Join(homeDir1, "trust-base.json")
	trustBase, err := util.ReadJsonFile(trustBasePath, &types.RootTrustBaseV1{})
	require.NoError(t, err)
	require.Equal(t, types.NetworkID(5), trustBase.NetworkID)
	require.Equal(t, uint64(1), trustBase.Epoch)
	require.Len(t, trustBase.RootNodes, 2)

	// root node 1 signs the trust base in its home dir
	cmd = New(logF)
	cmd.baseCmd.SetArgs([]string{"trust-base", "sign", "--home", homeDir1, "--trust-base", trustBasePath})
	require.NoError(t, cmd.Execute(ctx))

	// root node 2 signs the trust base at custom location
	cmd = New(logF)
	cmd.baseCmd.SetArgs([]string{"trust-base", "sign", "--home", homeDir2, "--trust-base", trustBasePath})
	require.NoError(t, cmd.Execute(ctx))

	// verify trust base has 2 signatures
	trustBase, err = util.ReadJsonFile(filepath.Join(homeDir1, "trust-base.json"), &types.RootTrustBaseV1{})
	require.NoError(t, err)
	require.Len(t, trustBase.GetRootNodes(), 2)
	require.Len(t, trustBase.Signatures, 2)
}

func TestTrustBaseSignPrevious(t *testing.T) {
	// generate trust base with nodes 1 and 2
	// generate trust base with nodes 3 and 4
	logF := testobserve.NewFactory(t)

	// generate node 1
	homeDir1 := t.TempDir()
	cmd := New(logF)
	cmd.baseCmd.SetArgs([]string{"root-node", "init", "--home", homeDir1, "--generate"})
	require.NoError(t, cmd.Execute(context.Background()))
	nodeInfoFile1 := filepath.Join(homeDir1, nodeInfoFileName)

	// generate node 2
	homeDir2 := t.TempDir()
	cmd = New(logF)
	cmd.baseCmd.SetArgs([]string{"root-node", "init", "--home", homeDir2, "--generate"})
	require.NoError(t, cmd.Execute(context.Background()))
	nodeInfoFile2 := filepath.Join(homeDir2, nodeInfoFileName)

	// generate trust base for epoch 1
	trustBase0Path := filepath.Join(homeDir1, "trust-base-0.json")
	cmd = New(logF)
	cmd.baseCmd.SetArgs([]string{
		"trust-base", "generate",
		"--home", homeDir1,
		"--output-file-name", "trust-base-0.json",
		"--node-info", nodeInfoFile1,
		"--node-info", nodeInfoFile2,
		"--epoch", "1",
	})
	require.NoError(t, cmd.Execute(context.Background()))

	// sign epoch 1 trust base
	cmd = New(logF)
	cmd.baseCmd.SetArgs([]string{"trust-base", "sign", "--home", homeDir1, "--trust-base", trustBase0Path})
	require.NoError(t, cmd.Execute(context.Background()))
	cmd = New(logF)
	cmd.baseCmd.SetArgs([]string{"trust-base", "sign", "--home", homeDir2, "--trust-base", trustBase0Path})
	require.NoError(t, cmd.Execute(context.Background()))

	// generate node 3
	homeDir3 := t.TempDir()
	cmd = New(logF)
	cmd.baseCmd.SetArgs([]string{"root-node", "init", "--home", homeDir3, "--generate"})
	require.NoError(t, cmd.Execute(context.Background()))
	nodeInfoFile3 := filepath.Join(homeDir3, nodeInfoFileName)

	// generate node 4
	homeDir4 := t.TempDir()
	cmd = New(logF)
	cmd.baseCmd.SetArgs([]string{"root-node", "init", "--home", homeDir4, "--generate"})
	require.NoError(t, cmd.Execute(context.Background()))
	nodeInfoFile4 := filepath.Join(homeDir4, nodeInfoFileName)

	// generate trust base for epoch 2
	trustBase1Path := filepath.Join(homeDir3, "trust-base-1.json")
	cmd = New(logF)
	cmd.baseCmd.SetArgs([]string{
		"trust-base", "generate",
		"--home", homeDir3,
		"--output-file-name", "trust-base-1.json",
		"--node-info", nodeInfoFile3,
		"--node-info", nodeInfoFile4,
		"--epoch", "2",
		"--epoch-start", "50",
		"--previous-trust-base", trustBase0Path,
	})
	require.NoError(t, cmd.Execute(context.Background()))

	// sign epoch 2 trust base with PREVIOUS epoch validators (node 1, 2)
	cmd = New(logF)
	cmd.baseCmd.SetArgs([]string{"trust-base", "sign", "--home", homeDir1, "--trust-base", trustBase1Path})
	require.NoError(t, cmd.Execute(context.Background()))
	cmd = New(logF)
	cmd.baseCmd.SetArgs([]string{"trust-base", "sign", "--home", homeDir2, "--trust-base", trustBase1Path})
	require.NoError(t, cmd.Execute(context.Background()))

	// verify signatures were added to the file
	trustBase1, err := util.ReadJsonFile(trustBase1Path, &types.RootTrustBaseV1{})
	require.NoError(t, err)
	require.Len(t, trustBase1.Signatures, 2)

	// verify the generated trust base files
	cmd = New(logF)
	cmd.baseCmd.SetArgs([]string{"trust-base", "verify", "--trust-base", trustBase0Path, "--trust-base", trustBase1Path})
	require.NoError(t, cmd.Execute(context.Background()))
}
