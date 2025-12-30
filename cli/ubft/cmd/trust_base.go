package cmd

import (
	"cmp"
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
	"github.com/unicitynetwork/bft-go-base/util"
)

const trustBaseFileName = "trust-base.json"

type (
	trustBaseFlags struct {
		TrustBaseFiles []string
	}

	trustBaseGenerateFlags struct {
		*baseFlags

		NetworkID         uint16
		NodeInfoFiles     []string // paths to node info files
		QuorumThreshold   uint64   // optional custom quorum threshold (default len(nodes)*2/3 + 1)
		Epoch             uint64
		EpochStart        uint64
		PreviousTrustBase string // path to previous trust base file
		OutputFileName    string // the generated trust base filename
	}

	trustBaseSignFlags struct {
		*baseFlags
		keyConfFlags
		trustBaseFlags
	}

	trustBaseVerifyFlags struct {
		*baseFlags
		trustBaseFlags
	}
)

func newTrustBaseCmd(baseConfig *baseFlags) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "trust-base",
		Short: "Tools to work with trust base files",
	}
	cmd.AddCommand(trustBaseGenerateCmd(baseConfig))
	cmd.AddCommand(trustBaseSignCmd(baseConfig))
	cmd.AddCommand(trustBaseVerifyCmd(baseConfig))
	return cmd
}

func trustBaseGenerateCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &trustBaseGenerateFlags{baseFlags: baseFlags}

	var cmd = &cobra.Command{
		Use:   "generate",
		Short: "Generates a new trust base from node-info files",
		RunE: func(cmd *cobra.Command, args []string) error {
			return trustBaseGenerate(flags)
		},
	}

	cmd.Flags().Uint16Var(&flags.NetworkID, "network-id", 0, "network identifier")
	cmd.Flags().StringSliceVarP(&flags.NodeInfoFiles, "node-info", "n", []string{}, "path to node info files")
	if err := cmd.MarkFlagRequired("node-info"); err != nil {
		panic(err)
	}
	cmd.Flags().Uint64Var(&flags.QuorumThreshold, "quorum-threshold", 0, "define custom quorum threshold (default: len(nodes)*2/3+1")
	cmd.Flags().Uint64Var(&flags.Epoch, "epoch", 1, "epoch assigned to this trust base, must be "+
		"one greater than the epoch of the previous trust base. The genesis epoch must be 1.")
	cmd.Flags().Uint64Var(&flags.EpochStart, "epoch-start", 0, "root round in which this trust base is activated")
	cmd.Flags().StringVar(&flags.PreviousTrustBase, "previous-trust-base", "", "previous epoch's trust base, not required for genesis epoch")
	cmd.Flags().StringVar(&flags.OutputFileName, "output-file-name", trustBaseFileName, "the generated trust base file name, stored to homedir")

	return cmd
}

func trustBaseGenerate(flags *trustBaseGenerateFlags) error {
	if err := os.MkdirAll(flags.HomeDir, 0700); err != nil { // -rwx------
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	var previousTrustBase *types.RootTrustBaseV1
	var previousTrustBaseHash hex.Bytes
	if flags.PreviousTrustBase != "" {
		_, err := util.ReadJsonFile(flags.PreviousTrustBase, &previousTrustBase)
		if err != nil {
			return fmt.Errorf("failed to load previous trust base file %q: %w", flags.PreviousTrustBase, err)
		}
		previousTrustBaseHash, err = previousTrustBase.Hash(crypto.SHA256)
		if err != nil {
			return fmt.Errorf("failed to hash previous trust base file %q: %w", flags.PreviousTrustBase, err)
		}
	}

	nodes, err := loadNodeInfoFiles(flags.NodeInfoFiles)
	if err != nil {
		return fmt.Errorf("failed to read node info files: %w", err)
	}

	trustBase, err := types.NewTrustBase(types.NetworkID(flags.NetworkID), nodes,
		types.WithQuorumThreshold(flags.QuorumThreshold),
		types.WithEpoch(flags.Epoch),
		types.WithEpochStart(flags.EpochStart),
		types.WithPreviousTrustBaseHash(previousTrustBaseHash),
	)
	if err != nil {
		return fmt.Errorf("failed to generate trust base: %w", err)
	}

	if err = trustBase.IsValid(previousTrustBase); err != nil {
		return fmt.Errorf("failed to verify trust base after generation: %w", err)
	}

	outputFile := filepath.Join(flags.HomeDir, flags.OutputFileName)
	if err = util.WriteJsonFile(outputFile, trustBase); err != nil {
		return fmt.Errorf("failed to save '%s': %w", outputFile, err)
	}
	return nil
}

func trustBaseSignCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &trustBaseSignFlags{baseFlags: baseFlags}
	var cmd = &cobra.Command{
		Use:   "sign",
		Short: "Sign a trust base file",
		RunE: func(cmd *cobra.Command, args []string) error {
			return trustBaseSign(flags)
		},
	}
	flags.addKeyConfFlags(cmd, false)
	flags.addTrustBaseFlags(cmd)
	return cmd
}

func trustBaseSign(flags *trustBaseSignFlags) error {
	keyConf, err := flags.loadKeyConf(flags.baseFlags, false)
	if err != nil {
		return err
	}
	nodeID, err := keyConf.NodeID()
	if err != nil {
		return fmt.Errorf("failed to get node id: %w", err)
	}
	signer, err := keyConf.Signer()
	if err != nil {
		return err
	}
	trustBases, err := flags.loadTrustBases(flags.baseFlags)
	if err != nil {
		return err
	}

	if len(trustBases) != 1 {
		return fmt.Errorf("exactly one trust base parameter expected")
	}

	for idx, trustBase := range trustBases {
		// sign trust base
		if err = trustBase.Sign(nodeID.String(), signer); err != nil {
			return fmt.Errorf("failed to sign trust base: %w", err)
		}

		// write trust base
		if err = util.WriteJsonFile(flags.trustBasePath(flags.baseFlags, idx), trustBase); err != nil {
			return fmt.Errorf("failed to save trust base: %w", err)
		}
	}
	return nil
}

func trustBaseVerifyCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &trustBaseVerifyFlags{baseFlags: baseFlags}

	var cmd = &cobra.Command{
		Use:   "verify",
		Short: "Verifies the trust base file is valid and correctly signed",
		RunE: func(cmd *cobra.Command, args []string) error {
			return trustBaseVerify(flags)
		},
	}
	flags.addTrustBaseFlags(cmd)
	return cmd
}

func trustBaseVerify(flags *trustBaseVerifyFlags) error {
	trustBases, err := flags.loadTrustBases(flags.baseFlags)
	if err != nil {
		return err
	}

	if len(trustBases) == 0 {
		return fmt.Errorf("at least one trust base parameter expected")
	}

	slices.SortFunc(trustBases, func(a, b *types.RootTrustBaseV1) int {
		return cmp.Compare(a.Epoch, b.Epoch)
	})

	var prev *types.RootTrustBaseV1
	for _, trustBase := range trustBases {
		if err := trustBase.Verify(prev); err != nil {
			return fmt.Errorf("failed to verify trust base: %w", err)
		}
		prev = trustBase
	}
	return nil
}

func loadNodeInfoFiles(paths []string) ([]*types.NodeInfo, error) {
	var nodes []*types.NodeInfo
	for _, p := range paths {
		node, err := util.ReadJsonFile(p, &types.NodeInfo{})
		if err != nil {
			return nil, fmt.Errorf("failed to read node info from '%s': %w", p, err)
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func (f *trustBaseFlags) addTrustBaseFlags(cmd *cobra.Command) {
	cmd.Flags().StringSliceVarP(&f.TrustBaseFiles, "trust-base", "t", []string{},
		fmt.Sprintf("path to trust base (default: %s)", filepath.Join("$UBFT_HOME", trustBaseFileName)))
}

func (f *trustBaseFlags) trustBasePath(baseFlags *baseFlags, idx int) string {
	return baseFlags.PathWithDefault(f.TrustBaseFiles[idx], trustBaseFileName)
}

func (f *trustBaseFlags) loadTrustBases(baseFlags *baseFlags) ([]*types.RootTrustBaseV1, error) {
	trustBases := make([]*types.RootTrustBaseV1, len(f.TrustBaseFiles))
	for i, trustBaseFile := range f.TrustBaseFiles {
		if err := baseFlags.loadConf(trustBaseFile, trustBaseFileName, &trustBases[i]); err != nil {
			return nil, err
		}
	}
	return trustBases, nil
}
