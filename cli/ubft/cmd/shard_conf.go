package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-go-base/types"
)

const shardConfFileName = "shard-conf.json"

type (
	shardConfFlags struct {
		ShardConfFiles []string
	}
)

func newShardConfCmd(baseConfig *baseFlags) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "shard-conf",
		Short: "Tools to work with shard configuration files",
	}
	cmd.AddCommand(shardConfGenerateCmd(baseConfig))
	cmd.AddCommand(shardConfGenesisCmd(baseConfig))
	return cmd
}

func (f *shardConfFlags) addShardConfFlags(cmd *cobra.Command, acceptMany bool) {
	cmd.Flags().StringSliceVarP(&f.ShardConfFiles, "shard-conf", "s", []string{},
		fmt.Sprintf("path to shard conf (default: %s)", filepath.Join("$UBFT_HOME", shardConfFileName)))
}

func (f *shardConfFlags) loadShardConfs(baseFlags *baseFlags) ([]*types.PartitionDescriptionRecord, error) {
	shardConfs := make([]*types.PartitionDescriptionRecord, len(f.ShardConfFiles))
	for i, shardConfFile := range f.ShardConfFiles {
		if err := baseFlags.loadConf(shardConfFile, shardConfFileName, &shardConfs[i]); err != nil {
			return nil, err
		}
	}
	return shardConfs, nil
}
