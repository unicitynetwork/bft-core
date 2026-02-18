package cmd

import (
	"github.com/spf13/cobra"
)

// newShardNodeCmd creates a new cobra command for shard node management.
func newShardNodeCmd(baseFlags *baseFlags) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "shard-node",
		Short: "Tools to run a shard node",
	}
	cmd.AddCommand(shardNodeInitCmd(baseFlags))
	return cmd
}
