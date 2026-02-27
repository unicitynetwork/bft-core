package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"
)

type (
	ShardConfGenerateFlags struct {
		*baseFlags

		NetworkID       uint16
		PartitionID     uint32
		PartitionTypeID uint32
		ShardID         string
		Epoch           uint64
		EpochStart      uint64
		T2Timeout       uint32
		NodeInfoFiles   []string
	}
)

func shardConfGenerateCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &ShardConfGenerateFlags{baseFlags: baseFlags}
	var cmd = &cobra.Command{
		Use:   "generate",
		Short: "Generate a new shard configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			return shardConfGenerate(flags)
		},
	}
	cmd.Flags().Uint16Var(&flags.NetworkID, "network-id", 0, "network identifier")
	cmd.Flags().Uint32Var(&flags.PartitionID, "partition-id", 0, "partition identifier")
	cmd.Flags().Uint32Var(&flags.PartitionTypeID, "partition-type-id", 0, "partition type identifier")
	cmd.Flags().StringVar(&flags.ShardID, "shard-id", "0x80", "the shard id in hex format with 0x prefix")

	cmd.Flags().Uint64Var(&flags.Epoch, "epoch", 0, "epoch assigned to this configuration, must be one greater than the epoch of the previous configuration")
	cmd.Flags().Uint64Var(&flags.EpochStart, "epoch-start", 0, "root round in which this configuration is activated")
	cmd.Flags().Uint32Var(&flags.T2Timeout, "t2-timeout", 2500, "T2 timeout in milliseconds")
	if err := cmd.MarkFlagRequired("epoch-start"); err != nil {
		panic(err)
	}
	cmd.Flags().StringSliceVarP(&flags.NodeInfoFiles, "node-info", "n", []string{}, "path to node info files")

	return cmd
}

func shardConfGenerate(flags *ShardConfGenerateFlags) error {
	if err := os.MkdirAll(flags.HomeDir, 0700); err != nil { // -rwx------
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	nodes, err := loadNodeInfoFiles(flags.NodeInfoFiles)
	if err != nil {
		return fmt.Errorf("failed to read node genesis files: %w", err)
	}

	// verify all nodes belong to the same network and partition
	if len(nodes) == 0 && flags.Epoch == 0 {
		return errors.New("at least one node info file must be provided for the first epoch")
	}

	// parse the shardID
	shardID := types.ShardID{}
	if err = shardID.UnmarshalText([]byte(flags.ShardID)); err != nil {
		return fmt.Errorf("failed to parse shard id: %w", err)
	}

	shardConf := &types.PartitionDescriptionRecord{
		Version:         1,
		NetworkID:       types.NetworkID(flags.NetworkID),
		PartitionID:     types.PartitionID(flags.PartitionID),
		PartitionTypeID: types.PartitionTypeID(flags.PartitionTypeID),
		ShardID:         shardID,
		Epoch:           flags.Epoch,
		EpochStart:      flags.EpochStart,
		TypeIDLen:       8,
		UnitIDLen:       256,
		T2Timeout:       time.Duration(flags.T2Timeout) * time.Millisecond,
		Validators:      nodes,
	}

	if err = shardConf.IsValid(); err != nil {
		return fmt.Errorf("invalid shard configuration: %w", err)
	}

	fileName := fmt.Sprintf("shard-conf-%d_%d.json", flags.PartitionID, flags.Epoch)
	outputFile := filepath.Join(flags.HomeDir, fileName)
	if err = util.WriteJsonFile(outputFile, shardConf); err != nil {
		return fmt.Errorf("failed to save '%s': %w", outputFile, err)
	}
	return nil
}
