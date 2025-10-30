package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/debug"
	"github.com/unicitynetwork/bft-core/logger"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/observability"
	"github.com/unicitynetwork/bft-core/partition"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-core/rpc"
	"github.com/unicitynetwork/bft-core/txsystem"
)

const (
	shardConfDBFileName = "shard.db"
	blockDBFileName     = "blocks.db"
	proofDBFileName     = "proof.db"
)

type ShardNodeRunFlags struct {
	*baseFlags
	keyConfFlags
	shardConfFlags
	trustBaseFlags
	p2pFlags
	rpcFlags

	StateFile       string
	BlockDBFile     string
	ProofDBFile     string
	ShardConfDBFile string
	TrustBaseDBFile string

	WithOwnerIndex bool
	WithGetUnits   bool

	LedgerReplicationMaxBlocksFetch uint64
	LedgerReplicationMaxBlocks      uint64
	LedgerReplicationMaxTx          uint32
	LedgerReplicationTimeoutMs      uint32
	BlockSubscriptionTimeoutMs      uint32
	T1TimeoutMs                     uint32
}

func shardNodeRunCmd(baseFlags *baseFlags, shardNodeRunFn nodeRunnable) *cobra.Command {
	flags := &ShardNodeRunFlags{baseFlags: baseFlags}
	var cmd = &cobra.Command{
		Use:   "run",
		Short: "Starts a shard node",
		Long:  `Starts a shard node for the shard described in shard configuration`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if shardNodeRunFn != nil {
				return shardNodeRunFn(cmd.Context(), flags)
			}
			return shardNodeRun(cmd.Context(), flags)
		},
	}

	flags.addKeyConfFlags(cmd, false)
	flags.addTrustBaseFlags(cmd)
	flags.addShardConfFlags(cmd, true)
	flags.addP2PFlags(cmd)
	flags.addRPCFlags(cmd)

	cmd.Flags().StringVarP(&flags.StateFile, "state", "", "",
		fmt.Sprintf("path to the state file (default %s)", filepath.Join("$UBFT_HOME", StateFileName)))
	cmd.Flags().StringVarP(&flags.BlockDBFile, "block-db", "", "",
		fmt.Sprintf("path to the block datatabase (default %s)", filepath.Join("$UBFT_HOME", blockDBFileName)))
	cmd.Flags().StringVarP(&flags.ShardConfDBFile, "shard-db", "", "",
		fmt.Sprintf("path to the shard configuration datatabase (default %s)", filepath.Join("$UBFT_HOME", shardConfDBFileName)))
	cmd.Flags().StringVarP(&flags.ProofDBFile, "proof-db", "", "",
		fmt.Sprintf("path to the proof datatabase (default %s)", filepath.Join("$UBFT_HOME", proofDBFileName)))

	cmd.Flags().BoolVar(&flags.WithOwnerIndex, "with-owner-index", true, "enable/disable owner indexer")
	cmd.Flags().BoolVar(&flags.WithGetUnits, "with-get-units", false, "enable/disable state_getUnits RPC endpoint")

	cmd.Flags().Uint64Var(&flags.LedgerReplicationMaxBlocksFetch, "ledger-replication-max-blocks-fetch", 1000,
		"maximum number of blocks to query in a single replication request")
	cmd.Flags().Uint64Var(&flags.LedgerReplicationMaxBlocks, "ledger-replication-max-blocks", 1000,
		"maximum number of blocks to return in a single replication response")
	cmd.Flags().Uint32Var(&flags.LedgerReplicationMaxTx, "ledger-replication-max-transactions", 10000,
		"maximum number of transactions to return in a single replication response")
	cmd.Flags().Uint32Var(&flags.LedgerReplicationTimeoutMs, "ledger-replication-timeout", 1500,
		"time since last received replication response when to trigger another request (in ms)")
	cmd.Flags().Uint32Var(&flags.BlockSubscriptionTimeoutMs, "block-subscription-timeout", 3000,
		"time since last received block when when to trigger recovery (in ms) for non-validating nodes")
	cmd.Flags().Uint32Var(&flags.T1TimeoutMs, "t1-timeout", partition.DefaultT1Timeout, "T1 timeout (consensus parameter)")

	hideFlags(cmd, "t1-timeout")
	return cmd
}

func shardNodeRun(ctx context.Context, flags *ShardNodeRunFlags) error {
	node, nodeConf, err := createNode(ctx, flags)
	if err != nil {
		return fmt.Errorf("failed to create node: %w", err)
	}

	obs := nodeConf.Observability()
	log := obs.Logger()
	partitionType := partitionTypeIDToString(node.PartitionTypeID(), flags)

	log.InfoContext(ctx, fmt.Sprintf("starting %s node: BuildInfo=%s", partitionType, debug.ReadBuildInfo()))
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return node.Run(ctx) })

	g.Go(func() error {
		if flags.rpcFlags.IsAddressEmpty() {
			return nil // return nil in this case in order not to kill the group!
		}
		routers := []rpc.Registrar{
			rpc.MetricsEndpoints(obs.PrometheusRegisterer()),
			rpc.NodeEndpoints(node, obs),
		}
		if flags.rpcFlags.Router != nil {
			routers = append(routers, flags.rpcFlags.Router)
		}
		flags.rpcFlags.APIs = []rpc.API{
			{
				Namespace: "state",
				Service: rpc.NewStateAPI(node, obs,
					rpc.WithOwnerIndex(nodeConf.OwnerIndexer()),
					rpc.WithGetUnits(flags.WithGetUnits),
					rpc.WithUnitTypeExtractor(nodeConf.ShardConf().ExtractUnitType),
					rpc.WithRateLimit(flags.StateRpcRateLimit),
					rpc.WithResponseItemLimit(flags.StateRpcResponseItemLimit),
				),
			},
			{
				Namespace: "admin",
				Service:   rpc.NewAdminAPI(node, node.Peer(), obs),
			},
		}

		rpcServer, err := rpc.NewHTTPServer(&flags.rpcFlags.ServerConfiguration, obs, routers...)
		if err != nil {
			return err
		}

		errch := make(chan error, 1)
		go func() {
			log.InfoContext(ctx, fmt.Sprintf("%s RPC server starting on %s", partitionType, rpcServer.Addr))
			if err := rpcServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errch <- err
				return
			}
			errch <- nil
		}()

		select {
		case <-ctx.Done():
			if err := rpcServer.Close(); err != nil {
				log.WarnContext(ctx, partitionType+" RPC server close error", logger.Error(err))
			}
			exitErr := <-errch
			if exitErr != nil {
				log.WarnContext(ctx, partitionType+" RPC server exited with error", logger.Error(err))
			} else {
				log.InfoContext(ctx, partitionType+" RPC server exited")
			}
			return ctx.Err()
		case err := <-errch:
			return err
		}
	})

	return g.Wait()
}

func createNode(ctx context.Context, flags *ShardNodeRunFlags) (*partition.Node, *partition.NodeConf, error) {
	keyConf, err := flags.loadKeyConf(flags.baseFlags, false)
	if err != nil {
		return nil, nil, err
	}
	nodeID, err := keyConf.NodeID()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to calculate nodeID: %w", err)
	}
	log := flags.observe.Logger().With(logger.NodeID(nodeID))

	shardConfs, err := flags.loadShardConfs(flags.baseFlags)
	if err != nil {
		return nil, nil, err
	}
	shardConfDB, err := flags.initDB(flags.ShardConfDBFile, shardConfDBFileName)
	if err != nil {
		return nil, nil, err
	}
	shardConfStore, err := partition.NewShardConfStore(shardConfDB, log)
	if err != nil {
		return nil, nil, err
	}
	for _, shardConf := range shardConfs {
		if err := shardConfStore.Store(shardConf); err != nil {
			return nil, nil, fmt.Errorf("failed to store shard configuration: %w", err)
		}
	}

	shardConf, err := shardConfStore.GetFirst()
	if err != nil {
		return nil, nil, err
	}
	log = log.With(logger.Shard(shardConf.PartitionID, shardConf.ShardID))
	obs := observability.WithLogger(flags.observe, log)

	trustBases, err := flags.loadTrustBases(flags.baseFlags)
	if err != nil {
		return nil, nil, err
	}
	trustBaseDB, err := flags.initDB(flags.TrustBaseDBFile, trustBaseDBFileName)
	if err != nil {
		return nil, nil, err
	}
	trustBaseStore, err := trustbase.NewTrustBaseStore(trustBaseDB, log)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create trust base store: %w", err)
	}
	for _, trustBase := range trustBases {
		if err := trustBaseStore.Store(trustBase); err != nil {
			return nil, nil, fmt.Errorf("failed to store trust base: %w", err)
		}
	}

	blockDB, err := flags.initDB(flags.BlockDBFile, blockDBFileName)
	if err != nil {
		return nil, nil, err
	}
	proofDB, err := flags.initDB(flags.ProofDBFile, proofDBFileName)
	if err != nil {
		return nil, nil, err
	}

	var ownerIndexer *partition.OwnerIndexer
	if flags.WithOwnerIndex {
		ownerIndexer = partition.NewOwnerIndexer(log)
	}

	bootstrapConnectRetry := &network.BootstrapConnectRetry{
		Count: flags.BootstrapConnectRetryCount,
		Delay: flags.BootstrapConnectRetryDelay,
	}

	nodeConf, err := partition.NewNodeConf(
		keyConf,
		shardConfStore,
		trustBaseStore,
		obs,
		partition.WithAddress(flags.p2pFlags.Address),
		partition.WithAnnounceAddresses(flags.AnnounceAddresses),
		partition.WithBootstrapAddresses(flags.BootstrapAddresses),
		partition.WithBootstrapConnectRetry(bootstrapConnectRetry),
		partition.WithBlockDB(blockDB),
		partition.WithReplicationParams(
			flags.LedgerReplicationMaxBlocksFetch,
			flags.LedgerReplicationMaxBlocks,
			flags.LedgerReplicationMaxTx,
			time.Duration(flags.LedgerReplicationTimeoutMs)*time.Millisecond),
		partition.WithProofIndex(proofDB, 20),
		partition.WithOwnerIndex(ownerIndexer),
		partition.WithBlockSubscriptionTimeout(time.Duration(flags.BlockSubscriptionTimeoutMs)*time.Millisecond),
		partition.WithT1Timeout(time.Duration(flags.T1TimeoutMs)*time.Millisecond),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create node configuration: %w", err)
	}

	txSystem, err := createTxSystem(flags, nodeConf)
	if err != nil {
		return nil, nil, err
	}
	node, err := partition.NewNode(ctx, txSystem, nodeConf)
	if err != nil {
		return nil, nil, err
	}
	return node, nodeConf, nil
}

func createTxSystem(flags *ShardNodeRunFlags, nodeConf *partition.NodeConf) (txsystem.TransactionSystem, error) {
	partition, ok := flags.baseFlags.partitions[nodeConf.ShardConf().GetPartitionTypeID()]
	if !ok {
		return nil, fmt.Errorf("unsupported partition type %d", nodeConf.ShardConf().GetPartitionTypeID())
	}
	return partition.CreateTxSystem(flags, nodeConf)
}

func partitionTypeIDToString(partitionTypeID types.PartitionTypeID, flags *ShardNodeRunFlags) string {
	partition, ok := flags.baseFlags.partitions[partitionTypeID]
	if !ok {
		return fmt.Sprintf("partition type %d", partitionTypeID)
	}
	return partition.PartitionTypeIDString()
}
