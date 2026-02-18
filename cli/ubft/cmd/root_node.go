package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ainvaltin/httpsrv"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/logger"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/observability"
	"github.com/unicitynetwork/bft-core/rootchain"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
)

const (
	rootDBFileName          = "rootchain.db"
	trustBaseDBFileName     = "trustbase.db"
	orchestrationDBFileName = "orchestration.db"
	defaultNetworkTimeout   = 300 * time.Millisecond
)

type (
	rootNodeRunFlags struct {
		*baseFlags
		keyConfFlags
		trustBaseFlags
		shardConfFlags
		p2pFlags

		RootDBFile          string // path to Bolt storage file
		TrustBaseDBFile     string
		OrchestrationDBFile string

		BlockRate        uint32
		MaxRequests      uint   // validator partition certification request channel capacity
		RPCServerAddress string // address on which http server is exposed with metrics endpoint
	}
)

func newRootNodeCmd(baseFlags *baseFlags) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "root-node",
		Short: "Tools to run a root node",
	}

	cmd.AddCommand(rootNodeInitCmd(baseFlags))
	cmd.AddCommand(rootNodeRunCmd(baseFlags))
	return cmd
}

func rootNodeInitCmd(baseFlags *baseFlags) *cobra.Command {
	// Currently root node init is the same as shard node init
	flags := &shardNodeInitFlags{baseFlags: baseFlags}

	var cmd = &cobra.Command{
		Use:   "init",
		Short: "Generate node keys and a public node info file",
		RunE: func(cmd *cobra.Command, args []string) error {
			return shardNodeInit(cmd.Context(), flags)
		},
	}

	flags.addKeyConfFlags(cmd, true)
	return cmd
}

func rootNodeRunCmd(baseFlags *baseFlags) *cobra.Command {
	flags := &rootNodeRunFlags{baseFlags: baseFlags}
	var cmd = &cobra.Command{
		Use:   "run",
		Short: "Run a node",
		RunE: func(cmd *cobra.Command, args []string) error {
			return rootNodeRun(cmd.Context(), flags)
		},
	}

	flags.addKeyConfFlags(cmd, false)
	flags.addTrustBaseFlags(cmd)
	flags.addShardConfFlags(cmd, true)
	flags.addP2PFlags(cmd)

	cmd.Flags().UintVar(&flags.MaxRequests, "max-requests", 1000, "request buffer capacity")
	cmd.Flags().StringVar(&flags.RPCServerAddress, "rpc-server-address", "",
		`Specifies the TCP address for the RPC server to listen on, in the form "host:port". RPC server isn't initialised if address is empty.`)

	cmd.Flags().StringVar(&flags.RootDBFile, "root-db", "",
		fmt.Sprintf("path to the root database (default: %s)", filepath.Join("$UBFT_HOME", rootDBFileName)))
	cmd.Flags().StringVar(&flags.TrustBaseDBFile, "trust-base-db", "",
		fmt.Sprintf("path to the trust base database (default: %s)", filepath.Join("$UBFT_HOME", trustBaseDBFileName)))
	cmd.Flags().StringVar(&flags.OrchestrationDBFile, "orchestration-db", "",
		fmt.Sprintf("path to the orchestration database (default: %s)", filepath.Join("$UBFT_HOME", orchestrationDBFileName)))

	cmd.Flags().Uint32Var(&flags.BlockRate, "block-rate", consensus.BlockRate, "block rate (consensus parameter)")

	hideFlags(cmd, "block-rate")
	return cmd
}

func getBootStrapNodes(bootNodesStr []string) ([]peer.AddrInfo, error) {
	bootNodes := make([]peer.AddrInfo, len(bootNodesStr))
	for i, str := range bootNodesStr {
		addrInfo, err := peer.AddrInfoFromString(str)
		if err != nil {
			return nil, fmt.Errorf("invalid bootstrap node parameter: %w", err)
		}
		bootNodes[i] = *addrInfo
	}
	return bootNodes, nil
}

func rootNodeRun(ctx context.Context, flags *rootNodeRunFlags) error {
	keyConf, err := flags.loadKeyConf(flags.baseFlags, false)
	if err != nil {
		return err
	}

	nodeID, err := keyConf.NodeID()
	if err != nil {
		return fmt.Errorf("failed to calculate nodeID: %w", err)
	}
	log := flags.observe.Logger().With(logger.NodeID(nodeID))
	obs := observability.WithLogger(flags.observe, log)

	host, err := createHost(ctx, keyConf, flags, obs)
	if err != nil {
		return fmt.Errorf("creating partition host: %w", err)
	}
	partitionNet, err := network.NewLibP2PRootChainNetwork(host, flags.MaxRequests, defaultNetworkTimeout, obs)
	if err != nil {
		return fmt.Errorf("partition network initialization failed: %w", err)
	}

	rootStore, err := storage.NewBoltStorage(flags.PathWithDefault(flags.RootDBFile, rootDBFileName))
	if err != nil {
		return err
	}

	trustBases, err := flags.loadTrustBases(flags.baseFlags)
	if err != nil {
		return err
	}

	trustBaseDB, err := flags.initDB(flags.TrustBaseDBFile, trustBaseDBFileName)
	if err != nil {
		return err
	}
	trustBaseStore, err := trustbase.NewTrustBaseStore(trustBaseDB, log)
	if err != nil {
		return err
	}

	for _, trustBase := range trustBases {
		if err := trustBaseStore.Store(trustBase); err != nil {
			if !errors.Is(err, trustbase.ErrAlreadyExists) {
				return fmt.Errorf("failed to store trust base: %w", err)
			}
			log.Warn(fmt.Sprintf("trust base already exists for epoch %d, not overwriting it", trustBase.Epoch))
		}
	}

	trustBase, err := trustBaseStore.LoadFirst()
	if err != nil {
		return err
	}

	orchestrationStorePath := flags.PathWithDefault(flags.OrchestrationDBFile, orchestrationDBFileName)
	orchestration, err := partitions.NewOrchestration(trustBase.GetNetworkID(), orchestrationStorePath, log)
	if err != nil {
		return fmt.Errorf("creating orchestration: %w", err)
	}

	shardConfs, err := flags.loadShardConfs(flags.baseFlags)
	if err != nil {
		return fmt.Errorf("failed to load shard confs: %w", err)
	}
	for _, shardConf := range shardConfs {
		if err := orchestration.AddShardConfig(shardConf); err != nil {
			return fmt.Errorf("failed to add shard conf for partition: %d, %w", shardConf.PartitionID, err)
		}
	}

	signer, err := keyConf.Signer()
	if err != nil {
		return err
	}

	rootNet, err := network.NewLibP2RootConsensusNetwork(host, flags.MaxRequests, defaultNetworkTimeout, obs)
	if err != nil {
		return fmt.Errorf("failed initiate root network, %w", err)
	}

	consensusParams := consensus.NewConsensusParams()
	consensusParams.BlockRate = time.Duration(flags.BlockRate) * time.Millisecond

	cm, err := consensus.NewConsensusManager(
		host.ID(),
		trustBaseStore,
		orchestration,
		rootNet,
		signer,
		rootStore,
		obs,
		consensus.WithConsensusParams(*consensusParams),
	)
	if err != nil {
		return fmt.Errorf("failed initiate distributed consensus manager: %w", err)
	}
	if err = host.BootstrapConnect(ctx, log); err != nil {
		return err
	}
	node, err := rootchain.New(
		host,
		partitionNet,
		cm,
		obs,
	)
	if err != nil {
		return fmt.Errorf("failed initiate root node: %w", err)
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return node.Run(ctx) })

	g.Go(func() error {
		if flags.RPCServerAddress == "" {
			return nil // do not kill the group!
		}

		mux := http.NewServeMux()
		if pr := flags.observe.PrometheusRegisterer(); pr != nil {
			mux.Handle("/api/v1/metrics", promhttp.HandlerFor(pr.(prometheus.Gatherer), promhttp.HandlerOpts{MaxRequestsInFlight: 1}))
		}
		mux.HandleFunc("PUT /api/v1/configurations", putShardConfigHandler(orchestration.AddShardConfig))
		mux.HandleFunc("PUT /api/v1/trustbases", putTrustBaseHandler(trustBaseStore.Store))
		mux.HandleFunc("GET /api/v1/trustbases", getTrustBaseHandler(trustBaseStore, obs))
		mux.HandleFunc("GET /api/v1/roundInfo", getRoundInfoHandler(cm.GetState, obs))
		return httpsrv.Run(ctx,
			&http.Server{
				Addr:              flags.RPCServerAddress,
				Handler:           mux,
				ReadTimeout:       3 * time.Second,
				ReadHeaderTimeout: time.Second,
				WriteTimeout:      5 * time.Second,
				IdleTimeout:       30 * time.Second,
			})
	})

	return g.Wait()
}

func createHost(ctx context.Context, keyConf *KeyConf, flags *rootNodeRunFlags, obs Observability) (*network.Peer, error) {
	bootNodes, err := getBootStrapNodes(flags.BootstrapAddresses)
	if err != nil {
		return nil, fmt.Errorf("boot nodes parameter error: %w", err)
	}
	authKeyPair, err := keyConf.AuthKeyPair()
	if err != nil {
		return nil, fmt.Errorf("invalid authentication key: %w", err)
	}
	bootstrapConnectRetry := &network.BootstrapConnectRetry{
		Count: flags.BootstrapConnectRetryCount,
		Delay: flags.BootstrapConnectRetryDelay,
	}
	peerConf, err := network.NewPeerConfiguration(flags.Address, flags.AnnounceAddresses, authKeyPair, bootNodes, bootstrapConnectRetry)
	if err != nil {
		return nil, err
	}
	return network.NewPeer(ctx, peerConf, obs.Logger(), obs.PrometheusRegisterer())
}

type TrustBasesResponse struct {
	_          struct{} `cbor:",toarray"`
	TrustBases []*types.RootTrustBaseV1
}

func getTrustBaseHandler(trustBaseStore *trustbase.TrustBaseStore, obs Observability) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// return trust base records for the epochs from <epoch1> to <epoch2>, inclusively.
		// Both parameters are optional and default to the latest epoch.
		// parameters are uint64 (0 value is not allowed by business rules)
		lastTrustBase, err := trustBaseStore.LoadLast()
		if err != nil {
			obs.Logger().Error(fmt.Sprintf("GET trustbases request: failed to load latest active epoch: %v", err))
			http.Error(w, "failed to load latest trust base", http.StatusInternalServerError)
			return
		}

		epoch1, epoch2, err := validateQueryParams(r, lastTrustBase.Epoch)
		if err != nil {
			obs.Logger().Warn(fmt.Sprintf("GET trustbases request: %v", err))
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		trustBases, err := fetchTrustBases(trustBaseStore, epoch1, epoch2)
		if err != nil {
			obs.Logger().Warn(fmt.Sprintf("GET trustbases request: %v", err))
			http.Error(w, "failed to load trust base", http.StatusInternalServerError)
			return
		}

		result := &TrustBasesResponse{TrustBases: trustBases}
		if err := writeCborResponse(w, result); err != nil {
			obs.Logger().Error(fmt.Sprintf("failed to write response: %v", err))
		}
	}
}

func fetchTrustBases(store *trustbase.TrustBaseStore, epoch1, epoch2 uint64) ([]*types.RootTrustBaseV1, error) {
	var trustBases []*types.RootTrustBaseV1
	for i := epoch1; i <= epoch2; i++ {
		tb, err := store.GetByEpoch(i)
		if err != nil {
			return nil, fmt.Errorf("failed to load trust base for epoch %d: %w", i, err)
		}
		trustBases = append(trustBases, tb)
	}
	return trustBases, nil
}

func writeCborResponse(w http.ResponseWriter, response any) error {
	w.Header().Set("Content-Type", "application/cbor")
	encoder, err := types.Cbor.GetEncoder(w)
	if err != nil {
		return fmt.Errorf("failed to create cbor encoder: %w", err)
	}
	if err := encoder.Encode(response); err != nil {
		return fmt.Errorf("failed to encode response: %w", err)
	}
	return nil
}

func validateQueryParams(r *http.Request, lastEpoch uint64) (uint64, uint64, error) {
	q := r.URL.Query()

	epoch1, err := parseUint64WithDefault(q, "from", lastEpoch)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse from query param: %v", err)
	}
	epoch2, err := parseUint64WithDefault(q, "to", lastEpoch)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse to query param: %v", err)
	}

	if epoch1 == 0 || epoch2 == 0 {
		return 0, 0, fmt.Errorf("from and to should be greater than 0")
	}
	if epoch1 > epoch2 {
		return 0, 0, fmt.Errorf("to must be greater than or equal to from")
	}
	if epoch1 > lastEpoch || epoch2 > lastEpoch {
		return 0, 0, fmt.Errorf("from and to cannot be greater than latest epoch")
	}
	return epoch1, epoch2, nil
}

func parseUint64WithDefault(q url.Values, key string, defaultValue uint64) (uint64, error) {
	valStr := q.Get(key)
	if valStr == "" {
		return defaultValue, nil
	}

	v, err := strconv.ParseUint(valStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", key, err)
	}

	return v, nil
}

func putTrustBaseHandler(addTrustBaseFn func(trustBase types.RootTrustBase) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		trustBase, err := parseTrustBase(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "parsing request body: %v", err)
			return
		}

		if err := addTrustBaseFn(trustBase); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "registering trust base: %v", err)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func putShardConfigHandler(addShardConfFn func(shardConf *types.PartitionDescriptionRecord) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		shardConf, err := parseShardConf(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "parsing request body: %v", err)
			return
		}

		if err := addShardConfFn(shardConf); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "registering shard conf: %v", err)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

func parseTrustBase(r io.ReadCloser) (types.RootTrustBase, error) {
	defer r.Close()
	var trustBase *types.RootTrustBaseV1
	if err := json.NewDecoder(r).Decode(&trustBase); err != nil {
		return nil, fmt.Errorf("decoding trust base json: %w", err)
	}
	return trustBase, nil
}

func parseShardConf(r io.ReadCloser) (*types.PartitionDescriptionRecord, error) {
	defer r.Close()
	var shardConf *types.PartitionDescriptionRecord
	if err := json.NewDecoder(r).Decode(&shardConf); err != nil {
		return nil, fmt.Errorf("decoding shard conf json: %w", err)
	}
	return shardConf, nil
}

type (
	shardInfo struct {
		PartitionID types.PartitionID `json:"partitionId"`
		ShardID     types.ShardID     `json:"shardId"`
		RoundNumber uint64            `json:"roundNumber,string"`
		EpochNumber uint64            `json:"epochNumber,string"`
	}
	roundInfoResponse struct {
		RoundNumber     uint64      `json:"roundNumber,string"`
		EpochNumber     uint64      `json:"epochNumber,string"`
		PartitionShards []shardInfo `json:"partitionShards"`
	}
)

func getRoundInfoHandler(getState func() (*abdrc.StateMsg, error), obs Observability) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := getState()
		if err != nil {
			obs.Logger().Warn(fmt.Sprintf("GET roundInfo request: failed to load state: %v", err))
			http.Error(w, "failed to load state", http.StatusInternalServerError)
			return
		}

		partitionShards := make([]shardInfo, 0, len(state.CommittedHead.ShardInfo))
		for _, si := range state.CommittedHead.ShardInfo {
			partitionShards = append(partitionShards, shardInfo{
				PartitionID: si.Partition,
				ShardID:     si.Shard,
				RoundNumber: si.IR.RoundNumber,
				EpochNumber: si.IR.Epoch,
			})
		}
		response := roundInfoResponse{
			RoundNumber:     state.CommittedHead.Block.Round,
			EpochNumber:     state.CommittedHead.Block.Epoch,
			PartitionShards: partitionShards,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			obs.Logger().Warn(fmt.Sprintf("GET roundInfo request: failed to write response: %v", err))
		}
	}
}
