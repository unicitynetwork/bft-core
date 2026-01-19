package cmd

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/internal/testutils/net"
	"github.com/unicitynetwork/bft-core/internal/testutils/observability"
	testsig "github.com/unicitynetwork/bft-core/internal/testutils/sig"
	testtime "github.com/unicitynetwork/bft-core/internal/testutils/time"
	testtb "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

func TestRootValidator_OK(t *testing.T) {
	ctx, ctxCancel := context.WithCancel(context.Background())
	observe := observability.Default(t)
	obsF := observe.Factory()

	// init money node
	moneyHome := writeShardConf(t, defaultMoneyShardConf)
	cmd := New(obsF)
	cmd.baseCmd.SetArgs([]string{
		"shard-node", "init", "--generate", "--home", moneyHome,
	})
	require.NoError(t, cmd.Execute(context.Background()))

	// init root node 1
	rootHome1 := t.TempDir()
	cmd = New(obsF)
	cmd.baseCmd.SetArgs([]string{
		"root-node", "init", "--generate", "--home", rootHome1,
	})
	require.NoError(t, cmd.Execute(context.Background()))

	// init root node 2
	rootHome2 := t.TempDir()
	cmd = New(obsF)
	cmd.baseCmd.SetArgs([]string{
		"root-node", "init", "--generate", "--home", rootHome2,
	})
	require.NoError(t, cmd.Execute(context.Background()))

	// generate trust base
	cmd = New(obsF)
	cmd.baseCmd.SetArgs([]string{
		"trust-base", "generate",
		"--home", rootHome1,
		"--node-info", filepath.Join(rootHome1, nodeInfoFileName),
		"--node-info", filepath.Join(rootHome2, nodeInfoFileName),
	})
	require.NoError(t, cmd.Execute(context.Background()))

	// sign trust base
	cmd = New(obsF)
	trustBaseFile := filepath.Join(rootHome1, "trust-base.json")
	cmd.baseCmd.SetArgs([]string{
		"trust-base", "sign",
		"--key-conf", filepath.Join(rootHome1, keyConfFileName),
		"--trust-base", trustBaseFile,
	})
	require.NoError(t, cmd.Execute(context.Background()))

	cmd = New(obsF)
	cmd.baseCmd.SetArgs([]string{
		"trust-base", "sign",
		"--key-conf", filepath.Join(rootHome2, keyConfFileName),
		"--trust-base", trustBaseFile,
	})
	require.NoError(t, cmd.Execute(context.Background()))

	// start the root node and expect no errors
	testtime.MustRunInTime(t, 5*time.Second, func() {
		appStoppedWg := sync.WaitGroup{}
		address := fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", net.GetFreeRandomPort(t))

		// start the root node in background
		appStoppedWg.Add(1)
		go func() {
			defer appStoppedWg.Done()
			cmd = New(obsF)
			cmd.baseCmd.SetArgs([]string{
				"root-node", "run",
				"--home", rootHome1,
				"--address", address,
				"--trust-base", filepath.Join(rootHome1, trustBaseFileName),
			})
			require.ErrorIs(t, cmd.Execute(ctx), context.Canceled)
		}()

		// Close the app
		ctxCancel()
		// Wait for test asserts to be completed
		appStoppedWg.Wait()
	})
}

func generateSingleNodeSetup(t *testing.T) (string, string) {
	t.Helper()
	rootHomeDir := t.TempDir()
	logF := observability.NewFactory(t)
	// init money node
	moneyHomeDir := writeShardConf(t, defaultMoneyShardConf)
	cmd := New(logF)
	args := "shard-node init -g --home " + moneyHomeDir
	cmd.baseCmd.SetArgs(strings.Split(args, " "))
	require.NoError(t, cmd.Execute(context.Background()))

	// init root node
	cmd = New(logF)
	args = "root-node init -g --home " + rootHomeDir
	cmd.baseCmd.SetArgs(strings.Split(args, " "))
	err := cmd.Execute(context.Background())
	require.NoError(t, err)

	// generate trust base
	cmd = New(logF)
	args = "trust-base generate --home " + rootHomeDir +
		" --node-info=" + filepath.Join(rootHomeDir, nodeInfoFileName)
	cmd.baseCmd.SetArgs(strings.Split(args, " "))
	require.NoError(t, cmd.Execute(context.Background()))
	return rootHomeDir, moneyHomeDir
}

func Test_rootNodeConfig_getBootStrapNodes(t *testing.T) {
	t.Run("ok: nil", func(t *testing.T) {
		bootNodes, err := getBootStrapNodes(nil)
		require.NoError(t, err)
		require.NotNil(t, bootNodes)
		require.Empty(t, bootNodes)
	})
	t.Run("ok", func(t *testing.T) {
		bootNodes, err := getBootStrapNodes([]string{"/ip4/127.0.0.1/tcp/1366/p2p/16Uiu2HAmLEmba2HMEEMe4NYsKnqKToAgi1FueNJaDiAnLeJpKktz"})
		require.NoError(t, err)
		require.Len(t, bootNodes, 1)
		require.Equal(t, bootNodes[0].ID.String(), "16Uiu2HAmLEmba2HMEEMe4NYsKnqKToAgi1FueNJaDiAnLeJpKktz")
		require.Len(t, bootNodes[0].Addrs, 1)
		require.Equal(t, bootNodes[0].Addrs[0].String(), "/ip4/127.0.0.1/tcp/1366")
	})
	t.Run("multiple nodes ok", func(t *testing.T) {
		bootNodes, err := getBootStrapNodes([]string{
			"/ip4/127.0.0.1/tcp/1366/p2p/16Uiu2HAmLEmba2HMEEMe4NYsKnqKToAgi1FueNJaDiAnLeJpKktz",
			"/ip4/127.0.0.1/tcp/1367/p2p/16Uiu2HAmLEmba2HMEEMe4NYsKnqKToAgi1FueNJaDiAnLeJpKktx",
		})
		require.NoError(t, err)
		require.Len(t, bootNodes, 2)

		require.Equal(t, bootNodes[0].ID.String(), "16Uiu2HAmLEmba2HMEEMe4NYsKnqKToAgi1FueNJaDiAnLeJpKktz")
		require.Len(t, bootNodes[0].Addrs, 1)
		require.Equal(t, bootNodes[0].Addrs[0].String(), "/ip4/127.0.0.1/tcp/1366")

		require.Equal(t, bootNodes[1].ID.String(), "16Uiu2HAmLEmba2HMEEMe4NYsKnqKToAgi1FueNJaDiAnLeJpKktx")
		require.Len(t, bootNodes[1].Addrs, 1)
		require.Equal(t, bootNodes[1].Addrs[0].String(), "/ip4/127.0.0.1/tcp/1367")
	})
}

func TestRootValidator_CannotBeStartedInvalidDBDir(t *testing.T) {
	rootHome, _ := generateSingleNodeSetup(t)

	cmd := New(observability.NewFactory(t))
	invalidStore := "/foobar/doesnotexist3454/"
	cmd.baseCmd.SetArgs([]string{"root-node", "run", "--home", rootHome, "--root-db", invalidStore})

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
	defer cancel()
	require.EqualError(t, cmd.Execute(ctx), fmt.Sprintf("open database: open %s: no such file or directory", invalidStore))
}

func Test_cfgHandler(t *testing.T) {
	// helper to set up handler for the case where we expect that the addConfig
	// callback is not called (ie handler fails before there is a reason to call it)
	setupNoCallbackHandler := func(t *testing.T) (http.HandlerFunc, *httptest.ResponseRecorder) {
		return putShardConfigHandler(func(shardConf *types.PartitionDescriptionRecord) error {
				err := fmt.Errorf("unexpected call of addConfig callback with %v", shardConf)
				t.Error(err)
				return err
			}),
			httptest.NewRecorder()
	}

	t.Run("missing request body", func(t *testing.T) {
		hf, w := setupNoCallbackHandler(t)
		hf(w, httptest.NewRequest("PUT", "/api/v1/configurations", nil))
		resp := w.Result()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, `parsing request body: decoding shard conf json: EOF`, string(body))
	})

	t.Run("invalid request body", func(t *testing.T) {
		hf, w := setupNoCallbackHandler(t)
		hf(w, httptest.NewRequest("PUT", "/api/v1/configurations", bytes.NewBufferString("not valid json")))
		resp := w.Result()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusBadRequest, resp.StatusCode)
		require.Equal(t, `parsing request body: decoding shard conf json: invalid character 'o' in literal null (expecting 'u')`, string(body))
	})

	shardConfJson, err := json.Marshal(defaultMoneyShardConf)
	require.NoError(t, err)

	t.Run("config registration fails", func(t *testing.T) {
		hf := putShardConfigHandler(func(shardConf *types.PartitionDescriptionRecord) error {
			return fmt.Errorf("nope, can't add this conf")
		})
		w := httptest.NewRecorder()
		hf(w, httptest.NewRequest("PUT", "/api/v1/configurations", bytes.NewBuffer(shardConfJson)))
		resp := w.Result()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusInternalServerError, resp.StatusCode)
		require.Equal(t, `registering shard conf: nope, can't add this conf`, string(body))
	})

	t.Run("success", func(t *testing.T) {
		cbCall := false
		hf := putShardConfigHandler(func(shardConf *types.PartitionDescriptionRecord) error {
			cbCall = true
			require.Equal(t, shardConf, defaultMoneyShardConf)
			return nil
		})
		w := httptest.NewRecorder()
		hf(w, httptest.NewRequest("PUT", "/api/v1/configurations", bytes.NewBuffer(shardConfJson)))
		resp := w.Result()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.EqualValues(t, http.StatusOK, resp.StatusCode)
		require.Empty(t, body)
		require.True(t, cbCall, "add configuration callback has not been called")
	})
}

func Test_roundInfoHandler(t *testing.T) {
	t.Run("state provider error", func(t *testing.T) {
		hf := getRoundInfoHandler(func() (*abdrc.StateMsg, error) {
			return nil, fmt.Errorf("some error")
		}, observability.Default(t))
		res, body := doRequest(t, hf, http.MethodGet, "/api/v1/roundInfo")
		require.EqualValues(t, http.StatusInternalServerError, res.StatusCode)
		require.Equal(t, "failed to load state\n", string(body))
		require.Equal(t, "text/plain; charset=utf-8", res.Header.Get("Content-Type"))
	})

	t.Run("ok", func(t *testing.T) {
		hf := getRoundInfoHandler(func() (*abdrc.StateMsg, error) {
			return &abdrc.StateMsg{
				CommittedHead: &abdrc.CommittedBlock{
					ShardInfo: []abdrc.ShardInfo{
						{
							Partition: 1,
							Shard:     types.ShardID{},
							IR:        &types.InputRecord{RoundNumber: 11, Epoch: 1},
						},
					},
					Block: &rctypes.BlockData{Round: 12, Epoch: 2},
				},
			}, nil
		}, observability.Default(t))
		res, body := doRequest(t, hf, http.MethodGet, "/api/v1/roundInfo")
		require.EqualValues(t, http.StatusOK, res.StatusCode)
		require.EqualValues(t, "application/json", res.Header.Get("Content-Type"))

		var actual roundInfoResponse
		require.NoError(t, json.Unmarshal(body, &actual))

		expected := roundInfoResponse{
			RoundNumber: 12,
			EpochNumber: 2,
			PartitionShards: []shardInfo{
				{
					PartitionID: 1,
					ShardID:     types.ShardID{},
					RoundNumber: 11,
					EpochNumber: 1,
				},
			},
		}
		require.Equal(t, expected, actual)
	})
}

func Test_GetTrustBases(t *testing.T) {
	s1, v1 := testsig.CreateSignerAndVerifier(t)
	trustBase1, err := types.NewTrustBase(types.NetworkLocal, []*types.NodeInfo{testtb.NewNodeInfoFromVerifier(t, "1", v1)},
		types.WithEpoch(1),
		types.WithEpochStart(1),
		types.WithQuorumThreshold(1),
	)
	require.NoError(t, err)
	require.NoError(t, trustBase1.Sign("1", s1))

	_, v2 := testsig.CreateSignerAndVerifier(t)
	trustBase1Hash, err := trustBase1.Hash(crypto.SHA256)
	require.NoError(t, err)
	trustBase2, err := types.NewTrustBase(types.NetworkLocal, []*types.NodeInfo{testtb.NewNodeInfoFromVerifier(t, "2", v2)},
		types.WithEpoch(2),
		types.WithEpochStart(2),
		types.WithQuorumThreshold(1),
		types.WithPreviousTrustBaseHash(trustBase1Hash),
	)
	require.NoError(t, err)
	require.NoError(t, trustBase2.Sign("1", s1)) // sign by previous validator

	tbs, err := trustbase.NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)
	require.NoError(t, tbs.Store(trustBase1))
	require.NoError(t, tbs.Store(trustBase2))

	hf := getTrustBaseHandler(tbs, observability.Default(t))

	t.Run("ok with default values", func(t *testing.T) {
		res, body := doRequest(t, hf, http.MethodGet, "/api/v1/trustbases")
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.Equal(t, "application/cbor", res.Header.Get("Content-Type"))

		var response TrustBasesResponse
		require.NoError(t, types.Cbor.Unmarshal(body, &response))
		require.Len(t, response.TrustBases, 1)

		require.EqualValues(t, 2, response.TrustBases[0].Epoch)
	})

	t.Run("ok with multiple trust bases", func(t *testing.T) {
		res, body := doRequest(t, hf, http.MethodGet, "/api/v1/trustbases?from=1&to=2")
		require.Equal(t, http.StatusOK, res.StatusCode)

		var response TrustBasesResponse
		require.NoError(t, types.Cbor.Unmarshal(body, &response))
		require.Len(t, response.TrustBases, 2)

		require.EqualValues(t, 1, response.TrustBases[0].Epoch)
		require.EqualValues(t, 2, response.TrustBases[1].Epoch)
	})

	t.Run("ok with explicit params", func(t *testing.T) {
		res, _ := doRequest(t, hf, http.MethodGet, "/api/v1/trustbases?from=2&to=2")
		require.Equal(t, http.StatusOK, res.StatusCode)
	})

	t.Run("bad_request_invalid_epoch", func(t *testing.T) {
		res, _ := doRequest(t, hf, http.MethodGet, "/api/v1/trustbases?from=0")
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("bad_request_from_gt_to", func(t *testing.T) {
		res, _ := doRequest(t, hf, http.MethodGet, "/api/v1/trustbases?from=5&to=3")
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("bad_request_epoch_gt_latest", func(t *testing.T) {
		res, _ := doRequest(t, hf, http.MethodGet, "/api/v1/trustbases?to=999")
		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})
}

func doRequest(t *testing.T, hf http.HandlerFunc, method, path string) (*http.Response, []byte) {
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	hf(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	responseBody, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res, responseBody
}
