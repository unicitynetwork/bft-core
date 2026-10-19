package storage

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
)

// readFuzzSeeds returns the checked-in seeds of FuzzRecoveredState, in file order.
func readFuzzSeeds(t testing.TB) [][]byte {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "fuzz", "FuzzRecoveredState", "seed-*"))
	require.NoError(t, err)
	sort.Strings(files)
	var seeds [][]byte
	for _, file := range files {
		raw, err := os.ReadFile(file)
		require.NoError(t, err)
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		require.Len(t, lines, 2, file)
		require.Equal(t, "go test fuzz v1", lines[0])
		lit := strings.TrimSuffix(strings.TrimPrefix(lines[1], "[]byte("), ")")
		seed, err := strconv.Unquote(lit)
		require.NoError(t, err, file)
		seeds = append(seeds, []byte(seed))
	}
	return seeds
}

func decodeState(t *testing.T, raw []byte) *abdrc.StateMsg {
	t.Helper()
	var sm abdrc.StateMsg
	require.NoError(t, types.Cbor.Unmarshal(raw, &sm))
	return &sm
}

// The fixture belongs to its owner: it is built once, serves every input of the owner and is released when the owner
// ends, databases closed first and then the directory removed.
func Test_RecoveredFuzz_FixtureLifetimeIsTheOwners(t *testing.T) {
	var env *recFuzzEnv
	t.Run("owner", func(t *testing.T) {
		env = newRecFuzzEnv(t)
		require.DirExists(t, env.dir)
		r := env.exercise(decodeState(t, env.state))
		require.True(t, r.verified && r.installed, "%+v", r)
		_, err := env.db.LoadBlocks()
		require.NoError(t, err)
		_, err = env.orch.ShardConfigs(1)
		require.NoError(t, err)
	})
	// the owner ended: both database handles are closed and the directory is gone
	require.NoDirExists(t, env.dir)
	_, err := env.db.LoadBlocks()
	require.Error(t, err, "the database of the recovering node is closed")
	_, err = env.orch.ShardConfigs(1)
	require.Error(t, err, "the orchestration database is closed")
}

// Inputs are tests of their own which end before the next one starts. A fixture owned by the first input (the old
// shape) is closed by then, and these regressions fail visibly: the later inputs do not get installed.
func Test_RecoveredFuzz_LaterInputsDoNotDependOnTheFirst(t *testing.T) {
	env := newRecFuzzEnv(t)
	require.GreaterOrEqual(t, len(env.states), 8)
	reachesPostRecovery := func(t *testing.T, raw []byte, wantBlocks bool) {
		r := env.exercise(decodeState(t, raw))
		require.True(t, r.verified && r.installed, "%+v", r)
		if wantBlocks {
			require.GreaterOrEqual(t, r.blocks, 1, "blocks were added after the recovery")
		}
	}
	t.Run("first", func(t *testing.T) { reachesPostRecovery(t, env.states[5], true) })
	// the first input has ended, its cleanup has run
	t.Run("second", func(t *testing.T) { reachesPostRecovery(t, env.states[12], true) })
	t.Run("valid, rejected, valid", func(t *testing.T) {
		reachesPostRecovery(t, env.states[8], true)
		// a certified shard without UC/TR passes the verification but is not installed
		bad := decodeState(t, env.state)
		bad.CommittedHead.ShardInfo[0].UC, bad.CommittedHead.ShardInfo[0].TR = nil, nil
		r := env.exercise(bad)
		require.True(t, r.verified && !r.installed, "%+v", r)
		// a state which is not even decoded
		require.Error(t, types.Cbor.Unmarshal([]byte{0xff, 0x01}, new(abdrc.StateMsg)))
		reachesPostRecovery(t, env.states[10], true)
		reachesPostRecovery(t, env.state, true)
	})

	t.Run("an input of a fixture owned by an ended test cannot install (the old shape)", func(t *testing.T) {
		var owned *recFuzzEnv
		t.Run("first input", func(t *testing.T) { owned = newRecFuzzEnv(t) })
		r := owned.exercise(decodeState(t, env.state))
		require.False(t, r.installed, "the fixture of the first input was closed with it: %+v", r)
	})
}

// Every valid checked-in seed reaches the installation and the post-recovery code, the deliberately invalid ones are
// still rejected. Decode success is not useful coverage and is not what is asserted.
func Test_RecoveredFuzz_CheckedInSeedsReachTheirCode(t *testing.T) {
	env := newRecFuzzEnv(t)
	seeds := readFuzzSeeds(t)
	require.Len(t, seeds, len(env.states)+9, "16 heads of the run and 9 manipulated variants")
	for i, raw := range seeds {
		sm := decodeState(t, raw)
		r := env.exercise(sm)
		if i < len(env.states) {
			require.True(t, r.verified && r.installed, "valid seed %d: %+v", i, r)
			if i > 3 {
				require.GreaterOrEqual(t, r.blocks, 1, "valid seed %d: blocks were added after the recovery", i)
			}
			continue
		}
		require.False(t, r.verified && r.installed, "invalid seed %d is rejected: %+v", i, r)
	}
}
