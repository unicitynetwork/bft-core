package trustbase

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/logger"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"
)

var trustBasePrefix = []byte("trust_base_") // append version and epoch number bytes

var ErrNotFound = errors.New("trust base not found")

type TrustBaseStore struct {
	db    keyvaluedb.KeyValueDB
	mu    sync.RWMutex
	log   *slog.Logger
	cache map[uint64]*types.RootTrustBaseV1
}

func NewTrustBaseStore(db keyvaluedb.KeyValueDB, log *slog.Logger) (*TrustBaseStore, error) {
	if err := verifyDB(db, log); err != nil {
		return nil, fmt.Errorf("failed to verify shard conf store: %w", err)
	}

	return &TrustBaseStore{
		db:    db,
		log:   log,
		cache: make(map[uint64]*types.RootTrustBaseV1),
	}, nil
}

// Load returns trust base for the given epoch.
func (s *TrustBaseStore) GetByEpoch(epoch uint64) (*types.RootTrustBaseV1, error) {
	s.mu.RLock()
	if tb, found := s.cache[epoch]; found {
		s.mu.RUnlock()
		return tb, nil
	}

	s.mu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()

	// double-check to see if someone else already loaded it while we acquired lock
	if tb, found := s.cache[epoch]; found {
		return tb, nil
	}

	tb, err := s.load(epoch)
	if err != nil {
		return nil, err
	}

	sort.Slice(tb.RootNodes, func(i, j int) bool {
		return tb.RootNodes[i].NodeID < tb.RootNodes[j].NodeID
	})

	s.cache[epoch] = tb
	return tb, nil
}

// Load returns the trust base for the given root round.
func (s *TrustBaseStore) GetByRound(round uint64) (*types.RootTrustBaseV1, error) {
	trustBase, err := s.LoadFirst()
	if err != nil {
		return nil, err
	}

	if trustBase.EpochStart > round {
		return nil, fmt.Errorf("trust base not found for round %d", round)
	}
	for {
		nextTrustBase, err := s.GetByEpoch(trustBase.Epoch+1)
		if err != nil && err != ErrNotFound {
			return nil, err
		}
		if err == ErrNotFound || round < nextTrustBase.EpochStart {
			// We reached a not yet active trustBase
			break
		}
		trustBase = nextTrustBase
	}
	return trustBase, nil
}

func (s *TrustBaseStore) LoadFirst() (*types.RootTrustBaseV1, error) {
	dbIt := s.db.First()
	defer func() {
		if err := dbIt.Close(); err != nil {
			s.log.Warn("closing DB iterator", logger.Error(err))
		}
	}()

	if !dbIt.Valid() {
		return nil, fmt.Errorf("empty trust base db")
	}

	_, epoch := fromDBKey(dbIt.Key())
	return s.GetByEpoch(epoch)
}

// Store saves CBOR encoded trust base to db, indexed by the version and epoch.
func (s *TrustBaseStore) Store(trustBase types.RootTrustBase) error {
	version := s.GetVersion(trustBase.GetEpoch())
	dbKey := toDBKey(version, trustBase.GetEpoch())
	if err := s.db.Write(dbKey, trustBase); err != nil {
		s.log.Error(fmt.Sprintf("Failed to add trust base epoch %d", trustBase.GetEpoch()), logger.Error(err))
		return fmt.Errorf("failed to store trust base for epoch %d: %w", trustBase.GetEpoch(), err)

	}
	s.log.Info(fmt.Sprintf("Added trust base epoch %d, epoch start %d", trustBase.GetEpoch(), trustBase.GetEpochStart()))
	return nil
}

// GetVersion returns trust base version based on epoch
func (s *TrustBaseStore) GetVersion(epoch uint64) uint64 {
	return 0
}

func (s *TrustBaseStore) load(epoch uint64) (*types.RootTrustBaseV1, error) {
	version := s.GetVersion(epoch)
	dbKey := toDBKey(version, epoch)
	if version == 0 {
		var tb *types.RootTrustBaseV1
		ok, err := s.db.Read(dbKey, &tb)
		if err != nil {
			return nil, fmt.Errorf("failed to read trust base for version %d and epoch %d: %w", version, epoch, err)
		}
		if !ok {
			return nil, ErrNotFound
		}
		return tb, nil
	} else {
		return nil, fmt.Errorf("trust base version %d not implemented", version)
	}
}

func toDBKey(version, epoch uint64) []byte {
	var trustBaseKey []byte
	trustBaseKey = append(trustBaseKey, trustBasePrefix...)
	trustBaseKey = append(trustBaseKey, util.Uint64ToBytes(version)...)
	trustBaseKey = append(trustBaseKey, util.Uint64ToBytes(epoch)...)
	return trustBaseKey
}

func fromDBKey(dbKey []byte) (version, epoch uint64) {
	versionStart := len(trustBasePrefix)
	epochStart := len(trustBasePrefix)+8
	return util.BytesToUint64(dbKey[versionStart:versionStart+8]), util.BytesToUint64(dbKey[epochStart:epochStart+8])
}

func verifyDB(db keyvaluedb.KeyValueDB, log *slog.Logger) error {
	dbIt := db.First()
	defer func() {
		if err := dbIt.Close(); err != nil {
			log.Warn("closing DB iterator", logger.Error(err))
		}
	}()

	var prevTrustBase *types.RootTrustBaseV1
	for ; dbIt.Valid(); dbIt.Next() {
		version, epoch := fromDBKey(dbIt.Key())

		if version == 1 {
			var trustBase types.RootTrustBaseV1
			if err := dbIt.Value(&trustBase); err != nil {
				return fmt.Errorf("failed to read trust base for epoch %d: %w", epoch, err)
			}
			if prevTrustBase == nil {
				prevTrustBase = &trustBase
			}
			if prevTrustBase.NetworkID == trustBase.NetworkID {
				return fmt.Errorf("inconsistent network id in trust base for epoch %d", epoch)
			}
		} else {
			return fmt.Errorf("unknown trust base version %d in db", version)
		}
	}
	return nil
}
