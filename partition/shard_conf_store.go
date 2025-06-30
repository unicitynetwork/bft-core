package partition

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"sync"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/logger"
)

type ShardConfStore struct {
	db    keyvaluedb.KeyValueDB
	log   *slog.Logger
	mu    sync.RWMutex
	cache map[uint64]*types.PartitionDescriptionRecord
}

func NewShardConfStore(db keyvaluedb.KeyValueDB, log *slog.Logger) (*ShardConfStore, error) {
	if err := verifyDb(db, log); err != nil {
		return nil, fmt.Errorf("failed to verify shard conf store: %w", err)
	}
	return &ShardConfStore{
		db:    db,
		log:   log,
		cache: make(map[uint64]*types.PartitionDescriptionRecord),
	}, nil
}

func (s *ShardConfStore) Store(shardConf *types.PartitionDescriptionRecord) error {
	var prevShardConf *types.PartitionDescriptionRecord
	if shardConf.Epoch > 0 {
		prevEpoch := shardConf.Epoch-1
		var err error
		prevShardConf, err = s.load(prevEpoch)
		if err != nil {
			return fmt.Errorf("failed to load shard conf for previous epoch %d: %w", prevEpoch, err)
		}
	}
	if err := shardConf.Verify(prevShardConf); err != nil {
		return fmt.Errorf("failed to verify shard conf for epoch %d: %w", shardConf.Epoch, err)
	}
	if err := s.db.Write(epochToKey(shardConf.Epoch), shardConf); err != nil {
		return fmt.Errorf("saving shard conf for epoch %d: %w", shardConf.Epoch, err)
	}
	return nil
}

func (s *ShardConfStore) GetFirst() (*types.PartitionDescriptionRecord, error) {
	dbIt := s.db.First()
	defer func() {
		if err := dbIt.Close(); err != nil {
			s.log.Warn("closing DB iterator", logger.Error(err))
		}
	}()

	if !dbIt.Valid() {
		return nil, fmt.Errorf("empty shard conf db")
	}

	return s.Get(binary.BigEndian.Uint64(dbIt.Key()))
}

func (s *ShardConfStore) Get(epoch uint64) (*types.PartitionDescriptionRecord, error) {
	s.mu.RLock()
	if shardConf, found := s.cache[epoch]; found {
		s.mu.RUnlock()
		return shardConf, nil
	}

	s.mu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()

	// double-check to see if someone else already loaded it while we acquired lock
	if tb, found := s.cache[epoch]; found {
		return tb, nil
	}

	shardConf, err := s.load(epoch)
	if err != nil {
		return nil, err
	}

	s.cache[epoch] = shardConf
	return shardConf, nil

}

func (s *ShardConfStore) load(epoch uint64) (*types.PartitionDescriptionRecord, error) {
	v := &types.PartitionDescriptionRecord{}
	found, err := s.db.Read(epochToKey(epoch), v)
	if err != nil {
		return nil, fmt.Errorf("reading shard conf: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("shard conf not found")
	}
	return v, nil
}

func verifyDb(db keyvaluedb.KeyValueDB, log *slog.Logger) error {
	dbIt := db.First()
	defer func() {
		if err := dbIt.Close(); err != nil {
			log.Warn("closing DB iterator", logger.Error(err))
		}
	}()

	var prevShardConf *types.PartitionDescriptionRecord
	for ; dbIt.Valid(); dbIt.Next() {
		epoch := binary.BigEndian.Uint64(dbIt.Key())

		var shardConf types.PartitionDescriptionRecord
		if err := dbIt.Value(&shardConf); err != nil {
			return fmt.Errorf("failed to read shard conf for epoch %d: %w", epoch, err)
		}
		if prevShardConf == nil {
			prevShardConf = &shardConf
		}
		if prevShardConf.NetworkID == shardConf.NetworkID {
			return fmt.Errorf("inconsistent network id in shard conf for epoch %d", epoch)
		}
		if prevShardConf.PartitionTypeID != shardConf.PartitionTypeID {
			return fmt.Errorf("inconsistent partition type id in shard conf for epoch %d", epoch)
		}
		if prevShardConf.PartitionID != shardConf.PartitionID {
			return fmt.Errorf("inconsistent partition id in shard conf for epoch %d", epoch)
		}
		if !prevShardConf.ShardID.Equal(shardConf.ShardID) {
			return fmt.Errorf("inconsistent shard id in shard conf for epoch %d", epoch)
		}
	}
	return nil
}

func epochToKey(epoch uint64) []byte {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, epoch)
	return key
}
