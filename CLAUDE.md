# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Unicity BFT Core is a Byzantine Fault Tolerant (BFT) consensus system implementing a two-layer architecture: a root chain for consensus coordination and partitions for transaction processing. This is the reference implementation in Go.

## Build and Development

### Prerequisites

- Go 1.24 or higher
- C compiler (GCC recommended - part of build-essential on Debian/Ubuntu, available via Homebrew on macOS)
- For ZK proof verification: SP1 verifier dependencies

### Essential Commands

```bash
# Build the ubft binary
make build              # Outputs to build/ubft

# Run tests with coverage
make test              # Uses -count=1 to disable caching

# Run single test
go test ./path/to/package -run TestName

# Run security analysis
make gosec

# Clean build artifacts and test nodes
make clean

# Full build pipeline
make all               # clean + tools + test + build + gosec
```

### Running Nodes

The CLI binary `ubft` provides commands for different node types:

```bash
# Root node (consensus coordinator)
./build/ubft root-node run --home path/to/node-dir

# Shard/partition node (transaction processor)
./build/ubft shard-node run --home path/to/node-dir

# View available commands
./build/ubft -h
```

### Test Environment Setup

```bash
# Set up root chain + 3 money partition nodes
./setup-nodes.sh -m 3 -t 0

# Set up root + money + token partitions
./setup-nodes.sh -m 3 -t 3

# Start nodes
./start.sh -r -p money           # root + money partitions
./start.sh -r -p money -p tokens # root + money + tokens

# Stop all
./stop.sh -a
```

Generated node configurations are in `test-nodes/` directory.

## Architecture

### Two-Layer BFT System

**Root Chain** (`rootchain/`):
- Coordinates consensus across all partitions
- Maintains trust bases and validator sets
- Processes block certification requests from partitions
- Returns Unicity Certificates (UCs) to certify partition state
- Single root chain can coordinate multiple partitions

**Partitions/Shards** (`partition/`):
- Process transactions independently
- Submit block certification requests to root chain
- Receive UCs to finalize blocks
- Types: Money partition, Token partition, Orchestration partition, Custom partitions

### Key Components

**Consensus** (`rootchain/consensus/`):
- Byzantine consensus algorithm for root chain
- Processes proposals, votes, quorum certificates (QCs)
- Leader election and rotation
- State machine: new round → propose → vote → commit

**Networking** (`network/`):
- libp2p-based P2P networking
- Protocol definitions in `network/protocol/`:
  - `certification/`: Block certification request/response
  - `handshake/`: UC feed subscription
  - `abdrc/`: Consensus messages (proposals, votes, recovery)
  - `blockproposal/`: Block proposals
  - `replication/`: Ledger replication

**State Management** (`state/`):
- Partition state trees
- Merkle tree implementations for state commitments
- State replication and recovery

**Transaction Systems** (`txsystem/`):
- Pluggable transaction processing
- Money partition: transfers, splits, swaps, fee credits
- Token partition: NFTs, fungible tokens
- Predicates: WASM-based smart contract execution

**Storage** (`keyvaluedb/`):
- Abstraction over storage backends
- BoltDB implementation for production
- MemoryDB for testing
- Transaction-based read/write operations

### Critical Data Structures

**Unicity Certificate (UC)**: Proof that root chain reached consensus on a partition's state
- Contains `InputRecord` (partition's proposed state)
- Contains `UnicitySeal` (root chain's certification with signatures)
- Contains `TechnicalRecord` (synchronization data: next round, epoch, leader)

**InputRecord (IR)**: Partition's state transition proposal
- Round number, epoch, timestamp
- Previous state hash, new state hash
- Block hash
- Validation rules (bft-go-base/types/input_record.go:75):
  - If state hash unchanged: block hash must be nil (no transactions)
  - If state hash changed: block hash must be non-nil (has transactions)

**BlockCertificationRequest**: Partition sends to root chain
- InputRecord with proposed state
- ZK proof (optional, separate from IR)
- Signature from partition validator
- Uses CBOR serialization with tuple/array format

**TechnicalRecord**: Root chain provides to partition for synchronization
- Next round number (partition must use this for next request)
- Current epoch
- Current leader
- Ensures partition stays synchronized with root chain rounds

### CBOR Serialization

All network messages use CBOR (Compact Binary Object Representation) with `toarray` format (array/tuple serialization, not maps).

**Important**: Go structs use `cbor:",toarray"` tags. When implementing clients in other languages:
- Use array serialization (not map/object)
- Nil values serialize as CBOR null (0xf6), not empty byte strings (0x40)
- Byte slices use CBOR byte string type (major type 2)

Example from certification protocol:
```
[partition_id, shard_id, node_id, input_record, zk_proof, block_size, state_size, signature]
```

### Partition Integration Pattern

When building a new partition/blockchain that integrates with BFT Core:

1. **Initialization**:
   - Subscribe to UC feed via Handshake message
   - Receive initial sync UC (may have null hashes for pre-state)
   - Store sync UC for timestamp/epoch but don't finalize blocks

2. **Block Production**:
   - Use `next_round` from last UC's TechnicalRecord
   - Use `timestamp` from last UC's UnicitySeal
   - Use `epoch` from last UC's InputRecord
   - Previous hash = last certified state hash (from UC.InputRecord.Hash)
   - For first block: previous_hash = None (let BFT Core use genesis)

3. **Certification**:
   - Build InputRecord with round from TechnicalRecord
   - Set block_hash = actual block header hash (not state root!)
   - Set hash = new state root
   - Sign entire BlockCertificationRequest (with signature set to nil)
   - Send via `/ab/block-certification/0.0.1` protocol

4. **UC Validation**:
   - Check UC.InputRecord.Hash matches proposed state
   - Sync UCs (both hashes null): update round state, don't finalize
   - Repeat UCs (same IR, higher root round): timeout, resync
   - Valid UCs: finalize block, store as last UC

5. **State Continuity**:
   - Each block's previous_hash must equal last certified UC's hash
   - Maintains chain of certified states
   - Root chain validates this continuity

## Configuration

Configuration sources (in precedence order):
1. Command line flags: `--flag=value`
2. Environment variables: `UBFT_FLAG=value`
3. Config file: `$UBFT_HOME/config.props`
4. Default values

Default `$UBFT_HOME` is `$HOME/.ubft`

### Logging

Logger config file: `$UBFT_HOME/logger-config.yaml` (see `cli/ubft/config/logger-config.yaml` for example)

Log format options: text, json, console, ecs
Log level options: DEBUG, INFO, WARN, ERROR

### Tracing

Enable distributed tracing:
```bash
UBFT_TRACING=otlptracehttp ./build/ubft root-node run ...
```

Exporter options: stdout, otlptracehttp, zipkin

For tests:
```bash
UBFT_TEST_TRACER=otlptracehttp go test ./...
```

## Testing

### Test Structure

- Unit tests alongside production code (`*_test.go`)
- Test utilities in `internal/testutils/`
- Integration tests use real network components with mock partitions

### Test Helpers

- `internal/testutils/eventually.go`: Async condition checking
- `internal/testutils/logger/`: Test logger setup
- `internal/testutils/network/`: Mock network implementations
- `internal/testutils/trustbase/`: Test trust base generation
- `internal/testutils/txsystem/`: Counter-based test transaction system

### Running Tests

```bash
# All tests with coverage
make test

# Specific package
go test ./rootchain/consensus

# Specific test
go test ./partition -run TestNode_StartAndStop

# With race detector
go test -race ./...

# Generate tests for Rust SDK
UBFT_RUST_SDK_ROOT="/path/to/rust-sdk" go test ./...
```

## Docker

```bash
# Build Docker image
make build-docker

# With local go dependencies
DOCKER_GO_DEPENDENCY=../bft-go-base make build-docker
```

## Common Pitfalls


1. **Round Synchronization**: Partitions must use `TechnicalRecord.Round` for next certification request, not block number or self-incremented counter

2. **CBOR Serialization**: Use `cbor:",toarray"` for struct tags and ensure nil values serialize as CBOR null (0xf6), not empty byte strings

3. **InputRecord Validation**: State hash changes require non-nil block hash; unchanged state requires nil block hash

4. **UC Types**: Distinguish between sync UCs (null hashes), repeat UCs (timeout), and valid UCs (certified blocks)

5. **Timestamp Source**: Use UnicitySeal.timestamp from last UC, not system time

6. **Previous Hash**: For certification requests, use previous round's state root hash as the PreviousHash. It MUST match the previous UC's luc.InputRecord.Hash to be successful. That is, rounds' root hashes must form a continuous chain certified by InputRecords.

7. **First Block**: Send previous_hash=nil to let BFT Core use genesis state

8. **Database Cleanup**: When testing, clean both partition AND root chain databases for fresh state. Otherwise, the BFT Core and partition can not produce a synchronized chain of root hashes, following the ledger rules.

## Related Repositories

- `bft-go-base`: Shared types and utilities (InputRecord, UnicityCertificate, validation rules)
- Integration clients should implement CBOR serialization matching Go's `toarray` format
