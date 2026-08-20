# ZK Verifier Build System

This directory contains optional Rust FFI components for ZK proof verification. The build system is configurable and supports building with or without these Rust dependencies.

## Architecture

The ZK verifier supports multiple proof types through a common interface.
Verifiers fall into two families:

**Pure-Go, always compiled in (no build tag):**
- **No-Op Verifier** (`proof_type` unset or `none`): Disabled verification for testing.
- **Aggregator RSMT Verifier** (`proof_type=aggregator_rsmt_v1`): Verifies a
  Radix Sparse Merkle Tree consistency proof produced by the Rust aggregator
  (`crates/rsmt/src/consistency.rs`). Recomputes the `prev → new` root
  transition for a batch of newly inserted leaves. Implementation lives in
  the `rsmt/` sub-package.

**FFI-gated (`-tags zkverifier_ffi`):**
- **SP1 Verifier** (`proof_type=sp1`): Verifies SP1 zkVM proofs.
- **Light Client Verifier** (`proof_type=light_client`): Executes full witness validation.

### Aggregator RSMT verifier

Enable it on a partition by setting `proof_type=aggregator_rsmt_v1` in the
partition's `PartitionParams` when generating the shard config, e.g.:

```bash
ubft shard-conf generate \
  ... \
  --partition-params "proof_type=aggregator_rsmt_v1"
```

Once set, `node.verifyZKProof()` rejects any `BlockCertificationRequest` whose
`ZkProof` envelope does not recompute `InputRecord.PreviousHash →
InputRecord.Hash` for the carried batch — no UC is issued.

**Wire format of `ZkProof`** (no version tag; the format is selected by
`proof_type`):

```
offset  size           field
0       4              leaf_count (big-endian u32)
4       ...            leaves: leaf_count × { key[32] || value_len (u16 BE) || value[value_len] }
...     to end-of-buf  consistency-proof opcode stream (flat bytes)
```

A leaf's `value` is the declared transaction hash, not the value the tree
stores. Before verifying, the Core derives each stored leaf value as
`SHA256(CBOR([transactionHash, referenceTime]))`, where `referenceTime` is
`InputRecord.Timestamp` — the value it already requires to equal the previous
seal's timestamp. Deriving rather than accepting a supplied leaf value is what
makes a wrong reference time unrepresentable: a shard that built its tree under
any other reference time produces a root the Core does not reproduce. `O_L`
opcodes open a leaf preserved from an earlier round and keep carrying that
leaf's stored value verbatim; only the current batch is derived.

Opcodes (post-order stack machine):
- `0x00 || h[32]`  — `S`: unchanged subtree hash
- `0x01`           — `L`: pop next leaf from the wire batch
- `0x02 || depth`  — `N`: inner node at `depth ∈ 0..=255`, pops 2 children

Invariants enforced by the verifier:
- Leaves MUST be pre-sorted by `SortKey` (per-byte bit-reversal, LSB-first
  lexicographic order). Unsorted or duplicate leaves → `ErrLeavesUnsorted`.
- Empty batch ⇒ empty proof and `prev == new`; otherwise `ErrEmptyBatchNonEmptyProof` /
  `ErrEmptyBatchRootChange`.
- After stream consumption: stack size 1, leaves fully consumed, bytes fully
  consumed, and `stack[0] == (prev, new)`.
- Leaf count is capped at `MaxLeafCount = 1<<20` to prevent OOM from malicious
  inputs. Value length is naturally capped at 65 535 by `u16`.

Hash functions (SHA-256, matching `crates/rsmt/src/hash.rs`):
- `HashLeaf(key, value) = SHA256(0x00 || key[32] || value)`
- `HashNode(left, right, depth) = SHA256(0x01 || depth || left[32] || right[32])`

## Build Configurations

### Default Build (No FFI)

Build without Rust dependencies (default behavior):

```bash
make build
# or
go build ./...
```

This uses Go build tag stubs that return errors when FFI verifiers are requested. The system will still build and run, but cannot verify ZK proofs.

### Build with FFI

Build with Rust FFI support for full ZK verification:

```bash
make build-with-ffi
```

This will:
1. Check for Rust toolchain
2. Build SP1 verifier FFI library
3. Build Light Client verifier FFI library
4. Build Go binary with `-tags zkverifier_ffi`

**Requirements:**
- Rust toolchain (install from https://rustup.rs)
- C compiler (GCC/Clang)
- Internet connection (to fetch ethrex dependencies from GitHub)

### Manual FFI Build

Build individual FFI components:

```bash
# Build SP1 verifier only
make build-sp1-ffi

# Build Light Client verifier only
make build-light-client-ffi

# Build both
make build-rust-ffi
```

Then build Go with FFI tags:

```bash
cd cli/ubft && go build -tags zkverifier_ffi -o ../../build/ubft
```

## Testing

### Test without FFI

```bash
make test
# or
go test ./...
```

### Test with FFI

```bash
make test ZKVERIFIER_FFI=1
# or
go test -tags zkverifier_ffi ./...
```

## CI/CD

The CI pipeline (`.github/workflows/ci.yml`) runs both configurations:

1. **build** job: Builds without FFI (fast, no Rust required)
2. **build-with-ffi** job: Builds with FFI (requires Rust setup)
3. **test** job: Tests without FFI
4. **test-with-ffi** job: Tests with FFI

This ensures the codebase works in both configurations.

## How It Works

### Build Tags

- **FFI files** (`*_ffi.go`): Tagged with `//go:build zkverifier_ffi`
  - Only compiled when `-tags zkverifier_ffi` is used
  - Contains cgo directives to link Rust libraries

- **Stub files** (`*_ffi_stub.go`): Tagged with `//go:build !zkverifier_ffi`
  - Compiled by default (without tags)
  - Provides stub implementations that return errors

### FFI Libraries

Located in:
- `sp1-verifier-ffi/`: SP1 proof verification
- `light-client-verifier-ffi/`: Light client witness validation

Built as static libraries (`.a` files) and linked via cgo:
```c
#cgo LDFLAGS: -L${SRCDIR}/sp1-verifier-ffi/target/release -lsp1_verifier_ffi -ldl -lm
```

**Dependencies:**
- `sp1-verifier-ffi`: Uses sp1-sdk from crates.io
- `light-client-verifier-ffi`: Uses ethrex fork from GitHub (https://github.com/ristik/ethrex branch uni-evm)
  - Dependencies are fetched automatically during Rust build
  - No local submodules or path dependencies required

### Configuration

The verifier factory (`NewVerifier()`) checks if FFI is available at runtime:

```go
cfg := &zkverifier.Config{
    Enabled: true,
    ProofType: zkverifier.ProofTypeSP1,
    VerificationKeyPath: "/path/to/vkey",
}
verifier, err := zkverifier.NewVerifier(cfg)
```

Without FFI, this returns an error indicating FFI is not available. With FFI, it initializes the Rust verifier.

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make build` | Build without FFI (default) |
| `make build-with-ffi` | Build with FFI support |
| `make build-rust-ffi` | Build Rust FFI libraries only |
| `make build-sp1-ffi` | Build SP1 verifier FFI |
| `make build-light-client-ffi` | Build Light Client verifier FFI |
| `make test` | Run tests without FFI |
| `make test ZKVERIFIER_FFI=1` | Run tests with FFI |
| `make clean` | Clean Go build artifacts |
| `make clean-ffi` | Clean Rust build artifacts |
| `make check-rust` | Verify Rust toolchain is available |

## Environment Variables

- `ZKVERIFIER_FFI=1`: Enable FFI build (used internally by Makefile)
- `CGO_ENABLED=1`: Required for cgo (usually set by default)

## Troubleshooting

### "FFI verifier not available" error

This means the binary was built without FFI support. Rebuild with:
```bash
make build-with-ffi
```

### Rust toolchain not found

Install Rust:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### ethrex dependencies not found

The Rust FFI uses ethrex dependencies from GitHub (https://github.com/ristik/ethrex branch uni-evm). If you see errors fetching these, ensure you have:
- Internet connectivity
- Git configured with GitHub access

### Duplicate library warnings

When building with FFI, you may see:
```
ld: warning: ignoring duplicate libraries: '-ldl', '-lm'
```

This is harmless - both FFI libraries link these system libraries.

## Production Deployment

For production deployments that need ZK verification:

1. Ensure Rust toolchain is available in build environment
2. Use `make build-with-ffi` in CI/CD
3. Distribute the binary with embedded FFI libraries
4. Provide appropriate verification keys at runtime

For deployments that don't need ZK verification (e.g., testing environments):

1. Use `make build` (no Rust required)
2. Configure verifier with `Enabled: false` or `ProofType: ProofTypeNone`
