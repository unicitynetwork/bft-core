# Light Client Verifier FFI

Rust FFI library for verifying uni-evm light client proofs in BFT Core.

## Overview

This library provides a Foreign Function Interface (FFI) for BFT Core (written in Go) to verify light client proofs from uni-evm. In light client mode, instead of generating zero-knowledge proofs (which take 5+ minutes), uni-evm sends the full witness data to BFT Core, which executes the validation logic directly.

**Performance**: Light client mode is ~300x faster than SP1 mode for development:
- SP1 mode: 5+ minutes per block
- Light client mode: ~5 seconds per block

## How It Works

### Light Client Proof Format

```
┌─────────────┬──────────────────────────────────────┐
│ Magic (8B)  │ Serialized ProgramInput (varies)     │
│ "LCPROOF\0" │ (witness + blocks + config)          │
└─────────────┴──────────────────────────────────────┘
```

### Verification Process

1. **Magic Header Check**: Validates the first 8 bytes are `LCPROOF\0`
2. **Deserialization**: Deserializes `ProgramInput` from the payload (rkyv format)
3. **Execution**: Calls `guest_program::execution::stateless_validation_l1()`
4. **State Root Validation**: Verifies `prev_state_root` and `new_state_root` match

## Building

### Prerequisites

- Rust nightly (ethrex uses unstable features)
- Access to uni-evm's ethrex submodule

### Build Steps

```bash
# From this directory
./build.sh

# Or manually
cargo build --release
```

Output:
- `target/release/liblight_client_verifier_ffi.a` - Static library
- `target/release/liblight_client_verifier_ffi.dylib` - Dynamic library (macOS)
- `target/release/liblight_client_verifier_ffi.so` - Dynamic library (Linux)

## Usage from Go

### Include in BFT Core

The library is automatically linked when building BFT Core's zkverifier package:

```go
// In bft-core/rootchain/consensus/zkverifier/verifier.go
cfg := &zkverifier.Config{
    Enabled: true,
    ProofType: zkverifier.ProofTypeLightClient,
}

verifier, err := zkverifier.NewVerifier(cfg)
// verifier will use light client FFI automatically
```

### Direct FFI Usage (Advanced)

```go
import "C"
// #cgo LDFLAGS: -L${SRCDIR}/light-client-verifier-ffi/target/release -llight_client_verifier_ffi
// #include "light-client-verifier-ffi/light_client_verifier.h"

// Verify a light client proof
result := C.light_client_verify_proof(
    (*C.uint8_t)(unsafe.Pointer(&payload[0])),
    C.size_t(len(payload)),
    (*C.uint8_t)(unsafe.Pointer(&prevStateRoot[0])),
    (*C.uint8_t)(unsafe.Pointer(&newStateRoot[0])),
    &errorOut,
)
```

## API Reference

### C Functions

#### `light_client_verify_proof`

Verifies a light client proof payload.

```c
LightClientVerifyResult light_client_verify_proof(
    const uint8_t* payload_bytes,
    size_t payload_len,
    const uint8_t* prev_state_root,  // 32 bytes
    const uint8_t* new_state_root,   // 32 bytes
    char** error_out
);
```

**Returns**:
- `LIGHT_CLIENT_VERIFY_SUCCESS` (0) - Proof is valid
- `LIGHT_CLIENT_VERIFY_INVALID_PROOF` (1) - Proof data is malformed
- `LIGHT_CLIENT_VERIFY_INVALID_MAGIC_HEADER` (2) - Magic header mismatch
- `LIGHT_CLIENT_VERIFY_INVALID_PUBLIC_INPUTS` (3) - State roots don't match
- `LIGHT_CLIENT_VERIFY_VERIFICATION_FAILED` (4) - Validation logic failed
- `LIGHT_CLIENT_VERIFY_INTERNAL_ERROR` (5) - Internal error

#### `light_client_validate_payload`

Validates payload format without executing validation logic.

```c
LightClientVerifyResult light_client_validate_payload(
    const uint8_t* payload_bytes,
    size_t payload_len,
    char** error_out
);
```

#### `light_client_ffi_version`

Returns the FFI library version string.

```c
const char* light_client_ffi_version(void);
```

#### `light_client_free_string`

Frees a string allocated by the library.

```c
void light_client_free_string(char* s);
```

## Testing

### Unit Tests

```bash
cargo test
```

### Integration Tests

See `bft-core/rootchain/consensus/zkverifier/verifier_test.go` for Go integration tests.

## Architecture

### Dependencies

- **rkyv** - Zero-copy deserialization (matches uni-evm's serialization format)
- **ethrex-common** - Core types (Block, H256, etc.)
- **guest_program** - Validation logic (`stateless_validation_l1`)

### File Structure

```
light-client-verifier-ffi/
├── src/
│   └── lib.rs                      # FFI implementation
├── light_client_verifier.h         # C header
├── Cargo.toml                      # Dependencies
├── build.sh                        # Build script
└── README.md                       # This file
```

## Configuration

### Chain ID

Currently hardcoded to `1` (matching uni-evm default). TODO: Make configurable via BFT Core config.

```rust
// In lib.rs
let chain_id = 1;  // TODO: Get from BFT Core configuration
```

## Troubleshooting

### Build Errors

**Error**: `failed to load manifest for dependency 'ethrex-common'`

**Solution**: Ensure you're building from within the uni-evm repository structure, where the ethrex submodule is available at `../../../../../ethrex/`.

**Error**: `undefined reference to 'light_client_verify_proof'`

**Solution**: Ensure the Rust library is built before building Go code:
```bash
cd light-client-verifier-ffi
cargo build --release
cd ../..
go build
```

### Runtime Errors

**Error**: "invalid magic header"

**Cause**: Payload doesn't start with `LCPROOF\0` or is from SP1 mode.

**Solution**: Ensure uni-evm is configured with `prover_type = "light_client"`.

**Error**: "Failed to deserialize ProgramInput"

**Cause**: Payload format mismatch between uni-evm and BFT Core versions.

**Solution**: Ensure both uni-evm and BFT Core are using compatible ethrex versions.

## Performance

### Proof Sizes

| Block Type | Payload Size |
|------------|-------------|
| Empty block | ~1.4 KB |
| 3 transactions | ~2 KB |
| 10 transactions | ~5-10 KB |
| 100 transactions | ~50-100 KB |

Compare to:
- Exec mode: 4 bytes (dummy)
- SP1 mode: ~50 KB (compressed STARK)

### Verification Time

| Mode | Time |
|------|------|
| Light client | ~100-200ms |
| SP1 | ~10ms (proof verification only) |

Light client is slower to verify but much faster to generate (no proving overhead).

## Development Workflow

### Modify Validation Logic

1. Edit `guest_program` crate in ethrex
2. Rebuild this FFI library: `cargo build --release`
3. Rebuild BFT Core: `cd ../.. && go build`

### Add New Exports

1. Add Rust function with `#[no_mangle]` and `extern "C"`
2. Add declaration to `light_client_verifier.h`
3. Add Go wrapper in `light_client_verifier_ffi.go`

## Security Considerations

- **Not succinct**: Full witness data is transmitted (1-5MB vs 50KB for SP1)
- **Development only**: Recommended for local development and testing
- **Production use**: Switch to SP1 mode for production deployments

## See Also

- [LIGHT_CLIENT_MODE.md](../../../../../LIGHT_CLIENT_MODE.md) - User documentation
- [LIGHT_CLIENT_MODE_PLAN.md](../../../../../LIGHT_CLIENT_MODE_PLAN.md) - Implementation plan
- [SP1 Verifier FFI](../sp1-verifier-ffi/README.md) - Similar FFI for SP1 proofs
