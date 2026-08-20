# SP1 Verifier FFI Library

Foreign Function Interface (FFI) library for verifying SP1 ZK proofs from Go.

## Overview

This Rust library provides C-compatible functions for verifying SP1 (Succinct Processor 1) zero-knowledge proofs. It wraps the SP1 SDK and exposes a simple interface that can be called from Go using CGO.

## Architecture

```
┌─────────────────┐
│   Go (BFT Core) │
│   zkverifier    │
└────────┬────────┘
         │ CGO
         ▼
┌─────────────────┐
│  C Header       │
│  sp1_verifier.h │
└────────┬────────┘
         │ FFI
         ▼
┌─────────────────┐
│  Rust Library   │
│  sp1-verifier   │
│  -ffi           │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  SP1 SDK        │
│  (Rust)         │
└─────────────────┘
```

## Building

### Prerequisites

- Rust toolchain (1.70+): https://rustup.rs/
- Cargo

### Build Commands

```bash
# Build release version
./build.sh

# Or manually:
cargo build --release

# Run tests
cargo test

# Clean build
cargo clean
```

### Build Artifacts

After building, you'll find:
- `target/release/libsp1_verifier_ffi.so` (Linux)
- `target/release/libsp1_verifier_ffi.dylib` (macOS)
- `target/release/libsp1_verifier_ffi.a` (static library)

## API

### C Interface

```c
/**
 * Verify an SP1 compressed proof
 *
 * Returns: SP1VerifyResult status code
 */
SP1VerifyResult sp1_verify_proof(
    const uint8_t* vkey_bytes,
    size_t vkey_len,
    const uint8_t* proof_bytes,
    size_t proof_len,
    const uint8_t* prev_state_root,    // 32 bytes
    const uint8_t* new_state_root,     // 32 bytes
    char** error_out                   // Must free with sp1_free_string
);

/**
 * Free error string
 */
void sp1_free_string(char* s);

/**
 * Get library version
 */
const char* sp1_ffi_version(void);
```

### Result Codes

| Code | Meaning |
|------|---------|
| `SP1_VERIFY_SUCCESS` (0) | Proof verified successfully |
| `SP1_VERIFY_INVALID_PROOF` (1) | Proof data is malformed |
| `SP1_VERIFY_INVALID_VKEY` (2) | Verification key is invalid |
| `SP1_VERIFY_INVALID_PUBLIC_INPUTS` (3) | Public inputs don't match |
| `SP1_VERIFY_VERIFICATION_FAILED` (4) | Cryptographic verification failed |
| `SP1_VERIFY_INTERNAL_ERROR` (5) | Internal error |

## Usage from Go

### Setup

1. Build the Rust library:
   ```bash
   cd sp1-verifier-ffi
   ./build.sh
   ```

2. The Go code will automatically link to the library using CGO directives in `sp1_verifier_ffi.go`:
   ```go
   // #cgo LDFLAGS: -L${SRCDIR}/sp1-verifier-ffi/target/release -lsp1_verifier_ffi
   // #include "sp1-verifier-ffi/sp1_verifier.h"
   import "C"
   ```

### Example

```go
package main

import (
    "fmt"
    "github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier"
)

func main() {
    // Create verifier
    verifier, err := zkverifier.NewSP1Verifier("/path/to/verification.vkey")
    if err != nil {
        panic(err)
    }

    // Verify proof
    proof := loadProofBytes()
    prevRoot := make([]byte, 32)  // Previous state root
    newRoot := make([]byte, 32)   // New state root

    err = verifier.VerifyProof(proof, prevRoot, newRoot)
    if err != nil {
        fmt.Printf("Verification failed: %v\n", err)
    } else {
        fmt.Println("Proof verified successfully!")
    }
}
```

## Proof Format

The library expects SP1 compressed proofs in the following format:

1. **Verification Key**: Serialized SP1 verification key (bincode format)
2. **Proof**: Serialized `SP1ProofWithPublicValues` (bincode format)
3. **Public Values**: First 64 bytes must be:
   - Bytes 0-31: Previous state root
   - Bytes 32-63: New state root

## Development

### Project Structure

```
sp1-verifier-ffi/
├── Cargo.toml          # Rust package configuration
├── build.sh            # Build script
├── src/
│   └── lib.rs          # FFI implementation
├── sp1_verifier.h      # C header file
└── README.md           # This file
```

### Adding New Functions

1. Add Rust function with `#[no_mangle]` and `extern "C"`:
   ```rust
   #[no_mangle]
   pub extern "C" fn new_function() -> i32 {
       // Implementation
   }
   ```

2. Add declaration to `sp1_verifier.h`:
   ```c
   int32_t new_function(void);
   ```

3. Update Go bindings in `../sp1_verifier_ffi.go`

### Testing

```bash
# Rust tests
cargo test

# Go integration tests (from parent directory)
cd ..
go test -v ./...
```

## Troubleshooting

### "library not found" error

Make sure the library is built and CGO can find it:
```bash
export CGO_LDFLAGS="-L$(pwd)/target/release"
export LD_LIBRARY_PATH="$(pwd)/target/release:$LD_LIBRARY_PATH"  # Linux
export DYLD_LIBRARY_PATH="$(pwd)/target/release:$DYLD_LIBRARY_PATH"  # macOS
```

### "undefined symbol" error

The library may not be linked correctly. Check:
1. Library was built with same architecture as Go binary
2. CGO flags are correct
3. Header file matches library exports

### SP1 SDK errors

Make sure you're using a compatible SP1 SDK version:
```bash
cargo update
cargo build --release
```

## Performance

Typical verification times on modern hardware:
- Compressed proof verification: 10-100ms
- Memory usage: ~50-200MB during verification

## Security

⚠️ **Important Security Notes:**

1. **Verification Key**: Must be generated from trusted source
2. **Public Inputs**: Always validated against expected values
3. **Memory Safety**: FFI uses unsafe Rust - reviewed for safety
4. **Error Handling**: All errors propagated to Go caller

## License

Same license as BFT Core parent project.

## References

- [SP1 Documentation](https://docs.succinct.xyz/)
- [SP1 GitHub](https://github.com/succinctlabs/sp1)
- [Rust FFI Guide](https://doc.rust-lang.org/nomicon/ffi.html)
- [CGO Documentation](https://pkg.go.dev/cmd/cgo)
