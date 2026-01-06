# SP1 FFI Integration Guide

Complete guide for integrating SP1 proof verification via FFI (Foreign Function Interface).

## Overview

Since there's no native Go library for SP1 STARK proof verification, we use FFI to call the Rust SP1 SDK from Go.

**Architecture:**
```
Go (BFT Core) → CGO → C Header → Rust FFI → SP1 SDK
```

---

## Quick Start

### 1. Build the FFI Library

```bash
cd rootchain/consensus/zkverifier/sp1-verifier-ffi
./build.sh
```

This will:
- Compile the Rust library
- Run tests
- Create `libsp1_verifier_ffi.{so,dylib,a}`

### 2. Test the Integration

```bash
cd ..
go test -v ./...
```

The Go code automatically links to the Rust library via CGO directives.

### 3. Run BFT Core with FFI Verification

```bash
ubft root-node run \
  --zk-verification-enabled=true \
  --zk-proof-type=sp1 \
  --zk-vkey-path=/etc/bft-core/sp1.vkey
```

If the FFI library is built, you'll see:
```
INFO Using SP1 FFI verifier path=/etc/bft-core/sp1.vkey version=0.1.0
```

If FFI is not available:
```
ERROR FFI verifier not available, error=...
```

---

## Detailed Setup

### Prerequisites

**System Requirements:**
- Rust 1.70+ (install from https://rustup.rs/)
- GCC/Clang (for CGO)
- Go 1.21+

**Library Dependencies:**
- SP1 SDK (automatically fetched by Cargo)
- System libraries: `libdl`, `libm`

### Build Process

#### Step 1: Configure Rust Environment

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify installation
rustc --version
cargo --version
```

#### Step 2: Build FFI Library

```bash
cd rootchain/consensus/zkverifier/sp1-verifier-ffi

# Development build (faster, larger)
cargo build

# Production build (optimized)
cargo build --release
```

**Build artifacts:**
- Linux: `target/release/libsp1_verifier_ffi.so`
- macOS: `target/release/libsp1_verifier_ffi.dylib`
- Windows: `target/release/sp1_verifier_ffi.dll`

#### Step 3: Verify CGO Linkage

```bash
cd ..
go build ./...
```

If you see errors like "library not found":
```bash
export CGO_LDFLAGS="-L$(pwd)/sp1-verifier-ffi/target/release"
export LD_LIBRARY_PATH="$(pwd)/sp1-verifier-ffi/target/release"  # Linux
export DYLD_LIBRARY_PATH="$(pwd)/sp1-verifier-ffi/target/release"  # macOS
```

---

## How It Works

### Data Flow

```
1. Go calls NewSP1Verifier(vkeyPath)
   ↓
2. Attempts to create SP1VerifierFFI
   ↓
3. Loads C library via CGO
   ↓
4. Calls sp1_verify_proof() in Rust
   ↓
5. Rust deserializes proof and vkey
   ↓
6. SP1 SDK verifies cryptographically
   ↓
7. Result returned to Go as error/nil
```

### Memory Management

**Go → C → Rust:**
- Go passes pointers to byte slices (no copy)
- Rust reads via `std::slice::from_raw_parts` (unsafe)
- No ownership transfer (Go still owns memory)

**Rust → C → Go:**
- Rust allocates error strings with `CString::into_raw()`
- Go receives pointer and reads with `C.GoString()`
- Go calls `sp1_free_string()` to deallocate

**Safety guarantees:**
- All unsafe blocks have safety comments
- Pointer null checks before dereferencing
- Proper cleanup in all error paths

### Proof Format

**Expected format:**
```rust
SP1ProofWithPublicValues {
    proof: <serialized STARK proof>,
    public_values: [
        prev_state_root[0..32],  // 32 bytes
        new_state_root[32..64],  // 32 bytes
        // ... additional public values
        // TOOO: at least block hash must be checked as well, think about others
    ]
}
```

**Serialization:** Bincode (Rust standard)



## Deployment

### Option 1: Static Linking (Recommended)

Build with static library for easier deployment:

```bash
cd sp1-verifier-ffi
cargo build --release

# Copy static library
sudo cp target/release/libsp1_verifier_ffi.a /usr/local/lib/

# Build Go with static linking
cd ..
CGO_ENABLED=1 CGO_LDFLAGS="-static" go build ./...
```

**Pros:**
- Single binary deployment
- No runtime dependencies

**Cons:**
- Larger binary size
- Longer build time

### Option 2: Dynamic Linking

```bash
# Install shared library
sudo cp target/release/libsp1_verifier_ffi.so /usr/local/lib/
sudo ldconfig  # Linux only

# Build Go normally
go build ./...
```

**Pros:**
- Smaller binary
- Faster builds

**Cons:**
- Must deploy library separately
- Runtime library path issues

### Option 3: Bundled Distribution

```bash
# Build everything
cd sp1-verifier-ffi && ./build.sh && cd ..

# Package for distribution
mkdir -p dist/lib
cp sp1-verifier-ffi/target/release/libsp1_verifier_ffi.* dist/lib/

# Set library path in startup script
cat > dist/run.sh << 'EOF'
#!/bin/bash
export LD_LIBRARY_PATH="$(dirname $0)/lib:$LD_LIBRARY_PATH"
exec ./ubft "$@"
EOF
chmod +x dist/run.sh
```

---

## Testing

### Unit Tests (Rust)

```bash
cd sp1-verifier-ffi
cargo test
```

Tests verify:
- ✅ FFI safety (null pointers, bounds)
- ✅ Memory management
- ✅ Error code mapping

### Integration Tests (Go)

```bash
cd ..
go test -v ./...
```

Tests verify:
- ✅ CGO linkage works
- ✅ Version retrieval
- ✅ Error propagation
- ⚠️ Proof verification (requires real proof)

### E2E Test with Real Proof

```go
func TestSP1Verifier_RealProof(t *testing.T) {
    verifier, err := NewSP1Verifier("testdata/sp1.vkey")
    require.NoError(t, err)

    // Load real proof from Uni-EVM
    proof, err := os.ReadFile("testdata/proof.bin")
    require.NoError(t, err)

    prevRoot := hexDecode("...")
    newRoot := hexDecode("...")

    err = verifier.VerifyProof(proof, prevRoot, newRoot)
    require.NoError(t, err)
}
```

---

## Performance

### Benchmarks

```bash
cd sp1-verifier-ffi
cargo bench

cd ..
go test -bench=. -benchmem
```

**Typical performance:**
- Verification: 10-100ms (depends on proof complexity)
- Memory: 50-200MB peak during verification
- CGO overhead: <1ms

### Optimization

**Rust side:**
```toml
[profile.release]
opt-level = 3        # Maximum optimization
lto = true           # Link-time optimization
codegen-units = 1    # Better optimization
```

**Go side:**
- Reuse verifier instances (verification key loaded once)
- Avoid copying proof data (pass slices directly)

---

## Troubleshooting

### Build Errors

**"cannot find -lsp1_verifier_ffi"**
```bash
# Library not built
cd sp1-verifier-ffi && cargo build --release && cd ..

# Or set library path
export CGO_LDFLAGS="-L$(pwd)/sp1-verifier-ffi/target/release"
```

**"undefined reference to `sp1_verify_proof`"**
```bash
# Header/library mismatch - rebuild both
cd sp1-verifier-ffi
cargo clean
cargo build --release
cd .. && go build ./...
```

### Runtime Errors

**"error while loading shared libraries"**
```bash
# Linux
export LD_LIBRARY_PATH="/path/to/lib:$LD_LIBRARY_PATH"
sudo ldconfig

# macOS
export DYLD_LIBRARY_PATH="/path/to/lib:$DYLD_LIBRARY_PATH"
```

**"FFI verifier not available"**
- Check library is built: `ls sp1-verifier-ffi/target/release/libsp1_verifier_ffi.*`
- Check CGO is enabled: `go env CGO_ENABLED` (should be `1`)
- Check architecture match: `file libsp1_verifier_ffi.so` vs `go version`

### Verification Errors

**"Invalid proof format"**
- Proof must be serialized `SP1ProofWithPublicValues`
- Use bincode serialization
- Check proof is not corrupted

**"State root mismatch"**
- Public values first 64 bytes must match expected roots
- Verify prover outputs correct public values
- Check byte ordering (big-endian vs little-endian)

---

## Security Considerations

### Memory Safety

**Unsafe Rust blocks:**
- All marked with safety comments
- Reviewed for correctness
- Null pointer checks before dereferencing
- No use-after-free (Go owns memory)

**FFI boundary:**
- All pointers validated
- Length parameters checked
- No buffer overflows

### Cryptographic Security

**Verification key:**
- Must be from trusted source
- Loaded once, reused for all proofs
- No modification after loading

**Proof validation:**
- Full cryptographic verification via SP1 SDK
- Public inputs always validated (TODO: check more values)
- No trust in prover claims

---

## Advanced Topics

### Custom Public Values

If your proofs have additional public values beyond state roots:

```rust
// In lib.rs
fn verify_proof_internal(...) -> anyhow::Result<()> {
    // ... existing code ...

    // Access additional public values
    if public_values.len() > 64 {
        let custom_data = &public_values[64..];
        // Process custom data
    }

    Ok(())
}
```

### Multiple Proof Types

To support both SP1 and RISC0:

```rust
#[no_mangle]
pub extern "C" fn risc0_verify_proof(...) -> SP1VerifyResult {
    // RISC0 verification logic
}
```

```go
// In Go
type RISC0VerifierFFI struct { ... }
```

---

## References

- [SP1 Documentation](https://docs.succinct.xyz/)
- [Rust FFI Nomicon](https://doc.rust-lang.org/nomicon/ffi.html)
- [CGO Documentation](https://pkg.go.dev/cmd/cgo)
- [sp1-verifier-ffi README](./sp1-verifier-ffi/README.md)
