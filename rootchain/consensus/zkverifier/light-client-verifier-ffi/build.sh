#!/bin/bash

# Build script for light-client-verifier-ffi
# This builds the Rust FFI library that BFT Core uses to verify light client proofs

set -e

echo "Building light-client-verifier-ffi..."

# Build in release mode for optimal performance
cargo build --release

echo "Build complete!"
echo "Library: target/release/liblight_client_verifier_ffi.a"
echo "         target/release/liblight_client_verifier_ffi.so (Linux)"
echo "         target/release/liblight_client_verifier_ffi.dylib (macOS)"
