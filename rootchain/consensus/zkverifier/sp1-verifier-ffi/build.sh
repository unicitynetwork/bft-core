#!/bin/bash
#
# Build script for SP1 Verifier FFI library
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Building SP1 Verifier FFI Library${NC}"
echo "====================================="

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}Error: Rust/Cargo not found${NC}"
    echo "Please install Rust from https://rustup.rs/"
    exit 1
fi

# Check Rust version
RUST_VERSION=$(cargo --version | cut -d' ' -f2)
echo -e "${GREEN}Rust version: ${RUST_VERSION}${NC}"

# Build the library
echo -e "\n${YELLOW}Building Rust library...${NC}"
cargo build --release

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi

# Check build artifacts
LIB_PATH="target/release"
if [[ "$OSTYPE" == "darwin"* ]]; then
    LIB_FILE="libsp1_verifier_ffi.dylib"
    STATIC_LIB="libsp1_verifier_ffi.a"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    LIB_FILE="libsp1_verifier_ffi.so"
    STATIC_LIB="libsp1_verifier_ffi.a"
else
    echo -e "${YELLOW}Warning: Unknown OS type, library names may differ${NC}"
    LIB_FILE="libsp1_verifier_ffi.*"
    STATIC_LIB="libsp1_verifier_ffi.a"
fi

echo -e "\n${YELLOW}Build artifacts:${NC}"
if [ -f "${LIB_PATH}/${LIB_FILE}" ]; then
    ls -lh "${LIB_PATH}/${LIB_FILE}"
    echo -e "${GREEN}✓ Dynamic library created${NC}"
else
    echo -e "${RED}✗ Dynamic library not found${NC}"
fi

if [ -f "${LIB_PATH}/${STATIC_LIB}" ]; then
    ls -lh "${LIB_PATH}/${STATIC_LIB}"
    echo -e "${GREEN}✓ Static library created${NC}"
else
    echo -e "${YELLOW}⚠ Static library not found (optional)${NC}"
fi

# Run tests
echo -e "\n${YELLOW}Running Rust tests...${NC}"
cargo test

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed${NC}"
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi

echo -e "\n${GREEN}Build complete!${NC}"
echo -e "\nTo use this library with Go:"
echo -e "  1. Set CGO_LDFLAGS to point to ${LIB_PATH}"
echo -e "  2. Run: go test ./... in the parent directory"
echo -e "\nExample:"
echo -e "  export CGO_LDFLAGS=\"-L$(pwd)/${LIB_PATH}\""
echo -e "  cd .. && go test -v"
