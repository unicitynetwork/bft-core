#!/bin/bash
#
# Build script for the Aggregator ZK Verifier FFI library.
# Uses SP1 6.0.2; independent of sp1-verifier-ffi (SP1 5.0.8).
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Building Aggregator ZK Verifier FFI Library${NC}"
echo "============================================="

if ! command -v cargo &> /dev/null; then
    echo -e "${RED}Error: Rust/Cargo not found${NC}"
    echo "Please install Rust from https://rustup.rs/"
    exit 1
fi

RUST_VERSION=$(cargo --version | cut -d' ' -f2)
echo -e "${GREEN}Rust version: ${RUST_VERSION}${NC}"

echo -e "\n${YELLOW}Building Rust library...${NC}"
cargo build --release

echo -e "${GREEN}✓ Build successful${NC}"

LIB_PATH="target/release"
if [[ "$OSTYPE" == "darwin"* ]]; then
    LIB_FILE="libaggregator_zk_verifier_ffi.dylib"
    STATIC_LIB="libaggregator_zk_verifier_ffi.a"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    LIB_FILE="libaggregator_zk_verifier_ffi.so"
    STATIC_LIB="libaggregator_zk_verifier_ffi.a"
else
    echo -e "${YELLOW}Warning: Unknown OS type, library names may differ${NC}"
    LIB_FILE="libaggregator_zk_verifier_ffi.*"
    STATIC_LIB="libaggregator_zk_verifier_ffi.a"
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

echo -e "\n${YELLOW}Running Rust tests...${NC}"
cargo test

echo -e "${GREEN}✓ All tests passed${NC}"

echo -e "\n${GREEN}Build complete!${NC}"
echo -e "\nTo use with Go:"
echo -e "  export CGO_LDFLAGS=\"-L\$(pwd)/${LIB_PATH}\""
echo -e "  cd .. && go build -tags zkverifier_aggregator_zk_ffi ./..."
