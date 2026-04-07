# Customizable arguments for Docker build
DOCKER_ARGUMENTS ?=

ifdef DOCKER_GO_DEPENDENCY
	DOCKER_ARGUMENTS += --build-context go-dependency=${DOCKER_GO_DEPENDENCY} --build-arg DOCKER_GO_DEPENDENCY=${DOCKER_GO_DEPENDENCY}
endif

# ZK Verifier FFI configuration
# Set ZKVERIFIER_FFI=1 to enable Rust FFI components (SP1 and light-client verifiers)
# Set ZKVERIFIER_AGGREGATOR_ZK_FFI=1 to enable the aggregator ZK verifier FFI (SP1 6.0.2)
# Default: all disabled (builds without Rust dependencies)
ZKVERIFIER_FFI ?= 0
ZKVERIFIER_AGGREGATOR_ZK_FFI ?= 0

# Accumulate Go build tags
GO_BUILD_TAGS_LIST =
GO_TEST_TAGS_LIST  =

ifeq ($(ZKVERIFIER_FFI),1)
	GO_BUILD_TAGS_LIST += zkverifier_ffi
	GO_TEST_TAGS_LIST  += zkverifier_ffi
endif

ifeq ($(ZKVERIFIER_AGGREGATOR_ZK_FFI),1)
	GO_BUILD_TAGS_LIST += zkverifier_aggregator_zk_ffi
	GO_TEST_TAGS_LIST  += zkverifier_aggregator_zk_ffi
endif

ifneq ($(strip $(GO_BUILD_TAGS_LIST)),)
	GO_BUILD_TAGS = -tags $(subst $(space),$(comma),$(strip $(GO_BUILD_TAGS_LIST)))
	GO_TEST_TAGS  = -tags $(subst $(space),$(comma),$(strip $(GO_TEST_TAGS_LIST)))
else
	GO_BUILD_TAGS =
	GO_TEST_TAGS  =
endif

comma = ,
space = $(empty) $(empty)

# FFI library paths
SP1_VERIFIER_FFI_DIR           = rootchain/consensus/zkverifier/sp1-verifier-ffi
LIGHT_CLIENT_VERIFIER_FFI_DIR  = rootchain/consensus/zkverifier/light-client-verifier-ffi
AGGREGATOR_ZK_VERIFIER_FFI_DIR = rootchain/consensus/zkverifier/aggregator-zk-verifier-ffi

all: clean tools test build gosec

clean:
	rm -rf build/
	rm -rf test-nodes/

clean-ffi:
	@if [ -d "$(SP1_VERIFIER_FFI_DIR)" ]; then \
		cd $(SP1_VERIFIER_FFI_DIR) && cargo clean; \
	fi
	@if [ -d "$(LIGHT_CLIENT_VERIFIER_FFI_DIR)" ]; then \
		cd $(LIGHT_CLIENT_VERIFIER_FFI_DIR) && cargo clean; \
	fi
	@if [ -d "$(AGGREGATOR_ZK_VERIFIER_FFI_DIR)" ]; then \
		cd $(AGGREGATOR_ZK_VERIFIER_FFI_DIR) && cargo clean; \
	fi

test:
	go test $(GO_TEST_TAGS) ./... -coverpkg=./... -count=1 -coverprofile test-coverage.out

build:
    # cd to directory where main.go exits, hack fix for go bug to embed version control data
    # https://github.com/golang/go/issues/51279
	cd ./cli/ubft && go build $(GO_BUILD_TAGS) -o ../../build/ubft

# Build with ZK verifier FFI support (SP1 + light-client, requires Rust toolchain)
build-with-ffi: build-rust-ffi
	$(MAKE) build ZKVERIFIER_FFI=1

# Build with aggregator ZK verifier FFI support only (SP1 6.0.2, requires Rust toolchain)
build-with-aggregator-zk-ffi: build-aggregator-zk-ffi
	$(MAKE) build ZKVERIFIER_AGGREGATOR_ZK_FFI=1

# Build with all FFI verifiers enabled
build-with-all-ffi: build-rust-ffi build-aggregator-zk-ffi
	$(MAKE) build ZKVERIFIER_FFI=1 ZKVERIFIER_AGGREGATOR_ZK_FFI=1

# Build all Rust FFI libraries (SP1 + light-client)
build-rust-ffi: check-rust build-sp1-ffi build-light-client-ffi

build-sp1-ffi:
	@echo "Building SP1 verifier FFI..."
	@if [ -d "$(SP1_VERIFIER_FFI_DIR)" ]; then \
		cd $(SP1_VERIFIER_FFI_DIR) && cargo build --release; \
	else \
		echo "Warning: $(SP1_VERIFIER_FFI_DIR) not found"; \
	fi

build-light-client-ffi:
	@echo "Building Light Client verifier FFI..."
	@if [ -d "$(LIGHT_CLIENT_VERIFIER_FFI_DIR)" ]; then \
		cd $(LIGHT_CLIENT_VERIFIER_FFI_DIR) && cargo build --release; \
	else \
		echo "Warning: $(LIGHT_CLIENT_VERIFIER_FFI_DIR) not found"; \
	fi

build-aggregator-zk-ffi: check-rust
	@echo "Building Aggregator ZK verifier FFI (SP1 6.0.2)..."
	@if [ -d "$(AGGREGATOR_ZK_VERIFIER_FFI_DIR)" ]; then \
		cd $(AGGREGATOR_ZK_VERIFIER_FFI_DIR) && cargo build --release; \
	else \
		echo "Warning: $(AGGREGATOR_ZK_VERIFIER_FFI_DIR) not found"; \
	fi

# Check if Rust toolchain is available
check-rust:
	@command -v cargo >/dev/null 2>&1 || { \
		echo "Error: Rust toolchain not found. Install from https://rustup.rs"; \
		exit 1; \
	}
	@echo "Rust toolchain found: $$(rustc --version)"

build-docker:
	docker build ${DOCKER_ARGUMENTS} --file scripts/Dockerfile --tag unicity-bft:local .

gosec:
	gosec -exclude-generated ./...

tools:
	go install github.com/securego/gosec/v2/cmd/gosec@latest

.PHONY: \
	all \
	clean \
	clean-ffi \
	tools \
	test \
	build \
	build-with-ffi \
	build-with-aggregator-zk-ffi \
	build-with-all-ffi \
	build-rust-ffi \
	build-sp1-ffi \
	build-light-client-ffi \
	build-aggregator-zk-ffi \
	check-rust \
	build-docker \
	gosec
