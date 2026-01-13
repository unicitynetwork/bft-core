# Customizable arguments for Docker build
DOCKER_ARGUMENTS ?=

ifdef DOCKER_GO_DEPENDENCY
	DOCKER_ARGUMENTS += --build-context go-dependency=${DOCKER_GO_DEPENDENCY} --build-arg DOCKER_GO_DEPENDENCY=${DOCKER_GO_DEPENDENCY}
endif

# ZK Verifier FFI configuration
# Set ZKVERIFIER_FFI=1 to enable Rust FFI components (SP1 and light-client verifiers)
# Default: disabled (builds without Rust dependencies)
ZKVERIFIER_FFI ?= 0

# Go build tags based on FFI configuration
ifeq ($(ZKVERIFIER_FFI),1)
	GO_BUILD_TAGS = -tags zkverifier_ffi
	GO_TEST_TAGS = -tags zkverifier_ffi
else
	GO_BUILD_TAGS =
	GO_TEST_TAGS =
endif

# FFI library paths
SP1_VERIFIER_FFI_DIR = rootchain/consensus/zkverifier/sp1-verifier-ffi
LIGHT_CLIENT_VERIFIER_FFI_DIR = rootchain/consensus/zkverifier/light-client-verifier-ffi

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

test:
	go test $(GO_TEST_TAGS) ./... -coverpkg=./... -count=1 -coverprofile test-coverage.out

build:
    # cd to directory where main.go exits, hack fix for go bug to embed version control data
    # https://github.com/golang/go/issues/51279
	cd ./cli/ubft && go build $(GO_BUILD_TAGS) -o ../../build/ubft

# Build with ZK verifier FFI support (requires Rust toolchain)
build-with-ffi: build-rust-ffi
	$(MAKE) build ZKVERIFIER_FFI=1

# Build Rust FFI libraries
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
	build-rust-ffi \
	build-sp1-ffi \
	build-light-client-ffi \
	check-rust \
	build-docker \
	gosec
