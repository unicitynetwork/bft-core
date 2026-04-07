# Build

Run `make build` to build the application. Executable will be built to `build/ubft`.

### Build dependencies

* [`Go`](https://go.dev/doc/install) version 1.24.
* `C` compiler, recent versions of [GCC](https://gcc.gnu.org/) are recommended. In Debian and Ubuntu repositories, GCC is part of the build-essential package. On macOS, GCC can be installed with [Homebrew](https://formulae.brew.sh/formula/gcc).

### Build targets

| Target | Description |
|--------|-------------|
| `make build` | Build without FFI (default, no Rust required) |
| `make build-with-ffi` | Build with SP1 + Light Client FFI verifiers |
| `make build-with-aggregator-zk-ffi` | Build with aggregator ZK verifier FFI (SP1 6.0.2) |
| `make build-with-all-ffi` | Build with all FFI verifiers enabled |
| `make build-rust-ffi` | Build SP1 + Light Client Rust FFI libraries only |
| `make build-aggregator-zk-ffi` | Build aggregator ZK verifier Rust FFI library only |
| `make build-sp1-ffi` | Build SP1 verifier FFI library only |
| `make build-light-client-ffi` | Build Light Client verifier FFI library only |
| `make clean-ffi` | Clean all Rust FFI build artifacts |
| `make check-rust` | Verify Rust toolchain is available |


# Configuration

It's possible to define the configuration values from (in the order of precedence):

* Command line flags (e.g. `--address="/ip4/127.0.0.1/tcp/26652"`)
* Environment (Prefix 'UBFT' must be used. E.g. `UBFT_ADDRESS="/ip4/127.0.0.1/tcp/26652"`)
* Configuration file (properties file) (E.g. `address="/ip4/127.0.0.1/tcp/26652"`)
* Default values

The default location of configuration file is `$UBFT_HOME/config.props`

The default `$UBFT_HOME` is `$HOME/.ubft`

## Logging configuration

Logging can be configured through a yaml configuration file. See [logger-config.yaml](cli/ubft/config/logger-config.yaml) for example.

Default location of the logger configuration file is `$UBFT_HOME/logger-config.yaml`

The location can be changed through `--logger-config` configuration key. If it's relative URL, then it's relative
to `$UBFT_HOME`. Some logging related parameters can be set via command line parameters too - run `ubft -h`
for more.

See [logging.md](./docs/logging.md) for information about log schema.

# Distributed Tracing

To enable tracing environment variable `UBFT_TRACING` (or command line flag `--tracing`) has
to be set to one of the supported exporter names: `stdout`, `otlptracehttp` or `zipkin`.

Exporter can be further configured using
[General SDK Configuration](https://opentelemetry.io/docs/concepts/sdk-configuration/general-sdk-configuration/)
and exporter specific
[OpenTelemetry Protocol Exporter](https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/protocol/exporter.md)
environment variables.
Exceptions are:

- instead of `OTEL_TRACES_EXPORTER` and `OTEL_METRICS_EXPORTER` we use specific
  environment variables (ie `UBFT_TRACING`) or command line flags to select the exporter;
- propagators are set (`OTEL_PROPAGATORS`)  to “tracecontext,baggage”;
- `OTEL_SERVICE_NAME` is set based on "best guess" of current binary's role

## Tracing tests

To enable trace exporter for test the `UBFT_TEST_TRACER` environment variable has to be set
to desired exporter name, ie

```sh
UBFT_TEST_TRACER=otlptracehttp go test ./...
```

The test tracing will pick up the same OTEL environment variables linked above except that
some parameters are already "hardcoded":

- "always_on" sampler is used (`OTEL_TRACES_SAMPLER`);
- the `otlptracehttp` exporter is created with "insecure client transport"
  (`OTEL_EXPORTER_OTLP_INSECURE`);

# Set up autocompletion

To use autocompletion (supported with `bash`, `fish`, `powershell` and `zsh`), run the following commands after
building (this is `bash` example):

* `./ubft completion bash > /tmp/completion`
* `source /tmp/completion`

# CI setup

# Build Docker image with local dependencies

For example, if go.work is defined as follows:

```plain
go 1.23.2

use (
    .
    ../bft-go-base
)
```

The folder can add be added into Docker build context by specifying it as follow:

```console
DOCKER_GO_DEPENDENCY=../bft-go-base make build-docker
```
