package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"gopkg.in/yaml.v3"

	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/keyvaluedb/boltdb"
	"github.com/unicitynetwork/bft-core/logger"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"
)

type (
	LoggerFactory func(cfg *logger.LogConfiguration) (*slog.Logger, error)

	Observability interface {
		Tracer(name string, options ...trace.TracerOption) trace.Tracer
		TracerProvider() trace.TracerProvider
		Meter(name string, opts ...metric.MeterOption) metric.Meter
		PrometheusRegisterer() prometheus.Registerer
		Shutdown() error
		Logger() *slog.Logger
		RoundLogger(func() uint64) *slog.Logger
	}

	baseFlags struct {
		// The home directory
		HomeDir string
		// Configuration file URL. If it's relative, then it's relative from the HomeDir.
		CfgFile string
		// Logger configuration file URL.
		LogCfgFile string

		observe Observability

		partitions map[types.PartitionTypeID]Partition
	}
)

const (
	// The prefix for configuration keys inside environment.
	envPrefix = "UBFT"
	// The default name for config file.
	defaultConfigFile = "config.props"
	// the default directory.
	defaultDir = ".ubft"
	// The default logger configuration file name.
	defaultLoggerConfigFile = "logger-config.yaml"

	// The configuration key for home directory.
	keyHome = "home"
	// The configuration key for config file name.
	keyConfig = "config"
	// Enables or disables metrics collection
	keyMetrics = "metrics"
	keyTracing = "tracing"

	flagNameLoggerCfgFile = "logger-config"
	flagNameLogOutputFile = "log-file"
	flagNameLogLevel      = "log-level"
	flagNameLogFormat     = "log-format"
)

func (r *baseFlags) addBaseFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&r.HomeDir, keyHome, "", fmt.Sprintf("set the UBFT_HOME for this invocation (default is %s)", unicityHomeDir()))
	cmd.PersistentFlags().StringVar(&r.CfgFile, keyConfig, "", fmt.Sprintf("config file URL (default is $UBFT_HOME/%s)", defaultConfigFile))

	cmd.PersistentFlags().String(keyMetrics, "", "metrics exporter, disabled when not set. One of: stdout, prometheus")
	cmd.PersistentFlags().String(keyTracing, "", "traces exporter, disabled when not set. One of: stdout, otlptracehttp, zipkin")

	cmd.PersistentFlags().StringVar(&r.LogCfgFile, flagNameLoggerCfgFile, defaultLoggerConfigFile, "logger config file URL. Considered absolute if starts with '/'. Otherwise relative from $UBFT_HOME.")
	// do not set default values for these flags as then we can easily determine whether to load the value from cfg file or not
	cmd.PersistentFlags().String(flagNameLogOutputFile, "", "log file path or one of the special values: stdout, stderr, discard")
	cmd.PersistentFlags().String(flagNameLogLevel, "", "logging level, one of: DEBUG, INFO, WARN, ERROR")
	cmd.PersistentFlags().String(flagNameLogFormat, "", "log format, one of: text, json, console, ecs")
}

func (r *baseFlags) initConfigFileLocation() {
	// Home directory and config file are special configuration values as these are used for loading in rest of the configuration.
	// Handle these manually, before other configuration loaded with Viper.

	// Home dir is loaded from command line argument. If it's not set, then from env. If that's not set, then default is used.
	if r.HomeDir == "" {
		r.HomeDir = os.Getenv(envKey(keyHome))
		if r.HomeDir == "" {
			r.HomeDir = unicityHomeDir()
		}
	}

	// Config file name is loaded from command line argument. If it's not set, then from env. If that's not set, then default is used.
	if r.CfgFile == "" {
		r.CfgFile = os.Getenv(envKey(keyConfig))
		if r.CfgFile == "" {
			r.CfgFile = defaultConfigFile
		}
	}
	if !filepath.IsAbs(r.CfgFile) {
		r.CfgFile = filepath.Join(r.HomeDir, r.CfgFile)
	}
}

/*
LoggerCfgFilename always returns non-empty filename - either the value
of the flag set by user or default cfg location.
The flag will be assigned the default filename (ie without path) if user
doesn't specify that flag.
*/
func (r *baseFlags) LoggerCfgFilename() string {
	if !filepath.IsAbs(r.LogCfgFile) {
		return filepath.Join(r.HomeDir, r.LogCfgFile)
	}
	return r.LogCfgFile
}

func (r *baseFlags) configFileExists() bool {
	_, err := os.Stat(r.CfgFile)
	return err == nil
}

/*
initLogger creates Logger based on configuration flags in "cmd".
*/
func (r *baseFlags) initLogger(cmd *cobra.Command, loggerBuilder LoggerFactory) (*slog.Logger, error) {
	cfg := &logger.LogConfiguration{}

	loggerCfgFile := filepath.Clean(r.LoggerCfgFilename())
	if f, err := os.Open(loggerCfgFile); err != nil {
		defaultLoggerCfg := filepath.Join(r.HomeDir, defaultLoggerConfigFile)
		if loggerCfgFile != defaultLoggerCfg && !util.FileExists(loggerCfgFile) {
			return nil, fmt.Errorf("opening logger configuration file: %w", err)
		}
	} else {
		if err := yaml.NewDecoder(f).Decode(cfg); err != nil {
			return nil, fmt.Errorf("decoding logger configuration (%s): %w", loggerCfgFile, err)
		}
	}

	getFlagValueIfSet := func(flagName string, value *string) error {
		if cmd.Flags().Changed(flagName) {
			var err error
			if *value, err = cmd.Flags().GetString(flagName); err != nil {
				return fmt.Errorf("failed to read %s flag value: %w", flagName, err)
			}
		}
		return nil
	}

	// flags override values loaded from cfg file.
	// NB! these flags mustn't have default values in Cobra cmd definition!
	if err := getFlagValueIfSet(flagNameLogLevel, &cfg.Level); err != nil {
		return nil, err
	}
	if err := getFlagValueIfSet(flagNameLogFormat, &cfg.Format); err != nil {
		return nil, err
	}
	if err := getFlagValueIfSet(flagNameLogOutputFile, &cfg.OutputPath); err != nil {
		return nil, err
	}

	l, err := loggerBuilder(cfg)
	if err != nil {
		return nil, fmt.Errorf("building logger: %w", err)
	}
	return l, nil
}

func (r *baseFlags) PathWithDefault(path string, defaultFileName string) string {
	if path != "" {
		return path
	}
	return filepath.Join(r.HomeDir, defaultFileName)
}

func (r *baseFlags) loadConf(path string, defaultFileName string, conf any) error {
	path = r.PathWithDefault(path, defaultFileName)
	if _, err := util.ReadJsonFile(path, &conf); err != nil {
		return fmt.Errorf("failed to load %q: %w", path, err)
	}
	return nil
}

func (f *baseFlags) initStore(path string, defaultFileName string) (keyvaluedb.KeyValueDB, error) {
	path = f.PathWithDefault(path, defaultFileName)

	db, err := boltdb.New(path)
	if err != nil {
		return nil, fmt.Errorf("failed to init %q: %w", path, err)
	}
	return db, nil
}

func envKey(key string) string {
	return strings.ToUpper(envPrefix + "_" + key)
}

func unicityHomeDir() string {
	dir, err := os.UserHomeDir()
	if err != nil {
		panic("default user home dir not defined: " + err.Error())
	}
	return filepath.Join(dir, defaultDir)
}
