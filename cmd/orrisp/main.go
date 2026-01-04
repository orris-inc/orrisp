package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/easayliu/orrisp/internal/config"
	"github.com/easayliu/orrisp/internal/service"
)

var (
	version   = "dev"
	buildTime = "unknown"

	showVersion = flag.Bool("v", false, "show version and exit")
)

func main() {
	// Parse flags early to check for -v
	flag.Parse()

	// Handle -v flag
	if *showVersion {
		fmt.Printf("orrisp version %s (built %s)\n", version, buildTime)
		return
	}

	// Print version information
	fmt.Printf("Orrisp Node Agent\n")
	fmt.Printf("Version: %s\n", version)
	fmt.Printf("Build Time: %s\n\n", buildTime)

	// Set agent version for status reporting
	service.SetAgentVersion(version)

	// Load configuration from CLI flags or config file
	cfg, err := config.LoadFromCLI()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	logger, logFile, err := initLogger(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	if logFile != nil {
		defer logFile.Close()
	}

	// Get node instances
	instances := cfg.GetNodeInstances()
	logger.Info("configuration loaded",
		slog.String("config_path", cfg.Path),
		slog.String("api_base_url", cfg.API.BaseURL),
		slog.Int("node_count", len(instances)),
	)

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create and start multi-node service
	multiNodeService, err := service.NewMultiNodeService(cfg, logger)
	if err != nil {
		logger.Error("failed to create multi-node service", errAttr(err))
		os.Exit(1)
	}

	// Start all node services
	if err := multiNodeService.Start(ctx); err != nil {
		logger.Error("failed to start multi-node service", errAttr(err))
		os.Exit(1)
	}

	// Wait for signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	logger.Info("service started",
		slog.Int("node_count", len(instances)),
	)

	// Block waiting for signal
	sig := <-sigChan
	logger.Info("received shutdown signal", slog.String("signal", sig.String()))

	// Cancel context
	cancel()

	// Stop all services
	if err := multiNodeService.Stop(); err != nil {
		logger.Error("failed to stop multi-node service", errAttr(err))
		os.Exit(1)
	}

	logger.Info("service stopped gracefully")
}

// errAttr creates a standardized error attribute for slog
// Best practice: use consistent key name "err" for errors
func errAttr(err error) slog.Attr {
	return slog.Any("err", err)
}

// initLogger initializes the slog logger following best practices:
// - JSON format for production (machine-readable, easy to parse)
// - Text format for development (human-readable)
// - Consistent timestamp format (RFC3339)
// - Service metadata in every log entry
func initLogger(cfg *config.Config) (*slog.Logger, *os.File, error) {
	// Parse log level
	var level slog.Level
	switch cfg.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	// Configure output
	var writer io.Writer
	var logFile *os.File
	if cfg.Log.Output == "stdout" || cfg.Log.Output == "" {
		writer = os.Stdout
	} else {
		var err error
		logFile, err = os.OpenFile(cfg.Log.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open log file: %w", err)
		}
		writer = logFile
	}

	// Handler options with custom attribute replacement
	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Use RFC3339 format for timestamps
			if a.Key == slog.TimeKey {
				if t, ok := a.Value.Any().(time.Time); ok {
					a.Value = slog.StringValue(t.Format(time.RFC3339))
				}
			}
			// Shorten level key values for JSON
			if a.Key == slog.LevelKey {
				if lvl, ok := a.Value.Any().(slog.Level); ok {
					a.Value = slog.StringValue(lvl.String())
				}
			}
			return a
		},
	}

	// Create handler based on format
	var handler slog.Handler
	if cfg.Log.Format == "text" {
		handler = slog.NewTextHandler(writer, opts)
	} else {
		// Default to JSON format (best practice for production)
		handler = slog.NewJSONHandler(writer, opts)
	}

	// Add service metadata to all log entries
	logger := slog.New(handler).With(
		slog.String("service", "orrisp"),
		slog.String("version", version),
	)

	// Set as default logger for standard library compatibility
	slog.SetDefault(logger)

	return logger, logFile, nil
}
