package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/easayliu/orrisp/internal/config"
	"github.com/easayliu/orrisp/internal/service"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	// Print version information
	fmt.Printf("Orrisp Node Agent\n")
	fmt.Printf("Version: %s\n", version)
	fmt.Printf("Build Time: %s\n\n", buildTime)

	// Load configuration from CLI flags or config file
	cfg, err := config.LoadFromCLI()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	logger, err := initLogger(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	// Get node instances
	instances := cfg.GetNodeInstances()
	logger.Info("Configuration loaded successfully",
		zap.String("api_base_url", cfg.API.BaseURL),
		zap.Int("node_count", len(instances)),
	)

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create and start multi-node service
	multiNodeService, err := service.NewMultiNodeService(cfg, logger)
	if err != nil {
		logger.Fatal("Failed to create multi-node service", zap.Error(err))
	}

	// Start all node services
	if err := multiNodeService.Start(ctx); err != nil {
		logger.Fatal("Failed to start multi-node service", zap.Error(err))
	}

	// Wait for signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	logger.Info("Node service is running, press Ctrl+C to exit...",
		zap.Int("node_count", len(instances)),
	)

	// Block waiting for signal
	sig := <-sigChan
	logger.Info("Received shutdown signal", zap.String("signal", sig.String()))

	// Cancel context
	cancel()

	// Stop all services
	if err := multiNodeService.Stop(); err != nil {
		logger.Error("Failed to stop multi-node service", zap.Error(err))
		os.Exit(1)
	}

	logger.Info("Node service has been gracefully shut down")
}

// initLogger initializes the logger
func initLogger(cfg *config.Config) (*zap.Logger, error) {
	// Parse log level
	var level zapcore.Level
	switch cfg.Log.Level {
	case "debug":
		level = zapcore.DebugLevel
	case "info":
		level = zapcore.InfoLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	default:
		level = zapcore.InfoLevel
	}

	// Configure encoder
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder, // Colorized log level
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Configure output
	var writer zapcore.WriteSyncer
	if cfg.Log.Output == "stdout" || cfg.Log.Output == "" {
		writer = zapcore.AddSync(os.Stdout)
	} else {
		// Output to file
		file, err := os.OpenFile(cfg.Log.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		writer = zapcore.AddSync(file)
		// If output to file, don't use colorized encoding
		encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	}

	// Create core
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		writer,
		level,
	)

	// Create logger
	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(0))

	return logger, nil
}
