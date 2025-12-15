package singbox

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

// Service sing-box service wrapper, provides start, stop and reload configuration functionality
// Thread-safe, methods can be called concurrently
type Service struct {
	mu          sync.RWMutex
	box         *box.Box
	options     *option.Options
	ctx         context.Context
	cancel      context.CancelFunc
	interceptor *StderrInterceptor
	tracker     *TrafficTracker
	logger      *slog.Logger
}

// NewService creates sing-box service instance
func NewService(options *option.Options, logger *slog.Logger) (*Service, error) {
	if options == nil {
		return nil, fmt.Errorf("options cannot be nil")
	}

	// Create stderr interceptor to capture sing-box logs
	var interceptor *StderrInterceptor
	if logger != nil {
		var err error
		interceptor, err = NewStderrInterceptor(logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create stderr interceptor: %w", err)
		}
		interceptor.Start()
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Register sing-box protocol registries
	ctx = include.Context(ctx)

	// Create sing-box instance
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: *options,
	})
	if err != nil {
		if interceptor != nil {
			interceptor.Stop()
		}
		cancel()
		return nil, fmt.Errorf("failed to create sing-box instance: %w", err)
	}

	return &Service{
		box:         instance,
		options:     options,
		ctx:         ctx,
		cancel:      cancel,
		interceptor: interceptor,
		logger:      logger,
	}, nil
}

// SetTracker sets the traffic tracker for the service
func (s *Service) SetTracker(tracker *TrafficTracker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tracker = tracker
}

// Start starts sing-box service
func (s *Service) Start() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.box == nil {
		return fmt.Errorf("sing-box instance not initialized")
	}

	// Register traffic tracker to router if set
	if s.tracker != nil {
		s.box.Router().AppendTracker(s.tracker)
	}

	// Start sing-box
	if err := s.box.Start(); err != nil {
		return fmt.Errorf("failed to start sing-box: %w", err)
	}

	return nil
}

// Close closes sing-box service
func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.box == nil {
		return nil
	}

	// Close sing-box
	if err := s.box.Close(); err != nil {
		return fmt.Errorf("failed to close sing-box: %w", err)
	}

	// Cancel context
	if s.cancel != nil {
		s.cancel()
	}

	// Stop interceptor
	if s.interceptor != nil {
		s.interceptor.Stop()
	}

	return nil
}

// Reload reloads configuration with graceful instance swap
// Implements zero-downtime reload by creating new instance first, then swapping
func (s *Service) Reload(options *option.Options) error {
	if options == nil {
		return fmt.Errorf("options cannot be nil")
	}

	reloadStart := time.Now()
	if s.logger != nil {
		s.logger.Info("Starting graceful reload...")
	}

	// Step 1: Create new instance WITHOUT holding lock
	// This is the most time-consuming operation and doesn't need to block traffic
	createStart := time.Now()

	// Create new context with registries
	newCtx, newCancel := context.WithCancel(context.Background())
	newCtx = include.Context(newCtx)

	// Create new instance
	newInstance, err := box.New(box.Options{
		Context: newCtx,
		Options: *options,
	})
	if err != nil {
		newCancel()
		return fmt.Errorf("failed to create new sing-box instance: %w", err)
	}

	if s.logger != nil {
		s.logger.Debug("New instance created",
			slog.Duration("create_duration", time.Since(createStart)),
		)
	}

	// Step 2: Register tracker and start new instance (still no lock)
	startStart := time.Now()

	// Get tracker under read lock
	s.mu.RLock()
	tracker := s.tracker
	s.mu.RUnlock()

	// Register traffic tracker to router if set
	if tracker != nil {
		newInstance.Router().AppendTracker(tracker)
	}

	// Start new instance
	if err := newInstance.Start(); err != nil {
		newCancel()
		return fmt.Errorf("failed to start new sing-box instance: %w", err)
	}

	if s.logger != nil {
		s.logger.Debug("New instance started",
			slog.Duration("start_duration", time.Since(startStart)),
		)
	}

	// Step 3: Quick swap - MINIMAL lock time
	// This is the only operation that blocks incoming connections
	swapStart := time.Now()

	s.mu.Lock()
	oldBox := s.box
	oldCancel := s.cancel

	s.box = newInstance
	s.options = options
	s.ctx = newCtx
	s.cancel = newCancel
	s.mu.Unlock()

	if s.logger != nil {
		s.logger.Debug("Instance swap completed",
			slog.Duration("swap_duration", time.Since(swapStart)),
		)
	}

	// Step 4: Gracefully shutdown old instance in background
	// Give existing connections time to complete
	if oldBox != nil {
		go s.gracefulShutdown(oldBox, oldCancel)
	}

	if s.logger != nil {
		s.logger.Info("Graceful reload completed",
			slog.Duration("total_duration", time.Since(reloadStart)),
		)
	}

	return nil
}

// gracefulShutdown closes old instance with grace period for existing connections
func (s *Service) gracefulShutdown(oldBox *box.Box, oldCancel context.CancelFunc) {
	shutdownTimeout := 30 * time.Second

	if s.logger != nil {
		s.logger.Debug("Starting graceful shutdown of old instance",
			slog.Duration("timeout", shutdownTimeout),
		)
	}

	// Wait briefly for existing connections to finish
	time.Sleep(5 * time.Second)

	// Close old instance
	if err := oldBox.Close(); err != nil {
		if s.logger != nil {
			s.logger.Warn("Error closing old instance", slog.Any("err", err))
		}
	}

	// Cancel old context
	if oldCancel != nil {
		oldCancel()
	}

	if s.logger != nil {
		s.logger.Debug("Old instance shutdown completed")
	}
}
