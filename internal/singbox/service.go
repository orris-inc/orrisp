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
	reloading   bool // prevents concurrent Reload calls
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
	s.box = nil

	// Cancel context
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}

	// Stop interceptor
	if s.interceptor != nil {
		s.interceptor.Stop()
	}

	return nil
}

// Reload reloads configuration by stopping old instance and starting new one
// Note: This causes a brief service interruption while the port is released and rebound
// If new instance fails to start, attempts to recover with old configuration
// Returns ErrReloadInProgress if another reload is already in progress
func (s *Service) Reload(options *option.Options) error {
	if options == nil {
		return fmt.Errorf("options cannot be nil")
	}

	// Step 1: Check and set reloading flag
	s.mu.Lock()
	if s.reloading {
		s.mu.Unlock()
		return fmt.Errorf("reload already in progress")
	}
	s.reloading = true
	s.mu.Unlock()

	// Ensure reloading flag is cleared when done
	defer func() {
		s.mu.Lock()
		s.reloading = false
		s.mu.Unlock()
	}()

	reloadStart := time.Now()
	if s.logger != nil {
		s.logger.Info("Starting reload...")
	}

	// Step 2: Save old config and close old instance to release the port
	s.mu.Lock()
	oldBox := s.box
	oldCancel := s.cancel
	oldOptions := s.options
	tracker := s.tracker
	s.box = nil
	s.cancel = nil
	s.mu.Unlock()

	if oldBox != nil {
		closeStart := time.Now()
		if err := oldBox.Close(); err != nil {
			if s.logger != nil {
				s.logger.Warn("Error closing old instance", slog.Any("err", err))
			}
		}
		if oldCancel != nil {
			oldCancel()
		}
		if s.logger != nil {
			s.logger.Debug("Old instance closed",
				slog.Duration("close_duration", time.Since(closeStart)),
			)
		}
	}

	// Step 3: Try to start new instance
	newInstance, newCtx, newCancel, err := s.createAndStartInstance(options, tracker)
	if err != nil {
		// Step 4: New instance failed, try to recover with old config
		if oldOptions != nil {
			if s.logger != nil {
				s.logger.Warn("New instance failed, attempting recovery with old config",
					slog.Any("err", err),
				)
			}
			recoveredInstance, recoveredCtx, recoveredCancel, recoverErr := s.createAndStartInstance(oldOptions, tracker)
			if recoverErr != nil {
				// Recovery also failed, service is down
				if s.logger != nil {
					s.logger.Error("Recovery failed, service is down",
						slog.Any("original_err", err),
						slog.Any("recovery_err", recoverErr),
					)
				}
				return fmt.Errorf("reload failed and recovery failed: original: %w, recovery: %v", err, recoverErr)
			}
			// Recovery succeeded
			s.mu.Lock()
			s.box = recoveredInstance
			s.options = oldOptions
			s.ctx = recoveredCtx
			s.cancel = recoveredCancel
			s.mu.Unlock()
			if s.logger != nil {
				s.logger.Info("Recovery succeeded, running with old config")
			}
			return fmt.Errorf("reload failed, recovered with old config: %w", err)
		}
		return fmt.Errorf("failed to start new sing-box instance: %w", err)
	}

	// Step 5: Store new instance
	s.mu.Lock()
	s.box = newInstance
	s.options = options
	s.ctx = newCtx
	s.cancel = newCancel
	s.mu.Unlock()

	if s.logger != nil {
		s.logger.Info("Reload completed",
			slog.Duration("total_duration", time.Since(reloadStart)),
		)
	}

	return nil
}

// createAndStartInstance creates and starts a new sing-box instance
func (s *Service) createAndStartInstance(options *option.Options, tracker *TrafficTracker) (*box.Box, context.Context, context.CancelFunc, error) {
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
		return nil, nil, nil, fmt.Errorf("failed to create instance: %w", err)
	}

	// Register traffic tracker to router if set
	if tracker != nil {
		newInstance.Router().AppendTracker(tracker)
	}

	// Start new instance
	if err := newInstance.Start(); err != nil {
		_ = newInstance.Close()
		newCancel()
		return nil, nil, nil, fmt.Errorf("failed to start instance: %w", err)
	}

	return newInstance, newCtx, newCancel, nil
}
