package singbox

import (
	"context"
	"fmt"
	"sync"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"go.uber.org/zap"
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
}

// NewService creates sing-box service instance
func NewService(options *option.Options, logger *zap.Logger) (*Service, error) {
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

// Reload reloads configuration
// Implements configuration reload by closing current instance and creating new instance with new config
func (s *Service) Reload(options *option.Options) error {
	if options == nil {
		return fmt.Errorf("options cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Close current instance (don't use Close method to avoid double locking)
	if s.box != nil {
		if err := s.box.Close(); err != nil {
			return fmt.Errorf("failed to close current instance: %w", err)
		}
	}

	// Cancel old context
	if s.cancel != nil {
		s.cancel()
	}

	// Create new context with registries
	ctx, cancel := context.WithCancel(context.Background())
	ctx = include.Context(ctx)

	// Create new instance
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: *options,
	})
	if err != nil {
		cancel()
		return fmt.Errorf("failed to create new sing-box instance: %w", err)
	}

	// Register traffic tracker to router if set
	if s.tracker != nil {
		instance.Router().AppendTracker(s.tracker)
	}

	// Start new instance
	if err := instance.Start(); err != nil {
		cancel()
		return fmt.Errorf("failed to start new sing-box instance: %w", err)
	}

	// Update service state
	s.box = instance
	s.options = options
	s.ctx = ctx
	s.cancel = cancel

	return nil
}
