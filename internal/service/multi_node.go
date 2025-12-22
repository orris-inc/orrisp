package service

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/easayliu/orrisp/internal/config"
)

// MultiNodeService manages multiple node services
type MultiNodeService struct {
	config   *config.Config
	services []*NodeService
	logger   *slog.Logger
	mu       sync.RWMutex
}

// NewMultiNodeService creates a new multi-node service manager
func NewMultiNodeService(cfg *config.Config, logger *slog.Logger) (*MultiNodeService, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	instances := cfg.GetNodeInstances()
	if len(instances) == 0 {
		return nil, fmt.Errorf("no node instances configured")
	}

	services := make([]*NodeService, 0, len(instances))
	for _, instance := range instances {
		svc, err := NewNodeService(cfg, instance, logger)
		if err != nil {
			// Clean up already created services
			for _, s := range services {
				_ = s.Stop()
			}
			return nil, fmt.Errorf("failed to create service for node %s: %w", instance.SID, err)
		}
		services = append(services, svc)
	}

	logger.Info("MultiNodeService created",
		slog.Int("node_count", len(services)),
	)

	return &MultiNodeService{
		config:   cfg,
		services: services,
		logger:   logger,
	}, nil
}

// Start starts all node services
func (m *MultiNodeService) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("Starting multi-node service...",
		slog.Int("node_count", len(m.services)),
	)

	var wg sync.WaitGroup
	errChan := make(chan error, len(m.services))

	for _, svc := range m.services {
		wg.Add(1)
		go func(s *NodeService) {
			defer wg.Done()
			if err := s.Start(ctx); err != nil {
				errChan <- err
			}
		}(svc)
	}

	// Wait for all services to start
	wg.Wait()
	close(errChan)

	// Collect errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		// Stop successfully started services
		for _, svc := range m.services {
			_ = svc.Stop()
		}
		return fmt.Errorf("failed to start %d node(s): %v", len(errors), errors[0])
	}

	m.logger.Info("Multi-node service started successfully",
		slog.Int("node_count", len(m.services)),
	)
	return nil
}

// Stop stops all node services
func (m *MultiNodeService) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("Stopping multi-node service...",
		slog.Int("node_count", len(m.services)),
	)

	var wg sync.WaitGroup
	errChan := make(chan error, len(m.services))

	for _, svc := range m.services {
		wg.Add(1)
		go func(s *NodeService) {
			defer wg.Done()
			if err := s.Stop(); err != nil {
				errChan <- err
			}
		}(svc)
	}

	wg.Wait()
	close(errChan)

	// Collect errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		m.logger.Warn("Some nodes failed to stop",
			slog.Int("failed_count", len(errors)),
		)
		return fmt.Errorf("failed to stop %d node(s): %v", len(errors), errors[0])
	}

	m.logger.Info("Multi-node service stopped successfully")
	return nil
}

// GetServices returns all node services
func (m *MultiNodeService) GetServices() []*NodeService {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.services
}

// GetNodeInfo returns information about all nodes
func (m *MultiNodeService) GetNodeInfo() []map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	infos := make([]map[string]interface{}, 0, len(m.services))
	for _, svc := range m.services {
		infos = append(infos, svc.GetNodeInfo())
	}
	return infos
}
