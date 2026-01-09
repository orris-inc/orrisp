package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

var (
	errConfigNil   = errors.New("config cannot be nil")
	errLoggerNil   = errors.New("logger cannot be nil")
	errNoInstances = errors.New("no node instances configured")
)

// startMultiNode starts all node services
func startMultiNode(m *MultiNodeService, ctx context.Context) error {
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
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		// Stop successfully started services
		for _, svc := range m.services {
			_ = svc.Stop()
		}
		return fmt.Errorf("failed to start %d node(s): %v", len(errs), errs[0])
	}

	m.logger.Info("Multi-node service started successfully",
		slog.Int("node_count", len(m.services)),
	)
	return nil
}

// stopMultiNode stops all node services
func stopMultiNode(m *MultiNodeService) error {
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
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		m.logger.Warn("Some nodes failed to stop",
			slog.Int("failed_count", len(errs)),
		)
		return fmt.Errorf("failed to stop %d node(s): %v", len(errs), errs[0])
	}

	m.logger.Info("Multi-node service stopped successfully")
	return nil
}

// getServices returns all node services
func getServices(m *MultiNodeService) []*NodeService {
	return m.services
}

// getNodeInfo returns information about all nodes
func getNodeInfo(m *MultiNodeService) []map[string]interface{} {
	infos := make([]map[string]interface{}, 0, len(m.services))
	for _, svc := range m.services {
		infos = append(infos, svc.GetNodeInfo())
	}
	return infos
}
