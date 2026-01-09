// Package service provides node service management.
// This file re-exports types from the node subpackage for backward compatibility.
package service

import (
	"context"
	"log/slog"

	"github.com/easayliu/orrisp/internal/config"
	"github.com/easayliu/orrisp/internal/service/node"
)

// NodeService is an alias to node.Service for backward compatibility.
type NodeService = node.Service

// NewNodeService creates a new node service for a specific node instance.
// This is a wrapper around node.New for backward compatibility.
func NewNodeService(cfg *config.Config, nodeInstance config.NodeInstance, logger *slog.Logger) (*NodeService, error) {
	return node.New(cfg, nodeInstance, logger)
}

// SetAgentVersion sets the agent version for status reporting.
func SetAgentVersion(v string) {
	node.SetAgentVersion(v)
}

// MultiNodeService manages multiple node services
type MultiNodeService struct {
	config   *config.Config
	services []*NodeService
	logger   *slog.Logger
}

// NewMultiNodeService creates a new multi-node service manager
func NewMultiNodeService(cfg *config.Config, logger *slog.Logger) (*MultiNodeService, error) {
	if cfg == nil {
		return nil, errConfigNil
	}
	if logger == nil {
		return nil, errLoggerNil
	}

	instances := cfg.GetNodeInstances()
	if len(instances) == 0 {
		return nil, errNoInstances
	}

	services := make([]*NodeService, 0, len(instances))
	for _, instance := range instances {
		svc, err := NewNodeService(cfg, instance, logger)
		if err != nil {
			// Clean up already created services
			for _, s := range services {
				_ = s.Stop()
			}
			return nil, err
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
	return startMultiNode(m, ctx)
}

// Stop stops all node services
func (m *MultiNodeService) Stop() error {
	return stopMultiNode(m)
}

// GetServices returns all node services
func (m *MultiNodeService) GetServices() []*NodeService {
	return getServices(m)
}

// GetNodeInfo returns information about all nodes
func (m *MultiNodeService) GetNodeInfo() []map[string]interface{} {
	return getNodeInfo(m)
}
