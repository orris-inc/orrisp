// Package node provides the main NodeService implementation for managing proxy nodes.
package node

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/easayliu/orrisp/internal/api"
	"github.com/easayliu/orrisp/internal/config"
	"github.com/easayliu/orrisp/internal/singbox"
	"github.com/easayliu/orrisp/internal/stats"
)

// Node status constants define the operational status from the server.
const (
	nodeStatusActive      = "active"      // Normal operation
	nodeStatusInactive    = "inactive"    // Node should not serve traffic
	nodeStatusMaintenance = "maintenance" // Node is under maintenance
)

// Package-level version variable, set by main package (atomic for concurrent access)
var agentVersion atomic.Value

func init() {
	agentVersion.Store("dev")
}

// SetAgentVersion sets the agent version for status reporting.
func SetAgentVersion(v string) {
	agentVersion.Store(v)
}

// getAgentVersion returns the current agent version.
func getAgentVersion() string {
	return agentVersion.Load().(string)
}

// Service is the main node service that manages proxy operations.
// It handles user synchronization, sing-box management, and Hub connections.
type Service struct {
	config         *config.Config
	nodeInstance   config.NodeInstance // Node instance configuration
	apiClient      *api.Client
	hubClient      *api.HubClient // WebSocket Hub client
	singboxService *singbox.Service
	statsClient    *stats.Client
	trafficTracker *singbox.TrafficTracker
	logger         *slog.Logger

	mu           sync.RWMutex
	nodeConfig   *api.NodeConfig
	nodeStatus   string // Current node status from server (active, inactive, maintenance)
	currentUsers []api.Subscription
	startTime    time.Time
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup

	// Serializes sing-box start/reload operations to prevent concurrent access
	singboxMu sync.Mutex

	// Serializes config reload pipelines (fetch→sync→reload) to prevent
	// concurrent pipelines from overwriting each other's results
	configMu sync.Mutex

	// Hub connection state
	hubConnected       bool
	hubDisconnect      chan struct{} // Signal when hub disconnects (broadcast via close)
	hubDisconnectOnce  *sync.Once    // Ensures hubDisconnect is closed exactly once per connection

	// TLS certificate (auto-generated if not configured)
	certMu  sync.Mutex // protects cert fields below
	certSNI string     // SNI for current self-signed cert; empty if using configured paths
	certPath string
	keyPath  string

	// Cached public IP addresses
	cachedPublicIPv4 string
	cachedPublicIPv6 string
	lastIPCheck      time.Time // Last time public IP was checked
}

// New creates a new node service for a specific node instance
func New(cfg *config.Config, nodeInstance config.NodeInstance, logger *slog.Logger) (*Service, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	// Create logger with node SID context
	nodeLogger := logger.With(slog.String("node_sid", nodeInstance.SID))

	// Create API client with functional options
	apiClient, err := api.NewClient(
		cfg.API.BaseURL,
		nodeInstance.Token,
		nodeInstance.SID,
		api.WithTimeout(cfg.GetAPITimeout()),
	)
	if err != nil {
		return nil, fmt.Errorf("create api client: %w", err)
	}

	// Create traffic statistics client
	statsClient := stats.NewClient()

	// Create traffic tracker for sing-box
	trafficTracker := singbox.NewTrafficTracker(statsClient, nodeLogger)

	return &Service{
		config:         cfg,
		nodeInstance:   nodeInstance,
		apiClient:      apiClient,
		statsClient:    statsClient,
		trafficTracker: trafficTracker,
		logger:         nodeLogger,
		nodeStatus:     nodeStatusActive,
		startTime:      time.Now(),
	}, nil
}

// Start starts the node service
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return fmt.Errorf("service is already running")
	}

	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	s.logger.Info("Starting node service...")

	// Helper to clean up state on failure
	cleanupOnFailure := func() {
		s.mu.Lock()
		if s.cancel != nil {
			s.cancel()
			s.cancel = nil
		}
		s.mu.Unlock()
	}

	// 1. Get node configuration
	if err := s.fetchNodeConfig(); err != nil {
		cleanupOnFailure()
		return fmt.Errorf("failed to fetch node config: %w", err)
	}

	// 2. Get user list
	if _, err := s.syncUsers(); err != nil {
		cleanupOnFailure()
		return fmt.Errorf("failed to sync users: %w", err)
	}

	// 3. Start sing-box
	s.singboxMu.Lock()
	err := s.startSingbox()
	s.singboxMu.Unlock()
	if err != nil {
		cleanupOnFailure()
		return fmt.Errorf("failed to start sing-box: %w", err)
	}

	// 4. Connect to Hub (WebSocket) or start REST fallback
	if s.config.IsHubEnabled() {
		s.wg.Add(1)
		go s.hubConnectionLoop()
	} else {
		// Hub disabled, use REST polling only
		s.startScheduledTasks()
	}

	s.logger.Info("Node service started successfully")
	return nil
}

// Stop stops the node service
func (s *Service) Stop() error {
	s.mu.Lock()
	if s.cancel == nil {
		s.mu.Unlock()
		return nil
	}

	s.logger.Info("Stopping node service...")
	s.cancel()
	s.cancel = nil
	hubClient := s.hubClient
	s.hubClient = nil
	s.mu.Unlock()

	// Close Hub connection with timeout to avoid blocking on lock contention
	// (Connect() may hold the lock during WebSocket dial)
	if hubClient != nil {
		closeDone := make(chan struct{})
		go func() {
			if err := hubClient.Close(); err != nil {
				s.logger.Error("Failed to close hub connection", slog.Any("err", err))
			}
			close(closeDone)
		}()

		select {
		case <-closeDone:
			s.logger.Debug("Hub connection closed")
		case <-time.After(3 * time.Second):
			s.logger.Warn("Hub close timed out, proceeding with shutdown")
		}
	}

	// Wait for all goroutines to exit with timeout
	wgDone := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(wgDone)
	}()

	select {
	case <-wgDone:
		s.logger.Debug("All goroutines exited")
	case <-time.After(5 * time.Second):
		s.logger.Warn("Goroutine wait timed out, forcing shutdown")
	}

	// Stop sing-box
	s.singboxMu.Lock()
	svc := s.singboxService
	s.singboxService = nil
	s.singboxMu.Unlock()
	if svc != nil {
		if err := svc.Close(); err != nil {
			s.logger.Error("Failed to stop sing-box", slog.Any("err", err))
		}
	}

	s.logger.Info("Node service stopped")
	return nil
}

// isNodeInactive returns true if the node is not in active status.
func (s *Service) isNodeInactive() bool {
	s.mu.RLock()
	status := s.nodeStatus
	s.mu.RUnlock()
	return status != nodeStatusActive
}

// cancelService safely cancels the service context with lock protection.
// This prevents nil pointer panic when called concurrently with Stop().
func (s *Service) cancelService() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
}

// GetNodeInfo gets node information (for debugging)
func (s *Service) GetNodeInfo() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	info := map[string]interface{}{
		"uptime": time.Since(s.startTime).String(),
	}

	if s.nodeConfig != nil {
		info["node_sid"] = s.nodeConfig.NodeSID
		info["protocol"] = s.nodeConfig.Protocol
		info["port"] = s.nodeConfig.ServerPort
	}

	info["user_count"] = len(s.currentUsers)
	info["hub_connected"] = s.hubConnected
	info["node_status"] = s.nodeStatus

	return info
}

// fetchNodeConfig fetches node configuration from the API
func (s *Service) fetchNodeConfig() error {
	s.logger.Info("Fetching node configuration...")

	s.mu.RLock()
	client := s.apiClient
	s.mu.RUnlock()

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	nodeConfig, err := client.GetConfig(ctx)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.nodeConfig = nodeConfig
	s.mu.Unlock()

	s.logger.Info("Node configuration fetched successfully",
		slog.String("node_sid", nodeConfig.NodeSID),
		slog.String("protocol", nodeConfig.Protocol),
		slog.String("host", nodeConfig.ServerHost),
		slog.Int("port", nodeConfig.ServerPort),
		slog.String("method", nodeConfig.EncryptionMethod),
	)

	return nil
}
