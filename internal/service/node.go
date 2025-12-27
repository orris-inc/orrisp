package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/easayliu/orrisp/internal/api"
	"github.com/easayliu/orrisp/internal/cert"
	"github.com/easayliu/orrisp/internal/config"
	"github.com/easayliu/orrisp/internal/singbox"
	"github.com/easayliu/orrisp/internal/stats"
	"github.com/easayliu/orrisp/internal/util"
	"github.com/sagernet/sing-box/option"
)

// Package-level version variable, set by main package
var agentVersion = "dev"

// SetAgentVersion sets the agent version for status reporting.
func SetAgentVersion(v string) {
	agentVersion = v
}

// NodeService node service
type NodeService struct {
	config         *config.Config
	nodeInstance   config.NodeInstance // Node instance configuration
	apiClient      *api.Client
	singboxService *singbox.Service
	statsClient    *stats.Client
	trafficTracker *singbox.TrafficTracker
	logger         *slog.Logger

	mu           sync.RWMutex
	nodeConfig   *api.NodeConfig
	currentUsers []api.Subscription
	startTime    time.Time
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup

	// TLS certificate paths (auto-generated if not configured)
	certPath string
	keyPath  string

	// Cached public IP addresses
	cachedPublicIPv4 string
	cachedPublicIPv6 string
}

// NewNodeService creates new node service for a specific node instance
func NewNodeService(cfg *config.Config, nodeInstance config.NodeInstance, logger *slog.Logger) (*NodeService, error) {
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
		return nil, fmt.Errorf("failed to create API client: %w", err)
	}

	// Create traffic statistics client
	statsClient := stats.NewClient()

	// Create traffic tracker for sing-box
	trafficTracker := singbox.NewTrafficTracker(statsClient, nodeLogger)

	return &NodeService{
		config:         cfg,
		nodeInstance:   nodeInstance,
		apiClient:      apiClient,
		statsClient:    statsClient,
		trafficTracker: trafficTracker,
		logger:         nodeLogger,
		startTime:      time.Now(),
	}, nil
}

// Start starts service
func (s *NodeService) Start(ctx context.Context) error {
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
	if err := s.syncUsers(); err != nil {
		cleanupOnFailure()
		return fmt.Errorf("failed to sync users: %w", err)
	}

	// 3. Start sing-box
	if err := s.startSingbox(); err != nil {
		cleanupOnFailure()
		return fmt.Errorf("failed to start sing-box: %w", err)
	}

	// 4. Start scheduled tasks
	s.startScheduledTasks()

	s.logger.Info("Node service started successfully")
	return nil
}

// Stop stops service
func (s *NodeService) Stop() error {
	s.mu.Lock()
	if s.cancel == nil {
		s.mu.Unlock()
		return nil
	}

	s.logger.Info("Stopping node service...")
	s.cancel()
	s.cancel = nil
	s.mu.Unlock()

	// Wait for all goroutines to exit
	s.wg.Wait()

	// Stop sing-box
	if s.singboxService != nil {
		if err := s.singboxService.Close(); err != nil {
			s.logger.Error("Failed to stop sing-box", slog.Any("err", err))
		}
	}

	s.logger.Info("Node service stopped")
	return nil
}

// fetchNodeConfig fetches node configuration
func (s *NodeService) fetchNodeConfig() error {
	s.logger.Info("Fetching node configuration...")

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	nodeConfig, err := s.apiClient.GetConfig(ctx)
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

// syncUsers synchronizes user list
func (s *NodeService) syncUsers() error {
	s.logger.Debug("Synchronizing user list...")

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	users, err := s.apiClient.GetSubscriptions(ctx)
	if err != nil {
		return fmt.Errorf("failed to get user list: %w", err)
	}

	s.mu.Lock()
	oldUsers := s.currentUsers
	s.currentUsers = users
	s.mu.Unlock()

	// Update traffic tracker user mapping
	s.updateUserMap(users)

	s.logger.Info("User list synchronized successfully",
		slog.Int("old_count", len(oldUsers)),
		slog.Int("new_count", len(users)),
	)

	// Check if user list actually changed (compare content, not just count)
	changed := s.usersChanged(oldUsers, users)
	hasSingbox := s.singboxService != nil

	if changed && hasSingbox {
		s.logger.Info("User list changed, reloading sing-box...",
			slog.Int("old_users", len(oldUsers)),
			slog.Int("new_users", len(users)),
		)
		if err := s.reloadSingbox(); err != nil {
			s.logger.Error("Failed to reload sing-box", slog.Any("err", err))
			return err
		}
		s.logger.Info("sing-box reloaded with new user list")
	} else {
		s.logger.Info("User list sync completed",
			slog.Bool("changed", changed),
			slog.Bool("singbox_running", hasSingbox),
		)
	}

	return nil
}

// usersChanged checks if the user list has actually changed
// Returns true if users are different, false if they are the same
func (s *NodeService) usersChanged(oldUsers, newUsers []api.Subscription) bool {
	// Different lengths means definitely changed
	if len(oldUsers) != len(newUsers) {
		s.logger.Debug("User count changed",
			slog.Int("old", len(oldUsers)),
			slog.Int("new", len(newUsers)),
		)
		return true
	}

	// Build map of old users for efficient lookup
	oldMap := make(map[string]api.Subscription, len(oldUsers))
	for _, user := range oldUsers {
		oldMap[user.Name] = user
	}

	// Check if any new user is different or missing
	for _, newUser := range newUsers {
		oldUser, exists := oldMap[newUser.Name]
		if !exists {
			// New user added
			s.logger.Debug("New user detected", slog.String("name", newUser.Name))
			return true
		}
		// Check if user details changed
		if oldUser.SubscriptionSID != newUser.SubscriptionSID ||
			oldUser.Password != newUser.Password {
			s.logger.Debug("User details changed", slog.String("name", newUser.Name))
			return true
		}
	}

	// All users are the same
	return false
}

// updateUserMap updates the traffic tracker's user mapping
func (s *NodeService) updateUserMap(users []api.Subscription) {
	userMap := make(map[string]string, len(users))
	for _, user := range users {
		userMap[user.Name] = user.SubscriptionSID
	}
	s.trafficTracker.SetUserMap(userMap)
}

// reportTraffic reports traffic
func (s *NodeService) reportTraffic() error {
	// Get and reset traffic statistics
	trafficItems := s.statsClient.GetAndResetTraffic()

	if len(trafficItems) == 0 {
		s.logger.Debug("No traffic data to report")
		return nil
	}

	// Log detailed traffic data for debugging
	for _, item := range trafficItems {
		s.logger.Info("Traffic collected",
			slog.String("subscription_sid", item.SubscriptionSID),
			slog.Int64("upload", item.Upload),
			slog.Int64("download", item.Download),
		)
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	result, err := s.apiClient.ReportTraffic(ctx, trafficItems)
	if err != nil {
		s.logger.Error("Failed to report traffic", slog.Any("err", err))
		// Restore traffic data to prevent data loss
		s.statsClient.RestoreTraffic(trafficItems)
		s.logger.Warn("Traffic data restored due to report failure",
			slog.Int("count", len(trafficItems)),
		)
		return err
	}

	s.logger.Info("Traffic data reported successfully",
		slog.Int("count", len(trafficItems)),
		slog.Int("updated", result.SubscriptionsUpdated),
	)
	return nil
}

// reportStatus reports node status
func (s *NodeService) reportStatus() error {
	s.logger.Debug("Reporting node status...")

	// Collect system status
	status := s.collectSystemStatus()

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	if err := s.apiClient.UpdateStatus(ctx, status); err != nil {
		s.logger.Error("Failed to report node status", slog.Any("err", err))
		return err
	}

	s.logger.Debug("Node status reported successfully")
	return nil
}

// reportOnline reports online users
func (s *NodeService) reportOnline() error {
	s.logger.Debug("Reporting online users...")

	// TODO: Get online user information from sing-box
	// Need to implement logic to get online users
	onlineUsers := []api.OnlineSubscription{}

	if len(onlineUsers) == 0 {
		s.logger.Debug("No online users")
		return nil
	}

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	result, err := s.apiClient.UpdateOnlineSubscriptions(ctx, onlineUsers)
	if err != nil {
		s.logger.Error("Failed to report online users", slog.Any("err", err))
		return err
	}

	s.logger.Debug("Online users reported successfully", slog.Int("count", result.OnlineCount))
	return nil
}

// collectSystemStatus collects system status using prometheus/procfs
func (s *NodeService) collectSystemStatus() *api.NodeStatus {
	// Get system stats from procfs
	sysStats := util.GetSystemStats()

	// Get disk stats
	diskUsed, diskTotal, diskPercent := s.getDiskStats()

	// Detect public IP for auto-reporting
	ipv4, ipv6 := s.getPublicIPs()

	return &api.NodeStatus{
		// CPU
		CPUPercent: sysStats.CPUPercent,

		// Memory
		MemoryPercent: sysStats.MemoryPercent,
		MemoryUsed:    sysStats.MemoryUsed,
		MemoryTotal:   sysStats.MemoryTotal,
		MemoryAvail:   sysStats.MemoryAvail,

		// Disk
		DiskPercent: diskPercent,
		DiskUsed:    diskUsed,
		DiskTotal:   diskTotal,

		// Uptime
		UptimeSeconds: time.Since(s.startTime).Milliseconds() / 1000,

		// Load average
		LoadAvg1:  sysStats.LoadAvg1,
		LoadAvg5:  sysStats.LoadAvg5,
		LoadAvg15: sysStats.LoadAvg15,

		// Network
		NetworkRxBytes: sysStats.NetworkRxBytes,
		NetworkTxBytes: sysStats.NetworkTxBytes,
		NetworkRxRate:  sysStats.NetworkRxRate,
		NetworkTxRate:  sysStats.NetworkTxRate,

		// Connections
		TCPConnections: sysStats.TCPConnections,
		UDPConnections: sysStats.UDPConnections,

		// Network info
		PublicIPv4: ipv4,
		PublicIPv6: ipv6,

		// Agent info
		AgentVersion: agentVersion,
	}
}

// getPublicIPs gets the server's public IPv4 and IPv6 addresses with caching.
func (s *NodeService) getPublicIPs() (ipv4, ipv6 string) {
	s.mu.RLock()
	cachedIPv4 := s.cachedPublicIPv4
	cachedIPv6 := s.cachedPublicIPv6
	s.mu.RUnlock()

	// Return cached IPs if available (IPs rarely change during runtime)
	if cachedIPv4 != "" || cachedIPv6 != "" {
		return cachedIPv4, cachedIPv6
	}

	// Detect public IPs
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()

	ipv4, ipv6 = util.GetPublicIPs(ctx)

	s.mu.Lock()
	s.cachedPublicIPv4 = ipv4
	s.cachedPublicIPv6 = ipv6
	s.mu.Unlock()

	if ipv4 != "" {
		s.logger.Info("Public IPv4 detected", slog.String("ipv4", ipv4))
	}
	if ipv6 != "" {
		s.logger.Info("Public IPv6 detected", slog.String("ipv6", ipv6))
	}

	return ipv4, ipv6
}

// getDiskStats gets disk statistics for root filesystem
func (s *NodeService) getDiskStats() (used, total uint64, percent float64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		s.logger.Debug("Failed to get disk stats", slog.Any("err", err))
		return 0, 0, 0
	}

	total = stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used = total - free

	if total > 0 {
		percent = float64(used) / float64(total) * 100
	}

	return used, total, percent
}

// startSingbox starts sing-box
func (s *NodeService) startSingbox() error {
	s.logger.Info("Starting sing-box...")

	// Generate sing-box configuration
	options, err := s.generateSingboxOptions()
	if err != nil {
		return fmt.Errorf("failed to generate sing-box config: %w", err)
	}

	// Create sing-box service with logger
	service, err := singbox.NewService(options, s.logger)
	if err != nil {
		return fmt.Errorf("failed to create sing-box service: %w", err)
	}

	// Set traffic tracker for statistics
	service.SetTracker(s.trafficTracker)

	// Start service
	if err := service.Start(); err != nil {
		return fmt.Errorf("failed to start sing-box service: %w", err)
	}

	s.singboxService = service
	s.logger.Info("sing-box started successfully with traffic tracking enabled")
	return nil
}

// reloadSingbox reloads sing-box
func (s *NodeService) reloadSingbox() error {
	if s.singboxService == nil {
		return s.startSingbox()
	}

	// Generate new configuration
	options, err := s.generateSingboxOptions()
	if err != nil {
		return fmt.Errorf("failed to generate sing-box config: %w", err)
	}

	// Reload configuration
	if err := s.singboxService.Reload(options); err != nil {
		return fmt.Errorf("failed to reload sing-box: %w", err)
	}

	s.logger.Info("sing-box configuration reloaded successfully")
	return nil
}

// generateSingboxOptions generates sing-box configuration options
func (s *NodeService) generateSingboxOptions() (*option.Options, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.nodeConfig == nil {
		return nil, fmt.Errorf("node configuration not initialized")
	}

	// Copy node configuration
	nodeConfig := *s.nodeConfig
	// Use :: to listen on all addresses
	nodeConfig.ServerHost = "::"

	// Use builder to generate configuration
	// Traffic statistics is handled by ConnectionTracker, no need for Clash API
	clashAPIAddr := ""
	options, err := singbox.BuildConfig(&nodeConfig, s.currentUsers, clashAPIAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to build sing-box config: %w", err)
	}

	// Debug: log generated config
	hasClashAPI := options.Experimental != nil && options.Experimental.ClashAPI != nil
	s.logger.Info("Generated sing-box config",
		slog.String("listen_addr", nodeConfig.ServerHost),
		slog.Int("listen_port", nodeConfig.ServerPort),
		slog.String("protocol", nodeConfig.Protocol),
		slog.String("method", nodeConfig.EncryptionMethod),
		slog.Int("inbound_count", len(options.Inbounds)),
		slog.Int("user_count", len(s.currentUsers)),
		slog.Bool("has_clash_api", hasClashAPI),
	)

	// If using trojan or vless protocol, configure TLS certificate
	if nodeConfig.Protocol == "trojan" || nodeConfig.Protocol == "vless" {
		// Ensure certificate exists (generate self-signed if not configured)
		certPath, keyPath, err := s.ensureTLSCert(nodeConfig.SNI)
		if err != nil {
			return nil, fmt.Errorf("failed to ensure TLS certificate: %w", err)
		}

		for i := range options.Inbounds {
			if options.Inbounds[i].Type == "trojan" {
				if trojanOpts, ok := options.Inbounds[i].Options.(*option.TrojanInboundOptions); ok {
					if trojanOpts.TLS != nil {
						trojanOpts.TLS.CertificatePath = certPath
						trojanOpts.TLS.KeyPath = keyPath
					}
				}
			} else if options.Inbounds[i].Type == "vless" {
				if vlessOpts, ok := options.Inbounds[i].Options.(*option.VLESSInboundOptions); ok {
					if vlessOpts.TLS != nil {
						vlessOpts.TLS.CertificatePath = certPath
						vlessOpts.TLS.KeyPath = keyPath
					}
				}
			}
		}
	}

	return options, nil
}

// ensureTLSCert ensures TLS certificate exists, generates self-signed if not configured
func (s *NodeService) ensureTLSCert(sni string) (string, string, error) {
	// Use cached paths if already generated
	if s.certPath != "" && s.keyPath != "" {
		return s.certPath, s.keyPath, nil
	}

	// Use configured paths if available (check node instance first)
	if s.nodeInstance.CertPath != "" && s.nodeInstance.KeyPath != "" {
		s.certPath = s.nodeInstance.CertPath
		s.keyPath = s.nodeInstance.KeyPath
		s.logger.Info("Using configured TLS certificate",
			slog.String("cert_path", s.certPath),
			slog.String("key_path", s.keyPath),
		)
		return s.certPath, s.keyPath, nil
	}

	// Generate self-signed certificate (use node SID in path for multi-node support)
	// Try persistent directory first, fallback to temporary directory if needed
	persistentDir := fmt.Sprintf("/var/lib/orrisp/certs/%s", s.nodeInstance.SID)
	tempDir := fmt.Sprintf("/tmp/orrisp/certs/%s", s.nodeInstance.SID)

	// Try persistent directory first
	certDir := persistentDir
	if err := os.MkdirAll(certDir, 0700); err != nil {
		// Fallback to temporary directory
		s.logger.Warn("Failed to create persistent cert directory, using temporary directory",
			slog.String("persistent_dir", persistentDir),
			slog.String("temp_dir", tempDir),
			slog.Any("err", err),
		)
		certDir = tempDir
	}

	s.logger.Info("Generating self-signed TLS certificate",
		slog.String("sni", sni),
		slog.String("cert_dir", certDir),
	)
	selfSigned, err := cert.GenerateSelfSigned(certDir, sni)
	if err != nil {
		return "", "", err
	}

	s.certPath = selfSigned.CertPath
	s.keyPath = selfSigned.KeyPath
	s.logger.Info("Self-signed TLS certificate generated",
		slog.String("cert_path", s.certPath),
		slog.String("key_path", s.keyPath),
		slog.String("algorithm", "Ed25519"),
	)

	return s.certPath, s.keyPath, nil
}

// startScheduledTasks starts scheduled tasks
func (s *NodeService) startScheduledTasks() {
	s.logger.Info("Starting scheduled tasks...")

	// Report status immediately on startup
	if err := s.reportStatus(); err != nil {
		s.logger.Warn("Failed to report initial status", slog.Any("err", err))
	}

	// User synchronization task
	s.wg.Add(1)
	go s.scheduleTask("User synchronization", s.config.GetUserSyncInterval(), func() error {
		return s.syncUsers()
	})

	// Traffic report task
	s.wg.Add(1)
	go s.scheduleTask("Traffic report", s.config.GetTrafficReportInterval(), func() error {
		return s.reportTraffic()
	})

	// Status report task
	s.wg.Add(1)
	go s.scheduleTask("Status report", s.config.GetStatusReportInterval(), func() error {
		return s.reportStatus()
	})

	// Online users report task
	s.wg.Add(1)
	go s.scheduleTask("Online users report", s.config.GetOnlineReportInterval(), func() error {
		return s.reportOnline()
	})

	s.logger.Info("Scheduled tasks started")
}

// scheduleTask schedules a task
func (s *NodeService) scheduleTask(name string, interval time.Duration, task func() error) {
	defer s.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.logger.Info("Scheduled task started",
		slog.String("name", name),
		slog.Duration("interval", interval),
	)

	for {
		select {
		case <-s.ctx.Done():
			s.logger.Info("Scheduled task stopped", slog.String("name", name))
			return

		case <-ticker.C:
			if err := task(); err != nil {
				s.logger.Error("Scheduled task execution failed",
					slog.String("name", name),
					slog.Any("err", err),
				)

				// Stop service on authentication failure (401)
				if errors.Is(err, api.ErrUnauthorized) {
					s.logger.Error("Authentication failed, stopping service due to invalid token")
					s.cancel()
					return
				}
			}
		}
	}
}

// GetNodeInfo gets node information (for debugging)
func (s *NodeService) GetNodeInfo() map[string]interface{} {
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

	return info
}
