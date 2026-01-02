package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
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

// cancelService safely cancels the service context with lock protection.
// This prevents nil pointer panic when called concurrently with Stop().
func (s *NodeService) cancelService() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
}

// NodeService node service
type NodeService struct {
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
	currentUsers []api.Subscription
	startTime    time.Time
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup

	// Hub connection state
	hubConnected  bool
	hubDisconnect chan struct{} // Signal when hub disconnects (broadcast via close)

	// TLS certificate paths (auto-generated if not configured)
	certPath     string
	keyPath      string
	certInitOnce sync.Once
	certInitErr  error

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
		return nil, fmt.Errorf("create api client: %w", err)
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

		// CPU details
		CPUCores:     sysStats.CPUCores,
		CPUModelName: sysStats.CPUModelName,
		CPUMHz:       sysStats.CPUMHz,

		// Memory
		MemoryPercent: sysStats.MemoryPercent,
		MemoryUsed:    sysStats.MemoryUsed,
		MemoryTotal:   sysStats.MemoryTotal,
		MemoryAvail:   sysStats.MemoryAvail,

		// Swap memory
		SwapTotal:   sysStats.SwapTotal,
		SwapUsed:    sysStats.SwapUsed,
		SwapPercent: sysStats.SwapPercent,

		// Disk
		DiskPercent: diskPercent,
		DiskUsed:    diskUsed,
		DiskTotal:   diskTotal,

		// Disk I/O
		DiskReadBytes:  sysStats.DiskReadBytes,
		DiskWriteBytes: sysStats.DiskWriteBytes,
		DiskReadRate:   sysStats.DiskReadRate,
		DiskWriteRate:  sysStats.DiskWriteRate,
		DiskIOPS:       sysStats.DiskIOPS,

		// Uptime
		UptimeSeconds: int64(time.Since(s.startTime).Seconds()),

		// Load average
		LoadAvg1:  sysStats.LoadAvg1,
		LoadAvg5:  sysStats.LoadAvg5,
		LoadAvg15: sysStats.LoadAvg15,

		// Network
		NetworkRxBytes: sysStats.NetworkRxBytes,
		NetworkTxBytes: sysStats.NetworkTxBytes,
		NetworkRxRate:  sysStats.NetworkRxRate,
		NetworkTxRate:  sysStats.NetworkTxRate,

		// Network extended stats
		NetworkRxPackets: sysStats.NetworkRxPackets,
		NetworkTxPackets: sysStats.NetworkTxPackets,
		NetworkRxErrors:  sysStats.NetworkRxErrors,
		NetworkTxErrors:  sysStats.NetworkTxErrors,
		NetworkRxDropped: sysStats.NetworkRxDropped,
		NetworkTxDropped: sysStats.NetworkTxDropped,

		// Connections
		TCPConnections: sysStats.TCPConnections,
		UDPConnections: sysStats.UDPConnections,

		// Socket statistics
		SocketsUsed:      sysStats.SocketsUsed,
		SocketsTCPInUse:  sysStats.SocketsTCPInUse,
		SocketsUDPInUse:  sysStats.SocketsUDPInUse,
		SocketsTCPOrphan: sysStats.SocketsTCPOrphan,
		SocketsTCPTW:     sysStats.SocketsTCPTW,

		// PSI (Pressure Stall Information)
		PSICPUSome:    sysStats.PSICPUSome,
		PSICPUFull:    sysStats.PSICPUFull,
		PSIMemorySome: sysStats.PSIMemorySome,
		PSIMemoryFull: sysStats.PSIMemoryFull,
		PSIIOSome:     sysStats.PSIIOSome,
		PSIIOFull:     sysStats.PSIIOFull,

		// Process statistics
		ProcessesTotal:   sysStats.ProcessesTotal,
		ProcessesRunning: sysStats.ProcessesRunning,
		ProcessesBlocked: sysStats.ProcessesBlocked,

		// File descriptors
		FileNrAllocated: sysStats.FileNrAllocated,
		FileNrMax:       sysStats.FileNrMax,

		// Context switches and interrupts
		ContextSwitches: sysStats.ContextSwitches,
		Interrupts:      sysStats.Interrupts,

		// Kernel info
		KernelVersion: sysStats.KernelVersion,
		Hostname:      sysStats.Hostname,

		// Virtual memory statistics
		VMPageIn:  sysStats.VMPageIn,
		VMPageOut: sysStats.VMPageOut,
		VMSwapIn:  sysStats.VMSwapIn,
		VMSwapOut: sysStats.VMSwapOut,
		VMOOMKill: sysStats.VMOOMKill,

		// Entropy pool
		EntropyAvailable: sysStats.EntropyAvailable,

		// Network info
		PublicIPv4: ipv4,
		PublicIPv6: ipv6,

		// Agent info
		AgentVersion: getAgentVersion(),
		Platform:     runtime.GOOS,
		Arch:         runtime.GOARCH,
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

// ensureTLSCert ensures TLS certificate exists, generates self-signed if not configured.
// This method is safe for concurrent access using sync.Once.
func (s *NodeService) ensureTLSCert(sni string) (string, string, error) {
	s.certInitOnce.Do(func() {
		s.certInitErr = s.initTLSCert(sni)
	})

	if s.certInitErr != nil {
		return "", "", s.certInitErr
	}
	return s.certPath, s.keyPath, nil
}

// initTLSCert initializes TLS certificate paths. Called once via sync.Once.
func (s *NodeService) initTLSCert(sni string) error {
	// Use configured paths if available (check node instance first)
	if s.nodeInstance.CertPath != "" && s.nodeInstance.KeyPath != "" {
		s.certPath = s.nodeInstance.CertPath
		s.keyPath = s.nodeInstance.KeyPath
		s.logger.Info("Using configured TLS certificate",
			slog.String("cert_path", s.certPath),
			slog.String("key_path", s.keyPath),
		)
		return nil
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
		if err := os.MkdirAll(certDir, 0700); err != nil {
			return fmt.Errorf("failed to create cert directory: %w", err)
		}
	}

	s.logger.Info("Generating self-signed TLS certificate",
		slog.String("sni", sni),
		slog.String("cert_dir", certDir),
	)
	selfSigned, err := cert.GenerateSelfSigned(certDir, sni)
	if err != nil {
		return err
	}

	s.certPath = selfSigned.CertPath
	s.keyPath = selfSigned.KeyPath
	s.logger.Info("Self-signed TLS certificate generated",
		slog.String("cert_path", s.certPath),
		slog.String("key_path", s.keyPath),
		slog.String("algorithm", "Ed25519"),
	)

	return nil
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
					s.cancelService()
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
	info["hub_connected"] = s.hubConnected

	return info
}

// ============================================================================
// Hub (WebSocket) Connection Management
// ============================================================================

const (
	hubInitialBackoff = 1 * time.Second
	hubMaxBackoff     = 5 * time.Minute
	hubBackoffFactor  = 2.0
)

// hubConnectionLoop manages Hub connection with exponential backoff reconnection.
// When Hub is connected, server pushes config/command updates.
// When Hub is disconnected, falls back to REST API polling.
func (s *NodeService) hubConnectionLoop() {
	defer s.wg.Done()

	s.logger.Info("Starting Hub connection loop...")

	backoff := hubInitialBackoff
	var restTasksCancel context.CancelFunc

	for {
		select {
		case <-s.ctx.Done():
			if restTasksCancel != nil {
				restTasksCancel()
			}
			return
		default:
		}

		// Create new disconnect channel for this connection attempt
		s.mu.Lock()
		s.hubDisconnect = make(chan struct{})
		disconnectCh := s.hubDisconnect
		s.mu.Unlock()

		// Try to connect to Hub
		if err := s.connectHub(); err != nil {
			s.logger.Warn("Hub connection failed, using REST fallback",
				slog.Any("err", err),
				slog.Duration("retry_in", backoff),
			)

			// Start REST fallback if not already running
			if restTasksCancel == nil {
				var restCtx context.Context
				restCtx, restTasksCancel = context.WithCancel(s.ctx)
				s.startRESTFallback(restCtx)
			}

			// Wait before retry with exponential backoff
			select {
			case <-s.ctx.Done():
				if restTasksCancel != nil {
					restTasksCancel()
				}
				return
			case <-time.After(backoff):
				backoff = time.Duration(float64(backoff) * hubBackoffFactor)
				if backoff > hubMaxBackoff {
					backoff = hubMaxBackoff
				}
			}
			continue
		}

		// Hub connected successfully
		s.logger.Info("Hub connected, stopping REST fallback")
		backoff = hubInitialBackoff // Reset backoff on successful connection

		// Stop REST fallback (user sync polling)
		if restTasksCancel != nil {
			restTasksCancel()
			restTasksCancel = nil
		}

		s.mu.Lock()
		s.hubConnected = true
		s.mu.Unlock()

		// Start Hub tasks (status + traffic reporting)
		// These run while Hub is connected and stop when disconnected
		s.wg.Add(2)
		go s.hubStatusLoop(disconnectCh)
		go s.hubTrafficLoop(disconnectCh)

		// Wait for disconnect signal (channel will be closed by OnDisconnect)
		select {
		case <-s.ctx.Done():
			return
		case <-disconnectCh:
			s.logger.Info("Hub disconnected, will reconnect...")
			s.mu.Lock()
			s.hubConnected = false
			s.mu.Unlock()
		}
	}
}

// connectHub creates and connects the Hub client.
// It respects context cancellation so shutdown can interrupt connection attempts.
func (s *NodeService) connectHub() error {
	hubClient, err := api.NewHubClient(
		s.config.API.BaseURL,
		s.nodeInstance.Token,
		s.nodeInstance.SID,
		s, // NodeService implements HubHandler
		api.WithPingInterval(s.config.GetHubPingInterval()),
		api.WithPongWait(s.config.GetHubPongWait()),
	)
	if err != nil {
		return fmt.Errorf("create hub client: %w", err)
	}

	// Use goroutine to handle Connect so we can respond to context cancellation
	connectDone := make(chan error, 1)
	go func() {
		connectDone <- hubClient.Connect()
	}()

	select {
	case <-s.ctx.Done():
		// Context cancelled during connection attempt, clean up
		_ = hubClient.Close()
		return s.ctx.Err()
	case err := <-connectDone:
		if err != nil {
			_ = hubClient.Close()
			return fmt.Errorf("connect hub: %w", err)
		}
	}

	s.mu.Lock()
	s.hubClient = hubClient
	s.mu.Unlock()

	s.logger.Info("Hub WebSocket connected successfully")
	return nil
}

// hubStatusLoop sends periodic status updates via Hub WebSocket.
// Reports are sent every sample interval (default 1 second).
func (s *NodeService) hubStatusLoop(disconnectCh <-chan struct{}) {
	defer s.wg.Done()

	sampleInterval := s.config.GetHubSampleInterval()

	ticker := time.NewTicker(sampleInterval)
	defer ticker.Stop()

	// Send initial status immediately
	status := s.collectSystemStatus()
	s.sendHubStatusData(status)

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-disconnectCh:
			return
		case <-ticker.C:
			status := s.collectSystemStatus()
			s.sendHubStatusData(status)
		}
	}
}

// hubTrafficLoop sends periodic traffic reports while Hub is connected.
func (s *NodeService) hubTrafficLoop(disconnectCh <-chan struct{}) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.GetTrafficReportInterval())
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-disconnectCh:
			return
		case <-ticker.C:
			if err := s.reportTraffic(); err != nil {
				s.logger.Error("Failed to report traffic", slog.Any("err", err))
			}
		}
	}
}

// sendHubStatusData sends pre-collected status via Hub.
func (s *NodeService) sendHubStatusData(status *api.NodeStatus) {
	s.mu.RLock()
	hubClient := s.hubClient
	s.mu.RUnlock()

	if hubClient == nil {
		return
	}

	if err := hubClient.SendStatus(status); err != nil {
		s.logger.Warn("Failed to send status via hub", slog.Any("err", err))
	}
}

// startRESTFallback starts REST API polling as fallback when Hub is disconnected.
func (s *NodeService) startRESTFallback(ctx context.Context) {
	s.logger.Info("Starting REST fallback tasks...")

	// User synchronization task
	s.wg.Add(1)
	go s.scheduleTaskWithContext(ctx, "REST: User sync", s.config.GetUserSyncInterval(), func() error {
		return s.syncUsers()
	})

	// Traffic report task
	s.wg.Add(1)
	go s.scheduleTaskWithContext(ctx, "REST: Traffic report", s.config.GetTrafficReportInterval(), func() error {
		return s.reportTraffic()
	})

	// Status report task
	s.wg.Add(1)
	go s.scheduleTaskWithContext(ctx, "REST: Status report", s.config.GetStatusReportInterval(), func() error {
		return s.reportStatus()
	})
}

// scheduleTaskWithContext is like scheduleTask but uses a provided context.
func (s *NodeService) scheduleTaskWithContext(ctx context.Context, name string, interval time.Duration, task func() error) {
	defer s.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.logger.Info("Scheduled task started", slog.String("name", name), slog.Duration("interval", interval))

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("Scheduled task stopped", slog.String("name", name))
			return

		case <-ticker.C:
			if err := task(); err != nil {
				s.logger.Error("Scheduled task failed", slog.String("name", name), slog.Any("err", err))

				if errors.Is(err, api.ErrUnauthorized) {
					s.logger.Error("Authentication failed, stopping service")
					s.cancelService()
					return
				}
			}
		}
	}
}

// ============================================================================
// HubHandler Interface Implementation
// ============================================================================

// OnCommand handles commands from the server via Hub.
func (s *NodeService) OnCommand(cmd *api.CommandData) {
	s.logger.Info("Received command from hub",
		slog.String("command_id", cmd.CommandID),
		slog.String("action", cmd.Action),
	)

	switch cmd.Action {
	case api.CmdActionReloadConfig:
		s.logger.Info("Executing reload config command")
		go func() {
			if err := s.fetchNodeConfig(); err != nil {
				s.logger.Error("Failed to reload config", slog.Any("err", err))
				return
			}
			if err := s.syncUsers(); err != nil {
				s.logger.Error("Failed to sync users", slog.Any("err", err))
				return
			}
			if err := s.reloadSingbox(); err != nil {
				s.logger.Error("Failed to reload singbox", slog.Any("err", err))
				return
			}
			s.logger.Info("Config reloaded successfully via hub command")
		}()

	case api.CmdActionRestart:
		s.logger.Info("Executing restart command")
		go func() {
			if err := s.reloadSingbox(); err != nil {
				s.logger.Error("Failed to restart singbox", slog.Any("err", err))
			}
		}()

	case api.CmdActionStop:
		s.logger.Warn("Received stop command from hub")
		go s.Stop()

	case api.CmdActionUpdate:
		s.logger.Info("Executing update command")
		go s.handleUpdate(cmd)

	default:
		s.logger.Warn("Unknown command action", slog.String("action", cmd.Action))
	}
}

// OnConfigSync handles config sync from the server via Hub.
func (s *NodeService) OnConfigSync(sync *api.ConfigSyncData) {
	s.logger.Info("Received config sync from hub",
		slog.Uint64("version", sync.Version),
		slog.Bool("full_sync", sync.FullSync),
	)

	if sync.Config == nil {
		s.logger.Debug("Config sync has no config data, fetching via REST")
		go func() {
			if err := s.fetchNodeConfig(); err != nil {
				s.logger.Error("Failed to fetch config after sync notification", slog.Any("err", err))
				return
			}
			if err := s.syncUsers(); err != nil {
				s.logger.Error("Failed to sync users after config sync", slog.Any("err", err))
				return
			}
			if err := s.reloadSingbox(); err != nil {
				s.logger.Error("Failed to reload singbox after config sync", slog.Any("err", err))
			}
		}()
		return
	}

	// Apply config from Hub directly
	s.mu.Lock()
	s.nodeConfig = s.convertHubConfigToNodeConfig(sync.Config)
	s.mu.Unlock()

	s.logger.Info("Config updated from hub sync",
		slog.String("node_sid", sync.Config.NodeSID),
		slog.String("protocol", sync.Config.Protocol),
	)

	// Reload sing-box with new config
	go func() {
		if err := s.syncUsers(); err != nil {
			s.logger.Error("Failed to sync users after hub config sync", slog.Any("err", err))
			return
		}
		if err := s.reloadSingbox(); err != nil {
			s.logger.Error("Failed to reload singbox after hub config sync", slog.Any("err", err))
		}
	}()
}

// convertHubConfigToNodeConfig converts Hub ConfigData to NodeConfig.
func (s *NodeService) convertHubConfigToNodeConfig(hubConfig *api.ConfigData) *api.NodeConfig {
	return &api.NodeConfig{
		NodeSID:           hubConfig.NodeSID,
		Protocol:          hubConfig.Protocol,
		ServerHost:        hubConfig.ServerHost,
		ServerPort:        hubConfig.ServerPort,
		EncryptionMethod:  hubConfig.EncryptionMethod,
		ServerKey:         hubConfig.ServerKey,
		TransportProtocol: hubConfig.TransportProtocol,
		Host:              hubConfig.Host,
		Path:              hubConfig.Path,
		ServiceName:       hubConfig.ServiceName,
		SNI:               hubConfig.SNI,
		AllowInsecure:     hubConfig.AllowInsecure,
		Route:             hubConfig.Route,
		Outbounds:         hubConfig.Outbounds,
	}
}

// OnError handles errors from the Hub connection.
func (s *NodeService) OnError(err error) {
	s.logger.Error("Hub error", slog.Any("err", err))
}

// OnDisconnect handles Hub disconnection.
func (s *NodeService) OnDisconnect() {
	s.logger.Warn("Hub disconnected")

	s.mu.Lock()
	s.hubClient = nil
	// Close channel to broadcast disconnect to all listeners
	if s.hubDisconnect != nil {
		close(s.hubDisconnect)
		s.hubDisconnect = nil
	}
	s.mu.Unlock()
}
