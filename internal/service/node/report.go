package node

import (
	"context"
	"log/slog"
	"runtime"
	"syscall"
	"time"

	"github.com/easayliu/orrisp/internal/api"
	"github.com/easayliu/orrisp/internal/util"
)

// reportTraffic reports traffic statistics to the API
func (s *Service) reportTraffic() error {
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

// reportStatus reports node status to the API
func (s *Service) reportStatus() error {
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

// reportOnline reports online users to the API
func (s *Service) reportOnline() error {
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
func (s *Service) collectSystemStatus() *api.NodeStatus {
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

		// Uptime (system uptime, not agent uptime)
		UptimeSeconds: sysStats.UptimeSeconds,

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
// It periodically refreshes the cached IPs based on the configured interval.
func (s *Service) getPublicIPs() (ipv4, ipv6 string) {
	refreshInterval := s.config.GetIPRefreshInterval()

	s.mu.RLock()
	cachedIPv4 := s.cachedPublicIPv4
	cachedIPv6 := s.cachedPublicIPv6
	lastCheck := s.lastIPCheck
	s.mu.RUnlock()

	// Return cached IPs if available and not expired
	if (cachedIPv4 != "" || cachedIPv6 != "") && time.Since(lastCheck) < refreshInterval {
		return cachedIPv4, cachedIPv6
	}

	// Detect public IPs
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()

	ipv4, ipv6 = util.GetPublicIPs(ctx)

	s.mu.Lock()
	oldIPv4 := s.cachedPublicIPv4
	oldIPv6 := s.cachedPublicIPv6
	s.cachedPublicIPv4 = ipv4
	s.cachedPublicIPv6 = ipv6
	s.lastIPCheck = time.Now()
	s.mu.Unlock()

	// Log IP detection or changes
	if oldIPv4 == "" && oldIPv6 == "" {
		// First detection
		if ipv4 != "" {
			s.logger.Info("Public IPv4 detected", slog.String("ipv4", ipv4))
		}
		if ipv6 != "" {
			s.logger.Info("Public IPv6 detected", slog.String("ipv6", ipv6))
		}
	} else {
		// Check for changes
		if ipv4 != oldIPv4 {
			s.logger.Info("Public IPv4 changed",
				slog.String("old", oldIPv4),
				slog.String("new", ipv4),
			)
		}
		if ipv6 != oldIPv6 {
			s.logger.Info("Public IPv6 changed",
				slog.String("old", oldIPv6),
				slog.String("new", ipv6),
			)
		}
	}

	return ipv4, ipv6
}

// getDiskStats gets disk statistics for root filesystem
func (s *Service) getDiskStats() (used, total uint64, percent float64) {
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
