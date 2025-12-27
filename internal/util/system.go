package util

import (
	"sync"
	"time"

	"github.com/prometheus/procfs"
)

// SystemStats holds comprehensive system statistics.
type SystemStats struct {
	// CPU
	CPUPercent float64

	// Memory (in bytes)
	MemoryTotal   uint64
	MemoryUsed    uint64
	MemoryAvail   uint64
	MemoryPercent float64

	// Load average
	LoadAvg1  float64
	LoadAvg5  float64
	LoadAvg15 float64

	// Network bandwidth
	NetworkRxBytes uint64 // Total received bytes
	NetworkTxBytes uint64 // Total transmitted bytes
	NetworkRxRate  uint64 // Receive rate (bytes/sec)
	NetworkTxRate  uint64 // Transmit rate (bytes/sec)

	// Connections
	TCPConnections int
	UDPConnections int
}

// SystemMonitor monitors system resources using prometheus/procfs.
type SystemMonitor struct {
	mu sync.RWMutex
	fs procfs.FS

	// CPU state
	lastCPUStat procfs.CPUStat
	lastCPUTime time.Time
	cpuPercent  float64

	// Network state
	lastNetStats map[string]netIfaceStats
	lastNetTime  time.Time
	netRxRate    uint64
	netTxRate    uint64
}

type netIfaceStats struct {
	rxBytes uint64
	txBytes uint64
}

// NewSystemMonitor creates a new system monitor.
func NewSystemMonitor() *SystemMonitor {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return &SystemMonitor{
			lastNetStats: make(map[string]netIfaceStats),
		}
	}

	m := &SystemMonitor{
		fs:           fs,
		lastNetStats: make(map[string]netIfaceStats),
	}

	// Initialize CPU state
	if stat, err := fs.Stat(); err == nil {
		m.lastCPUStat = stat.CPUTotal
		m.lastCPUTime = time.Now()
	}

	// Initialize network state
	m.updateNetworkStats()

	return m
}

// GetStats returns current system statistics.
func (m *SystemMonitor) GetStats() SystemStats {
	var stats SystemStats

	// CPU
	stats.CPUPercent = m.getCPUPercent()

	// Memory
	if meminfo, err := m.fs.Meminfo(); err == nil {
		if meminfo.MemTotal != nil {
			stats.MemoryTotal = *meminfo.MemTotal * 1024 // Convert from KB to bytes
		}
		if meminfo.MemAvailable != nil {
			stats.MemoryAvail = *meminfo.MemAvailable * 1024
		} else if meminfo.MemFree != nil {
			// Fallback to MemFree if MemAvailable not present
			stats.MemoryAvail = *meminfo.MemFree * 1024
		}
		stats.MemoryUsed = stats.MemoryTotal - stats.MemoryAvail
		if stats.MemoryTotal > 0 {
			stats.MemoryPercent = float64(stats.MemoryUsed) / float64(stats.MemoryTotal) * 100
		}
	}

	// Load average
	if loadavg, err := m.fs.LoadAvg(); err == nil {
		stats.LoadAvg1 = loadavg.Load1
		stats.LoadAvg5 = loadavg.Load5
		stats.LoadAvg15 = loadavg.Load15
	}

	// Network
	rxBytes, txBytes, rxRate, txRate := m.getNetworkStats()
	stats.NetworkRxBytes = rxBytes
	stats.NetworkTxBytes = txBytes
	stats.NetworkRxRate = rxRate
	stats.NetworkTxRate = txRate

	// Connections
	stats.TCPConnections, stats.UDPConnections = m.getConnectionCounts()

	return stats
}

// getCPUPercent calculates CPU usage percentage.
func (m *SystemMonitor) getCPUPercent() float64 {
	stat, err := m.fs.Stat()
	if err != nil {
		m.mu.RLock()
		defer m.mu.RUnlock()
		return m.cpuPercent
	}

	current := stat.CPUTotal

	m.mu.Lock()
	defer m.mu.Unlock()

	prevTotal := m.cpuTotal(m.lastCPUStat)
	currTotal := m.cpuTotal(current)
	prevIdle := m.cpuIdle(m.lastCPUStat)
	currIdle := m.cpuIdle(current)

	totalDelta := currTotal - prevTotal
	idleDelta := currIdle - prevIdle

	m.lastCPUStat = current
	m.lastCPUTime = time.Now()

	if totalDelta == 0 {
		return m.cpuPercent
	}

	m.cpuPercent = (1.0 - idleDelta/totalDelta) * 100.0
	return m.cpuPercent
}

func (m *SystemMonitor) cpuTotal(s procfs.CPUStat) float64 {
	return s.User + s.Nice + s.System + s.Idle + s.Iowait + s.IRQ + s.SoftIRQ + s.Steal
}

func (m *SystemMonitor) cpuIdle(s procfs.CPUStat) float64 {
	return s.Idle + s.Iowait
}

// updateNetworkStats updates network statistics.
func (m *SystemMonitor) updateNetworkStats() {
	netDev, err := m.fs.NetDev()
	if err != nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for name, dev := range netDev {
		if name == "lo" {
			continue
		}
		m.lastNetStats[name] = netIfaceStats{
			rxBytes: dev.RxBytes,
			txBytes: dev.TxBytes,
		}
	}
	m.lastNetTime = time.Now()
}

// getNetworkStats returns network statistics and bandwidth.
func (m *SystemMonitor) getNetworkStats() (rxBytes, txBytes, rxRate, txRate uint64) {
	netDev, err := m.fs.NetDev()
	if err != nil {
		return
	}

	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	elapsed := now.Sub(m.lastNetTime).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}

	var totalRxBytes, totalTxBytes uint64
	var totalRxDelta, totalTxDelta uint64

	for name, dev := range netDev {
		if name == "lo" {
			continue
		}

		totalRxBytes += dev.RxBytes
		totalTxBytes += dev.TxBytes

		if last, ok := m.lastNetStats[name]; ok {
			if dev.RxBytes >= last.rxBytes {
				totalRxDelta += dev.RxBytes - last.rxBytes
			}
			if dev.TxBytes >= last.txBytes {
				totalTxDelta += dev.TxBytes - last.txBytes
			}
		}

		m.lastNetStats[name] = netIfaceStats{
			rxBytes: dev.RxBytes,
			txBytes: dev.TxBytes,
		}
	}

	m.lastNetTime = now
	m.netRxRate = uint64(float64(totalRxDelta) / elapsed)
	m.netTxRate = uint64(float64(totalTxDelta) / elapsed)

	return totalRxBytes, totalTxBytes, m.netRxRate, m.netTxRate
}

// getConnectionCounts returns TCP and UDP connection counts.
func (m *SystemMonitor) getConnectionCounts() (tcp, udp int) {
	// TCP connections
	if tcpConns, err := m.fs.NetTCP(); err == nil {
		tcp = len(tcpConns)
	}
	if tcp6Conns, err := m.fs.NetTCP6(); err == nil {
		tcp += len(tcp6Conns)
	}

	// UDP connections
	if udpConns, err := m.fs.NetUDP(); err == nil {
		udp = len(udpConns)
	}
	if udp6Conns, err := m.fs.NetUDP6(); err == nil {
		udp += len(udp6Conns)
	}

	return tcp, udp
}

// Global system monitor instance.
var globalSystemMonitor = NewSystemMonitor()

// GetSystemStats returns current system statistics using the global monitor.
func GetSystemStats() SystemStats {
	return globalSystemMonitor.GetStats()
}
