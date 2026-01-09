// Package system provides system monitoring utilities using prometheus/procfs.
package system

import (
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/procfs"
)

// Stats holds comprehensive system statistics.
type Stats struct {
	// CPU
	CPUPercent float64

	// CPU details
	CPUCores     int
	CPUModelName string
	CPUMHz       float64

	// Memory (in bytes)
	MemoryTotal   uint64
	MemoryUsed    uint64
	MemoryAvail   uint64
	MemoryPercent float64

	// Swap memory
	SwapTotal   uint64
	SwapUsed    uint64
	SwapPercent float64

	// Load average
	LoadAvg1  float64
	LoadAvg5  float64
	LoadAvg15 float64

	// Network bandwidth
	NetworkRxBytes uint64 // Total received bytes
	NetworkTxBytes uint64 // Total transmitted bytes
	NetworkRxRate  uint64 // Receive rate (bytes/sec)
	NetworkTxRate  uint64 // Transmit rate (bytes/sec)

	// Network extended stats
	NetworkRxPackets uint64
	NetworkTxPackets uint64
	NetworkRxErrors  uint64
	NetworkTxErrors  uint64
	NetworkRxDropped uint64
	NetworkTxDropped uint64

	// Connections
	TCPConnections int
	UDPConnections int

	// Socket statistics
	SocketsUsed      int
	SocketsTCPInUse  int
	SocketsUDPInUse  int
	SocketsTCPOrphan int
	SocketsTCPTW     int

	// Disk I/O
	DiskReadBytes  uint64
	DiskWriteBytes uint64
	DiskReadRate   uint64
	DiskWriteRate  uint64
	DiskIOPS       uint64

	// PSI (Pressure Stall Information) - Linux only
	PSICPUSome    float64
	PSICPUFull    float64
	PSIMemorySome float64
	PSIMemoryFull float64
	PSIIOSome     float64
	PSIIOFull     float64

	// Process statistics
	ProcessesTotal   uint64
	ProcessesRunning uint64
	ProcessesBlocked uint64

	// File descriptors
	FileNrAllocated uint64
	FileNrMax       uint64

	// Context switches and interrupts
	ContextSwitches uint64
	Interrupts      uint64

	// Kernel info
	KernelVersion string
	Hostname      string

	// Virtual memory statistics
	VMPageIn  uint64
	VMPageOut uint64
	VMSwapIn  uint64
	VMSwapOut uint64
	VMOOMKill uint64

	// Entropy pool
	EntropyAvailable uint64

	// System uptime
	UptimeSeconds int64
}

// Monitor monitors system resources using prometheus/procfs.
type Monitor struct {
	mu sync.RWMutex
	fs procfs.FS

	// initialized indicates whether procfs was successfully initialized
	initialized atomic.Bool

	// unavailable indicates procfs is permanently unavailable (non-Linux systems)
	unavailable atomic.Bool

	// reinitAttempts tracks the number of reinitialization attempts
	reinitAttempts atomic.Int32

	// CPU state
	lastCPUStat procfs.CPUStat
	lastCPUTime time.Time
	cpuPercent  float64

	// CPU info (cached, rarely changes)
	cpuCores     int
	cpuModelName string
	cpuMHz       float64
	cpuInfoOnce  sync.Once

	// Network state
	lastNetStats map[string]netIfaceStats
	lastNetTime  time.Time
	netRxRate    uint64
	netTxRate    uint64

	// Disk I/O state
	lastDiskStats diskIOStats
	lastDiskTime  time.Time
	diskReadRate  uint64
	diskWriteRate uint64
	diskIOPS      uint64

	// System info (cached)
	kernelVersion string
	hostname      string
	sysInfoOnce   sync.Once
}

type netIfaceStats struct {
	rxBytes   uint64
	txBytes   uint64
	rxPackets uint64
	txPackets uint64
	rxErrors  uint64
	txErrors  uint64
	rxDropped uint64
	txDropped uint64
}

type diskIOStats struct {
	readBytes  uint64
	writeBytes uint64
	readOps    uint64
	writeOps   uint64
}

// NewMonitor creates a new system monitor.
func NewMonitor() *Monitor {
	m := &Monitor{
		lastNetStats: make(map[string]netIfaceStats),
	}

	// procfs is only available on Linux
	if runtime.GOOS != "linux" {
		m.unavailable.Store(true)
		slog.Info("System stats unavailable on non-Linux platform",
			slog.String("platform", runtime.GOOS),
		)
		return m
	}

	fs, err := procfs.NewFS("/proc")
	if err != nil {
		slog.Error("Failed to initialize procfs, system stats will be unavailable",
			slog.Any("err", err),
		)
		return m
	}

	m.fs = fs
	m.initialized.Store(true)

	// Initialize CPU state
	if stat, err := fs.Stat(); err == nil {
		m.lastCPUStat = stat.CPUTotal
		m.lastCPUTime = time.Now()
	} else {
		slog.Warn("Failed to get initial CPU stats", slog.Any("err", err))
	}

	// Initialize network state
	m.updateNetworkStats()

	slog.Debug("System monitor initialized successfully")
	return m
}

// GetStats returns current system statistics.
func (m *Monitor) GetStats() Stats {
	var stats Stats

	// Skip if permanently unavailable (non-Linux)
	if m.unavailable.Load() {
		return stats
	}

	// Try to reinitialize if not initialized (lazy initialization)
	if !m.initialized.Load() {
		m.tryReinitialize()
	}

	// If still not initialized, return empty stats
	if !m.initialized.Load() {
		return stats
	}

	// CPU
	stats.CPUPercent = m.getCPUPercent()

	// CPU info (cached)
	m.loadCPUInfo()
	m.mu.RLock()
	stats.CPUCores = m.cpuCores
	stats.CPUModelName = m.cpuModelName
	stats.CPUMHz = m.cpuMHz
	m.mu.RUnlock()

	// Memory and Swap
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

		// Swap
		if meminfo.SwapTotal != nil {
			stats.SwapTotal = *meminfo.SwapTotal * 1024
		}
		if meminfo.SwapFree != nil && meminfo.SwapTotal != nil {
			stats.SwapUsed = (*meminfo.SwapTotal - *meminfo.SwapFree) * 1024
		}
		if stats.SwapTotal > 0 {
			stats.SwapPercent = float64(stats.SwapUsed) / float64(stats.SwapTotal) * 100
		}
	}

	// Load average
	if loadavg, err := m.fs.LoadAvg(); err == nil {
		stats.LoadAvg1 = loadavg.Load1
		stats.LoadAvg5 = loadavg.Load5
		stats.LoadAvg15 = loadavg.Load15
	}

	// Network (including extended stats)
	m.collectNetworkStats(&stats)

	// Connections and socket stats
	m.collectSocketStats(&stats)

	// Disk I/O
	m.collectDiskIOStats(&stats)

	// PSI (Pressure Stall Information)
	m.collectPSIStats(&stats)

	// Process statistics
	m.collectProcessStats(&stats)

	// File descriptors
	m.collectFileNrStats(&stats)

	// Context switches and interrupts
	m.collectKernelStats(&stats)

	// System info (cached)
	m.loadSystemInfo()
	m.mu.RLock()
	stats.KernelVersion = m.kernelVersion
	stats.Hostname = m.hostname
	m.mu.RUnlock()

	// VM statistics
	m.collectVMStats(&stats)

	// Entropy
	m.collectEntropyStats(&stats)

	// Uptime
	m.collectUptime(&stats)

	return stats
}

// maxReinitAttempts is the maximum number of reinitialization attempts before giving up.
const maxReinitAttempts = 3

// tryReinitialize attempts to reinitialize procfs (useful if /proc becomes available later).
func (m *Monitor) tryReinitialize() {
	// Check if we've exceeded max attempts
	attempts := m.reinitAttempts.Add(1)
	if attempts > maxReinitAttempts {
		if attempts == maxReinitAttempts+1 {
			// Only log once when we give up
			m.unavailable.Store(true)
			slog.Warn("Giving up on procfs initialization after max attempts",
				slog.Int("attempts", maxReinitAttempts),
			)
		}
		return
	}

	m.mu.Lock()

	// Double-check under lock
	if m.initialized.Load() {
		m.mu.Unlock()
		return
	}

	fs, err := procfs.NewFS("/proc")
	if err != nil {
		m.mu.Unlock()
		return
	}

	m.fs = fs
	m.initialized.Store(true)

	// Initialize CPU state
	if stat, err := fs.Stat(); err == nil {
		m.lastCPUStat = stat.CPUTotal
		m.lastCPUTime = time.Now()
	}

	// Release lock before calling updateNetworkStats (which also acquires the lock)
	m.mu.Unlock()

	// Initialize network state
	m.updateNetworkStats()

	slog.Info("System monitor reinitialized successfully")
}

// Global system monitor instance.
var globalMonitor = NewMonitor()

// GetStats returns current system statistics using the global monitor.
func GetStats() Stats {
	return globalMonitor.GetStats()
}
