package util

import (
	"bufio"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/procfs"
)

// SystemStats holds comprehensive system statistics.
type SystemStats struct {
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

// SystemMonitor monitors system resources using prometheus/procfs.
type SystemMonitor struct {
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

// NewSystemMonitor creates a new system monitor.
func NewSystemMonitor() *SystemMonitor {
	m := &SystemMonitor{
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
func (m *SystemMonitor) GetStats() SystemStats {
	var stats SystemStats

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
func (m *SystemMonitor) tryReinitialize() {
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
			rxBytes:   dev.RxBytes,
			txBytes:   dev.TxBytes,
			rxPackets: dev.RxPackets,
			txPackets: dev.TxPackets,
			rxErrors:  dev.RxErrors,
			txErrors:  dev.TxErrors,
			rxDropped: dev.RxDropped,
			txDropped: dev.TxDropped,
		}
	}
	m.lastNetTime = time.Now()
}

// collectNetworkStats collects network statistics into stats.
func (m *SystemMonitor) collectNetworkStats(stats *SystemStats) {
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
	var totalRxPackets, totalTxPackets uint64
	var totalRxErrors, totalTxErrors uint64
	var totalRxDropped, totalTxDropped uint64

	for name, dev := range netDev {
		if name == "lo" {
			continue
		}

		totalRxBytes += dev.RxBytes
		totalTxBytes += dev.TxBytes
		totalRxPackets += dev.RxPackets
		totalTxPackets += dev.TxPackets
		totalRxErrors += dev.RxErrors
		totalTxErrors += dev.TxErrors
		totalRxDropped += dev.RxDropped
		totalTxDropped += dev.TxDropped

		if last, ok := m.lastNetStats[name]; ok {
			if dev.RxBytes >= last.rxBytes {
				totalRxDelta += dev.RxBytes - last.rxBytes
			}
			if dev.TxBytes >= last.txBytes {
				totalTxDelta += dev.TxBytes - last.txBytes
			}
		}

		m.lastNetStats[name] = netIfaceStats{
			rxBytes:   dev.RxBytes,
			txBytes:   dev.TxBytes,
			rxPackets: dev.RxPackets,
			txPackets: dev.TxPackets,
			rxErrors:  dev.RxErrors,
			txErrors:  dev.TxErrors,
			rxDropped: dev.RxDropped,
			txDropped: dev.TxDropped,
		}
	}

	m.lastNetTime = now
	m.netRxRate = uint64(float64(totalRxDelta) / elapsed)
	m.netTxRate = uint64(float64(totalTxDelta) / elapsed)

	stats.NetworkRxBytes = totalRxBytes
	stats.NetworkTxBytes = totalTxBytes
	stats.NetworkRxRate = m.netRxRate
	stats.NetworkTxRate = m.netTxRate
	stats.NetworkRxPackets = totalRxPackets
	stats.NetworkTxPackets = totalTxPackets
	stats.NetworkRxErrors = totalRxErrors
	stats.NetworkTxErrors = totalTxErrors
	stats.NetworkRxDropped = totalRxDropped
	stats.NetworkTxDropped = totalTxDropped
}

// loadCPUInfo loads CPU information (cached, called once).
func (m *SystemMonitor) loadCPUInfo() {
	m.cpuInfoOnce.Do(func() {
		file, err := os.Open("/proc/cpuinfo")
		if err != nil {
			slog.Warn("Failed to open /proc/cpuinfo, CPU info will be unavailable",
				slog.Any("err", err),
			)
			return
		}
		defer file.Close()

		var cores int
		var modelName string
		var cpuMHz float64

		// ARM-specific fields
		var cpuImplementer, cpuPart, cpuArchitecture string

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}

			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			switch key {
			case "processor":
				cores++
			case "model name":
				if modelName == "" {
					modelName = value
				}
			case "cpu MHz":
				if cpuMHz == 0 {
					if v, err := strconv.ParseFloat(value, 64); err == nil {
						cpuMHz = v
					}
				}
			// ARM-specific fields
			case "CPU implementer":
				cpuImplementer = value
			case "CPU part":
				cpuPart = value
			case "CPU architecture":
				cpuArchitecture = value
			}
		}

		// If model name is empty (ARM architecture), try to construct one
		if modelName == "" && cpuImplementer != "" {
			modelName = m.getARMModelName(cpuImplementer, cpuPart, cpuArchitecture)
			slog.Debug("Using ARM CPU model name",
				slog.String("model_name", modelName),
				slog.String("implementer", cpuImplementer),
				slog.String("part", cpuPart),
			)
		}

		// If CPU MHz is still 0, try to read from sysfs (common on ARM)
		if cpuMHz == 0 {
			cpuMHz = m.getCPUMHzFromSysfs()
			if cpuMHz > 0 {
				slog.Debug("Read CPU frequency from sysfs",
					slog.Float64("cpu_mhz", cpuMHz),
				)
			}
		}

		m.mu.Lock()
		defer m.mu.Unlock()

		m.cpuCores = cores
		m.cpuModelName = modelName
		m.cpuMHz = cpuMHz

		slog.Info("CPU info loaded",
			slog.Int("cores", cores),
			slog.String("model_name", modelName),
			slog.Float64("cpu_mhz", cpuMHz),
		)
	})
}

// getARMModelName returns a human-readable model name for ARM CPUs.
func (m *SystemMonitor) getARMModelName(implementer, part, architecture string) string {
	// Common ARM implementers
	implementerNames := map[string]string{
		"0x41": "ARM",
		"0x42": "Broadcom",
		"0x43": "Cavium",
		"0x44": "DEC",
		"0x46": "Fujitsu",
		"0x48": "HiSilicon",
		"0x49": "Infineon",
		"0x4d": "Motorola",
		"0x4e": "NVIDIA",
		"0x50": "APM",
		"0x51": "Qualcomm",
		"0x53": "Samsung",
		"0x56": "Marvell",
		"0x61": "Apple",
		"0x66": "Faraday",
		"0x69": "Intel",
		"0xc0": "Ampere",
	}

	// Common ARM part numbers (for ARM implementer 0x41)
	partNames := map[string]string{
		"0xd03": "Cortex-A53",
		"0xd04": "Cortex-A35",
		"0xd05": "Cortex-A55",
		"0xd07": "Cortex-A57",
		"0xd08": "Cortex-A72",
		"0xd09": "Cortex-A73",
		"0xd0a": "Cortex-A75",
		"0xd0b": "Cortex-A76",
		"0xd0c": "Neoverse-N1",
		"0xd0d": "Cortex-A77",
		"0xd0e": "Cortex-A76AE",
		"0xd40": "Neoverse-V1",
		"0xd41": "Cortex-A78",
		"0xd42": "Cortex-A78AE",
		"0xd43": "Cortex-A65AE",
		"0xd44": "Cortex-X1",
		"0xd46": "Cortex-A510",
		"0xd47": "Cortex-A710",
		"0xd48": "Cortex-X2",
		"0xd49": "Neoverse-N2",
		"0xd4a": "Neoverse-E1",
		"0xd4b": "Cortex-A78C",
		"0xd4c": "Cortex-X1C",
		"0xd4d": "Cortex-A715",
		"0xd4e": "Cortex-X3",
	}

	implName := implementerNames[implementer]
	if implName == "" {
		implName = "ARM"
	}

	partName := partNames[part]
	if partName == "" {
		partName = "CPU"
		if part != "" {
			partName = "CPU " + part
		}
	}

	result := implName + " " + partName
	if architecture != "" {
		result += " (ARMv" + architecture + ")"
	}
	return result
}

// getCPUMHzFromSysfs reads CPU frequency from sysfs (common on ARM).
func (m *SystemMonitor) getCPUMHzFromSysfs() float64 {
	// Try cpuinfo_max_freq first (in kHz)
	paths := []string{
		"/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq",
		"/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq",
		"/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		kHz, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
		if err != nil {
			continue
		}
		// Convert kHz to MHz
		return kHz / 1000.0
	}

	return 0
}

// loadSystemInfo loads system information (cached, called once).
func (m *SystemMonitor) loadSystemInfo() {
	m.sysInfoOnce.Do(func() {
		m.mu.Lock()
		defer m.mu.Unlock()

		// Kernel version from /proc/sys/kernel/osrelease
		if data, err := m.fs.SysctlStrings("kernel/osrelease"); err == nil && len(data) > 0 {
			m.kernelVersion = data[0]
		}

		// Hostname from /proc/sys/kernel/hostname
		if data, err := m.fs.SysctlStrings("kernel/hostname"); err == nil && len(data) > 0 {
			m.hostname = data[0]
		}
	})
}

// collectSocketStats collects socket statistics into stats.
func (m *SystemMonitor) collectSocketStats(stats *SystemStats) {
	// TCP connections count
	if tcpConns, err := m.fs.NetTCP(); err == nil {
		stats.TCPConnections = len(tcpConns)
		for _, conn := range tcpConns {
			switch conn.St {
			case 1: // ESTABLISHED
				stats.SocketsTCPInUse++
			case 6: // TIME_WAIT
				stats.SocketsTCPTW++
			case 8: // CLOSE_WAIT (orphan-like)
				stats.SocketsTCPOrphan++
			}
		}
	}
	if tcp6Conns, err := m.fs.NetTCP6(); err == nil {
		stats.TCPConnections += len(tcp6Conns)
		for _, conn := range tcp6Conns {
			switch conn.St {
			case 1:
				stats.SocketsTCPInUse++
			case 6:
				stats.SocketsTCPTW++
			case 8:
				stats.SocketsTCPOrphan++
			}
		}
	}

	// UDP connections count
	if udpConns, err := m.fs.NetUDP(); err == nil {
		stats.UDPConnections = len(udpConns)
		stats.SocketsUDPInUse = len(udpConns)
	}
	if udp6Conns, err := m.fs.NetUDP6(); err == nil {
		stats.UDPConnections += len(udp6Conns)
		stats.SocketsUDPInUse += len(udp6Conns)
	}

	stats.SocketsUsed = stats.TCPConnections + stats.UDPConnections
}

// collectDiskIOStats collects disk I/O statistics from /proc/diskstats.
func (m *SystemMonitor) collectDiskIOStats(stats *SystemStats) {
	file, err := os.Open("/proc/diskstats")
	if err != nil {
		return
	}
	defer file.Close()

	now := time.Now()
	var totalReadBytes, totalWriteBytes uint64
	var totalReadOps, totalWriteOps uint64

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 14 {
			continue
		}

		deviceName := fields[2]

		// Skip partitions and virtual devices (only count physical disks)
		if !isPhysicalDisk(deviceName) {
			continue
		}

		// Field 3: reads completed
		// Field 5: sectors read
		// Field 7: writes completed
		// Field 9: sectors written
		readOps, _ := strconv.ParseUint(fields[3], 10, 64)
		readSectors, _ := strconv.ParseUint(fields[5], 10, 64)
		writeOps, _ := strconv.ParseUint(fields[7], 10, 64)
		writeSectors, _ := strconv.ParseUint(fields[9], 10, 64)

		// Convert sectors to bytes (sector = 512 bytes)
		totalReadBytes += readSectors * 512
		totalWriteBytes += writeSectors * 512
		totalReadOps += readOps
		totalWriteOps += writeOps
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Calculate rates if we have previous data
	if !m.lastDiskTime.IsZero() {
		elapsed := now.Sub(m.lastDiskTime).Seconds()
		if elapsed > 0 {
			// Check for counter overflow (wrap-around)
			if totalReadBytes >= m.lastDiskStats.readBytes {
				readDelta := totalReadBytes - m.lastDiskStats.readBytes
				m.diskReadRate = uint64(float64(readDelta) / elapsed)
			}
			if totalWriteBytes >= m.lastDiskStats.writeBytes {
				writeDelta := totalWriteBytes - m.lastDiskStats.writeBytes
				m.diskWriteRate = uint64(float64(writeDelta) / elapsed)
			}
			totalOps := totalReadOps + totalWriteOps
			lastOps := m.lastDiskStats.readOps + m.lastDiskStats.writeOps
			if totalOps >= lastOps {
				opsDelta := totalOps - lastOps
				m.diskIOPS = uint64(float64(opsDelta) / elapsed)
			}
		}
	}

	m.lastDiskStats = diskIOStats{
		readBytes:  totalReadBytes,
		writeBytes: totalWriteBytes,
		readOps:    totalReadOps,
		writeOps:   totalWriteOps,
	}
	m.lastDiskTime = now

	stats.DiskReadBytes = totalReadBytes
	stats.DiskWriteBytes = totalWriteBytes
	stats.DiskReadRate = m.diskReadRate
	stats.DiskWriteRate = m.diskWriteRate
	stats.DiskIOPS = m.diskIOPS
}

// isPhysicalDisk checks if a device name is a physical disk (not partition or virtual device).
// Returns true for: sda, sdb, nvme0n1, vda, xvda, hda
// Returns false for: sda1, nvme0n1p1, loop0, ram0, dm-0
func isPhysicalDisk(name string) bool {
	if len(name) == 0 {
		return false
	}

	// Skip virtual devices
	if strings.HasPrefix(name, "loop") ||
		strings.HasPrefix(name, "ram") ||
		strings.HasPrefix(name, "dm-") ||
		strings.HasPrefix(name, "md") ||
		strings.HasPrefix(name, "sr") ||
		strings.HasPrefix(name, "fd") {
		return false
	}

	// NVMe devices: nvme0n1 is disk, nvme0n1p1 is partition
	if strings.HasPrefix(name, "nvme") {
		// Partition has 'p' followed by digits at the end
		return !strings.Contains(name, "p") || !isNVMePartition(name)
	}

	// SCSI/SATA/virtio/Xen disks: sda, vda, xvda, hda are disks; sda1, vda1 are partitions
	if len(name) >= 3 {
		prefix := name[:2]
		if prefix == "sd" || prefix == "vd" || prefix == "hd" ||
			(len(name) >= 4 && name[:3] == "xvd") {
			// Check if last character is a digit (partition)
			lastChar := name[len(name)-1]
			return lastChar < '0' || lastChar > '9'
		}
	}

	return false
}

// isNVMePartition checks if an NVMe device name is a partition.
func isNVMePartition(name string) bool {
	// nvme0n1p1 format: find 'p' after 'n'
	nIdx := strings.LastIndex(name, "n")
	if nIdx == -1 {
		return false
	}
	pIdx := strings.LastIndex(name, "p")
	// Partition if 'p' comes after 'n' and is followed by digits
	return pIdx > nIdx && pIdx < len(name)-1
}

// collectPSIStats collects Pressure Stall Information (Linux 4.20+).
func (m *SystemMonitor) collectPSIStats(stats *SystemStats) {
	// CPU pressure
	if psi, err := m.fs.PSIStatsForResource("cpu"); err == nil {
		stats.PSICPUSome = psi.Some.Avg10
		stats.PSICPUFull = psi.Full.Avg10
	}

	// Memory pressure
	if psi, err := m.fs.PSIStatsForResource("memory"); err == nil {
		stats.PSIMemorySome = psi.Some.Avg10
		stats.PSIMemoryFull = psi.Full.Avg10
	}

	// I/O pressure
	if psi, err := m.fs.PSIStatsForResource("io"); err == nil {
		stats.PSIIOSome = psi.Some.Avg10
		stats.PSIIOFull = psi.Full.Avg10
	}
}

// collectProcessStats collects process statistics.
func (m *SystemMonitor) collectProcessStats(stats *SystemStats) {
	procStat, err := m.fs.Stat()
	if err != nil {
		return
	}

	// ProcessCreated is cumulative count of processes created since boot
	stats.ProcessesTotal = procStat.ProcessCreated
	stats.ProcessesRunning = procStat.ProcessesRunning
	stats.ProcessesBlocked = procStat.ProcessesBlocked
}

// collectFileNrStats collects file descriptor statistics from /proc/sys/fs/file-nr.
func (m *SystemMonitor) collectFileNrStats(stats *SystemStats) {
	data, err := os.ReadFile("/proc/sys/fs/file-nr")
	if err != nil {
		return
	}

	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		stats.FileNrAllocated, _ = strconv.ParseUint(fields[0], 10, 64)
		stats.FileNrMax, _ = strconv.ParseUint(fields[2], 10, 64)
	}
}

// collectKernelStats collects context switches and interrupts.
func (m *SystemMonitor) collectKernelStats(stats *SystemStats) {
	procStat, err := m.fs.Stat()
	if err != nil {
		return
	}

	stats.ContextSwitches = procStat.ContextSwitches
	stats.Interrupts = procStat.IRQTotal
}

// collectVMStats collects virtual memory statistics from /proc/vmstat.
func (m *SystemMonitor) collectVMStats(stats *SystemStats) {
	file, err := os.Open("/proc/vmstat")
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}

		key := fields[0]
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}

		switch key {
		case "pgpgin":
			stats.VMPageIn = value
		case "pgpgout":
			stats.VMPageOut = value
		case "pswpin":
			stats.VMSwapIn = value
		case "pswpout":
			stats.VMSwapOut = value
		case "oom_kill":
			stats.VMOOMKill = value
		}
	}
}

// collectEntropyStats collects entropy pool statistics.
func (m *SystemMonitor) collectEntropyStats(stats *SystemStats) {
	// Read from /proc/sys/kernel/random/entropy_avail
	if data, err := m.fs.SysctlInts("kernel/random/entropy_avail"); err == nil && len(data) > 0 {
		if data[0] >= 0 {
			stats.EntropyAvailable = uint64(data[0])
		}
	}
}

// collectUptime collects system uptime from /proc/uptime.
func (m *SystemMonitor) collectUptime(stats *SystemStats) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return
	}

	fields := strings.Fields(string(data))
	if len(fields) >= 1 {
		// First field is uptime in seconds (with decimal)
		uptime, err := strconv.ParseFloat(fields[0], 64)
		if err == nil {
			stats.UptimeSeconds = int64(uptime)
		}
	}
}

// Global system monitor instance.
var globalSystemMonitor = NewSystemMonitor()

// GetSystemStats returns current system statistics using the global monitor.
func GetSystemStats() SystemStats {
	return globalSystemMonitor.GetStats()
}
