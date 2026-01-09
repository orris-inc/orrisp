package system

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

// collectDiskIOStats collects disk I/O statistics from /proc/diskstats.
func (m *Monitor) collectDiskIOStats(stats *Stats) {
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
func (m *Monitor) collectPSIStats(stats *Stats) {
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
func (m *Monitor) collectProcessStats(stats *Stats) {
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
func (m *Monitor) collectFileNrStats(stats *Stats) {
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
func (m *Monitor) collectKernelStats(stats *Stats) {
	procStat, err := m.fs.Stat()
	if err != nil {
		return
	}

	stats.ContextSwitches = procStat.ContextSwitches
	stats.Interrupts = procStat.IRQTotal
}

// loadSystemInfo loads system information (cached, called once).
func (m *Monitor) loadSystemInfo() {
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

// collectVMStats collects virtual memory statistics from /proc/vmstat.
func (m *Monitor) collectVMStats(stats *Stats) {
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
func (m *Monitor) collectEntropyStats(stats *Stats) {
	// Read from /proc/sys/kernel/random/entropy_avail
	if data, err := m.fs.SysctlInts("kernel/random/entropy_avail"); err == nil && len(data) > 0 {
		if data[0] >= 0 {
			stats.EntropyAvailable = uint64(data[0])
		}
	}
}

// collectUptime collects system uptime from /proc/uptime.
func (m *Monitor) collectUptime(stats *Stats) {
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
