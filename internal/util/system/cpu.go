package system

import (
	"bufio"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/procfs"
)

// getCPUPercent calculates CPU usage percentage.
//
// Lock pattern explanation:
// This function uses a dual-lock pattern for performance optimization:
//
//   - On failure path (procfs read error): Uses RLock to return cached value.
//     This is safe because we only read m.cpuPercent without modification.
//
//   - On success path: Uses Lock (write lock) because we need to:
//     1. Read m.lastCPUStat (previous CPU stats)
//     2. Write m.lastCPUStat (update with current stats)
//     3. Write m.cpuPercent (update calculated percentage)
//
// This design minimizes lock contention in error scenarios while ensuring
// thread-safe updates during normal operation. The procfs.Stat() call is
// performed outside any lock to avoid holding locks during I/O operations.
func (m *Monitor) getCPUPercent() float64 {
	stat, err := m.fs.Stat()
	if err != nil {
		// Failure path: return cached value under read lock
		m.mu.RLock()
		defer m.mu.RUnlock()
		return m.cpuPercent
	}

	current := stat.CPUTotal

	// Success path: update state under write lock
	m.mu.Lock()
	defer m.mu.Unlock()

	prevTotal := m.cpuTotal(m.lastCPUStat)
	currTotal := m.cpuTotal(current)
	prevIdle := m.cpuIdle(m.lastCPUStat)
	currIdle := m.cpuIdle(current)

	totalDelta := currTotal - prevTotal
	idleDelta := currIdle - prevIdle

	m.lastCPUStat = current

	if totalDelta == 0 {
		return m.cpuPercent
	}

	m.cpuPercent = (1.0 - idleDelta/totalDelta) * 100.0
	return m.cpuPercent
}

func (m *Monitor) cpuTotal(s procfs.CPUStat) float64 {
	return s.User + s.Nice + s.System + s.Idle + s.Iowait + s.IRQ + s.SoftIRQ + s.Steal
}

func (m *Monitor) cpuIdle(s procfs.CPUStat) float64 {
	return s.Idle + s.Iowait
}

// loadCPUInfo loads CPU information (cached, called once).
func (m *Monitor) loadCPUInfo() {
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
func (m *Monitor) getARMModelName(implementer, part, architecture string) string {
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
func (m *Monitor) getCPUMHzFromSysfs() float64 {
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
