// Package util provides utility functions.
// This file re-exports types from the system subpackage for backward compatibility.
package util

import (
	"github.com/easayliu/orrisp/internal/util/system"
)

// SystemStats is an alias to system.Stats for backward compatibility.
type SystemStats = system.Stats

// SystemMonitor is an alias to system.Monitor for backward compatibility.
type SystemMonitor = system.Monitor

// NewSystemMonitor creates a new system monitor.
// This is a wrapper around system.NewMonitor for backward compatibility.
func NewSystemMonitor() *SystemMonitor {
	return system.NewMonitor()
}

// GetSystemStats returns current system statistics using the global monitor.
// This is a wrapper around system.GetStats for backward compatibility.
func GetSystemStats() SystemStats {
	return system.GetStats()
}
