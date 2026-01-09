package system

import (
	"time"
)

// updateNetworkStats updates network statistics.
func (m *Monitor) updateNetworkStats() {
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
func (m *Monitor) collectNetworkStats(stats *Stats) {
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

// collectSocketStats collects socket statistics into stats.
func (m *Monitor) collectSocketStats(stats *Stats) {
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
