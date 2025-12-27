// Package api provides a Go SDK for interacting with the Orris Agent API.
package api

// NodeConfig represents the node configuration returned by the API.
// Compatible with sing-box inbound configuration.
type NodeConfig struct {
	NodeSID           string `json:"node_id"`                     // Node SID (Stripe-style: node_xxx)
	Protocol          string `json:"protocol"`                    // shadowsocks or trojan
	ServerHost        string `json:"server_host"`                 // Server hostname or IP address
	ServerPort        int    `json:"server_port"`                 // Server port number
	EncryptionMethod  string `json:"encryption_method,omitempty"` // Encryption method for Shadowsocks
	ServerKey         string `json:"server_key,omitempty"`        // Server password for SS
	TransportProtocol string `json:"transport_protocol"`          // Transport protocol (tcp, ws, grpc)
	Host              string `json:"host,omitempty"`              // WebSocket host header
	Path              string `json:"path,omitempty"`              // WebSocket path
	ServiceName       string `json:"service_name,omitempty"`      // gRPC service name
	SNI               string `json:"sni,omitempty"`               // TLS Server Name Indication
	AllowInsecure     bool   `json:"allow_insecure"`              // Allow insecure TLS connection
	EnableVless       bool   `json:"enable_vless"`
	EnableXTLS        bool   `json:"enable_xtls"`
	SpeedLimit        uint64 `json:"speed_limit"`
	DeviceLimit       int    `json:"device_limit"`
	RuleListPath      string `json:"rule_list_path,omitempty"`
}

// IsTrojan returns true if the node is configured for Trojan protocol.
func (c *NodeConfig) IsTrojan() bool {
	return c.Protocol == "trojan"
}

// IsShadowsocks returns true if the node is configured for Shadowsocks protocol.
func (c *NodeConfig) IsShadowsocks() bool {
	return c.Protocol == "shadowsocks"
}

// Subscription represents an individual subscription authorized for the node.
type Subscription struct {
	SubscriptionSID string `json:"subscription_id"` // Subscription SID (Stripe-style: sub_xxx)
	Password        string `json:"password"`
	Name            string `json:"name"`
	SpeedLimit      uint64 `json:"speed_limit"`
	DeviceLimit     int    `json:"device_limit"`
	ExpireTime      int64  `json:"expire_time"`
}

// TrafficReport represents traffic data for a single subscription.
type TrafficReport struct {
	SubscriptionSID string `json:"subscription_id"` // Subscription SID (Stripe-style: sub_xxx)
	Upload          int64  `json:"upload"`
	Download        int64  `json:"download"`
}

// NodeStatus represents node system status for reporting to the server
// All metrics should be collected using prometheus/procfs or equivalent libraries
type NodeStatus struct {
	// System resources
	CPUPercent    float64 `json:"cpu_percent"`    // CPU usage percentage (0-100)
	MemoryPercent float64 `json:"memory_percent"` // Memory usage percentage (0-100)
	MemoryUsed    uint64  `json:"memory_used"`    // Memory used in bytes
	MemoryTotal   uint64  `json:"memory_total"`   // Total memory in bytes
	MemoryAvail   uint64  `json:"memory_avail"`   // Available memory in bytes (from procfs Meminfo)
	DiskPercent   float64 `json:"disk_percent"`   // Disk usage percentage (0-100)
	DiskUsed      uint64  `json:"disk_used"`      // Disk used in bytes
	DiskTotal     uint64  `json:"disk_total"`     // Total disk in bytes
	UptimeSeconds int64   `json:"uptime_seconds"` // System uptime in seconds

	// System load (from procfs LoadAvg)
	LoadAvg1  float64 `json:"load_avg_1"`  // 1-minute load average
	LoadAvg5  float64 `json:"load_avg_5"`  // 5-minute load average
	LoadAvg15 float64 `json:"load_avg_15"` // 15-minute load average

	// Network statistics (from procfs NetDev, excluding loopback)
	NetworkRxBytes uint64 `json:"network_rx_bytes"` // Total received bytes across all interfaces
	NetworkTxBytes uint64 `json:"network_tx_bytes"` // Total transmitted bytes across all interfaces

	// Network bandwidth (calculated by agent from delta/time)
	NetworkRxRate uint64 `json:"network_rx_rate"` // Current receive rate in bytes per second
	NetworkTxRate uint64 `json:"network_tx_rate"` // Current transmit rate in bytes per second

	// Connection statistics
	TCPConnections int `json:"tcp_connections"` // Number of TCP connections
	UDPConnections int `json:"udp_connections"` // Number of UDP connections

	// Network info
	PublicIPv4 string `json:"public_ipv4,omitempty"` // Public IPv4 address
	PublicIPv6 string `json:"public_ipv6,omitempty"` // Public IPv6 address

	// Agent info
	AgentVersion string `json:"agent_version,omitempty"` // Agent software version
}

// OnlineSubscription represents an online subscription connection.
type OnlineSubscription struct {
	SubscriptionSID string `json:"subscription_id"` // Subscription SID (Stripe-style: sub_xxx)
	IP              string `json:"ip"`
}

// TrafficReportResult represents the result of a traffic report.
type TrafficReportResult struct {
	SubscriptionsUpdated int `json:"subscriptions_updated"`
}

// OnlineSubscriptionsResult represents the result of updating online subscriptions.
type OnlineSubscriptionsResult struct {
	OnlineCount int `json:"online_count"`
}

// apiResponse represents the standard API response structure.
type apiResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}
