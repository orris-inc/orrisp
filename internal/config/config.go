package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config application configuration
type Config struct {
	API   APIConfig      `yaml:"api"`
	Hub   HubConfig      `yaml:"hub"`
	Nodes []NodeInstance `yaml:"nodes"` // Node instances configuration
	Sync  SyncConfig     `yaml:"sync"`
	Log   LogConfig      `yaml:"log"`

	// Path is the config file path (not serialized, set at load time)
	Path string `yaml:"-"`
}

// APIConfig API related configuration
type APIConfig struct {
	BaseURL string `yaml:"base_url"`
	Timeout int    `yaml:"timeout"` // Request timeout (seconds)
}

// HubConfig Hub WebSocket configuration
type HubConfig struct {
	Enabled           bool    `yaml:"enabled"`             // Enable Hub connection
	PingInterval      int     `yaml:"ping_interval"`       // Ping interval (seconds)
	PongWait          int     `yaml:"pong_wait"`           // Pong wait timeout (seconds)
	SampleInterval    int     `yaml:"sample_interval"`     // Status sampling interval (seconds), default 1
	TrafficInterval   int     `yaml:"traffic_interval"`    // Traffic report interval (seconds), default 1
	MaxSilentInterval int     `yaml:"max_silent_interval"` // Max time without status report (seconds), default 30
	ChangeThreshold   float64 `yaml:"change_threshold"`    // Change threshold to trigger report (percent), default 5.0
}

// NodeInstance represents a single node instance configuration
type NodeInstance struct {
	SID      string `yaml:"sid"`       // Node SID (Stripe-style: node_xxx)
	Token    string `yaml:"token"`     // Node authentication token
	CertPath string `yaml:"cert_path"` // TLS certificate path
	KeyPath  string `yaml:"key_path"`  // TLS private key path
}

// SyncConfig synchronization configuration
type SyncConfig struct {
	UserInterval      int `yaml:"user_interval"`       // User sync interval (seconds)
	TrafficInterval   int `yaml:"traffic_interval"`    // Traffic report interval (seconds)
	StatusInterval    int `yaml:"status_interval"`     // Status report interval (seconds)
	OnlineInterval    int `yaml:"online_interval"`     // Online users report interval (seconds)
	IPRefreshInterval int `yaml:"ip_refresh_interval"` // Public IP refresh interval (seconds), default 60
}

// LogConfig log configuration
type LogConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // json or text (default: json)
	Output string `yaml:"output"` // stdout or file path
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		API: APIConfig{
			Timeout: 30,
		},
		Hub: HubConfig{
			Enabled:           true, // Default: use WebSocket, fallback to REST on disconnect
			PingInterval:      30,
			PongWait:          60,
			SampleInterval:    1,   // Sample and report every 1 second
			TrafficInterval:   1,   // Report traffic every 1 second via WebSocket
			MaxSilentInterval: 30,  // Report at least every 30 seconds
			ChangeThreshold:   5.0, // Report when change exceeds 5%
		},
		Sync: SyncConfig{
			UserInterval:    60,
			TrafficInterval: 60,
			StatusInterval:  30,
			OnlineInterval:  10,
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
	}
}

// Load loads configuration from file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := DefaultConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Store the config file path for later use (e.g., saving updates)
	config.Path = path

	return config, nil
}

// Save saves configuration to its original file path.
// Returns error if Path is empty (config was loaded from CLI flags).
func (c *Config) Save() error {
	if c.Path == "" {
		return fmt.Errorf("cannot save config: no file path (loaded from CLI flags)")
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(c.Path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate validates configuration
func (c *Config) Validate() error {
	if c.API.BaseURL == "" {
		return fmt.Errorf("api.base_url cannot be empty")
	}

	if len(c.Nodes) == 0 {
		return fmt.Errorf("nodes cannot be empty, at least one node is required")
	}

	// Validate each node instance
	seenSIDs := make(map[string]bool)
	for i, node := range c.Nodes {
		if node.SID == "" {
			return fmt.Errorf("nodes[%d].sid cannot be empty", i)
		}
		if node.Token == "" {
			return fmt.Errorf("nodes[%d].token cannot be empty", i)
		}
		if seenSIDs[node.SID] {
			return fmt.Errorf("duplicate node sid: %s", node.SID)
		}
		seenSIDs[node.SID] = true
	}
	return nil
}

// GetNodeInstances returns all node instances to run
func (c *Config) GetNodeInstances() []NodeInstance {
	return c.Nodes
}

// GetUserSyncInterval gets user sync interval
func (c *Config) GetUserSyncInterval() time.Duration {
	if c.Sync.UserInterval <= 0 {
		return 60 * time.Second
	}
	return time.Duration(c.Sync.UserInterval) * time.Second
}

// GetTrafficReportInterval gets traffic report interval
func (c *Config) GetTrafficReportInterval() time.Duration {
	if c.Sync.TrafficInterval <= 0 {
		return 60 * time.Second
	}
	return time.Duration(c.Sync.TrafficInterval) * time.Second
}

// GetStatusReportInterval gets status report interval
func (c *Config) GetStatusReportInterval() time.Duration {
	if c.Sync.StatusInterval <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.Sync.StatusInterval) * time.Second
}

// GetOnlineReportInterval gets online users report interval
func (c *Config) GetOnlineReportInterval() time.Duration {
	if c.Sync.OnlineInterval <= 0 {
		return 10 * time.Second
	}
	return time.Duration(c.Sync.OnlineInterval) * time.Second
}

// GetIPRefreshInterval gets public IP refresh interval
func (c *Config) GetIPRefreshInterval() time.Duration {
	if c.Sync.IPRefreshInterval <= 0 {
		return 1 * time.Minute // Default: refresh every 1 minute
	}
	return time.Duration(c.Sync.IPRefreshInterval) * time.Second
}

// GetAPITimeout gets API request timeout
func (c *Config) GetAPITimeout() time.Duration {
	if c.API.Timeout <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.API.Timeout) * time.Second
}

// IsHubEnabled returns whether Hub is enabled
func (c *Config) IsHubEnabled() bool {
	return c.Hub.Enabled
}

// GetHubPingInterval gets Hub ping interval
func (c *Config) GetHubPingInterval() time.Duration {
	if c.Hub.PingInterval <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.Hub.PingInterval) * time.Second
}

// GetHubPongWait gets Hub pong wait timeout
func (c *Config) GetHubPongWait() time.Duration {
	if c.Hub.PongWait <= 0 {
		return 60 * time.Second
	}
	return time.Duration(c.Hub.PongWait) * time.Second
}

// GetHubSampleInterval gets Hub status sampling interval
func (c *Config) GetHubSampleInterval() time.Duration {
	if c.Hub.SampleInterval <= 0 {
		return 1 * time.Second
	}
	return time.Duration(c.Hub.SampleInterval) * time.Second
}

// GetHubTrafficInterval gets Hub traffic report interval
func (c *Config) GetHubTrafficInterval() time.Duration {
	if c.Hub.TrafficInterval <= 0 {
		return 1 * time.Second
	}
	return time.Duration(c.Hub.TrafficInterval) * time.Second
}

// GetHubMaxSilentInterval gets max time without status report
func (c *Config) GetHubMaxSilentInterval() time.Duration {
	if c.Hub.MaxSilentInterval <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.Hub.MaxSilentInterval) * time.Second
}

// GetHubChangeThreshold gets change threshold to trigger report
func (c *Config) GetHubChangeThreshold() float64 {
	if c.Hub.ChangeThreshold <= 0 {
		return 5.0
	}
	return c.Hub.ChangeThreshold
}
