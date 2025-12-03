package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config application configuration
type Config struct {
	API  APIConfig  `yaml:"api"`
	Node NodeConfig `yaml:"node"`
	Sync SyncConfig `yaml:"sync"`
	Log  LogConfig  `yaml:"log"`
}

// APIConfig API related configuration
type APIConfig struct {
	BaseURL   string `yaml:"base_url"`
	NodeID    int    `yaml:"node_id"`
	NodeToken string `yaml:"node_token"`
	Timeout   int    `yaml:"timeout"` // Request timeout (seconds)
}

// NodeConfig node configuration
type NodeConfig struct {
	ListenPort int    `yaml:"listen_port"` // Override server-side configuration
	CertPath   string `yaml:"cert_path"`   // TLS certificate path
	KeyPath    string `yaml:"key_path"`    // TLS private key path
}

// SyncConfig synchronization configuration
type SyncConfig struct {
	UserInterval    int `yaml:"user_interval"`    // User sync interval (seconds)
	TrafficInterval int `yaml:"traffic_interval"` // Traffic report interval (seconds)
	StatusInterval  int `yaml:"status_interval"`  // Status report interval (seconds)
	OnlineInterval  int `yaml:"online_interval"`  // Online users report interval (seconds)
}

// LogConfig log configuration
type LogConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Output string `yaml:"output"` // stdout or file path
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		API: APIConfig{
			Timeout: 30,
		},
		Sync: SyncConfig{
			UserInterval:    60,
			TrafficInterval: 60,
			StatusInterval:  30,
			OnlineInterval:  10,
		},
		Log: LogConfig{
			Level:  "info",
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

	return config, nil
}

// Validate validates configuration
func (c *Config) Validate() error {
	if c.API.BaseURL == "" {
		return fmt.Errorf("api.base_url cannot be empty")
	}
	if c.API.NodeID <= 0 {
		return fmt.Errorf("api.node_id must be greater than 0")
	}
	if c.API.NodeToken == "" {
		return fmt.Errorf("api.node_token cannot be empty")
	}
	return nil
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

// GetAPITimeout gets API request timeout
func (c *Config) GetAPITimeout() time.Duration {
	if c.API.Timeout <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.API.Timeout) * time.Second
}
