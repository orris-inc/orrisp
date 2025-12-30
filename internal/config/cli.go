package config

import (
	"flag"
	"fmt"
	"strings"
)

// nodeFlags holds multiple --node flags
type nodeFlags []string

func (n *nodeFlags) String() string {
	return strings.Join(*n, ",")
}

func (n *nodeFlags) Set(value string) error {
	*n = append(*n, value)
	return nil
}

var (
	configPath string
	apiURL     string
	logLevel   string
	nodes      nodeFlags
)

func init() {
	// -c: config file path
	flag.StringVar(&configPath, "c", "", "config file path")

	// --api-url: API base URL (required when using CLI mode)
	flag.StringVar(&apiURL, "api-url", "", "API base URL")

	// -l, --log-level: log level
	flag.StringVar(&logLevel, "l", "info", "log level: debug, info, warn, error")
	flag.StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")

	// --node: node configuration (can be specified multiple times)
	flag.Var(&nodes, "node", "node config as 'sid:token' (repeatable)")
}

// LoadFromCLI loads configuration from CLI flags or config file.
// Priority: CLI flags > config file
func LoadFromCLI() (*Config, error) {
	// Check if CLI flags are provided
	if apiURL != "" && len(nodes) > 0 {
		return buildConfigFromCLI()
	}

	// Fall back to config file
	configFile := configPath
	if configFile == "" {
		configFile = "configs/config.yaml"
	}
	return Load(configFile)
}

// buildConfigFromCLI builds configuration from CLI flags.
func buildConfigFromCLI() (*Config, error) {
	cfg := DefaultConfig()
	cfg.API.BaseURL = apiURL
	cfg.Log.Level = logLevel

	for _, n := range nodes {
		parts := strings.SplitN(n, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid --node format '%s', expected 'sid:token'", n)
		}
		sid := parts[0]
		if sid == "" {
			return nil, fmt.Errorf("node sid cannot be empty in '%s'", n)
		}
		cfg.Nodes = append(cfg.Nodes, NodeInstance{
			SID:   sid,
			Token: parts[1],
		})
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}
