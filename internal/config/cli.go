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
	// Config file
	configPath = flag.String("c", "", "configuration file path")

	// CLI flags
	apiURL   = flag.String("api-url", "", "API base URL")
	nodes    nodeFlags
	logLevel = flag.String("log-level", "info", "log level: debug, info, warn, error")
)

func init() {
	flag.Var(&nodes, "node", "node configuration in format 'id:token' (can be specified multiple times)")
}

// LoadFromCLI loads configuration from CLI flags or config file
// Priority: CLI flags > config file
func LoadFromCLI() (*Config, error) {
	flag.Parse()

	// Check if CLI flags are provided
	if *apiURL != "" && len(nodes) > 0 {
		return buildConfigFromCLI()
	}

	// Fall back to config file
	configFile := *configPath
	if configFile == "" {
		configFile = "configs/config.yaml"
	}
	return Load(configFile)
}

// buildConfigFromCLI builds configuration from CLI flags
func buildConfigFromCLI() (*Config, error) {
	cfg := DefaultConfig()
	cfg.API.BaseURL = *apiURL
	cfg.Log.Level = *logLevel

	for _, n := range nodes {
		parts := strings.SplitN(n, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid --node format '%s', expected 'id:token'", n)
		}
		var id int
		if _, err := fmt.Sscanf(parts[0], "%d", &id); err != nil {
			return nil, fmt.Errorf("invalid node id '%s': %w", parts[0], err)
		}
		cfg.Nodes = append(cfg.Nodes, NodeInstance{
			ID:    id,
			Token: parts[1],
		})
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}
