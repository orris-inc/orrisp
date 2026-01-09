// Package builder provides sing-box configuration generation utilities.
package builder

import (
	"fmt"

	"github.com/easayliu/orrisp/internal/api"
	"github.com/sagernet/sing-box/option"
)

// BuildConfig generates sing-box configuration based on node config and subscription list
// Supports multi-user configuration for shadowsocks and trojan protocols
func BuildConfig(nodeConfig *api.NodeConfig, subscriptions []api.Subscription, clashAPIAddr string) (*option.Options, error) {
	if nodeConfig == nil {
		return nil, fmt.Errorf("node configuration cannot be nil")
	}

	options := &option.Options{
		Log: &option.LogOptions{
			Disabled:  false,
			Level:     "info",   // info level shows connections, debug shows more details
			Output:    "stderr", // Output to stderr to separate from application logs
			Timestamp: true,
		},
	}

	// Configure Clash API for traffic statistics
	if clashAPIAddr != "" {
		options.Experimental = &option.ExperimentalOptions{
			ClashAPI: &option.ClashAPIOptions{
				ExternalController: clashAPIAddr,
				DefaultMode:        "rule",
			},
		}
	}

	// Build inbound configuration based on protocol type
	switch nodeConfig.Protocol {
	case "shadowsocks":
		inbound, err := buildShadowsocksInbound(nodeConfig, subscriptions)
		if err != nil {
			return nil, fmt.Errorf("failed to build shadowsocks inbound config: %w", err)
		}
		options.Inbounds = append(options.Inbounds, *inbound)

	case "trojan":
		inbound, err := buildTrojanInbound(nodeConfig, subscriptions)
		if err != nil {
			return nil, fmt.Errorf("failed to build trojan inbound config: %w", err)
		}
		options.Inbounds = append(options.Inbounds, *inbound)

	case "vless":
		inbound, err := buildVlessInbound(nodeConfig, subscriptions)
		if err != nil {
			return nil, fmt.Errorf("failed to build vless inbound config: %w", err)
		}
		options.Inbounds = append(options.Inbounds, *inbound)

	case "vmess":
		inbound, err := buildVMessInbound(nodeConfig, subscriptions)
		if err != nil {
			return nil, fmt.Errorf("failed to build vmess inbound config: %w", err)
		}
		options.Inbounds = append(options.Inbounds, *inbound)

	case "hysteria2":
		inbound, err := buildHysteria2Inbound(nodeConfig, subscriptions)
		if err != nil {
			return nil, fmt.Errorf("failed to build hysteria2 inbound config: %w", err)
		}
		options.Inbounds = append(options.Inbounds, *inbound)

	case "tuic":
		inbound, err := buildTUICInbound(nodeConfig, subscriptions)
		if err != nil {
			return nil, fmt.Errorf("failed to build tuic inbound config: %w", err)
		}
		options.Inbounds = append(options.Inbounds, *inbound)

	default:
		return nil, fmt.Errorf("unsupported protocol type: %s", nodeConfig.Protocol)
	}

	// Add default outbounds
	options.Outbounds = append(options.Outbounds,
		option.Outbound{
			Type: "direct",
			Tag:  "direct",
		},
		option.Outbound{
			Type: "block",
			Tag:  "block",
		},
		option.Outbound{
			Type: "direct",
			Tag:  "proxy", // proxy = normal proxy traffic (same as direct for inbound nodes)
		},
	)

	// Add custom outbounds from config (for node_xxx routing)
	for _, ob := range nodeConfig.Outbounds {
		singOutbound, err := convertOutbound(ob)
		if err != nil {
			return nil, fmt.Errorf("failed to convert outbound %s: %w", ob.Tag, err)
		}
		options.Outbounds = append(options.Outbounds, singOutbound)
	}

	// Add route configuration if present
	if nodeConfig.Route != nil {
		routeOpts := buildRouteConfig(nodeConfig.Route)
		options.Route = routeOpts
	}

	return options, nil
}

// buildTLSOptions builds TLS options with performance optimizations
func buildTLSOptions(nodeConfig *api.NodeConfig) *option.InboundTLSOptions {
	tlsOptions := &option.InboundTLSOptions{
		Enabled:    true,
		MinVersion: "1.3", // Force TLS 1.3 for better performance
		MaxVersion: "1.3", // Only use TLS 1.3
		ALPN: []string{
			"h2",       // HTTP/2 for better multiplexing
			"http/1.1", // HTTP/1.1 fallback
		},
	}
	if nodeConfig.SNI != "" {
		tlsOptions.ServerName = nodeConfig.SNI
	}
	if nodeConfig.AllowInsecure {
		tlsOptions.Insecure = true
	}
	return tlsOptions
}
