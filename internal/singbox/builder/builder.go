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

	case "anytls":
		inbound, err := buildAnyTLSInbound(nodeConfig, subscriptions)
		if err != nil {
			return nil, fmt.Errorf("failed to build anytls inbound config: %w", err)
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

	// Build merged route config from node-level route and per-forward-rule routes
	mergedRoute := mergeRouteConfigs(nodeConfig.Route, nodeConfig.ForwardRuleRoutes)

	// Add custom outbounds from merged route config
	if mergedRoute != nil {
		for _, co := range mergedRoute.CustomOutbounds {
			singOutbound, err := convertCustomOutbound(co)
			if err != nil {
				return nil, fmt.Errorf("failed to convert custom outbound %s: %w", co.Tag, err)
			}
			options.Outbounds = append(options.Outbounds, singOutbound)
		}

		routeOpts := buildRouteConfig(mergedRoute)
		options.Route = routeOpts
	}

	// Add DNS configuration if present
	if nodeConfig.DNS != nil {
		dnsOpts := buildDNSConfig(nodeConfig.DNS)
		options.DNS = dnsOpts
	}

	return options, nil
}

// mergeRouteConfigs merges the node-level route config with per-forward-rule route configs.
// Forward-rule routes contribute their rules, custom outbounds, and rule-set entries
// into a single RouteConfig so sing-box sees one unified routing table.
func mergeRouteConfigs(nodeRoute *api.RouteConfig, forwardRuleRoutes []api.ForwardRuleRoute) *api.RouteConfig {
	if nodeRoute == nil && len(forwardRuleRoutes) == 0 {
		return nil
	}

	merged := &api.RouteConfig{}
	if nodeRoute != nil {
		merged.Rules = append(merged.Rules, nodeRoute.Rules...)
		merged.Final = nodeRoute.Final
		merged.CustomOutbounds = append(merged.CustomOutbounds, nodeRoute.CustomOutbounds...)
		merged.RuleSetEntries = append(merged.RuleSetEntries, nodeRoute.RuleSetEntries...)
	}

	for _, frr := range forwardRuleRoutes {
		if frr.Route == nil {
			continue
		}
		merged.Rules = append(merged.Rules, frr.Route.Rules...)
		merged.CustomOutbounds = append(merged.CustomOutbounds, frr.Route.CustomOutbounds...)
		merged.RuleSetEntries = append(merged.RuleSetEntries, frr.Route.RuleSetEntries...)

		// Convert per-forward-rule Final into a catch-all rule with inbound matching.
		// sing-box only supports one global Final, so we emit an inbound-scoped
		// fallback rule to preserve per-forward-rule default routing behavior.
		if frr.Route.Final != "" && frr.RuleSID != "" {
			merged.Rules = append(merged.Rules, api.RouteRule{
				Inbound:  []string{frr.RuleSID},
				Outbound: frr.Route.Final,
			})
		}
	}

	return merged
}

// buildTLSOptions builds TLS options with compatibility settings.
// For VLESS with Reality security, it configures Reality-specific options.
func buildTLSOptions(nodeConfig *api.NodeConfig) *option.InboundTLSOptions {
	tlsOptions := &option.InboundTLSOptions{
		Enabled:    true,
		MinVersion: "1.2", // Allow TLS 1.2 for compatibility
		MaxVersion: "1.3", // Prefer TLS 1.3
	}
	if nodeConfig.SNI != "" {
		tlsOptions.ServerName = nodeConfig.SNI
	}
	if nodeConfig.AllowInsecure {
		tlsOptions.Insecure = true
	}

	// Configure Reality for VLESS if security type is "reality"
	if nodeConfig.VLESSSecurity == "reality" && nodeConfig.VLESSRealityPrivateKey != "" {
		tlsOptions.Reality = &option.InboundRealityOptions{
			Enabled:    true,
			PrivateKey: nodeConfig.VLESSRealityPrivateKey,
			ShortID:    []string{nodeConfig.VLESSRealityShortID},
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{
					Server:     nodeConfig.SNI, // Use SNI as handshake server for TLS camouflage
					ServerPort: 443,
				},
			},
		}
	}

	return tlsOptions
}
