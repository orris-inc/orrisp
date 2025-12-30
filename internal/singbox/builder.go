package singbox

import (
	"fmt"
	"net/netip"

	"github.com/easayliu/orrisp/internal/api"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
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

// buildShadowsocksInbound builds Shadowsocks inbound configuration
func buildShadowsocksInbound(nodeConfig *api.NodeConfig, subscriptions []api.Subscription) (*option.Inbound, error) {
	// Parse listen address
	listenAddr, err := netip.ParseAddr(nodeConfig.ServerHost)
	if err != nil {
		return nil, fmt.Errorf("failed to parse listen address: %w", err)
	}

	// Build user list
	if len(subscriptions) == 0 {
		return nil, fmt.Errorf("no subscriptions available for shadowsocks inbound")
	}

	users := make([]option.ShadowsocksUser, 0, len(subscriptions))
	for _, sub := range subscriptions {
		users = append(users, option.ShadowsocksUser{
			Name:     sub.Name,
			Password: sub.Password,
		})
	}

	// Use ServerKey as server password if available, otherwise use first user's password
	serverPassword := nodeConfig.ServerKey
	if serverPassword == "" {
		serverPassword = subscriptions[0].Password
	}

	// Convert netip.Addr to badoption.Addr
	badAddr := badoption.Addr(listenAddr)

	inbound := &option.Inbound{
		Type: "shadowsocks",
		Tag:  "ss-in",
		Options: &option.ShadowsocksInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     &badAddr,
				ListenPort: uint16(nodeConfig.ServerPort),
				//lint:ignore SA1019 InboundOptions is embedded in ListenOptions, still functional
				InboundOptions: option.InboundOptions{
					SniffEnabled:             true,  // Enable sniffing to detect destination domain
					SniffOverrideDestination: false, // Keep original destination
				},
			},
			Method:   nodeConfig.EncryptionMethod,
			Password: serverPassword,
			Users:    users,
		},
	}

	return inbound, nil
}

// buildTrojanInbound builds Trojan inbound configuration
func buildTrojanInbound(nodeConfig *api.NodeConfig, subscriptions []api.Subscription) (*option.Inbound, error) {
	// Parse listen address
	listenAddr, err := netip.ParseAddr(nodeConfig.ServerHost)
	if err != nil {
		return nil, fmt.Errorf("failed to parse listen address: %w", err)
	}

	// Build user list
	if len(subscriptions) == 0 {
		return nil, fmt.Errorf("no subscriptions available for trojan inbound")
	}

	users := make([]option.TrojanUser, 0, len(subscriptions))
	for _, sub := range subscriptions {
		users = append(users, option.TrojanUser{
			Name:     sub.Name,
			Password: sub.Password,
		})
	}

	// Convert netip.Addr to badoption.Addr
	badAddr := badoption.Addr(listenAddr)

	inbound := &option.Inbound{
		Type: "trojan",
		Tag:  "trojan-in",
		Options: &option.TrojanInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     &badAddr,
				ListenPort: uint16(nodeConfig.ServerPort),
				//lint:ignore SA1019 InboundOptions is embedded in ListenOptions, still functional
				InboundOptions: option.InboundOptions{
					SniffEnabled:             true,  // Enable sniffing to detect destination domain
					SniffOverrideDestination: false, // Keep original destination
				},
			},
			Users: users,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: buildTLSOptions(nodeConfig),
			},
		},
	}

	return inbound, nil
}

// buildVlessInbound builds VLESS inbound configuration
func buildVlessInbound(nodeConfig *api.NodeConfig, subscriptions []api.Subscription) (*option.Inbound, error) {
	// Parse listen address
	listenAddr, err := netip.ParseAddr(nodeConfig.ServerHost)
	if err != nil {
		return nil, fmt.Errorf("failed to parse listen address: %w", err)
	}

	// Build user list
	if len(subscriptions) == 0 {
		return nil, fmt.Errorf("no subscriptions available for vless inbound")
	}

	users := make([]option.VLESSUser, 0, len(subscriptions))
	for _, sub := range subscriptions {
		users = append(users, option.VLESSUser{
			Name: sub.Name,
			UUID: sub.Password, // For VLESS, password field contains UUID
		})
	}

	// Convert netip.Addr to badoption.Addr
	badAddr := badoption.Addr(listenAddr)

	inbound := &option.Inbound{
		Type: "vless",
		Tag:  "vless-in",
		Options: &option.VLESSInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     &badAddr,
				ListenPort: uint16(nodeConfig.ServerPort),
				//lint:ignore SA1019 InboundOptions is embedded in ListenOptions, still functional
				InboundOptions: option.InboundOptions{
					SniffEnabled:             true,  // Enable sniffing to detect destination domain
					SniffOverrideDestination: false, // Keep original destination
				},
			},
			Users: users,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: buildTLSOptions(nodeConfig),
			},
		},
	}

	return inbound, nil
}

// buildRouteConfig converts api.RouteConfig to sing-box RouteOptions
func buildRouteConfig(routeConfig *api.RouteConfig) *option.RouteOptions {
	if routeConfig == nil {
		return nil
	}

	routeOpts := &option.RouteOptions{
		Final:               routeConfig.Final,
		AutoDetectInterface: true,
	}

	// Convert rules
	for _, rule := range routeConfig.Rules {
		singRule := convertRouteRule(rule)
		routeOpts.Rules = append(routeOpts.Rules, singRule)
	}

	return routeOpts
}

// convertRouteRule converts a single api.RouteRule to sing-box Rule
func convertRouteRule(rule api.RouteRule) option.Rule {
	defaultRule := option.DefaultRule{
		RawDefaultRule: option.RawDefaultRule{},
		RuleAction: option.RuleAction{
			Action: "route",
			RouteOptions: option.RouteActionOptions{
				Outbound: rule.Outbound,
			},
		},
	}

	// Domain matching
	if len(rule.Domain) > 0 {
		defaultRule.Domain = rule.Domain
	}
	if len(rule.DomainSuffix) > 0 {
		defaultRule.DomainSuffix = rule.DomainSuffix
	}
	if len(rule.DomainKeyword) > 0 {
		defaultRule.DomainKeyword = rule.DomainKeyword
	}
	if len(rule.DomainRegex) > 0 {
		defaultRule.DomainRegex = rule.DomainRegex
	}

	// IP matching
	if len(rule.IPCIDR) > 0 {
		defaultRule.IPCIDR = rule.IPCIDR
	}
	if len(rule.SourceIPCIDR) > 0 {
		defaultRule.SourceIPCIDR = rule.SourceIPCIDR
	}
	if rule.IPIsPrivate {
		defaultRule.IPIsPrivate = true
	}

	// GeoIP/GeoSite matching
	if len(rule.GeoIP) > 0 {
		defaultRule.GeoIP = rule.GeoIP
	}
	if len(rule.GeoSite) > 0 {
		defaultRule.Geosite = rule.GeoSite
	}

	// Port matching - convert int to uint16
	if len(rule.Port) > 0 {
		ports := make([]uint16, 0, len(rule.Port))
		for _, p := range rule.Port {
			ports = append(ports, uint16(p))
		}
		defaultRule.Port = ports
	}
	if len(rule.SourcePort) > 0 {
		ports := make([]uint16, 0, len(rule.SourcePort))
		for _, p := range rule.SourcePort {
			ports = append(ports, uint16(p))
		}
		defaultRule.SourcePort = ports
	}

	// Protocol/Network matching
	if len(rule.Protocol) > 0 {
		defaultRule.Protocol = rule.Protocol
	}
	if len(rule.Network) > 0 {
		defaultRule.Network = rule.Network
	}

	// Rule set reference
	if len(rule.RuleSet) > 0 {
		defaultRule.RuleSet = rule.RuleSet
	}

	return option.Rule{
		Type:           "",
		DefaultOptions: defaultRule,
	}
}

// convertOutbound converts api.Outbound to sing-box option.Outbound
func convertOutbound(ob api.Outbound) (option.Outbound, error) {
	outbound := option.Outbound{
		Tag:  ob.Tag,
		Type: ob.Type,
	}

	// Validate required fields for proxy types
	switch ob.Type {
	case "shadowsocks", "trojan":
		if ob.Server == "" {
			return outbound, fmt.Errorf("server address is required for %s outbound %q (received: server=%q, port=%d)", ob.Type, ob.Tag, ob.Server, ob.Port)
		}
		if ob.Port <= 0 {
			return outbound, fmt.Errorf("server port is required for %s outbound %q (received: server=%q, port=%d)", ob.Type, ob.Tag, ob.Server, ob.Port)
		}
		if ob.Password == "" {
			return outbound, fmt.Errorf("password is required for %s outbound %q", ob.Type, ob.Tag)
		}
	}

	switch ob.Type {
	case "shadowsocks":
		ssOpts := option.ShadowsocksOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     ob.Server,
				ServerPort: uint16(ob.Port),
			},
			Method:   ob.Method,
			Password: ob.Password,
		}
		outbound.Options = &ssOpts

	case "trojan":
		trojanOpts := option.TrojanOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     ob.Server,
				ServerPort: uint16(ob.Port),
			},
			Password: ob.Password,
		}
		if ob.TLS != nil {
			trojanOpts.TLS = &option.OutboundTLSOptions{
				Enabled:    ob.TLS.Enabled,
				ServerName: ob.TLS.ServerName,
				Insecure:   ob.TLS.Insecure,
				DisableSNI: ob.TLS.DisableSNI,
				ALPN:       ob.TLS.ALPN,
			}
		}
		if ob.Transport != nil {
			trojanOpts.Transport = convertOutboundTransport(ob.Transport)
		}
		outbound.Options = &trojanOpts

	case "direct", "block":
		// Simple types, no additional configuration needed

	default:
		return outbound, fmt.Errorf("unsupported outbound type: %s", ob.Type)
	}

	return outbound, nil
}

// convertOutboundTransport converts api.OutboundTransport to sing-box V2RayTransportOptions
func convertOutboundTransport(t *api.OutboundTransport) *option.V2RayTransportOptions {
	if t == nil {
		return nil
	}

	transport := &option.V2RayTransportOptions{
		Type: t.Type,
	}

	switch t.Type {
	case "ws":
		transport.WebsocketOptions = option.V2RayWebsocketOptions{
			Path: t.Path,
		}
		if len(t.Headers) > 0 {
			headers := make(badoption.HTTPHeader)
			for k, v := range t.Headers {
				headers[k] = badoption.Listable[string]{v}
			}
			transport.WebsocketOptions.Headers = headers
		}
	case "grpc":
		transport.GRPCOptions = option.V2RayGRPCOptions{
			ServiceName: t.ServiceName,
		}
	}

	return transport
}
