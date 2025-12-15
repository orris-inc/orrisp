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

	// Add default outbound
	options.Outbounds = append(options.Outbounds, option.Outbound{
		Type: "direct",
		Tag:  "direct",
	})

	return options, nil
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
	users := make([]option.TrojanUser, 0, len(subscriptions))
	for _, sub := range subscriptions {
		users = append(users, option.TrojanUser{
			Name:     sub.Name,
			Password: sub.Password,
		})
	}

	// Convert netip.Addr to badoption.Addr
	badAddr := badoption.Addr(listenAddr)

	// Build TLS options with performance optimizations
	tlsOptions := &option.InboundTLSOptions{
		Enabled:    true,
		MinVersion: "1.3", // Force TLS 1.3 for better performance
		MaxVersion: "1.3", // Only use TLS 1.3
		ALPN: []string{ // Application-Layer Protocol Negotiation
			"h2",       // HTTP/2 for better multiplexing
			"http/1.1", // HTTP/1.1 fallback
		},
		ECH: nil, // Encrypted Client Hello (optional, for privacy)
	}
	if nodeConfig.SNI != "" {
		tlsOptions.ServerName = nodeConfig.SNI
	}
	if nodeConfig.AllowInsecure {
		tlsOptions.Insecure = true
	}

	inbound := &option.Inbound{
		Type: "trojan",
		Tag:  "trojan-in",
		Options: &option.TrojanInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     &badAddr,
				ListenPort: uint16(nodeConfig.ServerPort),
				InboundOptions: option.InboundOptions{
					SniffEnabled:             true,  // Enable sniffing to detect destination domain
					SniffOverrideDestination: false, // Keep original destination
				},
			},
			Users: users,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: tlsOptions,
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
	users := make([]option.VLESSUser, 0, len(subscriptions))
	for _, sub := range subscriptions {
		users = append(users, option.VLESSUser{
			Name: sub.Name,
			UUID: sub.Password, // For VLESS, password field contains UUID
		})
	}

	// Convert netip.Addr to badoption.Addr
	badAddr := badoption.Addr(listenAddr)

	// Build TLS options with performance optimizations
	tlsOptions := &option.InboundTLSOptions{
		Enabled:    true,
		MinVersion: "1.3", // Force TLS 1.3 for better performance
		MaxVersion: "1.3", // Only use TLS 1.3
		ALPN: []string{ // Application-Layer Protocol Negotiation
			"h2",       // HTTP/2 for better multiplexing
			"http/1.1", // HTTP/1.1 fallback
		},
		ECH: nil, // Encrypted Client Hello (optional, for privacy)
	}
	if nodeConfig.SNI != "" {
		tlsOptions.ServerName = nodeConfig.SNI
	}
	if nodeConfig.AllowInsecure {
		tlsOptions.Insecure = true
	}

	inbound := &option.Inbound{
		Type: "vless",
		Tag:  "vless-in",
		Options: &option.VLESSInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     &badAddr,
				ListenPort: uint16(nodeConfig.ServerPort),
				InboundOptions: option.InboundOptions{
					SniffEnabled:             true,  // Enable sniffing to detect destination domain
					SniffOverrideDestination: false, // Keep original destination
				},
			},
			Users: users,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: tlsOptions,
			},
		},
	}

	return inbound, nil
}
