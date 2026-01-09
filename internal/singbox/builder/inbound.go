package builder

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/easayliu/orrisp/internal/api"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// buildShadowsocksInbound builds Shadowsocks inbound configuration
func buildShadowsocksInbound(nodeConfig *api.NodeConfig, subscriptions []api.Subscription) (*option.Inbound, error) {
	// Validate port range
	if nodeConfig.ServerPort <= 0 || nodeConfig.ServerPort > 65535 {
		return nil, fmt.Errorf("invalid server port: %d", nodeConfig.ServerPort)
	}

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

	// Use ServerKey as server password if available, otherwise use first user's password.
	// Using first user's password is a fallback that may have security implications.
	serverPassword := nodeConfig.ServerKey
	if serverPassword == "" {
		serverPassword = subscriptions[0].Password
		slog.Warn("ServerKey not configured, using first user's password as server password. "+
			"Consider configuring a dedicated ServerKey for better security.",
			slog.String("protocol", "shadowsocks"),
		)
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
	// Validate port range
	if nodeConfig.ServerPort <= 0 || nodeConfig.ServerPort > 65535 {
		return nil, fmt.Errorf("invalid server port: %d", nodeConfig.ServerPort)
	}

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
	// Validate port range
	if nodeConfig.ServerPort <= 0 || nodeConfig.ServerPort > 65535 {
		return nil, fmt.Errorf("invalid server port: %d", nodeConfig.ServerPort)
	}

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

// buildVMessInbound builds VMess inbound configuration
func buildVMessInbound(nodeConfig *api.NodeConfig, subscriptions []api.Subscription) (*option.Inbound, error) {
	// Validate port range
	if nodeConfig.ServerPort <= 0 || nodeConfig.ServerPort > 65535 {
		return nil, fmt.Errorf("invalid server port: %d", nodeConfig.ServerPort)
	}

	// Parse listen address
	listenAddr, err := netip.ParseAddr(nodeConfig.ServerHost)
	if err != nil {
		return nil, fmt.Errorf("failed to parse listen address: %w", err)
	}

	// Build user list
	if len(subscriptions) == 0 {
		return nil, fmt.Errorf("no subscriptions available for vmess inbound")
	}

	users := make([]option.VMessUser, 0, len(subscriptions))
	for _, sub := range subscriptions {
		users = append(users, option.VMessUser{
			Name:    sub.Name,
			UUID:    sub.Password, // For VMess, password field contains UUID
			AlterId: nodeConfig.VMessAlterID,
		})
	}

	// Convert netip.Addr to badoption.Addr
	badAddr := badoption.Addr(listenAddr)

	inbound := &option.Inbound{
		Type: "vmess",
		Tag:  "vmess-in",
		Options: &option.VMessInboundOptions{
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
		},
	}

	// Add TLS configuration if enabled
	if nodeConfig.VMessTLS {
		vmessOpts := inbound.Options.(*option.VMessInboundOptions)
		vmessOpts.TLS = buildTLSOptions(nodeConfig)
	}

	return inbound, nil
}

// buildHysteria2Inbound builds Hysteria2 inbound configuration
func buildHysteria2Inbound(nodeConfig *api.NodeConfig, subscriptions []api.Subscription) (*option.Inbound, error) {
	// Validate port range
	if nodeConfig.ServerPort <= 0 || nodeConfig.ServerPort > 65535 {
		return nil, fmt.Errorf("invalid server port: %d", nodeConfig.ServerPort)
	}

	// Parse listen address
	listenAddr, err := netip.ParseAddr(nodeConfig.ServerHost)
	if err != nil {
		return nil, fmt.Errorf("failed to parse listen address: %w", err)
	}

	// Build user list
	if len(subscriptions) == 0 {
		return nil, fmt.Errorf("no subscriptions available for hysteria2 inbound")
	}

	users := make([]option.Hysteria2User, 0, len(subscriptions))
	for _, sub := range subscriptions {
		users = append(users, option.Hysteria2User{
			Name:     sub.Name,
			Password: sub.Password,
		})
	}

	// Convert netip.Addr to badoption.Addr
	badAddr := badoption.Addr(listenAddr)

	hysteria2Opts := &option.Hysteria2InboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     &badAddr,
			ListenPort: uint16(nodeConfig.ServerPort),
			//lint:ignore SA1019 InboundOptions is embedded in ListenOptions, still functional
			InboundOptions: option.InboundOptions{
				SniffEnabled:             true,
				SniffOverrideDestination: false,
			},
		},
		Users: users,
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: buildTLSOptions(nodeConfig),
		},
	}

	// Set bandwidth limits if configured
	if nodeConfig.Hysteria2UpMbps != nil && *nodeConfig.Hysteria2UpMbps > 0 {
		hysteria2Opts.UpMbps = *nodeConfig.Hysteria2UpMbps
	}
	if nodeConfig.Hysteria2DownMbps != nil && *nodeConfig.Hysteria2DownMbps > 0 {
		hysteria2Opts.DownMbps = *nodeConfig.Hysteria2DownMbps
	}

	// Set obfuscation if configured
	if nodeConfig.Hysteria2Obfs != "" && nodeConfig.Hysteria2ObfsPassword != "" {
		hysteria2Opts.Obfs = &option.Hysteria2Obfs{
			Type:     nodeConfig.Hysteria2Obfs,
			Password: nodeConfig.Hysteria2ObfsPassword,
		}
	}

	inbound := &option.Inbound{
		Type:    "hysteria2",
		Tag:     "hysteria2-in",
		Options: hysteria2Opts,
	}

	return inbound, nil
}

// buildTUICInbound builds TUIC inbound configuration
func buildTUICInbound(nodeConfig *api.NodeConfig, subscriptions []api.Subscription) (*option.Inbound, error) {
	// Validate port range
	if nodeConfig.ServerPort <= 0 || nodeConfig.ServerPort > 65535 {
		return nil, fmt.Errorf("invalid server port: %d", nodeConfig.ServerPort)
	}

	// Parse listen address
	listenAddr, err := netip.ParseAddr(nodeConfig.ServerHost)
	if err != nil {
		return nil, fmt.Errorf("failed to parse listen address: %w", err)
	}

	// Build user list
	if len(subscriptions) == 0 {
		return nil, fmt.Errorf("no subscriptions available for tuic inbound")
	}

	// For TUIC v5, both UUID and Password are required for authentication.
	// The Subscription.Password field stores the UUID value, and we use
	// the same value for both fields as per the backend design.
	users := make([]option.TUICUser, 0, len(subscriptions))
	for _, sub := range subscriptions {
		users = append(users, option.TUICUser{
			Name:     sub.Name,
			UUID:     sub.Password,
			Password: sub.Password,
		})
	}

	// Convert netip.Addr to badoption.Addr
	badAddr := badoption.Addr(listenAddr)

	tuicOpts := &option.TUICInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     &badAddr,
			ListenPort: uint16(nodeConfig.ServerPort),
			//lint:ignore SA1019 InboundOptions is embedded in ListenOptions, still functional
			InboundOptions: option.InboundOptions{
				SniffEnabled:             true,
				SniffOverrideDestination: false,
			},
		},
		Users: users,
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: buildTLSOptions(nodeConfig),
		},
	}

	// Set congestion control if configured
	if nodeConfig.TUICCongestionControl != "" {
		tuicOpts.CongestionControl = nodeConfig.TUICCongestionControl
	}

	inbound := &option.Inbound{
		Type:    "tuic",
		Tag:     "tuic-in",
		Options: tuicOpts,
	}

	return inbound, nil
}
