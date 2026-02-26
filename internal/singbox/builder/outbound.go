package builder

import (
	"fmt"
	"time"

	"github.com/easayliu/orrisp/internal/api"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

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

	// Port matching - convert int to uint16 with validation
	// Invalid ports (<=0 or >65535) are silently skipped to avoid breaking routing
	if len(rule.Port) > 0 {
		ports := make([]uint16, 0, len(rule.Port))
		for _, p := range rule.Port {
			if p > 0 && p <= 65535 {
				ports = append(ports, uint16(p))
			}
		}
		if len(ports) > 0 {
			defaultRule.Port = ports
		}
	}
	if len(rule.SourcePort) > 0 {
		ports := make([]uint16, 0, len(rule.SourcePort))
		for _, p := range rule.SourcePort {
			if p > 0 && p <= 65535 {
				ports = append(ports, uint16(p))
			}
		}
		if len(ports) > 0 {
			defaultRule.SourcePort = ports
		}
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
		if ob.Port <= 0 || ob.Port > 65535 {
			return outbound, fmt.Errorf("invalid server port for %s outbound %q (received: server=%q, port=%d)", ob.Type, ob.Tag, ob.Server, ob.Port)
		}
		if ob.Password == "" {
			return outbound, fmt.Errorf("password is required for %s outbound %q", ob.Type, ob.Tag)
		}
	case "vless", "vmess":
		if ob.Server == "" {
			return outbound, fmt.Errorf("server address is required for %s outbound %q", ob.Type, ob.Tag)
		}
		if ob.Port <= 0 || ob.Port > 65535 {
			return outbound, fmt.Errorf("invalid server port for %s outbound %q", ob.Type, ob.Tag)
		}
		if ob.UUID == "" {
			return outbound, fmt.Errorf("uuid is required for %s outbound %q", ob.Type, ob.Tag)
		}
	case "tuic":
		if ob.Server == "" {
			return outbound, fmt.Errorf("server address is required for %s outbound %q", ob.Type, ob.Tag)
		}
		if ob.Port <= 0 || ob.Port > 65535 {
			return outbound, fmt.Errorf("invalid server port for %s outbound %q", ob.Type, ob.Tag)
		}
		if ob.UUID == "" {
			return outbound, fmt.Errorf("uuid is required for %s outbound %q", ob.Type, ob.Tag)
		}
		if ob.Password == "" {
			return outbound, fmt.Errorf("password is required for %s outbound %q", ob.Type, ob.Tag)
		}
	case "hysteria2":
		if ob.Server == "" {
			return outbound, fmt.Errorf("server address is required for %s outbound %q", ob.Type, ob.Tag)
		}
		if ob.Port <= 0 || ob.Port > 65535 {
			return outbound, fmt.Errorf("invalid server port for %s outbound %q", ob.Type, ob.Tag)
		}
		if ob.Password == "" {
			return outbound, fmt.Errorf("password is required for %s outbound %q", ob.Type, ob.Tag)
		}
	case "anytls":
		if ob.Server == "" {
			return outbound, fmt.Errorf("server address is required for %s outbound %q", ob.Type, ob.Tag)
		}
		if ob.Port <= 0 || ob.Port > 65535 {
			return outbound, fmt.Errorf("invalid server port for %s outbound %q", ob.Type, ob.Tag)
		}
		if ob.Password == "" {
			return outbound, fmt.Errorf("password is required for %s outbound %q", ob.Type, ob.Tag)
		}
	case "socks", "http":
		if ob.Server == "" {
			return outbound, fmt.Errorf("server address is required for %s outbound %q", ob.Type, ob.Tag)
		}
		if ob.Port <= 0 || ob.Port > 65535 {
			return outbound, fmt.Errorf("invalid server port for %s outbound %q", ob.Type, ob.Tag)
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
			trojanOpts.TLS = convertOutboundTLS(ob.TLS)
		}
		if ob.Transport != nil {
			trojanOpts.Transport = convertOutboundTransport(ob.Transport)
		}
		outbound.Options = &trojanOpts

	case "vless":
		vlessOpts := option.VLESSOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     ob.Server,
				ServerPort: uint16(ob.Port),
			},
			UUID: ob.UUID,
			Flow: ob.VLESSFlow,
		}
		if ob.TLS != nil {
			vlessOpts.TLS = convertOutboundTLS(ob.TLS)
		}
		if ob.Transport != nil {
			vlessOpts.Transport = convertOutboundTransport(ob.Transport)
		}
		outbound.Options = &vlessOpts

	case "vmess":
		vmessOpts := option.VMessOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     ob.Server,
				ServerPort: uint16(ob.Port),
			},
			UUID:     ob.UUID,
			Security: ob.VMessSecurity,
			AlterId:  ob.VMessAlterID,
		}
		if ob.TLS != nil {
			vmessOpts.TLS = convertOutboundTLS(ob.TLS)
		}
		if ob.Transport != nil {
			vmessOpts.Transport = convertOutboundTransport(ob.Transport)
		}
		outbound.Options = &vmessOpts

	case "hysteria2":
		hysteria2Opts := option.Hysteria2OutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     ob.Server,
				ServerPort: uint16(ob.Port),
			},
			Password: ob.Password,
		}
		if ob.TLS != nil {
			hysteria2Opts.TLS = convertOutboundTLS(ob.TLS)
		}
		// Set obfuscation if configured
		if ob.Hysteria2Obfs != "" && ob.Hysteria2ObfsPassword != "" {
			hysteria2Opts.Obfs = &option.Hysteria2Obfs{
				Type:     ob.Hysteria2Obfs,
				Password: ob.Hysteria2ObfsPassword,
			}
		}
		// Set bandwidth limits if configured
		if ob.Hysteria2UpMbps != nil && *ob.Hysteria2UpMbps > 0 {
			hysteria2Opts.UpMbps = *ob.Hysteria2UpMbps
		}
		if ob.Hysteria2DownMbps != nil && *ob.Hysteria2DownMbps > 0 {
			hysteria2Opts.DownMbps = *ob.Hysteria2DownMbps
		}
		outbound.Options = &hysteria2Opts

	case "tuic":
		tuicOpts := option.TUICOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     ob.Server,
				ServerPort: uint16(ob.Port),
			},
			UUID:     ob.UUID,
			Password: ob.Password,
		}
		if ob.TLS != nil {
			tuicOpts.TLS = convertOutboundTLS(ob.TLS)
		}
		// Set congestion control if configured
		if ob.TUICCongestionControl != "" {
			tuicOpts.CongestionControl = ob.TUICCongestionControl
		}
		// Set UDP relay mode if configured
		if ob.TUICUDPRelayMode != "" {
			tuicOpts.UDPRelayMode = ob.TUICUDPRelayMode
		}
		outbound.Options = &tuicOpts

	case "anytls":
		anytlsOpts := option.AnyTLSOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     ob.Server,
				ServerPort: uint16(ob.Port),
			},
			Password: ob.Password,
		}
		if ob.TLS != nil {
			tlsOpts := convertOutboundTLS(ob.TLS)
			// Set UTLS fingerprint for AnyTLS if configured
			if ob.AnyTLSFingerprint != "" {
				if tlsOpts.UTLS == nil {
					tlsOpts.UTLS = &option.OutboundUTLSOptions{}
				}
				tlsOpts.UTLS.Fingerprint = ob.AnyTLSFingerprint
			}
			anytlsOpts.TLS = tlsOpts
		}
		if ob.AnyTLSIdleSessionCheckInterval != "" {
			d, err := time.ParseDuration(ob.AnyTLSIdleSessionCheckInterval)
			if err != nil {
				return outbound, fmt.Errorf("invalid idle_session_check_interval %q for anytls outbound %q: %w",
					ob.AnyTLSIdleSessionCheckInterval, ob.Tag, err)
			}
			anytlsOpts.IdleSessionCheckInterval = badoption.Duration(d)
		}
		if ob.AnyTLSIdleSessionTimeout != "" {
			d, err := time.ParseDuration(ob.AnyTLSIdleSessionTimeout)
			if err != nil {
				return outbound, fmt.Errorf("invalid idle_session_timeout %q for anytls outbound %q: %w",
					ob.AnyTLSIdleSessionTimeout, ob.Tag, err)
			}
			anytlsOpts.IdleSessionTimeout = badoption.Duration(d)
		}
		if ob.AnyTLSMinIdleSession > 0 {
			anytlsOpts.MinIdleSession = ob.AnyTLSMinIdleSession
		}
		outbound.Options = &anytlsOpts

	case "socks":
		socksOpts := option.SOCKSOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     ob.Server,
				ServerPort: uint16(ob.Port),
			},
			Version:  ob.Version,
			Username: ob.Username,
			Password: ob.Password,
		}
		outbound.Options = &socksOpts

	case "http":
		httpOpts := option.HTTPOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     ob.Server,
				ServerPort: uint16(ob.Port),
			},
			Username: ob.Username,
			Password: ob.Password,
		}
		if ob.TLS != nil {
			httpOpts.TLS = convertOutboundTLS(ob.TLS)
		}
		outbound.Options = &httpOpts

	case "direct", "block":
		// Simple types, no additional configuration needed

	default:
		return outbound, fmt.Errorf("unsupported outbound type: %s", ob.Type)
	}

	return outbound, nil
}

// convertCustomOutbound converts api.CustomOutbound to sing-box option.Outbound.
// CustomOutbound uses a Settings map for protocol-specific configuration.
func convertCustomOutbound(co api.CustomOutbound) (option.Outbound, error) {
	outbound := option.Outbound{
		Tag:  co.Tag,
		Type: co.Type,
	}

	// Helper to extract string value from settings
	getString := func(key string) string {
		if v, ok := co.Settings[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}

	// Validate required fields for proxy types
	switch co.Type {
	case "socks", "http":
		if co.Server == "" {
			return outbound, fmt.Errorf("server address is required for %s custom outbound %q", co.Type, co.Tag)
		}
		if co.Port <= 0 || co.Port > 65535 {
			return outbound, fmt.Errorf("invalid server port for %s custom outbound %q", co.Type, co.Tag)
		}
	}

	switch co.Type {
	case "socks":
		socksOpts := option.SOCKSOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     co.Server,
				ServerPort: uint16(co.Port),
			},
			Version:  getString("version"),
			Username: getString("username"),
			Password: getString("password"),
		}
		outbound.Options = &socksOpts

	case "http":
		httpOpts := option.HTTPOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     co.Server,
				ServerPort: uint16(co.Port),
			},
			Username: getString("username"),
			Password: getString("password"),
		}
		outbound.Options = &httpOpts

	case "direct", "block":
		// Simple types, no additional configuration needed

	default:
		return outbound, fmt.Errorf("unsupported custom outbound type: %s", co.Type)
	}

	return outbound, nil
}

// convertOutboundTLS converts api.OutboundTLS to sing-box OutboundTLSOptions
func convertOutboundTLS(tls *api.OutboundTLS) *option.OutboundTLSOptions {
	if tls == nil {
		return nil
	}

	tlsOpts := &option.OutboundTLSOptions{
		Enabled:    tls.Enabled,
		ServerName: tls.ServerName,
		Insecure:   tls.Insecure,
		DisableSNI: tls.DisableSNI,
		ALPN:       tls.ALPN,
	}

	// Handle Reality configuration for VLESS
	if tls.Reality != nil && tls.Reality.Enabled {
		tlsOpts.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: tls.Reality.PublicKey,
			ShortID:   tls.Reality.ShortID,
		}
	}

	return tlsOpts
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
