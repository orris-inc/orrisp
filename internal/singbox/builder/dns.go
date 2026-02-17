package builder

import (
	"log/slog"
	"net/url"

	"github.com/easayliu/orrisp/internal/api"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

// buildDNSConfig converts api.DnsConfig to sing-box DNSOptions.
func buildDNSConfig(dnsConfig *api.DnsConfig) *option.DNSOptions {
	if dnsConfig == nil {
		return nil
	}

	dnsOpts := &option.DNSOptions{
		RawDNSOptions: option.RawDNSOptions{
			Final:          dnsConfig.Final,
			ReverseMapping: dnsConfig.ReverseMapping,
			DNSClientOptions: option.DNSClientOptions{
				Strategy:         parseDomainStrategy(dnsConfig.Strategy),
				DisableCache:     dnsConfig.DisableCache,
				DisableExpire:    dnsConfig.DisableExpire,
				IndependentCache: dnsConfig.IndependentCache,
			},
		},
	}

	// Convert DNS servers, skip entries with empty tag (invalid config).
	for _, server := range dnsConfig.Servers {
		singServer := convertDNSServer(server)
		if singServer.Tag == "" {
			continue
		}
		dnsOpts.Servers = append(dnsOpts.Servers, singServer)
	}

	// Convert DNS rules
	for _, rule := range dnsConfig.Rules {
		singRule := convertDNSRule(rule)
		dnsOpts.Rules = append(dnsOpts.Rules, singRule)
	}

	return dnsOpts
}

// convertDNSServer converts api.DnsServer to sing-box DNSServerOptions.
// It parses the address URL scheme to determine the transport type and
// constructs the appropriate options struct.
func convertDNSServer(server api.DnsServer) option.DNSServerOptions {
	address := server.Address

	// Validate required fields to prevent generating invalid sing-box config.
	if server.Tag == "" {
		slog.Warn("DNS server has empty tag, skipping", "address", address)
		return option.DNSServerOptions{}
	}
	if address == "" {
		slog.Warn("DNS server has empty address, skipping", "tag", server.Tag)
		return option.DNSServerOptions{}
	}

	// url.Parse is very permissive in Go and almost never returns an error.
	// Even malformed inputs will produce a non-nil *url.URL with partial fields,
	// so the error is safe to discard here.
	serverURL, _ := url.Parse(address)

	// Determine server type from address scheme
	var serverType string
	if serverURL != nil && serverURL.Scheme != "" {
		serverType = serverURL.Scheme
	} else {
		switch address {
		case "local":
			serverType = C.DNSTypeLocal
		default:
			serverType = C.DNSTypeUDP
		}
	}

	// Build base remote options with detour and domain resolver
	baseLocal := option.LocalDNSServerOptions{
		DialerOptions: option.DialerOptions{
			Detour: server.Detour,
		},
	}
	if server.AddressResolver != "" {
		baseLocal.DialerOptions.DomainResolver = &option.DomainResolveOptions{
			Server:   server.AddressResolver,
			Strategy: parseDomainStrategy(server.AddressStrategy),
		}
	}

	baseRemote := option.RemoteDNSServerOptions{
		LocalDNSServerOptions: baseLocal,
	}

	// Parse server address and port from URL
	switch serverType {
	case C.DNSTypeLocal:
		return option.DNSServerOptions{
			Type:    C.DNSTypeLocal,
			Tag:     server.Tag,
			Options: &baseLocal,
		}

	case C.DNSTypeUDP:
		var serverAddr M.Socksaddr
		if serverURL == nil || serverURL.Scheme == "" {
			serverAddr = M.ParseSocksaddr(address)
		} else {
			// Use extractHost to guard against empty Host from malformed URLs like "udp://".
			serverAddr = M.ParseSocksaddr(extractHost(serverURL, address))
		}
		baseRemote.Server = serverAddr.AddrString()
		if serverAddr.Port != 0 && serverAddr.Port != 53 {
			baseRemote.ServerPort = serverAddr.Port
		}
		return option.DNSServerOptions{
			Type:    C.DNSTypeUDP,
			Tag:     server.Tag,
			Options: &baseRemote,
		}

	case C.DNSTypeTCP:
		if serverURL != nil {
			serverAddr := M.ParseSocksaddr(extractHost(serverURL, address))
			baseRemote.Server = serverAddr.AddrString()
			if serverAddr.Port != 0 && serverAddr.Port != 53 {
				baseRemote.ServerPort = serverAddr.Port
			}
		}
		return option.DNSServerOptions{
			Type:    C.DNSTypeTCP,
			Tag:     server.Tag,
			Options: &baseRemote,
		}

	case C.DNSTypeTLS, C.DNSTypeQUIC:
		if serverURL != nil {
			serverAddr := M.ParseSocksaddr(extractHost(serverURL, address))
			baseRemote.Server = serverAddr.AddrString()
			if serverAddr.Port != 0 && serverAddr.Port != 853 {
				baseRemote.ServerPort = serverAddr.Port
			}
		}
		return option.DNSServerOptions{
			Type: serverType,
			Tag:  server.Tag,
			Options: &option.RemoteTLSDNSServerOptions{
				RemoteDNSServerOptions: baseRemote,
			},
		}

	case C.DNSTypeHTTPS, C.DNSTypeHTTP3:
		httpsOpts := option.RemoteHTTPSDNSServerOptions{
			RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{
				RemoteDNSServerOptions: baseRemote,
			},
		}
		if serverURL != nil {
			serverAddr := M.ParseSocksaddr(extractHost(serverURL, address))
			httpsOpts.Server = serverAddr.AddrString()
			if serverAddr.Port != 0 && serverAddr.Port != 443 {
				httpsOpts.ServerPort = serverAddr.Port
			}
			// Only override path when it differs from the DoH default.
			if serverURL.Path != "" && serverURL.Path != "/dns-query" {
				httpsOpts.Path = serverURL.Path
			}
		}
		return option.DNSServerOptions{
			Type:    serverType,
			Tag:     server.Tag,
			Options: &httpsOpts,
		}

	default:
		// Fallback: treat as UDP
		baseRemote.Server = address
		return option.DNSServerOptions{
			Type:    C.DNSTypeUDP,
			Tag:     server.Tag,
			Options: &baseRemote,
		}
	}
}

// convertDNSRule converts api.DnsRule to sing-box DNSRule.
func convertDNSRule(rule api.DnsRule) option.DNSRule {
	defaultRule := option.DefaultDNSRule{
		RawDefaultDNSRule: option.RawDefaultDNSRule{},
		DNSRuleAction: option.DNSRuleAction{
			Action: C.RuleActionTypeRoute,
			RouteOptions: option.DNSRouteActionOptions{
				Server:       rule.Server,
				DisableCache: rule.DisableCache,
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

	// GeoIP/GeoSite matching
	if len(rule.Geosite) > 0 {
		defaultRule.Geosite = rule.Geosite
	}
	if len(rule.GeoIP) > 0 {
		defaultRule.GeoIP = rule.GeoIP
	}

	// Rule set reference
	if len(rule.RuleSet) > 0 {
		defaultRule.RuleSet = rule.RuleSet
	}

	// Outbound matching
	if len(rule.Outbound) > 0 {
		defaultRule.Outbound = rule.Outbound
	}

	return option.DNSRule{
		Type:           C.RuleTypeDefault,
		DefaultOptions: defaultRule,
	}
}

// extractHost returns the host portion from a parsed URL.
// Falls back to the raw address if the URL host is empty (e.g., "https://").
func extractHost(serverURL *url.URL, rawAddress string) string {
	if serverURL != nil && serverURL.Host != "" {
		return serverURL.Host
	}
	return rawAddress
}

// parseDomainStrategy converts a strategy string to sing-box DomainStrategy.
func parseDomainStrategy(strategy string) option.DomainStrategy {
	switch strategy {
	case "prefer_ipv4":
		return option.DomainStrategy(C.DomainStrategyPreferIPv4)
	case "prefer_ipv6":
		return option.DomainStrategy(C.DomainStrategyPreferIPv6)
	case "ipv4_only":
		return option.DomainStrategy(C.DomainStrategyIPv4Only)
	case "ipv6_only":
		return option.DomainStrategy(C.DomainStrategyIPv6Only)
	default:
		return option.DomainStrategy(C.DomainStrategyAsIS)
	}
}
