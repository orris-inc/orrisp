package util

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// IPv4 detection services
var ipv4Services = []string{
	"https://api.ipify.org",
	"https://ipv4.icanhazip.com",
	"https://v4.ident.me",
}

// IPv6 detection services
var ipv6Services = []string{
	"https://api6.ipify.org",
	"https://ipv6.icanhazip.com",
	"https://v6.ident.me",
}

// GetPublicIPs detects both IPv4 and IPv6 public addresses concurrently.
func GetPublicIPs(ctx context.Context) (ipv4, ipv6 string) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		ipv4, _ = getPublicIPv4(ctx)
	}()

	go func() {
		defer wg.Done()
		ipv6, _ = getPublicIPv6(ctx)
	}()

	wg.Wait()
	return ipv4, ipv6
}

// getPublicIPv4 detects the public IPv4 address.
func getPublicIPv4(ctx context.Context) (string, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, url := range ipv4Services {
		ip, err := fetchIP(ctx, client, url)
		if err == nil && ip != "" && isIPv4(ip) {
			return ip, nil
		}
	}

	return "", nil
}

// getPublicIPv6 detects the public IPv6 address.
func getPublicIPv6(ctx context.Context) (string, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, url := range ipv6Services {
		ip, err := fetchIP(ctx, client, url)
		if err == nil && ip != "" && isIPv6(ip) {
			return ip, nil
		}
	}

	return "", nil
}

// fetchIP fetches the public IP from a single service.
func fetchIP(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}

	ip := strings.TrimSpace(string(body))
	return ip, nil
}

// isIPv4 checks if the given string is a valid IPv4 address.
func isIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
}

// isIPv6 checks if the given string is a valid IPv6 address.
func isIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}
