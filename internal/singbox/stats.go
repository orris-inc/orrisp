package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// StatsClient Clash API traffic statistics client
type StatsClient struct {
	clashAPIAddr string
	httpClient   *http.Client
}

// Connection connection information
type Connection struct {
	ID          string         `json:"id"`
	Upload      int64          `json:"upload"`
	Download    int64          `json:"download"`
	Metadata    ConnectionMeta `json:"metadata"`
	Start       time.Time      `json:"start"`
	Chains      []string       `json:"chains"`
	Rule        string         `json:"rule"`
	RulePayload string         `json:"rulePayload"`
}

// ConnectionMeta connection metadata
type ConnectionMeta struct {
	Network         string `json:"network"`
	Type            string `json:"type"`
	SourceIP        string `json:"sourceIP"`
	DestinationIP   string `json:"destinationIP"`
	SourcePort      string `json:"sourcePort"`
	DestinationPort string `json:"destinationPort"`
	Host            string `json:"host"`
	DNSMode         string `json:"dnsMode"`
	ProcessPath     string `json:"processPath"`
	SpecialProxy    string `json:"specialProxy"`
	// User field identifies the user, corresponds to subscription UUID or username
	User string `json:"user"`
}

// ClashConnectionsResponse Clash API connections list response
type ClashConnectionsResponse struct {
	Connections   []Connection `json:"connections"`
	DownloadTotal int64        `json:"downloadTotal"`
	UploadTotal   int64        `json:"uploadTotal"`
}

// NewStatsClient creates traffic statistics client
func NewStatsClient(clashAPIAddr string) *StatsClient {
	return &StatsClient{
		clashAPIAddr: clashAPIAddr,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetConnections gets active connections list
func (c *StatsClient) GetConnections(ctx context.Context) ([]Connection, error) {
	result, err := c.GetConnectionsWithTotal(ctx)
	if err != nil {
		return nil, err
	}
	return result.Connections, nil
}

// GetConnectionsWithTotal gets active connections list and total traffic statistics
func (c *StatsClient) GetConnectionsWithTotal(ctx context.Context) (*ClashConnectionsResponse, error) {
	if c.clashAPIAddr == "" {
		return nil, fmt.Errorf("Clash API address not configured")
	}

	// Build request URL
	url := fmt.Sprintf("http://%s/connections", c.clashAPIAddr)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed, status code: %d", resp.StatusCode)
	}

	// Parse response
	var result ClashConnectionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// CloseConnection closes specified connection
func (c *StatsClient) CloseConnection(ctx context.Context, connectionID string) error {
	if c.clashAPIAddr == "" {
		return fmt.Errorf("Clash API address not configured")
	}

	// Build request URL
	url := fmt.Sprintf("http://%s/connections/%s", c.clashAPIAddr, connectionID)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status code
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to close connection, status code: %d", resp.StatusCode)
	}

	return nil
}
