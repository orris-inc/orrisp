package api

import (
	"time"

	"github.com/orris-inc/orris/sdk/agent"
)

// Re-export SDK types for convenience
type (
	NodeConfig                = agent.NodeConfig
	Subscription              = agent.Subscription
	TrafficReport             = agent.TrafficReport
	NodeStatus                = agent.NodeStatus
	OnlineSubscription        = agent.OnlineSubscription
	TrafficReportResult       = agent.TrafficReportResult
	OnlineSubscriptionsResult = agent.OnlineSubscriptionsResult
)

// Client wraps the SDK agent client.
type Client = agent.Client

// Option is a functional option for configuring the Client.
type Option = agent.Option

// WithHTTPClient sets a custom HTTP client.
var WithHTTPClient = agent.WithHTTPClient

// WithTimeout sets the HTTP client timeout.
var WithTimeout = agent.WithTimeout

// NewClient creates a new API client with the given base URL, token, and node ID.
func NewClient(baseURL string, nodeID int, token string, opts ...Option) *Client {
	return agent.NewClient(baseURL, token, nodeID, opts...)
}

// NewClientWithTimeout creates a new API client with a custom timeout.
func NewClientWithTimeout(baseURL string, nodeID int, token string, timeout time.Duration) *Client {
	return agent.NewClient(baseURL, token, nodeID, agent.WithTimeout(timeout))
}
