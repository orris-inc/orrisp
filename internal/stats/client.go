package stats

import (
	"sync"

	"github.com/easayliu/orrisp/internal/api"
)

// Client traffic statistics client
type Client struct {
	mu      sync.RWMutex
	traffic map[int]*TrafficData // subscription_id -> traffic
}

// TrafficData traffic data
type TrafficData struct {
	Upload   int64 // Upload bytes
	Download int64 // Download bytes
}

// NewClient creates new traffic statistics client
func NewClient() *Client {
	return &Client{
		traffic: make(map[int]*TrafficData),
	}
}

// RecordTraffic records traffic data
func (c *Client) RecordTraffic(subscriptionID int, upload, download int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.traffic[subscriptionID]; !exists {
		c.traffic[subscriptionID] = &TrafficData{}
	}

	c.traffic[subscriptionID].Upload += upload
	c.traffic[subscriptionID].Download += download
}

// GetAndResetTraffic gets and resets traffic statistics
// Returns traffic data for all subscriptions and clears statistics
func (c *Client) GetAndResetTraffic() []api.TrafficReport {
	c.mu.Lock()
	defer c.mu.Unlock()

	var items []api.TrafficReport
	for subID, data := range c.traffic {
		if data.Upload > 0 || data.Download > 0 {
			items = append(items, api.TrafficReport{
				SubscriptionID: subID,
				Upload:         data.Upload,
				Download:       data.Download,
			})
		}
	}

	// Clear statistics
	c.traffic = make(map[int]*TrafficData)

	return items
}

// GetTraffic gets traffic statistics (without reset)
func (c *Client) GetTraffic() []api.TrafficReport {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var items []api.TrafficReport
	for subID, data := range c.traffic {
		if data.Upload > 0 || data.Download > 0 {
			items = append(items, api.TrafficReport{
				SubscriptionID: subID,
				Upload:         data.Upload,
				Download:       data.Download,
			})
		}
	}

	return items
}

// Reset resets all traffic statistics
func (c *Client) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.traffic = make(map[int]*TrafficData)
}
