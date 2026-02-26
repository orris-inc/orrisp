package singbox

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/easayliu/orrisp/internal/api"
	"github.com/easayliu/orrisp/internal/stats"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// onlineKey identifies a unique (subscription, source IP) pair for online tracking.
type onlineKey struct {
	subscriptionSID string
	ip              string
}

// TrafficTracker implements adapter.ConnectionTracker for traffic statistics
type TrafficTracker struct {
	statsClient *stats.Client
	logger      *slog.Logger
	userMu      sync.RWMutex       // protects userMap
	userMap     map[string]string   // username -> subscription_sid
	onlineMu    sync.RWMutex       // protects onlineMap
	onlineMap   map[onlineKey]int   // active connection reference counts
}

// NewTrafficTracker creates a new traffic tracker
func NewTrafficTracker(statsClient *stats.Client, logger *slog.Logger) *TrafficTracker {
	return &TrafficTracker{
		statsClient: statsClient,
		logger:      logger,
		userMap:     make(map[string]string),
		onlineMap:   make(map[onlineKey]int),
	}
}

// SetUserMap sets the username to subscription SID mapping
func (t *TrafficTracker) SetUserMap(userMap map[string]string) {
	t.userMu.Lock()
	defer t.userMu.Unlock()
	t.userMap = userMap
	t.logger.Debug("User map updated",
		slog.Int("user_count", len(userMap)),
	)
}

// getSubscriptionSID returns the subscription SID for a username
func (t *TrafficTracker) getSubscriptionSID(username string) (string, bool) {
	t.userMu.RLock()
	defer t.userMu.RUnlock()
	sid, ok := t.userMap[username]
	return sid, ok
}

// trackConnection increments the reference count for a (sid, ip) pair.
func (t *TrafficTracker) trackConnection(sid, ip string) {
	t.onlineMu.Lock()
	defer t.onlineMu.Unlock()
	t.onlineMap[onlineKey{subscriptionSID: sid, ip: ip}]++
}

// untrackConnection decrements the reference count and removes the entry when it reaches zero.
func (t *TrafficTracker) untrackConnection(sid, ip string) {
	t.onlineMu.Lock()
	defer t.onlineMu.Unlock()
	key := onlineKey{subscriptionSID: sid, ip: ip}
	if t.onlineMap[key] <= 1 {
		delete(t.onlineMap, key)
	} else {
		t.onlineMap[key]--
	}
}

// GetOnlineSubscriptions returns a snapshot of currently active (subscription, ip) pairs.
func (t *TrafficTracker) GetOnlineSubscriptions() []api.OnlineSubscription {
	t.onlineMu.RLock()
	defer t.onlineMu.RUnlock()
	result := make([]api.OnlineSubscription, 0, len(t.onlineMap))
	for key := range t.onlineMap {
		result = append(result, api.OnlineSubscription{
			SubscriptionSID: key.subscriptionSID,
			IP:              key.ip,
		})
	}
	return result
}

// RoutedConnection wraps a TCP connection to track traffic
func (t *TrafficTracker) RoutedConnection(
	ctx context.Context,
	conn net.Conn,
	metadata adapter.InboundContext,
	matchedRule adapter.Rule,
	matchOutbound adapter.Outbound,
) net.Conn {
	username := metadata.User

	if username == "" {
		return conn
	}

	subSID, ok := t.getSubscriptionSID(username)
	if !ok {
		t.logger.Warn("User not found in mapping",
			slog.String("user", username),
		)
		return conn
	}

	sourceIP := metadata.Source.Addr.Unmap().String()
	t.trackConnection(subSID, sourceIP)

	t.logger.Debug("Connection tracked",
		slog.String("user", username),
		slog.String("subscription_sid", subSID),
		slog.String("source_ip", sourceIP),
		slog.String("inbound", metadata.Inbound),
		slog.String("destination", metadata.Destination.String()),
	)
	return &countingConn{
		Conn:            conn,
		statsClient:     t.statsClient,
		subscriptionSID: subSID,
		logger:          t.logger,
		tracker:         t,
		sourceIP:        sourceIP,
	}
}

// RoutedPacketConnection wraps a UDP connection to track traffic
func (t *TrafficTracker) RoutedPacketConnection(
	ctx context.Context,
	conn N.PacketConn,
	metadata adapter.InboundContext,
	matchedRule adapter.Rule,
	matchOutbound adapter.Outbound,
) N.PacketConn {
	username := metadata.User
	if username == "" {
		return conn
	}

	subSID, ok := t.getSubscriptionSID(username)
	if !ok {
		t.logger.Warn("User not found in mapping",
			slog.String("user", username),
		)
		return conn
	}

	sourceIP := metadata.Source.Addr.Unmap().String()
	t.trackConnection(subSID, sourceIP)

	t.logger.Debug("Packet connection tracked",
		slog.String("user", username),
		slog.String("subscription_sid", subSID),
		slog.String("source_ip", sourceIP),
		slog.String("inbound", metadata.Inbound),
	)
	return &countingPacketConn{
		PacketConn:      conn,
		statsClient:     t.statsClient,
		subscriptionSID: subSID,
		logger:          t.logger,
		tracker:         t,
		sourceIP:        sourceIP,
	}
}

// countingConn wraps net.Conn to count bytes transferred
type countingConn struct {
	net.Conn
	statsClient     *stats.Client
	subscriptionSID string
	logger          *slog.Logger
	tracker         *TrafficTracker
	sourceIP        string
	upload          atomic.Int64
	download        atomic.Int64
	closed          atomic.Bool
}

func (c *countingConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		// Read from client = user upload
		c.upload.Add(int64(n))
	}
	return
}

func (c *countingConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		// Write to client = user download
		c.download.Add(int64(n))
	}
	return
}

// Upstream returns the underlying connection for capability detection traversal.
// This allows sing-box to discover the real connection type (e.g., syscall.Conn for splice)
// and correctly calculate buffer headroom for protocol headers.
func (c *countingConn) Upstream() any {
	return c.Conn
}

func (c *countingConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.tracker.untrackConnection(c.subscriptionSID, c.sourceIP)
		// Report accumulated traffic when connection closes
		upload := c.upload.Load()
		download := c.download.Load()
		if upload > 0 || download > 0 {
			c.logger.Debug("Connection closed",
				slog.String("subscription_sid", c.subscriptionSID),
				slog.Int64("upload", upload),
				slog.Int64("download", download),
			)
			c.statsClient.RecordTraffic(c.subscriptionSID, upload, download)
		}
	}
	return c.Conn.Close()
}

// countingPacketConn wraps N.PacketConn to count bytes transferred
type countingPacketConn struct {
	N.PacketConn
	statsClient     *stats.Client
	subscriptionSID string
	logger          *slog.Logger
	tracker         *TrafficTracker
	sourceIP        string
	upload          atomic.Int64
	download        atomic.Int64
	closed          atomic.Bool
}

func (c *countingPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	destination, err = c.PacketConn.ReadPacket(buffer)
	if err == nil {
		// Read from client = user upload
		c.upload.Add(int64(buffer.Len()))
	}
	return
}

func (c *countingPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	size := buffer.Len()
	err := c.PacketConn.WritePacket(buffer, destination)
	if err == nil {
		// Write to client = user download
		c.download.Add(int64(size))
	}
	return err
}

// Upstream returns the underlying connection for headroom calculation traversal
// This allows sing's CalculateFrontHeadroom to traverse the wrapper chain
// and correctly calculate buffer space needed for protocol headers (e.g., shadowsocks encryption)
func (c *countingPacketConn) Upstream() any {
	return c.PacketConn
}

func (c *countingPacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.tracker.untrackConnection(c.subscriptionSID, c.sourceIP)
		// Report accumulated traffic when connection closes
		upload := c.upload.Load()
		download := c.download.Load()
		if upload > 0 || download > 0 {
			c.logger.Debug("Packet connection closed",
				slog.String("subscription_sid", c.subscriptionSID),
				slog.Int64("upload", upload),
				slog.Int64("download", download),
			)
			c.statsClient.RecordTraffic(c.subscriptionSID, upload, download)
		}
	}
	return c.PacketConn.Close()
}
