package singbox

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/easayliu/orrisp/internal/stats"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TrafficTracker implements adapter.ConnectionTracker for traffic statistics
type TrafficTracker struct {
	statsClient *stats.Client
	logger      *slog.Logger
	mu          sync.RWMutex
	userMap     map[string]int // username -> subscription_id
}

// NewTrafficTracker creates a new traffic tracker
func NewTrafficTracker(statsClient *stats.Client, logger *slog.Logger) *TrafficTracker {
	return &TrafficTracker{
		statsClient: statsClient,
		logger:      logger,
		userMap:     make(map[string]int),
	}
}

// SetUserMap sets the username to subscription ID mapping
func (t *TrafficTracker) SetUserMap(userMap map[string]int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.userMap = userMap
	t.logger.Debug("User map updated",
		slog.Int("user_count", len(userMap)),
	)
}

// getSubscriptionID returns the subscription ID for a username
func (t *TrafficTracker) getSubscriptionID(username string) (int, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	id, ok := t.userMap[username]
	return id, ok
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

	subID, ok := t.getSubscriptionID(username)
	if !ok {
		t.logger.Warn("User not found in mapping",
			slog.String("user", username),
		)
		return conn
	}

	t.logger.Debug("Connection tracked",
		slog.String("user", username),
		slog.Int("subscription_id", subID),
		slog.String("inbound", metadata.Inbound),
		slog.String("destination", metadata.Destination.String()),
	)
	return &countingConn{
		Conn:           conn,
		statsClient:    t.statsClient,
		subscriptionID: subID,
		logger:         t.logger,
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

	subID, ok := t.getSubscriptionID(username)
	if !ok {
		t.logger.Warn("User not found in mapping",
			slog.String("user", username),
		)
		return conn
	}

	t.logger.Debug("Packet connection tracked",
		slog.String("user", username),
		slog.Int("subscription_id", subID),
		slog.String("inbound", metadata.Inbound),
	)
	return &countingPacketConn{
		PacketConn:     conn,
		statsClient:    t.statsClient,
		subscriptionID: subID,
		logger:         t.logger,
	}
}

// countingConn wraps net.Conn to count bytes transferred
type countingConn struct {
	net.Conn
	statsClient    *stats.Client
	subscriptionID int
	logger         *slog.Logger
	upload         atomic.Int64
	download       atomic.Int64
	closed         atomic.Bool
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

func (c *countingConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		// Report accumulated traffic when connection closes
		upload := c.upload.Load()
		download := c.download.Load()
		if upload > 0 || download > 0 {
			c.logger.Debug("Connection closed",
				slog.Int("subscription_id", c.subscriptionID),
				slog.Int64("upload", upload),
				slog.Int64("download", download),
			)
			c.statsClient.RecordTraffic(c.subscriptionID, upload, download)
		}
	}
	return c.Conn.Close()
}

// countingPacketConn wraps N.PacketConn to count bytes transferred
type countingPacketConn struct {
	N.PacketConn
	statsClient    *stats.Client
	subscriptionID int
	logger         *slog.Logger
	upload         atomic.Int64
	download       atomic.Int64
	closed         atomic.Bool
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

func (c *countingPacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		// Report accumulated traffic when connection closes
		upload := c.upload.Load()
		download := c.download.Load()
		if upload > 0 || download > 0 {
			c.logger.Debug("Packet connection closed",
				slog.Int("subscription_id", c.subscriptionID),
				slog.Int64("upload", upload),
				slog.Int64("download", download),
			)
			c.statsClient.RecordTraffic(c.subscriptionID, upload, download)
		}
	}
	return c.PacketConn.Close()
}
