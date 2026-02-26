package singbox

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/easayliu/orrisp/internal/stats"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

func TestTrafficTracker(t *testing.T) {
	// Create stats client and tracker
	statsClient := stats.NewClient()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tracker := NewTrafficTracker(statsClient, logger)

	// Set user mapping
	userMap := map[string]string{
		"testuser": "sub_100",
	}
	tracker.SetUserMap(userMap)

	// Create a mock connection pair
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Wrap connection with tracker
	metadata := adapter.InboundContext{
		User:   "testuser",
		Source: M.Socksaddr{Addr: netip.MustParseAddr("192.168.1.1")},
	}
	wrappedConn := tracker.RoutedConnection(context.Background(), client, metadata, nil, nil)

	// Write data through wrapped connection
	testData := []byte("hello world")
	go func() {
		buf := make([]byte, 1024)
		server.Read(buf)
		server.Write([]byte("response data"))
	}()

	// Write to server (proxy writes to client = user download)
	n, err := wrappedConn.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	t.Logf("Written %d bytes", n)

	// Read from server (proxy reads from client = user upload)
	buf := make([]byte, 1024)
	n, err = wrappedConn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	t.Logf("Read %d bytes", n)

	// Close connection to trigger traffic report
	wrappedConn.Close()

	// Give some time for the close to complete
	time.Sleep(10 * time.Millisecond)

	// Check traffic was recorded
	traffic := statsClient.GetTraffic()
	if len(traffic) == 0 {
		t.Fatal("No traffic recorded")
	}

	found := false
	for _, item := range traffic {
		if item.SubscriptionSID == "sub_100" {
			found = true
			t.Logf("Traffic for subscription sub_100: upload=%d, download=%d",
				item.Upload, item.Download)
			if item.Upload == 0 {
				t.Error("Upload should be > 0")
			}
			if item.Download == 0 {
				t.Error("Download should be > 0")
			}
		}
	}

	if !found {
		t.Error("Traffic for subscription sub_100 not found")
	}
}

func TestTrafficTrackerUnknownUser(t *testing.T) {
	statsClient := stats.NewClient()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tracker := NewTrafficTracker(statsClient, logger)

	// No user mapping set
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// User not in mapping should return original connection
	metadata := adapter.InboundContext{
		User: "unknownuser",
	}
	wrappedConn := tracker.RoutedConnection(context.Background(), client, metadata, nil, nil)

	// Should be the original connection, not wrapped
	if wrappedConn != client {
		t.Error("Unknown user connection should not be wrapped")
	}
}

func TestTrafficTrackerEmptyUser(t *testing.T) {
	statsClient := stats.NewClient()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tracker := NewTrafficTracker(statsClient, logger)

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Empty user should return original connection
	metadata := adapter.InboundContext{
		User: "",
	}
	wrappedConn := tracker.RoutedConnection(context.Background(), client, metadata, nil, nil)

	if wrappedConn != client {
		t.Error("Empty user connection should not be wrapped")
	}
}

func newTestTracker() *TrafficTracker {
	return NewTrafficTracker(stats.NewClient(), slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func makeMetadata(user, ip string) adapter.InboundContext {
	return adapter.InboundContext{
		User:   user,
		Source: M.Socksaddr{Addr: netip.MustParseAddr(ip)},
	}
}

func TestOnlineTrackingOpenClose(t *testing.T) {
	tracker := newTestTracker()
	tracker.SetUserMap(map[string]string{"alice": "sub_1"})

	s, c := net.Pipe()
	defer s.Close()

	conn := tracker.RoutedConnection(context.Background(), c, makeMetadata("alice", "10.0.0.1"), nil, nil)

	online := tracker.GetOnlineSubscriptions()
	if len(online) != 1 {
		t.Fatalf("expected 1 online entry, got %d", len(online))
	}
	if online[0].SubscriptionSID != "sub_1" || online[0].IP != "10.0.0.1" {
		t.Fatalf("unexpected online entry: %+v", online[0])
	}

	conn.Close()

	online = tracker.GetOnlineSubscriptions()
	if len(online) != 0 {
		t.Fatalf("expected 0 online entries after close, got %d", len(online))
	}
}

func TestOnlineTrackingRefCount(t *testing.T) {
	tracker := newTestTracker()
	tracker.SetUserMap(map[string]string{"alice": "sub_1"})

	// Open two connections from the same (sid, ip)
	s1, c1 := net.Pipe()
	defer s1.Close()
	s2, c2 := net.Pipe()
	defer s2.Close()

	conn1 := tracker.RoutedConnection(context.Background(), c1, makeMetadata("alice", "10.0.0.1"), nil, nil)
	conn2 := tracker.RoutedConnection(context.Background(), c2, makeMetadata("alice", "10.0.0.1"), nil, nil)

	// Should deduplicate to 1 entry
	online := tracker.GetOnlineSubscriptions()
	if len(online) != 1 {
		t.Fatalf("expected 1 deduplicated entry, got %d", len(online))
	}

	// Close first connection — entry should still exist
	conn1.Close()
	online = tracker.GetOnlineSubscriptions()
	if len(online) != 1 {
		t.Fatalf("expected 1 entry after first close, got %d", len(online))
	}

	// Close second — entry should be removed
	conn2.Close()
	online = tracker.GetOnlineSubscriptions()
	if len(online) != 0 {
		t.Fatalf("expected 0 entries after all closed, got %d", len(online))
	}
}

func TestOnlineTrackingMultipleIPs(t *testing.T) {
	tracker := newTestTracker()
	tracker.SetUserMap(map[string]string{
		"alice": "sub_1",
		"bob":   "sub_2",
	})

	s1, c1 := net.Pipe()
	defer s1.Close()
	s2, c2 := net.Pipe()
	defer s2.Close()

	conn1 := tracker.RoutedConnection(context.Background(), c1, makeMetadata("alice", "10.0.0.1"), nil, nil)
	conn2 := tracker.RoutedConnection(context.Background(), c2, makeMetadata("bob", "10.0.0.2"), nil, nil)

	online := tracker.GetOnlineSubscriptions()
	if len(online) != 2 {
		t.Fatalf("expected 2 online entries, got %d", len(online))
	}

	conn1.Close()
	conn2.Close()

	online = tracker.GetOnlineSubscriptions()
	if len(online) != 0 {
		t.Fatalf("expected 0 entries after close, got %d", len(online))
	}
}

func TestOnlineTrackingConcurrent(t *testing.T) {
	tracker := newTestTracker()
	tracker.SetUserMap(map[string]string{"user": "sub_1"})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, c := net.Pipe()
			defer s.Close()
			conn := tracker.RoutedConnection(context.Background(), c, makeMetadata("user", "10.0.0.1"), nil, nil)
			// Brief pause to ensure overlap
			time.Sleep(time.Millisecond)
			conn.Close()
		}()
	}
	wg.Wait()

	online := tracker.GetOnlineSubscriptions()
	if len(online) != 0 {
		t.Fatalf("expected 0 entries after all goroutines done, got %d", len(online))
	}
}

func TestOnlineTrackingDoubleClose(t *testing.T) {
	tracker := newTestTracker()
	tracker.SetUserMap(map[string]string{"alice": "sub_1"})

	s, c := net.Pipe()
	defer s.Close()

	conn := tracker.RoutedConnection(context.Background(), c, makeMetadata("alice", "10.0.0.1"), nil, nil)

	// Close twice — should not panic or double-decrement
	conn.Close()
	conn.Close()

	online := tracker.GetOnlineSubscriptions()
	if len(online) != 0 {
		t.Fatalf("expected 0 entries after double close, got %d", len(online))
	}
}
