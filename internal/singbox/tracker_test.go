package singbox

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/easayliu/orrisp/internal/stats"
	"github.com/sagernet/sing-box/adapter"
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
		User: "testuser",
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
