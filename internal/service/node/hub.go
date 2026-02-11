package node

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/easayliu/orrisp/internal/api"
)

// Hub connection constants
const (
	hubInitialBackoff = 1 * time.Second
	hubMaxBackoff     = 5 * time.Minute
	hubBackoffFactor  = 2.0
)

// hubConnectionLoop manages Hub connection with exponential backoff reconnection.
// When Hub is connected, server pushes config/command updates.
// When Hub is disconnected, falls back to REST API polling.
func (s *Service) hubConnectionLoop() {
	defer s.wg.Done()

	s.logger.Info("Starting Hub connection loop...")

	backoff := hubInitialBackoff
	var restTasksCancel context.CancelFunc

	for {
		select {
		case <-s.ctx.Done():
			if restTasksCancel != nil {
				restTasksCancel()
			}
			return
		default:
		}

		// Create new disconnect channel and sync.Once for this connection attempt.
		// The sync.Once ensures the channel is closed exactly once even if
		// OnDisconnect is called multiple times (e.g., from concurrent read/write errors).
		s.mu.Lock()
		s.hubDisconnect = make(chan struct{})
		s.hubDisconnectOnce = &sync.Once{}
		disconnectCh := s.hubDisconnect
		s.mu.Unlock()

		// Try to connect to Hub
		if err := s.connectHub(); err != nil {
			s.logger.Warn("Hub connection failed, using REST fallback",
				slog.Any("err", err),
				slog.Duration("retry_in", backoff),
			)

			// Start REST fallback if not already running
			if restTasksCancel == nil {
				var restCtx context.Context
				restCtx, restTasksCancel = context.WithCancel(s.ctx)
				s.startRESTFallback(restCtx)
			}

			// Wait before retry with exponential backoff
			select {
			case <-s.ctx.Done():
				if restTasksCancel != nil {
					restTasksCancel()
				}
				return
			case <-time.After(backoff):
				backoff = time.Duration(float64(backoff) * hubBackoffFactor)
				if backoff > hubMaxBackoff {
					backoff = hubMaxBackoff
				}
			}
			continue
		}

		// Hub connected successfully
		s.logger.Info("Hub connected, stopping REST fallback")
		backoff = hubInitialBackoff // Reset backoff on successful connection

		// Stop REST fallback (user sync polling)
		if restTasksCancel != nil {
			restTasksCancel()
			restTasksCancel = nil
		}

		s.mu.Lock()
		s.hubConnected = true
		s.mu.Unlock()

		// Start Hub tasks (status + traffic reporting)
		// These run while Hub is connected and stop when disconnected
		s.wg.Add(2)
		go s.hubStatusLoop(disconnectCh)
		go s.hubTrafficLoop(disconnectCh)

		// Wait for disconnect signal (channel will be closed by OnDisconnect)
		select {
		case <-s.ctx.Done():
			return
		case <-disconnectCh:
			s.logger.Info("Hub disconnected, will reconnect...")
			s.mu.Lock()
			s.hubConnected = false
			s.mu.Unlock()
		}
	}
}

// connectHub creates and connects the Hub client.
// It respects context cancellation so shutdown can interrupt connection attempts.
func (s *Service) connectHub() error {
	// Read config values under lock to avoid race with handleAPIURLChanged
	s.mu.RLock()
	baseURL := s.config.API.BaseURL
	pingInterval := s.config.GetHubPingInterval()
	pongWait := s.config.GetHubPongWait()
	s.mu.RUnlock()

	hubClient, err := api.NewHubClient(
		baseURL,
		s.nodeInstance.Token,
		s.nodeInstance.SID,
		s, // Service implements HubHandler
		api.WithPingInterval(pingInterval),
		api.WithPongWait(pongWait),
	)
	if err != nil {
		return err
	}

	// Use goroutine to handle Connect so we can respond to context cancellation
	connectDone := make(chan error, 1)
	go func() {
		connectDone <- hubClient.Connect()
	}()

	select {
	case <-s.ctx.Done():
		// Context cancelled during connection attempt, clean up
		_ = hubClient.Close()
		return s.ctx.Err()
	case err := <-connectDone:
		if err != nil {
			_ = hubClient.Close()
			return err
		}
	}

	s.mu.Lock()
	s.hubClient = hubClient
	s.mu.Unlock()

	s.logger.Info("Hub WebSocket connected successfully")
	return nil
}

// hubStatusLoop sends periodic status updates via Hub WebSocket.
// Reports are sent every sample interval (default 1 second).
func (s *Service) hubStatusLoop(disconnectCh <-chan struct{}) {
	defer s.wg.Done()

	sampleInterval := s.config.GetHubSampleInterval()

	ticker := time.NewTicker(sampleInterval)
	defer ticker.Stop()

	// Send initial status immediately
	status := s.collectSystemStatus()
	s.sendHubStatusData(status)

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-disconnectCh:
			return
		case <-ticker.C:
			status := s.collectSystemStatus()
			s.sendHubStatusData(status)
		}
	}
}

// hubTrafficLoop sends periodic traffic reports via WebSocket while Hub is connected.
func (s *Service) hubTrafficLoop(disconnectCh <-chan struct{}) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.GetHubTrafficInterval())
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-disconnectCh:
			return
		case <-ticker.C:
			s.reportTrafficViaHub()
		}
	}
}

// reportTrafficViaHub sends traffic data through WebSocket Hub.
func (s *Service) reportTrafficViaHub() {
	s.mu.RLock()
	hubClient := s.hubClient
	s.mu.RUnlock()

	if hubClient == nil {
		return
	}

	// Get and reset traffic - restore on failure
	trafficItems := s.statsClient.GetAndResetTraffic()
	if len(trafficItems) == 0 {
		return
	}

	// Send traffic via Hub event
	if err := hubClient.SendEvent(api.EventTypeTraffic, "", trafficItems); err != nil {
		s.logger.Warn("Failed to send traffic via hub, restoring data",
			slog.Any("err", err),
			slog.Int("count", len(trafficItems)),
		)
		// Restore traffic data on failure
		s.statsClient.RestoreTraffic(trafficItems)
		return
	}

	// Log traffic data
	for _, item := range trafficItems {
		s.logger.Debug("Traffic reported via hub",
			slog.String("subscription_sid", item.SubscriptionSID),
			slog.Int64("upload", item.Upload),
			slog.Int64("download", item.Download),
		)
	}
}

// sendHubStatusData sends pre-collected status via Hub.
func (s *Service) sendHubStatusData(status *api.NodeStatus) {
	s.mu.RLock()
	hubClient := s.hubClient
	s.mu.RUnlock()

	if hubClient == nil {
		return
	}

	if err := hubClient.SendStatus(status); err != nil {
		s.logger.Warn("Failed to send status via hub", slog.Any("err", err))
	}
}

// startRESTFallback starts REST API polling as fallback when Hub is disconnected.
func (s *Service) startRESTFallback(ctx context.Context) {
	s.logger.Info("Starting REST fallback tasks...")

	// User synchronization task
	s.wg.Add(1)
	go s.scheduleTaskWithContext(ctx, "REST: User sync", s.config.GetUserSyncInterval(), func() error {
		changed, err := s.syncUsers()
		if err != nil {
			return err
		}
		if changed {
			if err := s.reloadSingbox(); err != nil {
				return err
			}
		}
		return nil
	})

	// Traffic report task
	s.wg.Add(1)
	go s.scheduleTaskWithContext(ctx, "REST: Traffic report", s.config.GetTrafficReportInterval(), func() error {
		return s.reportTraffic()
	})

	// Status report task
	s.wg.Add(1)
	go s.scheduleTaskWithContext(ctx, "REST: Status report", s.config.GetStatusReportInterval(), func() error {
		return s.reportStatus()
	})
}
