package node

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/easayliu/orrisp/internal/api"
)

// startScheduledTasks starts scheduled tasks for REST-only mode
func (s *Service) startScheduledTasks() {
	s.logger.Info("Starting scheduled tasks...")

	// Report status immediately on startup
	if err := s.reportStatus(); err != nil {
		s.logger.Warn("Failed to report initial status", slog.Any("err", err))
	}

	// User synchronization task
	s.wg.Add(1)
	go s.scheduleTask("User synchronization", s.config.GetUserSyncInterval(), func() error {
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
	go s.scheduleTask("Traffic report", s.config.GetTrafficReportInterval(), func() error {
		return s.reportTraffic()
	})

	// Status report task
	s.wg.Add(1)
	go s.scheduleTask("Status report", s.config.GetStatusReportInterval(), func() error {
		return s.reportStatus()
	})

	// Online users report task
	s.wg.Add(1)
	go s.scheduleTask("Online users report", s.config.GetOnlineReportInterval(), func() error {
		return s.reportOnline()
	})

	s.logger.Info("Scheduled tasks started")
}

// scheduleTask schedules a task to run at the given interval
func (s *Service) scheduleTask(name string, interval time.Duration, task func() error) {
	defer s.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.logger.Info("Scheduled task started",
		slog.String("name", name),
		slog.Duration("interval", interval),
	)

	for {
		select {
		case <-s.ctx.Done():
			s.logger.Info("Scheduled task stopped", slog.String("name", name))
			return

		case <-ticker.C:
			if err := task(); err != nil {
				s.logger.Error("Scheduled task execution failed",
					slog.String("name", name),
					slog.Any("err", err),
				)

				// Stop service on authentication failure (401)
				if errors.Is(err, api.ErrUnauthorized) {
					s.logger.Error("Authentication failed, stopping service due to invalid token")
					s.cancelService()
					return
				}
			}
		}
	}
}

// scheduleTaskWithContext is like scheduleTask but uses a provided context.
func (s *Service) scheduleTaskWithContext(ctx context.Context, name string, interval time.Duration, task func() error) {
	defer s.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.logger.Info("Scheduled task started", slog.String("name", name), slog.Duration("interval", interval))

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("Scheduled task stopped", slog.String("name", name))
			return

		case <-ticker.C:
			if err := task(); err != nil {
				s.logger.Error("Scheduled task failed", slog.String("name", name), slog.Any("err", err))

				if errors.Is(err, api.ErrUnauthorized) {
					s.logger.Error("Authentication failed, stopping service")
					s.cancelService()
					return
				}
			}
		}
	}
}
