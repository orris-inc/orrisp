package node

import (
	"log/slog"
	"os"
	"time"

	"github.com/easayliu/orrisp/internal/api"
)

// ============================================================================
// HubHandler Interface Implementation
// ============================================================================

// OnCommand handles commands from the server via Hub.
func (s *Service) OnCommand(cmd *api.CommandData) {
	s.logger.Info("Received command from hub",
		slog.String("command_id", cmd.CommandID),
		slog.String("action", cmd.Action),
	)

	switch cmd.Action {
	case api.CmdActionReloadConfig:
		s.logger.Info("Executing reload config command")
		go func() {
			s.configMu.Lock()
			defer s.configMu.Unlock()

			if err := s.fetchNodeConfig(); err != nil {
				s.logger.Error("Failed to reload config", slog.Any("err", err))
				return
			}
			if _, err := s.syncUsers(); err != nil {
				s.logger.Error("Failed to sync users", slog.Any("err", err))
				return
			}
			if err := s.reloadSingbox(); err != nil {
				s.logger.Error("Failed to reload singbox", slog.Any("err", err))
				return
			}
			s.logger.Info("Config reloaded successfully via hub command")
		}()

	case api.CmdActionRestart:
		s.logger.Info("Executing restart command")
		go func() {
			if err := s.reloadSingbox(); err != nil {
				s.logger.Error("Failed to restart singbox", slog.Any("err", err))
			}
		}()

	case api.CmdActionStop:
		s.logger.Warn("Received stop command from hub")
		go s.Stop()

	case api.CmdActionUpdate:
		s.logger.Info("Executing update command")
		go s.handleUpdate(cmd)

	case api.CmdActionAPIURLChanged, api.CmdActionConfigRelocate:
		s.logger.Info("Executing API URL change command")
		go s.handleAPIURLChanged(cmd)

	default:
		s.logger.Warn("Unknown command action", slog.String("action", cmd.Action))
	}
}

// handleAPIURLChanged handles API URL change command from the server.
// It updates the local API URL configuration, saves to config file, and triggers Hub reconnection.
func (s *Service) handleAPIURLChanged(cmd *api.CommandData) {
	payload := api.ParseAPIURLChangedPayload(cmd.Payload)
	if payload == nil {
		s.logger.Error("Failed to parse API URL changed payload")
		return
	}

	if payload.NewURL == "" {
		s.logger.Error("API URL changed payload has empty new_url")
		return
	}

	s.logger.Info("API URL changed, updating configuration",
		slog.String("new_url", payload.NewURL),
		slog.String("reason", payload.Reason),
	)

	// Create new API client with new URL
	newAPIClient, err := api.NewClient(
		payload.NewURL,
		s.nodeInstance.Token,
		s.nodeInstance.SID,
		api.WithTimeout(s.config.GetAPITimeout()),
	)
	if err != nil {
		s.logger.Error("Failed to create new API client", slog.Any("err", err))
		return
	}

	// Update config, API client, and get hub client under lock
	s.mu.Lock()
	oldURL := s.config.API.BaseURL
	s.config.API.BaseURL = payload.NewURL
	s.apiClient = newAPIClient
	hubClient := s.hubClient

	// Save config while holding lock to ensure consistency
	var saveErr error
	if s.config.Path != "" {
		saveErr = s.config.Save()
	}
	s.mu.Unlock()

	s.logger.Info("API URL and client updated",
		slog.String("old_url", oldURL),
		slog.String("new_url", payload.NewURL),
	)

	// Log save result
	if s.config.Path == "" {
		s.logger.Warn("Config file not saved: no file path (loaded from CLI flags)")
	} else if saveErr != nil {
		s.logger.Warn("Failed to save config file", slog.Any("err", saveErr))
	} else {
		s.logger.Info("Config file updated with new API URL",
			slog.String("path", s.config.Path),
		)
	}

	// Close current Hub connection to trigger reconnect with new URL
	if hubClient != nil {
		s.logger.Info("Closing Hub connection to reconnect with new URL")
		if err := hubClient.Close(); err != nil {
			s.logger.Warn("Failed to close hub connection", slog.Any("err", err))
		}
	}
}

// OnConfigSync handles config sync from the server via Hub.
func (s *Service) OnConfigSync(sync *api.ConfigSyncData) {
	s.logger.Info("Received config sync from hub",
		slog.Uint64("version", sync.Version),
		slog.Bool("full_sync", sync.FullSync),
	)

	if sync.Config == nil {
		s.logger.Debug("Config sync has no config data, fetching via REST")
		go func() {
			s.configMu.Lock()
			defer s.configMu.Unlock()

			if err := s.fetchNodeConfig(); err != nil {
				s.logger.Error("Failed to fetch config after sync notification", slog.Any("err", err))
				return
			}
			if _, err := s.syncUsers(); err != nil {
				s.logger.Error("Failed to sync users after config sync", slog.Any("err", err))
				return
			}
			if err := s.reloadSingbox(); err != nil {
				s.logger.Error("Failed to reload singbox after config sync", slog.Any("err", err))
			}
		}()
		return
	}

	// Skip reload if protocol is not configured yet
	if sync.Config.Protocol == "" {
		s.mu.Lock()
		s.nodeConfig = s.convertHubConfigToNodeConfig(sync.Config)
		s.mu.Unlock()
		s.logger.Warn("Skipping singbox reload: protocol not configured")
		return
	}

	// Apply config, sync users, and reload sing-box atomically
	go func() {
		s.configMu.Lock()
		defer s.configMu.Unlock()

		s.mu.Lock()
		s.nodeConfig = s.convertHubConfigToNodeConfig(sync.Config)
		s.mu.Unlock()

		s.logger.Info("Config updated from hub sync",
			slog.String("protocol", sync.Config.Protocol),
			slog.Int("server_port", sync.Config.ServerPort),
		)

		if _, err := s.syncUsers(); err != nil {
			s.logger.Error("Failed to sync users after hub config sync", slog.Any("err", err))
			return
		}
		if err := s.reloadSingbox(); err != nil {
			s.logger.Error("Failed to reload singbox after hub config sync", slog.Any("err", err))
		}
	}()
}

// convertHubConfigToNodeConfig converts Hub ConfigData to NodeConfig.
func (s *Service) convertHubConfigToNodeConfig(hubConfig *api.ConfigData) *api.NodeConfig {
	return &api.NodeConfig{
		NodeSID:           hubConfig.NodeSID,
		Protocol:          hubConfig.Protocol,
		ServerHost:        hubConfig.ServerHost,
		ServerPort:        hubConfig.ServerPort,
		EncryptionMethod:  hubConfig.EncryptionMethod,
		ServerKey:         hubConfig.ServerKey,
		TransportProtocol: hubConfig.TransportProtocol,
		Host:              hubConfig.Host,
		Path:              hubConfig.Path,
		ServiceName:       hubConfig.ServiceName,
		SNI:               hubConfig.SNI,
		AllowInsecure:     hubConfig.AllowInsecure,
		Route:             hubConfig.Route,
		DNS:               hubConfig.DNS,
		Outbounds:         hubConfig.Outbounds,

		// VLESS specific fields (map from simplified ConfigData field names)
		VLESSFlow:              hubConfig.Flow,
		VLESSSecurity:          hubConfig.Security,
		VLESSFingerprint:       hubConfig.Fingerprint,
		VLESSRealityPrivateKey: hubConfig.PrivateKey,
		VLESSRealityPublicKey:  hubConfig.PublicKey,
		VLESSRealityShortID:    hubConfig.ShortID,
		VLESSRealitySpiderX:    hubConfig.SpiderX,

		// VMess specific fields
		VMessAlterID:  hubConfig.AlterID,
		VMessSecurity: hubConfig.Security,
		VMessTLS:      hubConfig.TLS,

		// Hysteria2 specific fields
		Hysteria2CongestionControl: hubConfig.CongestionControl,
		Hysteria2Obfs:              hubConfig.Obfs,
		Hysteria2ObfsPassword:      hubConfig.ObfsPassword,
		Hysteria2UpMbps:            hubConfig.UpMbps,
		Hysteria2DownMbps:          hubConfig.DownMbps,
		Hysteria2Fingerprint:       hubConfig.Fingerprint,

		// TUIC specific fields
		TUICCongestionControl: hubConfig.CongestionControl,
		TUICUDPRelayMode:      hubConfig.UDPRelayMode,
		TUICAlpn:              hubConfig.ALPN,
		TUICDisableSNI:        hubConfig.DisableSNI,

		// AnyTLS specific fields
		AnyTLSFingerprint:              hubConfig.AnyTLSFingerprint,
		AnyTLSIdleSessionCheckInterval: hubConfig.AnyTLSIdleSessionCheckInterval,
		AnyTLSIdleSessionTimeout:       hubConfig.AnyTLSIdleSessionTimeout,
		AnyTLSMinIdleSession:           hubConfig.AnyTLSMinIdleSession,
	}
}

// OnError handles errors from the Hub connection.
func (s *Service) OnError(err error) {
	s.logger.Error("Hub error", slog.Any("err", err))
}

// OnSubscriptionSync handles subscription sync from the server via Hub.
// This processes incremental subscription changes (added, updated, removed).
func (s *Service) OnSubscriptionSync(sync *api.SubscriptionSyncData) {
	s.logger.Info("Received subscription sync from hub",
		slog.String("change_type", sync.ChangeType),
		slog.Int("count", len(sync.Subscriptions)),
		slog.Int64("timestamp", sync.Timestamp),
	)

	oldCount, newCount, changed := s.applySubscriptionChanges(sync)

	if !changed {
		s.logger.Debug("No subscription changes applied")
		return
	}

	s.logger.Info("Subscriptions updated via hub sync",
		slog.Int("old_count", oldCount),
		slog.Int("new_count", newCount),
	)

	// Reload sing-box with updated subscriptions
	go func() {
		if err := s.reloadSingbox(); err != nil {
			s.logger.Error("Failed to reload singbox after subscription sync", slog.Any("err", err))
		} else {
			s.logger.Info("sing-box reloaded with updated subscriptions")
		}
	}()
}

// OnDisconnect handles Hub disconnection.
// This may be called multiple times (e.g., from read/write errors), so we use
// sync.Once to ensure the disconnect channel is closed exactly once per connection.
func (s *Service) OnDisconnect() {
	s.logger.Warn("Hub disconnected")

	s.mu.Lock()
	s.hubClient = nil
	// Close channel to broadcast disconnect to all listeners.
	// Use disconnectOnce to ensure channel is closed exactly once,
	// preventing panic from closing an already-closed channel.
	disconnectOnce := s.hubDisconnectOnce
	disconnectCh := s.hubDisconnect
	s.mu.Unlock()

	if disconnectOnce != nil && disconnectCh != nil {
		disconnectOnce.Do(func() {
			close(disconnectCh)
		})
	}
}

// handleUpdate is defined in update.go
// It handles the update command from hub.
func (s *Service) handleUpdate(cmd *api.CommandData) {
	// Parse payload
	payload, err := parseUpdatePayload(cmd.Payload)
	if err != nil {
		s.logger.Error("Failed to parse update payload",
			slog.Any("err", err),
			slog.Any("payload", cmd.Payload),
		)
		return
	}

	s.logger.Info("Starting self-update",
		slog.String("version", payload.Version),
		slog.String("download_url", payload.DownloadURL),
		slog.String("checksum", payload.Checksum),
	)

	// Validate required fields
	if payload.DownloadURL == "" {
		s.logger.Error("Update payload missing download_url")
		return
	}
	if payload.Checksum == "" {
		s.logger.Error("Update payload missing checksum")
		return
	}

	// Parse checksum (format: "sha256:hexstring" or raw hash)
	expectedHash, err := parseChecksum(payload.Checksum)
	if err != nil {
		s.logger.Error("Invalid checksum format",
			slog.Any("err", err),
			slog.String("checksum", payload.Checksum),
		)
		return
	}

	// Get current executable path
	execPath, err := os.Executable()
	if err != nil {
		s.logger.Error("Failed to get executable path", slog.Any("err", err))
		return
	}
	execPath, err = evalSymlinks(execPath)
	if err != nil {
		s.logger.Error("Failed to resolve executable symlinks", slog.Any("err", err))
		return
	}

	// Download new binary to temp file
	tempPath := execPath + ".new"
	if err := s.downloadFile(payload.DownloadURL, tempPath); err != nil {
		s.logger.Error("Failed to download update", slog.Any("err", err))
		_ = os.Remove(tempPath)
		return
	}

	// Verify SHA256 checksum
	actualHash, err := computeSHA256(tempPath)
	if err != nil {
		s.logger.Error("Failed to compute checksum", slog.Any("err", err))
		_ = os.Remove(tempPath)
		return
	}
	if actualHash != expectedHash {
		s.logger.Error("Checksum mismatch",
			slog.String("expected", expectedHash),
			slog.String("actual", actualHash),
		)
		_ = os.Remove(tempPath)
		return
	}
	s.logger.Info("Checksum verified successfully")

	// Set execute permission
	if err := os.Chmod(tempPath, 0755); err != nil {
		s.logger.Error("Failed to set execute permission", slog.Any("err", err))
		_ = os.Remove(tempPath)
		return
	}

	// Backup current binary
	backupPath := execPath + ".bak"
	if err := os.Rename(execPath, backupPath); err != nil {
		s.logger.Error("Failed to backup current binary", slog.Any("err", err))
		_ = os.Remove(tempPath)
		return
	}

	// Replace with new binary (atomic rename)
	if err := os.Rename(tempPath, execPath); err != nil {
		s.logger.Error("Failed to replace binary", slog.Any("err", err))
		// Try to restore backup
		if restoreErr := os.Rename(backupPath, execPath); restoreErr != nil {
			s.logger.Error("Failed to restore backup", slog.Any("err", restoreErr))
		}
		return
	}

	s.logger.Info("Update successful, initiating graceful shutdown for systemd restart",
		slog.String("version", payload.Version),
	)

	// Trigger graceful shutdown to allow proper resource cleanup.
	// This ensures deferred functions execute and resources are released cleanly.
	// After a short delay, exit with code 0 so systemd restarts with the new binary.
	s.cancelService()

	// Give the service time to clean up gracefully (stop sing-box, close connections, etc.)
	time.Sleep(2 * time.Second)

	// Exit with code 0, systemd will restart the service with new binary
	os.Exit(0)
}
