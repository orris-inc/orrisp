package node

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/easayliu/orrisp/internal/cert"
	"github.com/easayliu/orrisp/internal/singbox"
	"github.com/sagernet/sing-box/option"
)

// startSingbox starts sing-box service
func (s *Service) startSingbox() error {
	s.logger.Info("Starting sing-box...")

	// Generate sing-box configuration
	options, err := s.generateSingboxOptions()
	if err != nil {
		return fmt.Errorf("failed to generate sing-box config: %w", err)
	}

	// Create sing-box service with logger
	service, err := singbox.NewService(options, s.logger)
	if err != nil {
		return fmt.Errorf("failed to create sing-box service: %w", err)
	}

	// Set traffic tracker for statistics
	service.SetTracker(s.trafficTracker)

	// Start service
	if err := service.Start(); err != nil {
		return fmt.Errorf("failed to start sing-box service: %w", err)
	}

	s.singboxService = service
	s.logger.Info("sing-box started successfully with traffic tracking enabled")
	return nil
}

// reloadSingbox reloads sing-box configuration
func (s *Service) reloadSingbox() error {
	if s.singboxService == nil {
		return s.startSingbox()
	}

	// Generate new configuration
	options, err := s.generateSingboxOptions()
	if err != nil {
		return fmt.Errorf("failed to generate sing-box config: %w", err)
	}

	// Reload configuration
	if err := s.singboxService.Reload(options); err != nil {
		return fmt.Errorf("failed to reload sing-box: %w", err)
	}

	s.logger.Info("sing-box configuration reloaded successfully")
	return nil
}

// generateSingboxOptions generates sing-box configuration options
func (s *Service) generateSingboxOptions() (*option.Options, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.nodeConfig == nil {
		return nil, fmt.Errorf("node configuration not initialized")
	}

	// Copy node configuration
	nodeConfig := *s.nodeConfig
	// Use :: to listen on all addresses
	nodeConfig.ServerHost = "::"

	// Use builder to generate configuration
	// Traffic statistics is handled by ConnectionTracker, no need for Clash API
	clashAPIAddr := ""
	options, err := singbox.BuildConfig(&nodeConfig, s.currentUsers, clashAPIAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to build sing-box config: %w", err)
	}

	// Debug: log generated config
	hasClashAPI := options.Experimental != nil && options.Experimental.ClashAPI != nil
	s.logger.Info("Generated sing-box config",
		slog.String("listen_addr", nodeConfig.ServerHost),
		slog.Int("listen_port", nodeConfig.ServerPort),
		slog.String("protocol", nodeConfig.Protocol),
		slog.String("method", nodeConfig.EncryptionMethod),
		slog.Int("inbound_count", len(options.Inbounds)),
		slog.Int("user_count", len(s.currentUsers)),
		slog.Bool("has_clash_api", hasClashAPI),
	)

	// Configure TLS certificate for protocols that require TLS (except Reality which uses TLS camouflage)
	// Reality mode doesn't need certificates - it mimics the TLS handshake of real websites
	isReality := nodeConfig.Protocol == "vless" && nodeConfig.VLESSSecurity == "reality"
	requiresTLS := (nodeConfig.Protocol == "trojan" ||
		nodeConfig.Protocol == "vless" ||
		(nodeConfig.Protocol == "vmess" && nodeConfig.VMessTLS) ||
		nodeConfig.Protocol == "hysteria2" ||
		nodeConfig.Protocol == "tuic") && !isReality

	if requiresTLS {
		// Ensure certificate exists (generate self-signed if not configured)
		certPath, keyPath, err := s.ensureTLSCert(nodeConfig.SNI)
		if err != nil {
			return nil, fmt.Errorf("failed to ensure TLS certificate: %w", err)
		}

		for i := range options.Inbounds {
			switch options.Inbounds[i].Type {
			case "trojan":
				if trojanOpts, ok := options.Inbounds[i].Options.(*option.TrojanInboundOptions); ok {
					if trojanOpts.TLS != nil {
						trojanOpts.TLS.CertificatePath = certPath
						trojanOpts.TLS.KeyPath = keyPath
					}
				}
			case "vless":
				if vlessOpts, ok := options.Inbounds[i].Options.(*option.VLESSInboundOptions); ok {
					if vlessOpts.TLS != nil && vlessOpts.TLS.Reality == nil {
						// Only set certificate for non-Reality VLESS
						vlessOpts.TLS.CertificatePath = certPath
						vlessOpts.TLS.KeyPath = keyPath
					}
				}
			case "vmess":
				if vmessOpts, ok := options.Inbounds[i].Options.(*option.VMessInboundOptions); ok {
					if vmessOpts.TLS != nil {
						vmessOpts.TLS.CertificatePath = certPath
						vmessOpts.TLS.KeyPath = keyPath
					}
				}
			case "hysteria2":
				if hysteria2Opts, ok := options.Inbounds[i].Options.(*option.Hysteria2InboundOptions); ok {
					if hysteria2Opts.TLS != nil {
						hysteria2Opts.TLS.CertificatePath = certPath
						hysteria2Opts.TLS.KeyPath = keyPath
					}
				}
			case "tuic":
				if tuicOpts, ok := options.Inbounds[i].Options.(*option.TUICInboundOptions); ok {
					if tuicOpts.TLS != nil {
						tuicOpts.TLS.CertificatePath = certPath
						tuicOpts.TLS.KeyPath = keyPath
					}
				}
			}
		}
	}

	return options, nil
}

// ensureTLSCert ensures TLS certificate exists, generates self-signed if not configured.
// This method is safe for concurrent access using sync.Once.
func (s *Service) ensureTLSCert(sni string) (string, string, error) {
	s.certInitOnce.Do(func() {
		s.certInitErr = s.initTLSCert(sni)
	})

	if s.certInitErr != nil {
		return "", "", s.certInitErr
	}
	return s.certPath, s.keyPath, nil
}

// initTLSCert initializes TLS certificate paths. Called once via sync.Once.
func (s *Service) initTLSCert(sni string) error {
	// Use configured paths if available (check node instance first)
	if s.nodeInstance.CertPath != "" && s.nodeInstance.KeyPath != "" {
		s.certPath = s.nodeInstance.CertPath
		s.keyPath = s.nodeInstance.KeyPath
		s.logger.Info("Using configured TLS certificate",
			slog.String("cert_path", s.certPath),
			slog.String("key_path", s.keyPath),
		)
		return nil
	}

	// Generate self-signed certificate (use node SID in path for multi-node support)
	// Try persistent directory first, fallback to temporary directory if needed
	persistentDir := fmt.Sprintf("/var/lib/orrisp/certs/%s", s.nodeInstance.SID)
	tempDir := fmt.Sprintf("/tmp/orrisp/certs/%s", s.nodeInstance.SID)

	// Try persistent directory first
	certDir := persistentDir
	if err := os.MkdirAll(certDir, 0700); err != nil {
		// Fallback to temporary directory
		s.logger.Warn("Failed to create persistent cert directory, using temporary directory",
			slog.String("persistent_dir", persistentDir),
			slog.String("temp_dir", tempDir),
			slog.Any("err", err),
		)
		certDir = tempDir
		if err := os.MkdirAll(certDir, 0700); err != nil {
			return fmt.Errorf("failed to create cert directory: %w", err)
		}
	}

	s.logger.Info("Generating self-signed TLS certificate",
		slog.String("sni", sni),
		slog.String("cert_dir", certDir),
	)
	selfSigned, err := cert.GenerateSelfSigned(certDir, sni)
	if err != nil {
		return err
	}

	s.certPath = selfSigned.CertPath
	s.keyPath = selfSigned.KeyPath
	s.logger.Info("Self-signed TLS certificate generated",
		slog.String("cert_path", s.certPath),
		slog.String("key_path", s.keyPath),
		slog.String("algorithm", "Ed25519"),
	)

	return nil
}
