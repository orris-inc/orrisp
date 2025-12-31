package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/easayliu/orrisp/internal/api"
)

// Command action for update (not in SDK yet)
const cmdActionUpdate = "update"

// updatePayload represents the update command payload from hub.
type updatePayload struct {
	DownloadURL string `json:"download_url"` // Full URL to download new binary
	Checksum    string `json:"checksum"`     // Checksum in format "sha256:hexstring"
	Version     string `json:"version"`      // Target version string
}

// handleUpdate handles the update command from hub.
// It downloads the new binary, verifies checksum, and replaces the current executable.
func (s *NodeService) handleUpdate(cmd *api.CommandData) {
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
	execPath, err = filepath.EvalSymlinks(execPath)
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

	s.logger.Info("Update successful, exiting for systemd restart",
		slog.String("version", payload.Version),
	)

	// Exit with code 0, systemd will restart the service with new binary
	os.Exit(0)
}

// parseUpdatePayload parses the update payload from command data.
func parseUpdatePayload(payload any) (*updatePayload, error) {
	if payload == nil {
		return nil, fmt.Errorf("payload is nil")
	}

	// Convert payload to JSON bytes then unmarshal
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	var p updatePayload
	if err := json.Unmarshal(jsonBytes, &p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	return &p, nil
}

// downloadFile downloads a file from URL to the specified path.
func (s *NodeService) downloadFile(url, destPath string) error {
	client := &http.Client{
		Timeout: 5 * time.Minute, // Allow longer timeout for large files
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	// Create destination file
	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	// Copy with progress logging
	written, err := io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	s.logger.Info("Download completed",
		slog.Int64("bytes", written),
		slog.String("path", destPath),
	)

	return nil
}

// computeSHA256 computes the SHA256 hash of a file.
func computeSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// parseChecksum parses checksum string.
// Supports formats:
//   - "sha256:hexstring" (with algorithm prefix)
//   - "hexstring" (raw hash, assumes sha256)
func parseChecksum(checksum string) (string, error) {
	var hash string

	if strings.Contains(checksum, ":") {
		parts := strings.SplitN(checksum, ":", 2)
		algorithm := strings.ToLower(parts[0])
		if algorithm != "sha256" {
			return "", fmt.Errorf("unsupported checksum algorithm: %s", algorithm)
		}
		hash = strings.ToLower(parts[1])
	} else {
		// Raw hash without algorithm prefix, assume sha256
		hash = strings.ToLower(checksum)
	}

	// Validate hex string length (SHA256 = 64 hex chars)
	if len(hash) != 64 {
		return "", fmt.Errorf("invalid sha256 hash length: %d", len(hash))
	}

	return hash, nil
}
