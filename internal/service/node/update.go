package node

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

// parseUpdatePayload parses the update payload from command data.
func parseUpdatePayload(payload any) (*api.UpdatePayload, error) {
	if payload == nil {
		return nil, fmt.Errorf("payload is nil")
	}

	// Convert payload to JSON bytes then unmarshal
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	var p api.UpdatePayload
	if err := json.Unmarshal(jsonBytes, &p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	return &p, nil
}

// downloadFile downloads a file from URL to the specified path.
func (s *Service) downloadFile(url, destPath string) error {
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

// evalSymlinks is a wrapper around filepath.EvalSymlinks for testing purposes.
func evalSymlinks(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}
