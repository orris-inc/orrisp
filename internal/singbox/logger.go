package singbox

import (
	"bufio"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
)

// ansiEscapeRegex matches ANSI escape sequences (color codes, cursor movement, etc.)
var ansiEscapeRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// StderrInterceptor intercepts stderr output and forwards to slog logger
type StderrInterceptor struct {
	logger     *slog.Logger
	origStderr *os.File
	pipeReader *os.File
	pipeWriter *os.File
	done       chan struct{}
	wg         sync.WaitGroup
}

// NewStderrInterceptor creates a new stderr interceptor
func NewStderrInterceptor(logger *slog.Logger) (*StderrInterceptor, error) {
	// Create pipe
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	interceptor := &StderrInterceptor{
		logger:     logger,
		origStderr: os.Stderr,
		pipeReader: r,
		pipeWriter: w,
		done:       make(chan struct{}),
	}

	return interceptor, nil
}

// Start starts intercepting stderr
func (i *StderrInterceptor) Start() {
	// Replace stderr with pipe writer
	os.Stderr = i.pipeWriter

	// Start reading from pipe in background
	i.wg.Add(1)
	go i.readLoop()
}

// Stop stops intercepting and restores original stderr
func (i *StderrInterceptor) Stop() {
	// Signal done
	close(i.done)

	// Close pipe writer to unblock reader
	i.pipeWriter.Close()

	// Wait for reader to finish
	i.wg.Wait()

	// Restore original stderr
	os.Stderr = i.origStderr

	// Close pipe reader
	i.pipeReader.Close()
}

// readLoop reads from pipe and forwards to slog logger
func (i *StderrInterceptor) readLoop() {
	defer i.wg.Done()

	reader := bufio.NewReader(i.pipeReader)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				i.logger.Error("Failed to read from pipe", slog.Any("err", err))
			}
			return
		}

		// Parse and forward log line
		line = strings.TrimRight(line, "\n\r")
		if line == "" {
			continue
		}

		level, msg := parseSingboxLog(line)
		i.writeLog(level, msg)
	}
}

// stripAnsiCodes removes ANSI escape sequences from a string
func stripAnsiCodes(s string) string {
	return ansiEscapeRegex.ReplaceAllString(s, "")
}

// parseSingboxLog parses sing-box log format
// Format: "+0800 2025-12-02 18:36:40 INFO message" or "INFO[0000] message"
func parseSingboxLog(line string) (level, msg string) {
	// Remove ANSI color codes first
	line = stripAnsiCodes(line)

	// Try format: "+0800 2025-12-02 18:36:40 LEVEL message"
	// Skip timezone and timestamp (first 26 chars approximately)
	if len(line) > 26 && (line[0] == '+' || line[0] == '-') {
		// Find the level after timestamp
		parts := strings.SplitN(line, " ", 5)
		if len(parts) >= 5 {
			level = strings.ToUpper(parts[3])
			msg = parts[4]
			return level, msg
		}
	}

	// Try format: "LEVEL[timestamp] message" or "LEVEL message"
	prefixes := []string{"FATAL", "PANIC", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(strings.ToUpper(line), prefix) {
			rest := line[len(prefix):]
			// Skip [timestamp] if present
			if len(rest) > 0 && rest[0] == '[' {
				idx := strings.Index(rest, "] ")
				if idx > 0 {
					return prefix, strings.TrimSpace(rest[idx+2:])
				}
			}
			// Just "LEVEL message"
			if len(rest) > 0 && rest[0] == ' ' {
				return prefix, strings.TrimSpace(rest[1:])
			}
			// LEVEL: message
			if len(rest) > 0 && rest[0] == ':' {
				return prefix, strings.TrimSpace(rest[1:])
			}
		}
	}

	// Check for "tag: message" format (e.g., "inbound/shadowsocks[ss-in]: message")
	if idx := strings.Index(line, ": "); idx > 0 {
		return "INFO", line
	}

	return "INFO", line
}

// writeLog writes log with appropriate level
func (i *StderrInterceptor) writeLog(level, msg string) {
	switch level {
	case "FATAL":
		i.logger.Error(msg) // Don't use Fatal to avoid exit
	case "PANIC":
		i.logger.Error(msg) // Don't use Panic to avoid panic
	case "ERROR":
		i.logger.Error(msg)
	case "WARN", "WARNING":
		i.logger.Warn(msg)
	case "INFO":
		i.logger.Info(msg)
	case "DEBUG", "TRACE":
		i.logger.Debug(msg)
	default:
		i.logger.Info(msg)
	}
}
