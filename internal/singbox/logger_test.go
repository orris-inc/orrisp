package singbox

import "testing"

func TestStripAnsiCodes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no ansi codes",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "color code",
			input:    "\x1b[36mINFO\x1b[0m message",
			expected: "INFO message",
		},
		{
			name:     "256 color code",
			input:    "[\x1b[38;5;146m2962253698\x1b[0m 0ms]",
			expected: "[2962253698 0ms]",
		},
		{
			name:     "complex sing-box log",
			input:    "+0800 2025-12-12 13:53:11 \x1b[36mINFO\x1b[0m inbound/shadowsocks[ss-in]: [\x1b[38;5;149m3433905541\x1b[0m 0ms] connection",
			expected: "+0800 2025-12-12 13:53:11 INFO inbound/shadowsocks[ss-in]: [3433905541 0ms] connection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripAnsiCodes(tt.input)
			if result != tt.expected {
				t.Errorf("stripAnsiCodes(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseSingboxLog(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedLevel string
		expectedMsg   string
	}{
		{
			name:          "standard format with color",
			input:         "+0800 2025-12-12 13:53:11 \x1b[36mINFO\x1b[0m network: updated default interface",
			expectedLevel: "INFO",
			expectedMsg:   "network: updated default interface",
		},
		{
			name:          "connection log with color",
			input:         "+0800 2025-12-12 13:53:11 \x1b[36mINFO\x1b[0m [\x1b[38;5;149m3433905541\x1b[0m 0ms] inbound/shadowsocks[ss-in]: connection",
			expectedLevel: "INFO",
			expectedMsg:   "[3433905541 0ms] inbound/shadowsocks[ss-in]: connection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level, msg := parseSingboxLog(tt.input)
			if level != tt.expectedLevel {
				t.Errorf("level = %q, want %q", level, tt.expectedLevel)
			}
			if msg != tt.expectedMsg {
				t.Errorf("msg = %q, want %q", msg, tt.expectedMsg)
			}
		})
	}
}
