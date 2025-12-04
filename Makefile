# Makefile for Orrisp

# Variables
BINARY_NAME=orrisp
VERSION?=dev
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}"

# Default target
.PHONY: all
all: build

# Build
.PHONY: build
build:
	@echo "Building ${BINARY_NAME}..."
	@go build ${LDFLAGS} -o bin/${BINARY_NAME} cmd/orrisp/main.go
	@echo "Build complete: bin/${BINARY_NAME}"

# Clean
.PHONY: clean
clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -f /tmp/singbox-config.json
	@echo "Clean complete"

# Run
.PHONY: run
run: build
	@echo "Running ${BINARY_NAME}..."
	@./bin/${BINARY_NAME} -c configs/config.yaml

# Run with example config
.PHONY: run-example
run-example: build
	@echo "Running ${BINARY_NAME} (example config)..."
	@./bin/${BINARY_NAME} -c configs/config.example.yaml

# Test
.PHONY: test
test:
	@echo "Running tests..."
	@go test -v ./...

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Lint
.PHONY: lint
lint:
	@echo "Running linter..."
	@golangci-lint run

# Download dependencies
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy

# UPX flags (macOS requires --force-macos)
UPX_FLAGS=--best --lzma
ifeq ($(shell uname),Darwin)
	UPX_FLAGS+=--force-macos
endif

# Build with UPX compression
.PHONY: build-upx
build-upx:
	@echo "Building ${BINARY_NAME} with UPX compression..."
	@go build ${LDFLAGS} -o bin/${BINARY_NAME} cmd/orrisp/main.go
	@echo "Compressing with UPX..."
	@upx ${UPX_FLAGS} bin/${BINARY_NAME}
	@echo "Build complete: bin/${BINARY_NAME} (compressed)"

# Build release with stripped symbols and UPX
.PHONY: release
release:
	@echo "Building release ${BINARY_NAME}..."
	@go build -ldflags "-s -w -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}" -o bin/${BINARY_NAME} cmd/orrisp/main.go
	@echo "Compressing with UPX..."
	@upx ${UPX_FLAGS} bin/${BINARY_NAME}
	@echo "Release build complete: bin/${BINARY_NAME}"

# Build for Linux amd64
.PHONY: build-linux
build-linux:
	@echo "Building ${BINARY_NAME} for Linux amd64..."
	@GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o bin/${BINARY_NAME}-linux-amd64 cmd/orrisp/main.go
	@echo "Build complete: bin/${BINARY_NAME}-linux-amd64"

# Build for Linux arm64
.PHONY: build-linux-arm64
build-linux-arm64:
	@echo "Building ${BINARY_NAME} for Linux arm64..."
	@GOOS=linux GOARCH=arm64 go build ${LDFLAGS} -o bin/${BINARY_NAME}-linux-arm64 cmd/orrisp/main.go
	@echo "Build complete: bin/${BINARY_NAME}-linux-arm64"

# Build Linux with UPX compression
.PHONY: build-linux-upx
build-linux-upx:
	@echo "Building ${BINARY_NAME} for Linux amd64 with UPX..."
	@GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}" -o bin/${BINARY_NAME}-linux-amd64 cmd/orrisp/main.go
	@echo "Compressing with UPX..."
	@upx --best --lzma bin/${BINARY_NAME}-linux-amd64
	@echo "Build complete: bin/${BINARY_NAME}-linux-amd64 (compressed)"

# Build Linux arm64 with UPX compression
.PHONY: build-linux-arm64-upx
build-linux-arm64-upx:
	@echo "Building ${BINARY_NAME} for Linux arm64 with UPX..."
	@GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}" -o bin/${BINARY_NAME}-linux-arm64 cmd/orrisp/main.go
	@echo "Compressing with UPX..."
	@upx --best --lzma bin/${BINARY_NAME}-linux-arm64
	@echo "Build complete: bin/${BINARY_NAME}-linux-arm64 (compressed)"

# Build all Linux targets with UPX
.PHONY: release-linux
release-linux: build-linux-upx build-linux-arm64-upx
	@echo "All Linux release builds complete"

# Install
.PHONY: install
install: build
	@echo "Installing ${BINARY_NAME}..."
	@cp bin/${BINARY_NAME} /usr/local/bin/
	@echo "Installation complete"

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  make build              - Build project"
	@echo "  make build-upx          - Build with UPX compression"
	@echo "  make release            - Build release (stripped + UPX)"
	@echo "  make build-linux        - Build for Linux amd64"
	@echo "  make build-linux-arm64  - Build for Linux arm64"
	@echo "  make build-linux-upx    - Build Linux amd64 with UPX"
	@echo "  make build-linux-arm64-upx - Build Linux arm64 with UPX"
	@echo "  make release-linux      - Build all Linux releases with UPX"
	@echo "  make clean              - Clean build artifacts"
	@echo "  make run                - Build and run"
	@echo "  make run-example        - Run with example config"
	@echo "  make test               - Run tests"
	@echo "  make fmt                - Format code"
	@echo "  make lint               - Run linter"
	@echo "  make deps               - Download dependencies"
	@echo "  make install            - Install to system"
	@echo "  make help               - Show this help"
