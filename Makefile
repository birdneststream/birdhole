# Makefile for Birdhole

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt

# Binary name
BINARY_NAME=birdhole

# Default target
.PHONY: all
all: clean fmt lint build

# Build the binary
.PHONY: build
build:
	$(GOBUILD) -o $(BINARY_NAME) -v

# Run tests
.PHONY: test
test:
	$(GOTEST) -v ./...

# Clean build artifacts
.PHONY: clean
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)

# Format code
.PHONY: fmt
fmt:
	$(GOFMT) ./...
	gofumpt -w .

# Run all linters
.PHONY: lint
lint: lint-golangci lint-staticcheck lint-gosec

# Run golangci-lint (comprehensive linter suite)
.PHONY: lint-golangci
lint-golangci:
	@echo "Running golangci-lint..."
	golangci-lint run --timeout=5m

# Run staticcheck (advanced static analysis)
.PHONY: lint-staticcheck
lint-staticcheck:
	@echo "Running staticcheck..."
	staticcheck ./...

# Run gosec (security analysis)
.PHONY: lint-gosec
lint-gosec:
	@echo "Running gosec security scanner..."
	gosec ./...

# Vet code
.PHONY: vet
vet:
	$(GOCMD) vet ./...

# Quick check (format, vet, build)
.PHONY: check
check: fmt vet build

# Full CI pipeline (format, lint, test, build)
.PHONY: ci
ci: fmt lint test build

# Install dependencies
.PHONY: deps
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Docker targets
.PHONY: docker-build
docker-build:
	docker compose build

.PHONY: docker-up
docker-up:
	docker compose up -d

.PHONY: docker-down
docker-down:
	docker compose down

.PHONY: docker-logs
docker-logs:
	docker compose logs -f birdhole_container

# Development server
.PHONY: dev
dev: build
	./$(BINARY_NAME)

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all          - Clean, format, lint, and build (default)"
	@echo "  build        - Build the binary"
	@echo "  test         - Run tests"
	@echo "  clean        - Clean build artifacts"
	@echo "  fmt          - Format code with go fmt and gofumpt"
	@echo "  lint         - Run all linters (golangci-lint, staticcheck, gosec)"
	@echo "  lint-golangci- Run golangci-lint only"
	@echo "  lint-staticcheck - Run staticcheck only"
	@echo "  lint-gosec   - Run gosec security scanner only"
	@echo "  vet          - Run go vet"
	@echo "  check        - Quick check (format, vet, build)"
	@echo "  ci           - Full CI pipeline (format, lint, test, build)"
	@echo "  deps         - Install and tidy dependencies"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-up    - Start Docker container"
	@echo "  docker-down  - Stop Docker container"
	@echo "  docker-logs  - View Docker container logs"
	@echo "  dev          - Build and run development server"
	@echo "  help         - Show this help message"