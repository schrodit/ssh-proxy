# SSH Proxy Makefile

# Variables
BINARY_NAME=ssh-proxy
GO_FILES=$(shell find . -name "*.go" -type f)
YAML_FILES=$(shell find . -name "*.yaml" -o -name "*.yml" -type f)
PACKAGES=$(shell go list ./...)

# Default target
.DEFAULT_GOAL := build

# Help target
.PHONY: help
help: ## Show this help message
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ { printf "  %-15s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# Format code
.PHONY: fmt
fmt: ## Format Go code using gofmt and YAML files using yamlfmt
	@echo "Formatting Go code..."
	@gofmt -w -s $(GO_FILES)
	@echo "Formatting YAML files..."
	@if command -v yamlfmt >/dev/null 2>&1; then \
		yamlfmt $(YAML_FILES); \
		echo "YAML files formatted successfully"; \
	else \
		echo "yamlfmt not found. Install with: go install github.com/google/yamlfmt/cmd/yamlfmt@latest"; \
	fi
	@echo "Code formatted successfully"

# Format imports
.PHONY: imports
imports: ## Organize imports using goimports (install with: go install golang.org/x/tools/cmd/goimports@latest)
	@echo "Organizing imports..."
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w $(GO_FILES); \
		echo "Imports organized successfully"; \
	else \
		echo "goimports not found. Install with: go install golang.org/x/tools/cmd/goimports@latest"; \
	fi

# Format YAML files only
.PHONY: fmt-yaml
fmt-yaml: ## Format YAML files using yamlfmt
	@echo "Formatting YAML files..."
	@if command -v yamlfmt >/dev/null 2>&1; then \
		yamlfmt $(YAML_FILES); \
		echo "YAML files formatted successfully"; \
	else \
		echo "yamlfmt not found. Install with: go install github.com/google/yamlfmt/cmd/yamlfmt@latest"; \
	fi

.PHONY: install-tools
install-tools: ## Install development tools (goimports, yamlfmt, ginkgo, golangci-lint)
	@echo "Installing development tools..."
	@echo "Installing goimports..."
	@go install golang.org/x/tools/cmd/goimports@latest
	@echo "Installing yamlfmt..."
	@go install github.com/google/yamlfmt/cmd/yamlfmt@latest
	@echo "Installing ginkgo..."
	@go install github.com/onsi/ginkgo/v2/ginkgo@latest
	@echo "Development tools installed successfully"
	@echo "Installing golangci-lint..."
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin latest

# Lint code
.PHONY: lint
lint: ## Lint Go code using golangci-lint and YAML files using yamlfmt
	@echo "Linting Go code..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
		echo "Go linting completed successfully"; \
	else \
		echo "golangci-lint not found. Install from: https://golangci-lint.run/usage/install/"; \
		echo "Running basic go vet instead..."; \
		go vet ./...; \
	fi
	@echo "Linting YAML files..."
	@if command -v yamlfmt >/dev/null 2>&1; then \
		yamlfmt -lint $(YAML_FILES); \
		echo "YAML linting completed successfully"; \
	else \
		echo "yamlfmt not found. Install with: go install github.com/google/yamlfmt/cmd/yamlfmt@latest"; \
	fi

# Vet code
.PHONY: vet
vet: ## Run go vet
	@echo "Running go vet..."
	@go vet ./...
	@echo "go vet completed successfully"

# Run tests
.PHONY: test
test: ## Run tests
	@echo "Running tests..."
	@go test -v ./...
	@echo "Tests completed successfully"

# Run tests with coverage
.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	@echo "Running tests with coverage..."
	@go test -v -race -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run unit tests only (excluding integration tests)
.PHONY: test-unit
test-unit: ## Run unit tests only
	@echo "Running unit tests..."
	@go test -v ./config ./proxy
	@echo "Unit tests completed successfully"

# Run integration tests using Ginkgo
.PHONY: test-integration
test-integration: build ## Run integration tests with Docker environment
	@echo "Running integration tests..."
	@if command -v ginkgo >/dev/null 2>&1; then \
		cd test/integration && ginkgo -v; \
	else \
		echo "ginkgo not found. Install with: go install github.com/onsi/ginkgo/v2/ginkgo@latest"; \
		echo "Running with go test instead..."; \
		go test -v ./test/integration/...; \
	fi
	@echo "Integration tests completed successfully"

# Run all tests (unit + integration)
.PHONY: test-all
test-all: test-unit test-integration ## Run all tests (unit and integration)
	@echo "All tests completed successfully"

# Build binary
.PHONY: build
build: ## Build the binary
	@echo "Building $(BINARY_NAME)..."
	@go build -o $(BINARY_NAME) .
	@echo "Build completed: $(BINARY_NAME)"

# Install dependencies
.PHONY: deps
deps: ## Download and tidy dependencies
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy
	@echo "Dependencies updated successfully"

# Clean build artifacts
.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	@rm -f $(BINARY_NAME)
	@rm -f coverage.out coverage.html
	@rm -rf dist/
	@echo "Clean completed"

# Run the application
.PHONY: run
run: build ## Build and run the application
	@echo "Running $(BINARY_NAME)..."
	@./$(BINARY_NAME)

# Run with custom config
.PHONY: run-config
run-config: build ## Build and run with custom config (make run-config CONFIG=path/to/config.yaml)
	@echo "Running $(BINARY_NAME) with config $(CONFIG)..."
	@./$(BINARY_NAME) -config $(CONFIG)

# Docker targets
.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@docker build -t $(BINARY_NAME) .
	@echo "Docker image built: $(BINARY_NAME)"

# Development workflow
.PHONY: dev
dev: fmt vet test build ## Run full development workflow (format, vet, test, build)
	@echo "Development workflow completed successfully"

# Quick check
.PHONY: check
check: vet lint ## Quick code check (format and vet)
	@echo "Quick check completed successfully"