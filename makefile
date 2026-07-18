# ====================================================================================
# Variables
# ====================================================================================
BINARY_NAME=checkmarx-reviewer
BUILD_DIR=bin
MAIN_PACKAGE=.

# ====================================================================================
# Quality Control & Development
# ====================================================================================
.PHONY: audit
audit:
	@echo "Vetting code..."
	go vet ./...
	@echo "Running static analysis..."
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...
	@echo "Checking for vulnerabilities..."
	go run govulncheck@latest ./...

.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...

.PHONY: test
test:
	@echo "Running unit tests..."
	go test -v -race -cover ./...

# ====================================================================================
# Building & Running
# ====================================================================================
.PHONY: build
build: fmt
	@echo "Building binary..."
	mkdir -p $(BUILD_DIR)
	go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE)

.PHONY: run
run: build
	@echo "Running application..."
	@./$(BUILD_DIR)/$(BINARY_NAME)

.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)

# ====================================================================================
# Cross-Compilation
# ====================================================================================
.PHONY: compile
compile: compile-linux compile-darwin compile-windows
	@echo "Cross-compiled for all platforms."

.PHONY: compile-linux
compile-linux:
	@echo "Compiling for Linux (amd64)..."
	mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN_PACKAGE)

.PHONY: compile-darwin
compile-darwin:
	@echo "Compiling for macOS (arm64)..."
	mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(MAIN_PACKAGE)

.PHONY: compile-windows
compile-windows:
	@echo "Compiling for Windows (amd64)..."
	mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(MAIN_PACKAGE)

# ====================================================================================
# Help
# ====================================================================================
.PHONY: help
help:
	@echo "Available commands:"
	@echo "  make audit    - Run vet, staticcheck, and govulncheck"
	@echo "  make fmt      - Format code using go fmt"
	@echo "  make test     - Run unit tests with race detection"
	@echo "  make build    - Format code and build optimized binary"
	@echo "  make run      - Build and execute binary"
	@echo "  make clean    - Remove build artifacts directory"
	@echo "  make compile         - Cross-compile for Linux, macOS, and Windows"
	@echo "  make compile-linux   - Cross-compile for Linux (amd64)"
	@echo "  make compile-darwin  - Cross-compile for macOS (arm64)"
	@echo "  make compile-windows - Cross-compile for Windows (amd64)"
