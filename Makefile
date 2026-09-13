.PHONY: all build test bench lint clean docker-up docker-down keygen run-daemon run-api run-tiering

# Default target
all: lint test build

# Build all 5 binaries into bin/
build:
	@echo "Building all binaries into bin/..."
	go build -o bin/auditlogd ./cmd/daemon
	go build -o bin/apiserver ./cmd/apiserver
	go build -o bin/tiering ./cmd/tiering
	go build -o bin/keygen ./cmd/keygen
	go build -o bin/verify ./cmd/verify
	@echo "All binaries successfully built in bin/"

# Run the complete test suite with coverage
test:
	@echo "Running tests with race detector..."
	go test -v -race ./...

# Run cryptographic performance benchmarks
bench:
	@echo "Running benchmarks..."
	go test -bench Benchmark ./internal/merkle

# Run code linter / vet
lint:
	@echo "Running go vet..."
	go vet ./...

# Generate dev encrypted keyfile
keygen:
	@echo "Generating local encrypted keyfile..."
	go run ./cmd/keygen -action generate -keyfile ./keys/keys.enc -passphrase "dev-secure-passphrase" -version v1

# Start full multi-container stack with Docker Compose
docker-up:
	docker compose up -d

# Tear down multi-container stack
docker-down:
	docker compose down -v

# Clean up binaries and temporary artifacts
clean:
	@echo "Cleaning up build artifacts..."
	rm -rf bin/ coverage.txt
