# JX2 Paysys Build Configuration
# Builds static Linux binaries for deployment

.PHONY: all clean build-paysys build-test build-client

# Build configuration
GOOS=linux
GOARCH=amd64
CGO_ENABLED=0

# Build all binaries
all: build-paysys build-test build-client

# Build main paysys server
build-paysys:
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) go build -ldflags="-w -s" -o paysys-linux-bin ./cmd/paysys
	@echo "Built paysys-linux-bin server binary"

# Build test utility
build-test:
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) go build -ldflags="-w -s" -o test-linux ./cmd/test
	@echo "Built test-linux utility binary"

# Build client binary if it exists
build-client:
	@if [ -f "./cmd/client/main.go" ]; then \
		GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) go build -ldflags="-w -s" -o client-linux ./cmd/client; \
		echo "Built client-linux test binary"; \
	else \
		echo "No client found, skipping"; \
	fi

# Test the build
test:
	go test ./...

# Clean build artifacts
clean:
	rm -f paysys-linux-bin test-linux client-linux
	@echo "Cleaned build artifacts"

# Show binary sizes
sizes: all
	@echo "Binary sizes:"
	@ls -lh *-linux 2>/dev/null || echo "No binaries found"

# Quick development build (native)
dev:
	go build -o paysys-dev ./cmd/paysys
	@echo "Built development binary: paysys-dev"