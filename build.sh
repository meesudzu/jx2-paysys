#!/bin/bash

# JX2 Paysys Build Script
# Builds static Linux binaries with CGO disabled

set -e

echo "🏗️  Building JX2 Paysys binaries..."

# Set build environment for static Linux binaries
export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=0

# Build flags for smaller binaries
BUILD_FLAGS="-ldflags=-w -s"

echo "📦 Building main paysys server..."
go build -ldflags="-w -s" -o paysys-linux-bin ./cmd/paysys
echo "✅ Built: paysys-linux-bin"

echo "🔧 Building test utility..."
go build -ldflags="-w -s" -o test-linux ./cmd/test
echo "✅ Built: test-linux"

# Build client if it exists
if [ -f "./cmd/client/main.go" ]; then
    echo "🖥️  Building test client..."
    go build -ldflags="-w -s" -o client-linux ./cmd/client
    echo "✅ Built: client-linux"
else
    echo "ℹ️  No client found, skipping"
fi

echo ""
echo "📊 Binary sizes:"
ls -lh *-linux* 2>/dev/null | grep -E "(paysys|test|client)-linux" || echo "No binaries found"

echo ""
echo "🎉 Build completed successfully!"
echo "   Main server: ./paysys-linux-bin"
echo "   Test tool:   ./test-linux"
if [ -f "./client-linux" ]; then
    echo "   Test client: ./client-linux"
fi