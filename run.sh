#!/bin/bash

# JX2 Paysys Run Script
# Starts the paysys server with proper configuration

set -e

# Configuration
BINARY="./paysys-linux-bin"
CONFIG="paysys.ini"
FALLBACK_BINARY="./paysys-dev"

echo "🚀 Starting JX2 Paysys Server..."

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "❌ Binary not found: $BINARY"
    
    # Try fallback development binary
    if [ -f "$FALLBACK_BINARY" ]; then
        echo "🔄 Using development binary: $FALLBACK_BINARY"
        BINARY="$FALLBACK_BINARY"
    else
        echo "💡 Run ./build.sh first to create the binary"
        exit 1
    fi
fi

# Check if config exists
if [ ! -f "$CONFIG" ]; then
    echo "❌ Configuration file not found: $CONFIG"
    echo "💡 Creating default configuration..."
    
    cat > "$CONFIG" << EOF
[Paysys]
IP=127.0.0.1
Port=8000

PingCycle=10
InternalIPMask=127.0.0.0
LocalIP=

[Database]
IP=127.0.0.1
Port=3306
UserName=root
Password=1234
DBName=jx2_paysys
EOF
    echo "✅ Created default $CONFIG"
fi

# Make binary executable
chmod +x "$BINARY"

echo "📋 Configuration:"
echo "   Binary: $BINARY"
echo "   Config: $CONFIG"
echo "   Server: $(grep "IP=" $CONFIG | head -1 | cut -d'=' -f2):$(grep "Port=" $CONFIG | head -1 | cut -d'=' -f2)"
echo ""

# Handle interruption gracefully
trap 'echo ""; echo "🛑 Shutting down server..."; exit 0' INT TERM

echo "🎯 Starting server (Press Ctrl+C to stop)..."
echo "================================================"

# Run the server
exec "$BINARY"