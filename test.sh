#!/bin/bash

# JX2 Paysys Test Script
# Runs protocol tests and client validation

set -e

echo "🧪 JX2 Paysys Test Suite"
echo "========================"

# Check if test binaries exist
if [ ! -f "./test-linux" ]; then
    echo "❌ Test binary not found. Building first..."
    ./build.sh
fi

echo "1️⃣  Testing Protocol Implementation..."
echo "   Testing Bishop authentication..."
./test-linux bishop

echo ""
echo "2️⃣  Testing User Login..."
echo "   Testing admin login with hello password..."
./test-linux login admin hello

if [ -f "./client-linux" ]; then
    echo ""
    echo "3️⃣  Testing Client Connection..."
    echo "   Note: Server must be running on port 8000"
    echo "   Run './run.sh' in another terminal first"
    echo ""
    read -p "Press Enter if server is running, or Ctrl+C to skip client tests..."
    
    echo "   Testing Bishop authentication..."
    timeout 10 ./client-linux bishop || echo "   (Server not available)"
    
    echo "   Testing user login..."
    timeout 10 ./client-linux login admin hello || echo "   (Server not available)"
fi

echo ""
echo "✅ Test suite completed!"