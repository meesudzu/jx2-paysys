#!/bin/bash

# Enhanced PaySys Server Startup Script
# Based on complete protocol analysis of vzopaysys.exe and KG_SimulatePaysys_FS.exe

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "========================================"
echo "Enhanced PaySys Server"
echo "Complete Protocol Implementation"
echo "Based on vzopaysys.exe & KG_SimulatePaysys_FS.exe"
echo "========================================"

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "Error: Node.js is not installed"
    exit 1
fi

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "Installing dependencies..."
    npm install
fi

# Create logs directory
mkdir -p logs

echo "Starting Enhanced PaySys Server..."
echo "Implements all 22+ protocol handlers:"
echo "- Bishop identity verification"
echo "- Player login/logout management"
echo "- Complete item shop system"
echo "- Extended points operations"
echo "- CD-Key/gift code system"
echo "- MiBao/PassPod verification"
echo "- Coin transfer and exchange"
echo "- Account state management"
echo "- Zone charge flag operations"

# Start the enhanced server
node paysys-server.js

echo "Enhanced PaySys Server stopped"