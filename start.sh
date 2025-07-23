#!/bin/bash

# JX2 Paysys Start Script
# Complete build and run workflow

set -e

echo "🔥 JX2 Paysys - Complete Setup & Start"
echo "======================================"

# Build the project
echo "1️⃣  Building project..."
./build.sh

echo ""
echo "2️⃣  Starting server..."
./run.sh