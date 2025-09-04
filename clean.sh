#!/bin/bash

# JX2 Paysys Clean Script
# Removes build artifacts and temporary files

echo "🧹 Cleaning JX2 Paysys build artifacts..."

# Remove binary files
echo "   Removing binaries..."
rm -f paysys-linux-bin test-linux client-linux paysys-dev

# Remove temporary files
echo "   Removing temporary files..."
rm -rf /tmp/jx2-paysys-*

# Remove Go build cache (optional)
if [ "$1" == "--full" ]; then
    echo "   Cleaning Go module cache..."
    go clean -modcache -cache -testcache
fi

echo "✅ Clean completed!"
echo ""
echo "Removed files:"
echo "   • paysys-linux-bin (main server)"
echo "   • test-linux (test utility)" 
echo "   • client-linux (test client)"
echo "   • paysys-dev (development binary)"

if [ "$1" == "--full" ]; then
    echo "   • Go module and build cache"
fi

echo ""
echo "💡 Run './build.sh' to rebuild binaries"