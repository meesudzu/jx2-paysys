#!/bin/bash

# Build portable binary for older Linux systems
# This script creates a binary compatible with older GLIBC versions

echo "Building portable payment system binary..."

# Clean previous builds
make clean

# Set compiler flags for maximum compatibility
export CC=gcc
export CXX=g++

# Try to build with older GLIBC compatibility
# Use the no-database version for maximum portability
echo "Building no-database version for maximum compatibility..."
make nodb

if [ $? -eq 0 ]; then
    echo "Build successful!"
    echo "Binary created: bin/paysys"
    
    # Check dependencies
    echo ""
    echo "Binary dependencies:"
    ldd bin/paysys
    
    # Check size
    echo ""
    echo "Binary size:"
    ls -lh bin/paysys
    
    echo ""
    echo "This binary only requires basic system libraries and should work on most Linux distributions."
    echo "It runs in test mode without MySQL database dependencies."
    echo ""
    echo "Test accounts:"
    echo "  Username: test, Password: test"
    echo "  Username: bishop, Password: 1234"
    
else
    echo "Build failed!"
    exit 1
fi