#!/bin/bash

set -e

BUILD_DIR="./build"

echo "=== Building Threshold Schnorr Kerberos ==="

# Create build directory if it doesn't exist
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Run CMake configuration
echo "[1/2] Configuring with CMake..."
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build
echo "[2/2] Building..."
make -j$(nproc)

echo ""
echo "=== Build complete ==="
echo "Executables are in: $BUILD_DIR/"
echo ""
echo "Next steps:"
echo "  1. ./master_keygen          # Generate keys (run once)"
echo "  2. ./as_node 1 8001         # Start AS nodes"
echo "  3. ./tgs_node 1 8101        # Start TGS nodes"
echo "  4. ./service_server fileserver 9001"
echo "  5. ./client alice alice123 fileserver"