#!/bin/bash

BUILD_DIR="./build"
CONFIG_DIR="./config"

echo "=== Cleaning Threshold Schnorr Kerberos ==="

# Remove build directory
if [ -d "$BUILD_DIR" ]; then
    echo "Removing build directory: $BUILD_DIR"
    rm -rf "$BUILD_DIR"
fi

# Optionally remove config (generated keys)
if [ "$1" == "--all" ]; then
    if [ -d "$CONFIG_DIR" ]; then
        echo "Removing config directory: $CONFIG_DIR"
        rm -rf "$CONFIG_DIR"
    fi
    echo "=== Full clean complete (including keys) ==="
else
    echo "=== Clean complete ==="
    echo "Note: Config/keys preserved. Use './clean.sh --all' to remove everything."
fi