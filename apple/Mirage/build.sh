#!/bin/bash
# Build script for Mirage macOS App
# Usage: ./build.sh [debug|release]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_TYPE="${1:-debug}"

echo "=== Mirage macOS Build ==="
echo "Build type: $BUILD_TYPE"
echo ""

# Step 1: Build Rust FFI library
echo "▸ Building libmirage_ffi.a..."
if [ "$BUILD_TYPE" = "release" ]; then
    cargo build --release -p mirage-ffi --manifest-path "$REPO_ROOT/Cargo.toml"
else
    cargo build -p mirage-ffi --manifest-path "$REPO_ROOT/Cargo.toml"
fi
echo "  ✓ Rust library built"

# Step 2: Generate Xcode project (requires xcodegen)
if command -v xcodegen &>/dev/null; then
    echo "▸ Generating Xcode project..."
    cd "$SCRIPT_DIR"
    xcodegen generate
    echo "  ✓ Xcode project generated"
else
    echo "  ⚠ xcodegen not found. Install with: brew install xcodegen"
    echo "  ⚠ Or open Xcode and create the project manually using project.yml as reference"
fi

# Step 3: Build with xcodebuild (optional)
if [ "${BUILD_XCODE:-}" = "1" ]; then
    echo "▸ Building Xcode project..."
    cd "$SCRIPT_DIR"
    xcodebuild -project Mirage.xcodeproj \
        -scheme Mirage \
        -configuration "$([ "$BUILD_TYPE" = "release" ] && echo Release || echo Debug)" \
        build
    echo "  ✓ Xcode build complete"
fi

echo ""
echo "=== Done ==="
echo "Next steps:"
echo "  1. Open apple/Mirage/Mirage.xcodeproj in Xcode"
echo "  2. Select your Team in Signing & Capabilities"
echo "  3. Build and run (⌘R)"
