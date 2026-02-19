#!/bin/bash
# Build libmirage_ffi.a for all Apple platforms
# Usage: ./scripts/build-apple.sh [--debug]
#
# Targets:
#   aarch64-apple-ios        — iPhone / iPad / "Designed for iPad" on Mac
#   aarch64-apple-ios-sim    — iOS Simulator (Apple Silicon)
#   aarch64-apple-darwin     — macOS (Apple Silicon)
#   x86_64-apple-darwin      — macOS (Intel)
#
# Note: Uses `cargo rustc --crate-type staticlib` instead of `cargo build`
# because the cdylib target fails to link on iOS (BoringSSL ___chkstk_darwin issue).

set -euo pipefail

PROFILE="release"
PROFILE_FLAG="--release"
if [[ "${1:-}" == "--debug" ]]; then
    PROFILE="debug"
    PROFILE_FLAG=""
fi

TARGETS=(
    "aarch64-apple-ios"
    "aarch64-apple-ios-sim"
    "aarch64-apple-darwin"
    "x86_64-apple-darwin"
)

echo "🔨 Building libmirage_ffi.a ($PROFILE) for ${#TARGETS[@]} Apple targets..."
echo ""

FAILED=()

for target in "${TARGETS[@]}"; do
    echo "━━━ Building for $target ━━━"
    if IPHONEOS_DEPLOYMENT_TARGET=15.0 cargo rustc \
        -p mirage-ffi \
        --target "$target" \
        $PROFILE_FLAG \
        --crate-type staticlib 2>&1; then
        LIB="target/$target/$PROFILE/libmirage_ffi.a"
        SIZE=$(stat -f "%z" "$LIB" 2>/dev/null || echo "?")
        echo "  ✅ $LIB ($SIZE bytes)"
    else
        echo "  ❌ Failed: $target"
        FAILED+=("$target")
    fi
    echo ""
done

# Also generate C header (cbindgen runs during any cargo build)
echo "━━━ C Header ━━━"
echo "  📄 mirage-ffi/include/mirage_ffi.h"
echo ""

# Summary
echo "━━━ Summary ━━━"
if [[ ${#FAILED[@]} -eq 0 ]]; then
    echo "  ✅ All ${#TARGETS[@]} targets built successfully ($PROFILE)"
else
    echo "  ⚠️  ${#FAILED[@]} target(s) failed: ${FAILED[*]}"
    exit 1
fi
echo ""
echo "Next: Open Xcode → ⌘⇧K (Clean) → ⌘R (Run)"
