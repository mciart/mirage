#!/usr/bin/env bash
# Cross-compile mirage-ffi for the Android ABIs and install ONLY libmirage_ffi.so
# into android/app/src/main/jniLibs/<abi>/ (cargo-ndk also emits stray
# libtun_rs-<hash>.so files, which must never be shipped).
#
# Needs: ANDROID_NDK_HOME, cargo, cargo-ndk, the Rust Android targets.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME is not set}"

abis=(arm64-v8a armeabi-v7a x86_64)
jni_dir="android/app/src/main/jniLibs"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Android 15+ devices may use 16 KB pages: 64-bit libraries must be linked with
# a 16 KB max page size so their LOAD segments are 0x4000-aligned.
page_flags="-C link-arg=-Wl,-z,max-page-size=16384"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS="$page_flags"
export CARGO_TARGET_X86_64_LINUX_ANDROID_RUSTFLAGS="$page_flags"

cargo ndk \
  -t arm64-v8a -t armeabi-v7a -t x86_64 \
  --platform 24 \
  -o "$tmp" \
  build --release -p mirage-ffi

echo "cargo-ndk produced:"
find "$tmp" -name '*.so' -print | sort

# Start from a clean slate so stale libraries can never leak into the APK.
mkdir -p "$jni_dir"
find "$jni_dir" -name '*.so' -delete

for abi in "${abis[@]}"; do
  src="$tmp/$abi/libmirage_ffi.so"
  if [[ ! -f "$src" ]]; then
    echo "::error::cargo-ndk did not produce $abi/libmirage_ffi.so"
    exit 1
  fi
  install -D -m 0644 "$src" "$jni_dir/$abi/libmirage_ffi.so"
done

echo "Ignored (not shipped):"
find "$tmp" -name '*.so' ! -name libmirage_ffi.so -print | sort || true

echo "jniLibs contents:"
find "$jni_dir" -name '*.so' -print | sort

# Fail fast (before the long Gradle build) if the 16 KB flag did not take effect.
bash "$repo_root/.github/scripts/check-elf.sh" "$jni_dir"/*/libmirage_ffi.so
