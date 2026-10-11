#!/usr/bin/env bash
# Inspect native libraries.
#
# Usage: check-elf.sh <lib.so>...
#   The parent directory of each file must be its ABI (…/arm64-v8a/libfoo.so),
#   as in jniLibs/ and in an unzipped APK's lib/.
#
# For every library this prints the LOAD segment alignments and the NEEDED
# entries, and fails if
#   - an arm64-v8a / x86_64 library has a LOAD alignment below 0x4000 (16 KB), or
#   - a NEEDED library is neither a stable NDK system library nor shipped next
#     to it (it would fail to load at runtime, e.g. libc++_shared.so).
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <lib.so>..." >&2
  exit 2
fi

readelf=""
ndk_readelf="${ANDROID_NDK_HOME:-}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf"
if [[ -n "${ANDROID_NDK_HOME:-}" && -x "$ndk_readelf" ]]; then
  readelf="$ndk_readelf"
elif command -v llvm-readelf >/dev/null 2>&1; then
  readelf="llvm-readelf"
elif command -v readelf >/dev/null 2>&1; then
  readelf="readelf"
else
  echo "::error::no readelf available (set ANDROID_NDK_HOME)" >&2
  exit 1
fi

# Libraries every Android device provides (NDK stable ABI + libstdc++ stub).
system_libs=" libc.so libm.so libdl.so liblog.so libandroid.so libz.so libstdc++.so \
libEGL.so libGLESv1_CM.so libGLESv2.so libGLESv3.so libvulkan.so libjnigraphics.so \
libOpenSLES.so libaaudio.so libamidi.so libcamera2ndk.so libmediandk.so \
libnativewindow.so libnativehelper.so libbinder_ndk.so libneuralnetworks.so libsync.so "

fail=0
for so in "$@"; do
  abi="$(basename "$(dirname "$so")")"
  name="$(basename "$so")"
  dir="$(dirname "$so")"

  aligns="$("$readelf" -lW "$so" | awk '$1 == "LOAD" { print $NF }')"
  needed="$("$readelf" -dW "$so" | sed -n 's/.*(NEEDED).*\[\(.*\)\].*/\1/p')"

  echo "== $abi/$name"
  echo "   LOAD alignment: $(echo $aligns)"
  echo "   NEEDED:         $(echo $needed)"

  case "$abi" in
    arm64-v8a | x86_64)
      if [[ -z "$aligns" ]]; then
        echo "::error::$abi/$name has no LOAD segments"
        fail=1
      fi
      for a in $aligns; do
        if ((a < 0x4000)); then
          echo "::error::$abi/$name has LOAD alignment $a (< 0x4000): not 16 KB page compatible"
          fail=1
          break
        fi
      done
      ;;
  esac

  for n in $needed; do
    if [[ "$system_libs" != *" $n "* && ! -f "$dir/$n" ]]; then
      echo "::error::$abi/$name needs $n, which is neither a system library nor shipped"
      fail=1
    fi
  done
done

exit "$fail"
