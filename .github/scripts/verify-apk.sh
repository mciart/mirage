#!/usr/bin/env bash
# Verify a built APK: signature, 16 KB zip alignment, manifest, native libraries.
#
# Usage: verify-apk.sh <apk> [--pin-cert]
#
# Env in:
#   EXPECTED_VERSION_NAME, EXPECTED_VERSION_CODE   checked against `aapt2 dump badging`
#   APP_ID                  expected package (default com.mirage.vpn)
#   VERIFY_BUILD_TOOLS      SDK build-tools version to use (default 35.0.0; zipalign -P needs >= 35)
#   EXPECTED_CERT_SHA256    with --pin-cert: the signer certificate SHA-256 (colons/case ignored)
#   ANDROID_NDK_HOME        for llvm-readelf
set -euo pipefail

apk="${1:?usage: verify-apk.sh <apk> [--pin-cert]}"
pin_cert=false
[[ "${2:-}" == "--pin-cert" ]] && pin_cert=true

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sdk="${ANDROID_SDK_ROOT:-${ANDROID_HOME:?ANDROID_SDK_ROOT is not set}}"
bt="$sdk/build-tools/${VERIFY_BUILD_TOOLS:-35.0.0}"
app_id="${APP_ID:-com.mirage.vpn}"
abis=(arm64-v8a armeabi-v7a x86_64)

for tool in apksigner zipalign aapt2; do
  [[ -x "$bt/$tool" ]] || { echo "::error::$bt/$tool not found"; exit 1; }
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail() { echo "::error::$apk: $*"; exit 1; }

echo "##### Verifying $apk ($(du -h "$apk" | cut -f1))"

echo "--- apksigner"
if ! sig="$("$bt/apksigner" verify --verbose --print-certs "$apk" 2>&1)"; then
  echo "$sig"
  fail "apksigner verify failed"
fi
echo "$sig"
grep -q 'Verified using v2 scheme (APK Signature Scheme v2): true' <<<"$sig" ||
  fail "APK is not verified with the v2 signature scheme"
if [[ "$pin_cert" == true ]]; then
  : "${EXPECTED_CERT_SHA256:?EXPECTED_CERT_SHA256 is not set}"
  want="$(tr -d ':' <<<"$EXPECTED_CERT_SHA256" | tr 'A-F' 'a-f')"
  got="$(sed -n 's/^Signer #1 certificate SHA-256 digest: *//p' <<<"$sig" | head -n1 | tr 'A-F' 'a-f')"
  [[ -n "$got" ]] || fail "could not read the signer certificate digest"
  [[ "$got" == "$want" ]] || fail "signer certificate SHA-256 is $got, expected $want"
  echo "Signer certificate matches the pinned fingerprint."
fi

echo "--- zipalign (16 KB)"
# `-P <pagesize_kb>` only exists in build-tools >= 35 (an older zipalign rejects it).
if ! "$bt/zipalign" -c -P 16 -v 4 "$apk" >"$tmp/zipalign.txt" 2>&1; then
  cat "$tmp/zipalign.txt"
  fail "zipalign -c -P 16 -v 4 failed (build-tools in use: $bt)"
fi
grep -E ' lib/|Verification' "$tmp/zipalign.txt" || tail -n 3 "$tmp/zipalign.txt"

echo "--- aapt2 dump badging"
"$bt/aapt2" dump badging "$apk" >"$tmp/badging.txt"
grep -E '^(package|sdkVersion|targetSdkVersion|native-code|application-label):' "$tmp/badging.txt"
pkg_line="$(grep -m1 '^package:' "$tmp/badging.txt")"
attr() { sed -n "s/.* $1='\([^']*\)'.*/\1/p" <<<"$pkg_line"; }
[[ "$(attr name)" == "$app_id" ]] || fail "package is '$(attr name)', expected '$app_id'"
if [[ -n "${EXPECTED_VERSION_NAME:-}" && "$(attr versionName)" != "$EXPECTED_VERSION_NAME" ]]; then
  fail "versionName is '$(attr versionName)', expected '$EXPECTED_VERSION_NAME'"
fi
if [[ -n "${EXPECTED_VERSION_CODE:-}" && "$(attr versionCode)" != "$EXPECTED_VERSION_CODE" ]]; then
  fail "versionCode is '$(attr versionCode)', expected '$EXPECTED_VERSION_CODE'"
fi
native="$(grep -m1 '^native-code:' "$tmp/badging.txt" || true)"
for abi in "${abis[@]}"; do
  grep -q "'$abi'" <<<"$native" || fail "native-code is missing $abi"
done

echo "--- native libraries"
unzip -Z1 "$apk" >"$tmp/entries.txt"
if grep -q 'libtun_rs' "$tmp/entries.txt"; then
  grep 'libtun_rs' "$tmp/entries.txt"
  fail "stray libtun_rs library found in the APK"
fi
for abi in "${abis[@]}"; do
  grep -qx "lib/$abi/libmirage_ffi.so" "$tmp/entries.txt" || fail "lib/$abi/libmirage_ffi.so is missing"
done
mkdir "$tmp/x"
unzip -q "$apk" 'lib/*' -d "$tmp/x"
bash "$script_dir/check-elf.sh" "$tmp"/x/lib/*/*.so || fail "native library check failed"

echo "##### $apk OK"
