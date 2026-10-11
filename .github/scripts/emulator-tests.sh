#!/usr/bin/env bash
# Runs on the booted emulator (called as ONE line from android-emulator-runner,
# which executes `script:` line by line).
#
#   a) release smoke test: install the release APK, launch it, make sure it stays
#      alive and does not crash, then uninstall (debug and release are signed
#      with different keys)
#   b) debug + androidTest APKs: run the instrumentation tests, including the
#      end-to-end VPN test against the server started by e2e-server-setup.sh
#   c) always dump logcat
#
# Env in:
#   APK_DIR     directory with app-release.apk (optional), app-debug.apk,
#               app-debug-androidTest.apk
#   OUT_DIR     where logcat*.txt and instrumentation.txt are written
#   E2E_LINK    mirage:// access link for the e2e server
#   E2E_PING_TARGET   (default 10.11.12.1, the server's tunnel address)
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
apk_dir="${APK_DIR:?APK_DIR is not set}"
out_dir="${OUT_DIR:?OUT_DIR is not set}"
link="${E2E_LINK:?E2E_LINK is not set}"
ping_target="${E2E_PING_TARGET:-10.11.12.1}"
app=com.mirage.vpn
runner="$app.test/androidx.test.runner.AndroidJUnitRunner"

mkdir -p "$out_dir"
logcat_file="$out_dir/logcat.txt"
instr_file="$out_dir/instrumentation.txt"

# The link is embedded in single quotes in the remote command line below.
if [[ ! "$link" =~ ^mirage://[A-Za-z0-9._~:/?\&=%+-]+$ ]]; then
  echo "::error::E2E_LINK contains characters that cannot be quoted safely"
  exit 1
fi

# c) Always keep the logs, whatever happens below.
dump_logcat() {
  adb logcat -d -b all >"$logcat_file" 2>&1 || true
}
trap dump_logcat EXIT

adb wait-for-device
echo "Device: $(adb shell getprop ro.product.model | tr -d '\r') / Android $(adb shell getprop ro.build.version.release | tr -d '\r') / $(adb shell getprop ro.product.cpu.abi | tr -d '\r')"
adb logcat -G 16M || true # a bigger ring buffer, so the dump covers the whole run

# a) ---------------------------------------------------------------- release smoke test
if [[ -f "$apk_dir/app-release.apk" ]]; then
  echo "##### Release smoke test"
  adb uninstall "$app" >/dev/null 2>&1 || true
  adb install -r "$apk_dir/app-release.apk"
  adb logcat -c
  start_out="$(adb shell am start -W -n "$app/.MainActivity" | tr -d '\r')"
  echo "$start_out"
  if grep -qiE '^Error|Exception' <<<"$start_out" || ! grep -q '^Status: ok' <<<"$start_out"; then
    echo "::error::release build failed to start MainActivity"
    exit 1
  fi
  sleep 8
  pid="$(adb shell pidof "$app" | tr -d '\r' || true)"
  adb logcat -d -b all >"$out_dir/logcat-smoke.txt" 2>&1 || true
  if [[ -z "$pid" ]]; then
    echo "::error::$app is not running 8 s after launch (crashed?)"
    grep -B2 -A12 -E 'FATAL EXCEPTION|Process: ' "$out_dir/logcat-smoke.txt" | head -n 60 || true
    exit 1
  fi
  if grep -A4 'FATAL EXCEPTION' "$out_dir/logcat-smoke.txt" | grep -q "$app"; then
    echo "::error::FATAL EXCEPTION in $app during the smoke test"
    grep -A12 'FATAL EXCEPTION' "$out_dir/logcat-smoke.txt" | head -n 40
    exit 1
  fi
  echo "Release build is running (pid $pid), no fatal exception."
  adb shell am force-stop "$app"
  adb uninstall "$app"
else
  echo "##### No release APK in $apk_dir (signing secrets unavailable): skipping the smoke test"
fi

# b) -------------------------------------------------------------- instrumentation tests
echo "##### Instrumentation tests"
adb uninstall "$app" >/dev/null 2>&1 || true
adb uninstall "$app.test" >/dev/null 2>&1 || true
adb install -r -t -g "$apk_dir/app-debug.apk"
adb install -r -t "$apk_dir/app-debug-androidTest.apk"
adb logcat -c

# Raw mode (-r) so that every test reports its own status code; the runner's
# final summary ("OK (N tests)") is part of that output too. The link goes into
# the remote shell in single quotes (it contains & ? = %).
set +e
timeout 1200 adb shell "am instrument -w -r -e e2eLink '$link' -e e2ePingTarget '$ping_target' $runner" |
  tr -d '\r' | tee "$instr_file"
adb_rc=${PIPESTATUS[0]}
set -e
if [[ "$adb_rc" -ne 0 ]]; then
  echo "::error::adb shell am instrument exited with $adb_rc"
  exit 1
fi

python3 -I "$script_dir/check-instrumentation.py" "$instr_file" --require-passed EndToEndVpnTest
