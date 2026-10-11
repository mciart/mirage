#!/usr/bin/env bash
# Build the Turbo VPN APKs with Gradle and stage them in <repo>/dist/.
#
#   dist/app-release.apk           (only when the signing secrets are available)
#   dist/app-debug.apk
#   dist/app-debug-androidTest.apk
#
# Env in:
#   VERSION_NAME, VERSION_CODE      passed to Gradle as -PversionName / -PversionCode
#   IS_TAG                          "true" on a turbo-v* tag: missing signing secrets are fatal
#   ANDROID_KEYSTORE_B64            base64 of the PKCS12 release keystore (secret)
#   ANDROID_KEYSTORE_PASSWORD       store and key password (secret)
#   ANDROID_KEY_ALIAS               key alias (secret)
# Without all three secrets (e.g. a pull request from a fork) assembleRelease is
# skipped, unless IS_TAG is "true", in which case the build fails.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

: "${VERSION_NAME:?VERSION_NAME is not set}"
: "${VERSION_CODE:?VERSION_CODE is not set}"
is_tag="${IS_TAG:-false}"

keystore="${RUNNER_TEMP:?RUNNER_TEMP is not set}/release.p12"
trap 'rm -f "$keystore"' EXIT

tasks=(assembleDebug assembleDebugAndroidTest)
release_built=false

if [[ -n "${ANDROID_KEYSTORE_B64:-}" && -n "${ANDROID_KEYSTORE_PASSWORD:-}" && -n "${ANDROID_KEY_ALIAS:-}" ]]; then
  printf '%s' "$ANDROID_KEYSTORE_B64" | base64 -d >"$keystore"
  if [[ ! -s "$keystore" ]]; then
    echo "::error::ANDROID_KEYSTORE_B64 decoded to an empty file"
    exit 1
  fi
  # Fail early with a clear message if the password or alias does not match.
  if ! keytool_out="$(keytool -list -storetype PKCS12 -keystore "$keystore" \
    -storepass:env ANDROID_KEYSTORE_PASSWORD -alias "$ANDROID_KEY_ALIAS" 2>&1)"; then
    echo "$keytool_out"
    echo "::error::cannot open the release keystore (wrong password, alias or not a PKCS12 file)"
    exit 1
  fi
  export ANDROID_KEYSTORE_FILE="$keystore"
  export ANDROID_KEYSTORE_PASSWORD ANDROID_KEY_ALIAS
  tasks=(assembleRelease "${tasks[@]}")
  release_built=true
elif [[ "$is_tag" == "true" ]]; then
  echo "::error::Release build needs the ANDROID_KEYSTORE_B64, ANDROID_KEYSTORE_PASSWORD and ANDROID_KEY_ALIAS secrets"
  exit 1
else
  echo "::warning::Signing secrets are not available (fork PR?): skipping assembleRelease"
fi

(
  cd android
  ./gradlew "${tasks[@]}" \
    -PversionName="$VERSION_NAME" -PversionCode="$VERSION_CODE" \
    --stacktrace --no-daemon
)

out="android/app/build/outputs/apk"
rm -rf dist
mkdir -p dist
if [[ "$release_built" == true ]]; then
  cp "$out/release/app-release.apk" dist/app-release.apk
fi
cp "$out/debug/app-debug.apk" dist/app-debug.apk
cp "$out/androidTest/debug/app-debug-androidTest.apk" dist/app-debug-androidTest.apk

echo "Staged APKs:"
ls -l dist
