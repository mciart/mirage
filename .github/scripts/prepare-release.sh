#!/usr/bin/env bash
# Prepare the GitHub Release assets for a turbo-v* tag.
#
# Env in:
#   VERSION     release version without the tag prefix (e.g. 1.0.0)
#   APK         path to the signed release APK
#   OUT_DIR     output directory
#   CERT_SHA256 signing certificate fingerprint to show in the notes
# Writes in OUT_DIR:
#   TurboVPN-<version>.apk, TurboVPN-<version>.apk.sha256, notes.md
set -euo pipefail

version="${VERSION:?VERSION is not set}"
apk="${APK:?APK is not set}"
out="${OUT_DIR:?OUT_DIR is not set}"
cert="${CERT_SHA256:?CERT_SHA256 is not set}"

[[ -f "$apk" ]] || { echo "::error::release APK not found: $apk"; exit 1; }

name="TurboVPN-${version}.apk"
mkdir -p "$out"
cp "$apk" "$out/$name"
(cd "$out" && sha256sum "$name" >"$name.sha256")
sha="$(cut -d' ' -f1 "$out/$name.sha256")"

cat >"$out/notes.md" <<'EOF_NOTES'
**Turbo VPN @VERSION@** is the Android client for the Mirage VPN server (Android 7.0 or newer).

## Install

1. Download `@NAME@` on your phone.
2. When asked, allow your browser (or file manager) to install apps from unknown sources.
3. Open the downloaded file, tap Install, then open Turbo VPN.

## Verify (optional)

- APK SHA-256: `@SHA@`
- Signing certificate SHA-256: `@CERT@`

Check the download with `sha256sum -c @NAME@.sha256`, and the signature with `apksigner verify --print-certs @NAME@`.

## Add users on the server

```
mirage users --add users --username alice --link --host vpn.example.com --server-config server.toml
```

This creates the user and prints an access link and QR code; scan the QR code or paste the link in the app. Add `--embed-cert` if the server uses a self-signed certificate.
EOF_NOTES

sed -i \
  -e "s|@VERSION@|${version}|g" \
  -e "s|@NAME@|${name}|g" \
  -e "s|@SHA@|${sha}|g" \
  -e "s|@CERT@|${cert}|g" \
  "$out/notes.md"

echo "Prepared:"
ls -l "$out"
cat "$out/notes.md"
