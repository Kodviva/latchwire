#!/bin/sh
# Builds Latchwire.app next to this script, signed ad hoc for local use.
# Developer ID signing and notarization belong to packaging (plan 5).
# Usage: desktop/build_macos.sh [go build flags, for example -tags demo]
set -eu
cd "$(dirname "$0")"
app=build/Latchwire.app
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
go build -trimpath -o "$app/Contents/MacOS/latchwire-desktop" "$@" .
cp Info.plist "$app/Contents/Info.plist"
cp assets/icon.icns "$app/Contents/Resources/icon.icns"
codesign --force --sign - "$app"
echo "$app"
