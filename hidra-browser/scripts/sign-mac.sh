#!/bin/bash
#
# Sign and notarize an extracted HidraNet.app with a real Apple Developer ID,
# then staple the ticket. Run on a Mac, after build-mac.js has produced the
# bundle (unzip the package first, or point this at the .app the builder left).
#
#   bash scripts/sign-mac.sh /path/to/HidraNet.app
#
# It reads five values from the environment; when ANY is missing it does
# nothing and exits 0, so the ordinary unsigned build keeps working exactly as
# before and CI without secrets is unaffected:
#
#   APPLE_CERT_P12                base64 of the Developer ID Application .p12
#   APPLE_CERT_PASSWORD           the .p12 export password
#   APPLE_ID                      the Apple ID email of the developer account
#   APPLE_TEAM_ID                 the 10-character team id
#   APPLE_APP_SPECIFIC_PASSWORD   an app-specific password for notarytool
#
# See docs/code-signing.md for how to obtain these and the one-time setup.
#
set -uo pipefail

APP="${1:-}"
if [ -z "$APP" ] || [ ! -d "$APP" ]; then
  echo "usage: bash scripts/sign-mac.sh /path/to/HidraNet.app" >&2
  exit 2
fi

missing=""
for v in APPLE_CERT_P12 APPLE_CERT_PASSWORD APPLE_ID APPLE_TEAM_ID APPLE_APP_SPECIFIC_PASSWORD; do
  if [ -z "${!v:-}" ]; then missing="$missing $v"; fi
done
if [ -n "$missing" ]; then
  echo "sign-mac: no Developer ID secrets set ($missing ) — leaving the app"
  echo "          unsigned (ad-hoc). This is expected for local/unsigned builds."
  exit 0
fi

if [ "$(uname)" != "Darwin" ]; then
  echo "sign-mac: signing and notarization only run on macOS" >&2
  exit 1
fi
for tool in codesign security xcrun ditto; do
  command -v "$tool" >/dev/null 2>&1 || { echo "sign-mac: $tool not found (need Xcode command-line tools)" >&2; exit 1; }
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENTITLEMENTS="$ROOT/scripts/entitlements.mac.plist"
[ -f "$ENTITLEMENTS" ] || { echo "sign-mac: missing $ENTITLEMENTS" >&2; exit 1; }

# A throwaway keychain, and a temp .p12, both removed on exit however we leave.
WORK="$(mktemp -d)"
KEYCHAIN="$WORK/hidra-signing.keychain-db"
KEYCHAIN_PASS="$(uuidgen)"
P12="$WORK/cert.p12"
cleanup() {
  security delete-keychain "$KEYCHAIN" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "$APPLE_CERT_P12" | base64 --decode > "$P12"
security create-keychain -p "$KEYCHAIN_PASS" "$KEYCHAIN"
security set-keychain-settings -lut 21600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASS" "$KEYCHAIN"
security import "$P12" -k "$KEYCHAIN" -P "$APPLE_CERT_PASSWORD" -T /usr/bin/codesign
# Let codesign use the key without an interactive prompt.
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASS" "$KEYCHAIN" >/dev/null
# Search this keychain (plus the login keychain) for the identity.
security list-keychains -d user -s "$KEYCHAIN" "$(security list-keychains -d user | tr -d '" ' | head -1)" >/dev/null 2>&1 || true

IDENTITY="$(security find-identity -v -p codesigning "$KEYCHAIN" | grep 'Developer ID Application' | head -1 | awk '{print $2}')"
if [ -z "$IDENTITY" ]; then
  echo "sign-mac: no 'Developer ID Application' identity in the supplied certificate" >&2
  exit 1
fi
echo "sign-mac: signing with identity $IDENTITY (team $APPLE_TEAM_ID)"

sign() {
  codesign --force --options runtime --timestamp \
    --keychain "$KEYCHAIN" --sign "$IDENTITY" "$@"
}

# Deepest first. --deep does not descend into Resources/, so the bundled Tor
# (and anything else under Resources/bin) is signed on its own.
if [ -f "$APP/Contents/Resources/bin/tor/tor" ]; then
  sign "$APP/Contents/Resources/bin/tor/tor"
fi
# Electron's nested helper apps and frameworks, deepest first.
find "$APP/Contents/Frameworks" -type f \( -name '*.dylib' -o -name '*.so' \) 2>/dev/null | while read -r lib; do
  sign "$lib"
done
find "$APP/Contents/Frameworks" -maxdepth 1 -name '*.framework' 2>/dev/null | while read -r fw; do
  sign "$fw"
done
find "$APP/Contents/Frameworks" -maxdepth 1 -name '*.app' 2>/dev/null | while read -r helper; do
  sign --entitlements "$ENTITLEMENTS" "$helper"
done
# Finally the outer bundle, with the hardened-runtime entitlements.
sign --entitlements "$ENTITLEMENTS" "$APP"

# Notarize: zip the bundle, submit, wait, staple the ticket onto the .app.
NZIP="$WORK/notarize.zip"
ditto -c -k --keepParent "$APP" "$NZIP"
echo "sign-mac: submitting to Apple for notarization (this can take minutes)"
xcrun notarytool submit "$NZIP" \
  --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" \
  --password "$APPLE_APP_SPECIFIC_PASSWORD" --wait
xcrun stapler staple "$APP"

echo "sign-mac: verifying"
codesign --verify --deep --strict --verbose=2 "$APP"
xcrun stapler validate "$APP"
echo "sign-mac: done — $APP is signed, notarized and stapled"
