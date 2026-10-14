#!/usr/bin/env bash
# Writes the release manifest the browser installs HidraVPN from: for each
# platform, every file with its download address, SHA-256 and size. The
# maintainers then sign it OFFLINE with the release key and publish both:
#
#   hidravpn/scripts/make-release-manifest.sh --version 0.5.0 \
#       --base https://hidranet.org/vpn/release/0.5.0 \
#       --linux-x64 dist/linux --win32-x64 dist/windows > manifest.json
#   hidravpn-sign sign --key /offline/release.key manifest.json   # writes manifest.json.sig
#
# Publish manifest.json and manifest.json.sig at
# https://hidranet.org/vpn/release/manifest.json(.sig), and every listed file
# at <base>/<platform>/<name>. A browser refuses the manifest unless the
# signature checks out against the release key it carries, and refuses any
# file whose size or SHA-256 differs from what the manifest says.
#
# A platform folder holds the service and the client (hidravpn-service and
# hidravpn, with .exe on Windows) and, on Windows, wintun.dll.
set -euo pipefail

VERSION=""; BASE=""
declare -a PLATFORMS=()
declare -A DIRS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --base) BASE="${2%/}"; shift 2 ;;
    --linux-x64|--win32-x64) p="${1#--}"; PLATFORMS+=("$p"); DIRS[$p]="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$VERSION" =~ ^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$ ]] || { echo "--version X.Y.Z is required" >&2; exit 2; }
[[ "$BASE" == https://* ]] || { echo "--base must be an https:// address" >&2; exit 2; }
[ ${#PLATFORMS[@]} -gt 0 ] || { echo "give at least one --linux-x64 DIR or --win32-x64 DIR" >&2; exit 2; }

entry() { # platform dir name
  local f="$2/$3"
  [ -f "$f" ] || { echo "$f is missing" >&2; exit 1; }
  printf '        { "name": "%s", "url": "%s/%s/%s", "sha256": "%s", "size": %s }' \
    "$3" "$BASE" "$1" "$3" "$(sha256sum "$f" | cut -d' ' -f1)" "$(stat -c %s "$f")"
}

printf '{\n  "product": "hidravpn",\n  "version": "%s",\n  "generated": "%s",\n  "platforms": {\n' \
  "$VERSION" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
first=1
for p in "${PLATFORMS[@]}"; do
  d="${DIRS[$p]}"
  if [ "$p" = win32-x64 ]; then svc=hidravpn-service.exe; cli=hidravpn.exe; extra=(wintun.dll)
  else svc=hidravpn-service; cli=hidravpn; extra=(); fi
  [ $first = 1 ] || printf ',\n'
  first=0
  printf '    "%s": {\n      "service": "%s",\n      "client": "%s",\n      "files": [\n' "$p" "$svc" "$cli"
  entry "$p" "$d" "$svc"; printf ',\n'
  entry "$p" "$d" "$cli"
  for x in "${extra[@]}"; do printf ',\n'; entry "$p" "$d" "$x"; done
  printf '\n      ]\n    }'
done
printf '\n  }\n}\n'
