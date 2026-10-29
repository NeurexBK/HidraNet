#!/usr/bin/env bash
# Writes the release manifest the browser installs HidraVPN from: for each
# platform, every file with its download address, SHA-256 and size. The
# maintainers then sign it OFFLINE with the release key and publish both:
#
#   hidravpn/scripts/make-release-manifest.sh --version 0.5.0 --sequence N \
#       [--expires 2027-01-01T00:00:00Z] \
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
# Every past manifest stays validly signed, so a signature alone cannot tell
# the newest from an old one served again. --sequence must go up with every
# manifest published, a new release or the same one signed again (the date,
# as 2026110101, does); a browser refuses one lower than it has already
# accepted. It is 1 or more: the 0.1.0 manifest, from before sequences,
# counts as 0. --expires defaults to 90 days from now; after it browsers refuse
# the manifest, so sign it again with a higher sequence before then, or a
# server that keeps serving an old one would hold back every later release.
#
# A platform folder holds the service and the client (hidravpn-service and
# hidravpn, with .exe on Windows) and, on Windows, wintun.dll.
set -euo pipefail

VERSION=""; BASE=""; SEQ=""; EXPIRES=""
declare -a PLATFORMS=()
declare -A DIRS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --base) BASE="${2%/}"; shift 2 ;;
    --sequence) SEQ="${2:-}"; shift 2 ;;
    --expires) EXPIRES="${2:-}"; shift 2 ;;
    --linux-x64|--win32-x64) p="${1#--}"; PLATFORMS+=("$p"); DIRS[$p]="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$VERSION" =~ ^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$ ]] || { echo "--version X.Y.Z is required" >&2; exit 2; }
[[ "$SEQ" =~ ^[0-9]{1,15}$ ]] || { echo "--sequence N is required: a whole number, higher than the last manifest's" >&2; exit 2; }
# The 0.1.0 manifest, from before sequences, counts as 0: a new one at 0
# would set no floor above it, and a browser would still take 0.1.0 back.
[ "$((10#$SEQ))" -ge 1 ] || { echo "--sequence must be 1 or more: the 0.1.0 manifest counts as sequence 0, so one at 0 would not keep a browser from going back to it" >&2; exit 2; }
[ -n "$EXPIRES" ] || EXPIRES="$(date -u -d '+90 days' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+90d +%Y-%m-%dT%H:%M:%SZ)"
[[ "$EXPIRES" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || { echo "--expires must be a date like 2027-01-01T00:00:00Z" >&2; exit 2; }
[[ "$BASE" == https://* ]] || { echo "--base must be an https:// address" >&2; exit 2; }
[ ${#PLATFORMS[@]} -gt 0 ] || { echo "give at least one --linux-x64 DIR or --win32-x64 DIR" >&2; exit 2; }
# The address goes into the JSON as it is: nothing that would need escaping.
case "$BASE" in *'"'*|*'\'*|*[[:space:]]*) echo "--base must not hold quotes, backslashes or spaces" >&2; exit 2 ;; esac

files_of() { # platform -> the files it publishes
  if [ "$1" = win32-x64 ]; then echo hidravpn-service.exe hidravpn.exe wintun.dll
  else echo hidravpn-service hidravpn; fi
}
# Every file is there before anything is written: a missing one must not
# leave half a manifest in the file the output goes to.
for p in "${PLATFORMS[@]}"; do
  for x in $(files_of "$p"); do
    [ -f "${DIRS[$p]}/$x" ] || { echo "${DIRS[$p]}/$x is missing" >&2; exit 1; }
  done
done

entry() { # platform dir name
  local f="$2/$3"
  [ -f "$f" ] || { echo "$f is missing" >&2; exit 1; }
  printf '        { "name": "%s", "url": "%s/%s/%s", "sha256": "%s", "size": %s }' \
    "$3" "$BASE" "$1" "$3" "$(sha256sum "$f" | cut -d' ' -f1)" "$(stat -c %s "$f")"
}

printf '{\n  "product": "hidravpn",\n  "version": "%s",\n  "generated": "%s",\n  "sequence": %s,\n  "expires": "%s",\n  "platforms": {\n' \
  "$VERSION" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$((10#$SEQ))" "$EXPIRES"
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
