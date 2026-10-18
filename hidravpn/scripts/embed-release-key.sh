#!/usr/bin/env bash
# Write the public keys into the clients, once the maintainers have made them.
#
#   hidravpn-sign keygen --out release.key      # offline; prints the public key
#   hidravpn-sign keygen --out list.key         # offline; prints the public key
#   hidravpn/scripts/embed-release-key.sh --release <release public key> --list <list public key>
#
# It edits RELEASE_PUBLIC_KEY_B64 and LIST_PUBLIC_KEY_B64 in
# hidravpn/crates/hidravpn-core/src/release.rs and RELEASE_PUBLIC_KEY in
# hidravpn/browser/src/main/release-verify.js, then prints what to run to check.
# The secret keys stay where they were made; this script never sees them.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
RELEASE=""; LIST=""
while [ $# -gt 0 ]; do
  case "$1" in
    --release) RELEASE="${2:?}"; shift 2 ;;
    --list) LIST="${2:?}"; shift 2 ;;
    --root) ROOT="${2:?}"; shift 2 ;;
    -h|--help) awk 'NR > 1 && !/^#/ { exit } NR > 1' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ -n "$RELEASE" ] || [ -n "$LIST" ] || { echo "give --release and/or --list" >&2; exit 2; }
check() {
  # 44 base64 characters that decode to 32 bytes: an Ed25519 public key.
  local k="$1" n
  n=$(printf '%s' "$k" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
  [ "$n" = 32 ] || { echo "$2 is not a 32-byte base64 key: '$k'" >&2; exit 2; }
}
RS="$ROOT/hidravpn/crates/hidravpn-core/src/release.rs"
JS="$ROOT/hidravpn/browser/src/main/release-verify.js"
[ -f "$RS" ] && [ -f "$JS" ] || { echo "cannot find $RS or $JS (use --root)" >&2; exit 1; }
if [ -n "$RELEASE" ]; then
  check "$RELEASE" "--release"
  sed -i -E "s|^pub const RELEASE_PUBLIC_KEY_B64: &str = \"[^\"]*\";|pub const RELEASE_PUBLIC_KEY_B64: \&str = \"$RELEASE\";|" "$RS"
  sed -i -E "s|^const RELEASE_PUBLIC_KEY = '[^']*';|const RELEASE_PUBLIC_KEY = '$RELEASE';|" "$JS"
  grep -q "RELEASE_PUBLIC_KEY_B64: &str = \"$RELEASE\"" "$RS" && grep -q "RELEASE_PUBLIC_KEY = '$RELEASE'" "$JS" || { echo "could not write the release key" >&2; exit 1; }
  echo "release key embedded in release.rs and release-verify.js"
fi
if [ -n "$LIST" ]; then
  check "$LIST" "--list"
  sed -i -E "s|^pub const LIST_PUBLIC_KEY_B64: &str = \"[^\"]*\";|pub const LIST_PUBLIC_KEY_B64: \&str = \"$LIST\";|" "$RS"
  grep -q "LIST_PUBLIC_KEY_B64: &str = \"$LIST\"" "$RS" || { echo "could not write the list key" >&2; exit 1; }
  echo "list key embedded in release.rs"
fi
cat <<EOT
Now check and rebuild:
  cargo test --manifest-path hidravpn/Cargo.toml -p hidravpn-core     # the key must parse
  node hidravpn/browser/test/release-verify.js                         # the two constants must match
  cargo build --release --manifest-path hidravpn/Cargo.toml
Then commit release.rs and release-verify.js. The secret keys never enter the repository.
EOT
