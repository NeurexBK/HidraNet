#!/usr/bin/env bash
# Builds the Windows client and service (hidravpn.exe, hidravpn-service.exe)
# on a Linux machine that already builds the node — typically the node
# itself — so that a Windows test machine can fetch them with scp instead of
# trusting a download.
#
#   bash hidravpn/scripts/build-windows-client.sh [SOURCE_DIR] [OUT_DIR]
#
# SOURCE_DIR is a checkout of the repository (default /opt/hidranet-src); it
# is fast-forwarded to origin/main first (HIDRAVPN_BRANCH picks another
# branch). OUT_DIR (default /root/hidravpn-win) receives both executables
# and prints their SHA-256. Needs root for the one-time install of the MinGW
# cross toolchain.
set -euo pipefail

SRC="${1:-/opt/hidranet-src}"
OUT="${2:-/root/hidravpn-win}"
BRANCH="${HIDRAVPN_BRANCH:-main}"
TARGET=x86_64-pc-windows-gnu

say() { printf '>> %s\n' "$*" >&2; }

# cargo lives in ~/.cargo/bin, which a non-interactive ssh shell does not have.
if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi
command -v cargo >/dev/null || { echo "cargo not found: install Rust with rustup first" >&2; exit 1; }
command -v rustup >/dev/null || { echo "rustup not found: the Windows target needs a rustup-managed toolchain" >&2; exit 1; }

if ! command -v x86_64-w64-mingw32-gcc >/dev/null; then
  say "installing the MinGW cross toolchain (gcc-mingw-w64-x86-64), once"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends gcc-mingw-w64-x86-64 >/dev/null
fi
if ! rustup target list --installed | grep -qx "$TARGET"; then
  say "adding the Rust target $TARGET, once"
  rustup target add "$TARGET"
fi

[ -d "$SRC/.git" ] || { echo "no repository checkout at $SRC" >&2; exit 2; }
say "updating $SRC to origin/$BRANCH"
git -C "$SRC" fetch -q origin "$BRANCH"
git -C "$SRC" checkout -q "$BRANCH"
git -C "$SRC" merge -q --ff-only "origin/$BRANCH"
say "building hidravpn.exe and hidravpn-service.exe from $(git -C "$SRC" rev-parse --short HEAD) (a few minutes the first time)"
cargo build --release --manifest-path "$SRC/hidravpn/Cargo.toml" --target "$TARGET" -p hidravpn -p hidravpn-service

mkdir -p "$OUT"
install -m 0644 "$SRC/hidravpn/target/$TARGET/release/hidravpn.exe" "$OUT/hidravpn.exe"
install -m 0644 "$SRC/hidravpn/target/$TARGET/release/hidravpn-service.exe" "$OUT/hidravpn-service.exe"
say "done"
sha256sum "$OUT/hidravpn.exe" "$OUT/hidravpn-service.exe"
