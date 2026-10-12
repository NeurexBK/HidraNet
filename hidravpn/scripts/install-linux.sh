#!/usr/bin/env bash
# Install the HidraVPN client and its background service on Linux.
#
#   sudo bash hidravpn/scripts/install-linux.sh
#
# It builds the release binaries if they are not already built, installs them
# to /usr/local/bin, installs and starts the systemd service, makes this
# machine's key if there is none, and prints the public key to give the node's
# administrator. It touches only HidraVPN; nothing else on the machine changes.
#
# Uninstall with:  sudo hidravpn-service uninstall
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BIN="$ROOT/target/release"
PREFIX=/usr/local/bin

[ "$(id -u)" = 0 ] || { echo "run it with sudo: sudo bash $0" >&2; exit 1; }

# cargo may live in a user's ~/.cargo when invoked under sudo.
if [ -f "${SUDO_USER:+/home/$SUDO_USER/.cargo/env}" ]; then
  # shellcheck disable=SC1090
  . "/home/$SUDO_USER/.cargo/env"
fi

if [ ! -x "$BIN/hidravpn" ] || [ ! -x "$BIN/hidravpn-service" ]; then
  if ! command -v cargo >/dev/null; then
    echo "The binaries are not built and cargo is not installed." >&2
    echo "Either install Rust (https://rustup.rs) or build elsewhere and copy" >&2
    echo "hidravpn and hidravpn-service into $BIN, then run this again." >&2
    exit 1
  fi
  echo ">> building the client and the service (a few minutes)"
  ( cd "$ROOT" && cargo build --release -p hidravpn -p hidravpn-service )
fi

echo ">> installing the binaries to $PREFIX"
install -m 0755 "$BIN/hidravpn" "$PREFIX/hidravpn"
install -m 0755 "$BIN/hidravpn-service" "$PREFIX/hidravpn-service"

echo ">> installing and starting the service"
"$PREFIX/hidravpn-service" install

install -d -m 0755 /etc/hidravpn
if [ -f /etc/hidravpn/client.key ]; then
  PUB="$("$PREFIX/hidravpn" pubkey)"
  echo ">> keeping the existing key at /etc/hidravpn/client.key"
else
  PUB="$("$PREFIX/hidravpn" keygen)"
  echo ">> new key written to /etc/hidravpn/client.key (the secret stays there)"
fi

cat <<EOF

────────────────────────────────────────────────────────────────────────
HidraVPN is installed and the service is running.

This machine's public key — give it to the node's administrator:

  $PUB

On the node, the administrator runs:

  hidravpn-node admit --name <a-name> --pubkey '$PUB'

Save the invite it prints as invite.json on this machine, then:

  sudo hidravpn up invite.json      connect (routes everything, arms the kill switch)
  hidravpn status                   is it connected? is the kill switch on?
  sudo hidravpn down                disconnect and restore the network

Remove everything:  sudo hidravpn-service uninstall
────────────────────────────────────────────────────────────────────────
EOF
