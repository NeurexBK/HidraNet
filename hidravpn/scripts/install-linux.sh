#!/usr/bin/env bash
# Install the HidraVPN client and its background service on Linux.
#
#   sudo bash hidravpn/scripts/install-linux.sh
#
# It builds the release binaries if they are not already built, installs them
# to /usr/local/bin, installs and starts the systemd service, makes this
# machine's key if there is none, and says how to get admitted on a node. It
# touches only HidraVPN; nothing else on the machine changes.
#
# Uninstall with:  sudo hidravpn-service uninstall
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BIN="$ROOT/target/release"
PREFIX=/usr/local/bin

[ "$(id -u)" = 0 ] || { echo "run it with sudo: sudo bash $0" >&2; exit 1; }

if [ ! -x "$BIN/hidravpn" ] || [ ! -x "$BIN/hidravpn-service" ]; then
  # Built as the person who ran sudo, with their own Rust, never as root:
  # a build as root would leave target/ owned by root in their checkout,
  # and run their ~/.cargo/env as root.
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    BUILD=(sudo -u "$SUDO_USER" -H bash -c 'cd "$1" && { [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"; true; } && command -v cargo >/dev/null && cargo build --release -p hidravpn -p hidravpn-service' _ "$ROOT")
  elif command -v cargo >/dev/null; then
    BUILD=(bash -c 'cd "$1" && cargo build --release -p hidravpn -p hidravpn-service' _ "$ROOT")
  else
    BUILD=()
  fi
  echo ">> building the client and the service (a few minutes)"
  if [ ${#BUILD[@]} -eq 0 ] || ! "${BUILD[@]}"; then
    echo "The binaries are not built and could not be built here (is Rust installed for ${SUDO_USER:-root}?)." >&2
    echo "Either install Rust (https://rustup.rs) or build elsewhere and copy" >&2
    echo "hidravpn and hidravpn-service into $BIN, then run this again." >&2
    exit 1
  fi
fi

echo ">> installing the binaries to $PREFIX"
install -m 0755 "$BIN/hidravpn" "$PREFIX/hidravpn"
install -m 0755 "$BIN/hidravpn-service" "$PREFIX/hidravpn-service"

echo ">> installing and starting the service"
"$PREFIX/hidravpn-service" install

# The browser runs as the person, not as root, and drives the service through
# its control channel; membership of the hidravpn group is what lets it. The
# service's installer made the group; this puts the person who ran sudo in it.
if [ -n "${SUDO_USER:-}" ] && getent group hidravpn >/dev/null 2>&1; then
  if id -nG "$SUDO_USER" | tr ' ' '\n' | grep -qx hidravpn; then
    echo ">> $SUDO_USER is already in the hidravpn group"
  else
    usermod -aG hidravpn "$SUDO_USER"
    echo ">> added $SUDO_USER to the hidravpn group (log out and in once for it to take effect)"
  fi
fi

install -d -m 0755 /etc/hidravpn
if [ -f /etc/hidravpn/client.key ]; then
  echo ">> keeping the existing key at /etc/hidravpn/client.key"
else
  if ! OUT=$("$PREFIX/hidravpn" keygen 2>&1); then
    echo "making this machine's key failed: $OUT" >&2
    echo "the service is installed; make the key with: sudo hidravpn keygen" >&2
    exit 1
  fi
  echo ">> new master key written to /etc/hidravpn/client.key (the secret stays there)"
fi

cat <<EOF

────────────────────────────────────────────────────────────────────────
HidraVPN is installed and the service is running.

Nodes from the signed list that admit openly need no administrator:

  sudo hidravpn nodes import <signed list>   the nodes to start with
  sudo hidravpn nodes join --all             ask each open node for admission
  sudo hidravpn up --rapido                  connect (or --privado for two hops)

Every node is shown a different key, derived from this machine's one master
key. To be admitted on a node by its administrator instead:

  1. the node's administrator runs   hidravpn-node pubkey   and sends you the key
  2. you run                         hidravpn pubkey --node <that key>
  3. the administrator runs          hidravpn-node admit --name <a-name> --pubkey '<what step 2 printed>'

Save the invite it prints as invite.json on this machine, then:

  sudo hidravpn up invite.json      connect (routes everything, arms the kill switch)
  hidravpn status                   is it connected? is the kill switch on?
  sudo hidravpn down                disconnect and restore the network

Remove everything:  sudo hidravpn-service uninstall
────────────────────────────────────────────────────────────────────────
EOF
