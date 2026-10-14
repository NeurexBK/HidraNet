#!/usr/bin/env bash
# Install a HidraVPN node on a Linux server, in one command.
#
#   sudo bash hidravpn/scripts/install-node-linux.sh --endpoint <public-ip>:51820 --name <node-name>
#
# Options:
#   --endpoint IP:PORT    the address clients will reach this node at (required)
#   --name NAME           what clients see this node called (default: the hostname)
#   --dns URL ...         resolvers for DNS-over-HTTPS (default: the node's own list)
#   --out-interface IF    the interface traffic leaves by (default: the default route's)
#   --role ROLE           entry, exit or both (default both): what this node lets itself be
#   --operator WHO        who runs it, as clients and lists show it
#   --contact HOW         how to reach the operator (an address, a page)
#   --open-admission      admit any client that asks (rate-limited, capped), not by hand
#   --pass-admission      admit a client that redeems a pass (phase 5); then add the
#                         issuer's key with: hidravpn-node pass-key add <record.json>
#   --admission-port P    TCP port of the admission service (default 51821)
#   --max-clients N       how many clients may hold a lease at once (default 4000)
#   --idle-days N         days without a handshake after which an openly admitted client is forgotten (default 30; 0 never)
#   --dry-run             print every step and change nothing
#
# A node is meant for a rented server with a public address, not for a home
# connection behind a router: nothing here forwards ports, and nothing here
# can. The server must accept UDP on the endpoint's port; this script says how
# for the firewalls it recognises and otherwise prints the rule to add.
#
# What gets installed: the binary at /usr/local/bin/hidravpn-node, the node's
# key and settings in /etc/hidravpn/node.toml (made once, kept across runs),
# and a hardened systemd unit (scripts/hidravpn-node.service). The node logs
# counts and states, never an address or a name. Remove everything with
#   sudo systemctl disable --now hidravpn-node; sudo rm /etc/systemd/system/hidravpn-node.service /usr/local/bin/hidravpn-node
# and, if you want the key gone too, /etc/hidravpn/node.toml.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BIN="$ROOT/target/release"
PREFIX="${HIDRAVPN_PREFIX:-/usr/local/bin}"
ETC="${HIDRAVPN_ETC:-/etc/hidravpn}"
UNIT="${HIDRAVPN_UNIT:-/etc/systemd/system/hidravpn-node.service}"

ENDPOINT=""; NAME=""; OUT_IF=""; DRY=0; DNS=(); ROLE="both"; OPERATOR=""; CONTACT=""; OPEN=0; PASS=0; ADM_PORT=51821
usage() { sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; }
while [ $# -gt 0 ]; do
  case "$1" in
    --endpoint|--name|--out-interface|--role|--operator|--contact|--admission-port|--max-clients|--idle-days)
      [ $# -ge 2 ] || { echo "$1 needs a value" >&2; usage >&2; exit 2; }
      case "$1" in
        --endpoint) ENDPOINT="$2" ;;
        --name) NAME="$2" ;;
        --out-interface) OUT_IF="$2" ;;
        --role) ROLE="$2" ;;
        --operator) OPERATOR="$2" ;;
        --contact) CONTACT="$2" ;;
        --admission-port) ADM_PORT="$2" ;;
        --max-clients) MAX_CLIENTS="$2" ;;
        --idle-days) IDLE_DAYS="$2" ;;
      esac
      shift 2 ;;
    --open-admission) OPEN=1; shift ;;
    --pass-admission) PASS=1; shift ;;
    --dns) shift; while [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; do DNS+=("$1"); shift; done ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$ENDPOINT" ] || { echo "--endpoint IP:PORT is required: the public address clients will reach this node at" >&2; exit 2; }
case "$ENDPOINT" in
  *:*) ;;
  *) echo "--endpoint must be IP:PORT, for instance 203.0.113.10:51820" >&2; exit 2 ;;
esac
PORT="${ENDPOINT##*:}"
case "$PORT" in ''|*[!0-9]*) echo "--endpoint has no port" >&2; exit 2 ;; esac
case "$ROLE" in entry|exit|both) ;; *) echo "--role must be entry, exit or both" >&2; exit 2 ;; esac
[ "$OPEN" = 1 ] && [ "$PASS" = 1 ] && { echo "--open-admission and --pass-admission are two ways to admit; choose one" >&2; exit 2; }
case "$ADM_PORT" in ''|*[!0-9]*) echo "--admission-port must be a number" >&2; exit 2 ;; esac
case "${MAX_CLIENTS:-}" in *[!0-9]*) echo "--max-clients must be a number" >&2; exit 2 ;; esac
case "${IDLE_DAYS:-}" in *[!0-9]*) echo "--idle-days must be a number" >&2; exit 2 ;; esac
# Not the hostname: the name goes into every client's screen and into any
# published list, and a hostname is one more thing about the server.
[ -n "$NAME" ] || NAME="node-$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"

if [ "$DRY" = 1 ]; then
  run() { printf 'would run: %s\n' "$*"; }
else
  [ "$(id -u)" = 0 ] || { echo "run it with sudo: sudo bash $0 $*" >&2; exit 1; }
  run() { "$@"; }
fi
step() { echo ">> $*"; }

# What the node needs from the machine, checked before anything is changed:
# without these the unit would start, crash five times and stop.
step "checking the machine"
MISSING=0
if ! command -v nft >/dev/null 2>&1; then echo "   nft is missing: install nftables (apt install nftables / dnf install nftables)" >&2; MISSING=1; fi
if ! command -v systemctl >/dev/null 2>&1; then echo "   systemd is missing: this installer makes a systemd unit" >&2; MISSING=1; fi
if [ ! -c /dev/net/tun ]; then echo "   /dev/net/tun is missing: load the tun module (modprobe tun) or enable TUN at the provider (some containers have none)" >&2; MISSING=1; fi
if [ "$MISSING" = 1 ]; then
  if [ "$DRY" = 1 ]; then echo "   (a real run would stop here)"; else exit 1; fi
else
  echo "   nft, systemd and /dev/net/tun are there"
fi

# The interface the node's NAT sends traffic out of: the default route's,
# unless told otherwise.
if [ -z "$OUT_IF" ]; then
  OUT_IF="$( (ip -4 route show default 2>/dev/null || true) | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')"
  [ -n "$OUT_IF" ] || OUT_IF="eth0"
fi

# cargo may live in a user's ~/.cargo when invoked under sudo.
if [ -n "${SUDO_USER:-}" ] && [ -f "/home/$SUDO_USER/.cargo/env" ]; then
  # shellcheck disable=SC1090,SC1091
  . "/home/$SUDO_USER/.cargo/env"
fi

if [ ! -x "$BIN/hidravpn-node" ]; then
  if ! command -v cargo >/dev/null; then
    echo "hidravpn-node is not built and cargo is not installed." >&2
    echo "Either install Rust (https://rustup.rs) or build elsewhere and copy hidravpn-node into $BIN, then run this again." >&2
    [ "$DRY" = 1 ] || exit 1
  fi
  step "building the node (a few minutes; as root, from this checkout — build on another machine and copy the binary in if that is not what you want)"
  run cargo build --release --manifest-path "$ROOT/Cargo.toml" -p hidravpn-node
fi

step "installing the binary to $PREFIX/hidravpn-node"
run install -d -m 0755 "$PREFIX"
run install -m 0755 "$BIN/hidravpn-node" "$PREFIX/hidravpn-node"

step "the node's key and settings in $ETC/node.toml"
run install -d -m 0700 "$ETC"
if [ -f "$ETC/node.toml" ] && [ "$DRY" = 0 ]; then
  echo "   keeping the existing $ETC/node.toml (the node keeps its key; admitted clients live in /var/lib/hidravpn/peers.json and survive reboots)"
else
  INIT=("$PREFIX/hidravpn-node" --config "$ETC/node.toml" init --endpoint "$ENDPOINT" --port "$PORT" --name "$NAME" --out-interface "$OUT_IF" --role "$ROLE" --admission-port "$ADM_PORT")
  [ -n "$OPERATOR" ] && INIT+=(--operator "$OPERATOR")
  [ -n "$CONTACT" ] && INIT+=(--contact "$CONTACT")
  [ "$OPEN" = 1 ] && INIT+=(--open-admission)
  [ "$PASS" = 1 ] && INIT+=(--pass-admission)
  [ -n "${MAX_CLIENTS:-}" ] && INIT+=(--max-clients "$MAX_CLIENTS")
  [ -n "${IDLE_DAYS:-}" ] && INIT+=(--idle-days "$IDLE_DAYS")
  [ ${#DNS[@]} -gt 0 ] && INIT+=(--dns "${DNS[@]}")
  run "${INIT[@]}"
fi

step "the systemd unit at $UNIT"
run install -m 0644 "$HERE/hidravpn-node.service" "$UNIT"
run systemctl daemon-reload
run systemctl enable --now hidravpn-node

step "the firewall: UDP $PORT (the tunnel) and TCP $ADM_PORT (admission and the node's record) must reach this node; SSH stays as it is"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  run ufw allow "$PORT/udp" comment "HidraVPN node"
  run ufw allow "$ADM_PORT/tcp" comment "HidraVPN admission"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  run firewall-cmd --permanent --add-port="$PORT/udp"
  run firewall-cmd --permanent --add-port="$ADM_PORT/tcp"
  run firewall-cmd --reload
else
  echo "   no ufw or firewalld in charge here; if a firewall is in front of this server, allow UDP $PORT and TCP $ADM_PORT (and nothing else new):"
  echo "     nft:       nft add rule inet filter input udp dport $PORT accept; nft add rule inet filter input tcp dport $ADM_PORT accept"
  echo "     iptables:  iptables -I INPUT -p udp --dport $PORT -j ACCEPT; iptables -I INPUT -p tcp --dport $ADM_PORT -j ACCEPT"
  echo "     cloud:     open UDP $PORT and TCP $ADM_PORT in the provider's firewall or security group"
fi

if [ "$DRY" = 0 ]; then
  # A crash-looping unit is "active" for a moment; wait for it to settle and
  # for the node to say it is serving.
  UP=0
  for i in $(seq 1 20); do
    sleep 0.5
    if ! systemctl is-active --quiet hidravpn-node; then UP=0; break; fi
    if journalctl -u hidravpn-node --since "-2 min" --no-pager 2>/dev/null | grep -q "DNS forwarder ready"; then UP=1; break; fi
  done
  if [ "$UP" = 1 ]; then
    step "the node is running and serving"
  elif systemctl is-active --quiet hidravpn-node; then
    step "the node is running (it has not yet reported ready; check: journalctl -u hidravpn-node -f)"
  else
    echo "the node did not start; see: journalctl -u hidravpn-node -n 50" >&2
    exit 1
  fi
  NODE_PUB="$("$PREFIX/hidravpn-node" --config "$ETC/node.toml" pubkey 2>/dev/null || echo '<run: hidravpn-node pubkey>')"
else
  NODE_PUB='<printed by: hidravpn-node pubkey>'
fi

cat <<EOT

────────────────────────────────────────────────────────────────────────
HidraVPN node "$NAME" at $ENDPOINT (traffic leaves by $OUT_IF).
Role: $ROLE.  Admission: $([ "$OPEN" = 1 ] && echo "open (any client that asks is admitted, rate-limited)" || { [ "$PASS" = 1 ] && echo "with a pass (add the issuer's key: hidravpn-node pass-key add <record.json>, then restart)"; } || echo "by hand").

Node public key:  $NODE_PUB

Its record, for the node list:   hidravpn-node record > $NAME.json
(send that file to whoever makes the list; scripts/make-node-list.sh signs it in)

$([ "$OPEN" = 1 ] && echo "Clients that know this node (from the list, or hidravpn nodes discover $ENDPOINT) are admitted with: sudo hidravpn nodes join --all" || echo "To admit a client by hand, the person running it does:")
  1. installs the client (hidravpn/scripts/install-linux.sh or the Windows build)
  2. runs            hidravpn pubkey --node '$NODE_PUB'      and sends you what it prints
You then run:
  3.                 hidravpn-node admit --name <a-name> --pubkey '<what they sent>'
and send them the invite it prints. They add it with  hidravpn nodes add --exit invite.json
(or --entry, if this node is their first hop) and connect.

Status:  systemctl status hidravpn-node        Logs:  journalctl -u hidravpn-node -f
Logs hold counts and states, never an address or a name.

BACK UP $ETC/node.toml now, somewhere else: it holds the node's private key.
Lose it and this node's identity changes; every client would need admitting
again and every published entry for it is stale. Admitted clients are in
/var/lib/hidravpn/peers.json and survive reboots; back that up too.

From another machine, check the port is reachable:  nc -vzu <this ip> $PORT
(nothing answers an unauthenticated probe; "open" or no error is what you want,
a firewall in the way shows as a timeout).

This is an EXIT if clients route the internet through it: abuse complaints for
their traffic arrive at this server's owner. Run one only knowing that, with
an abuse contact of your own. An ENTRY sees clients' addresses and nothing
else. Mail (port 25) and the usual abuse ports never leave a node (the exit
policy in the node's firewall). hidravpn/docs/phase-4.md says what a node
does; docs/business/16-network-bootstrap.md says who runs which, and why.
────────────────────────────────────────────────────────────────────────
EOT
