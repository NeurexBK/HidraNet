#!/usr/bin/env bash
# Phase 4, end to end: the browser's half of the control channel against a
# REAL service and a real node — the three namespaces of test-service-netns.sh,
# driven through hidra-browser/src/main/vpn-manager.js (the module the VPN page
# uses) instead of the command line. It proves:
#
#   - the service picks the node from the pocket (`connect`), so the browser
#     never handles an invite or a key, and `nodes` names them without keys;
#   - a two-hop request with no entry in the pocket is refused by the service,
#     with the reason, and changes nothing;
#   - one hop connects, routes the machine, arms the kill switch; the exit
#     address the internet sees is the node's; disconnect puts it all back;
#   - the control channel can be used WITHOUT being root, by a member of the
#     hidravpn group — which is how the browser runs. The socket, the token and
#     their directory are checked for group ownership, and the whole sequence
#     runs as an unprivileged user in that group.
#
# Run as root:  hidravpn/scripts/test-browser-netns.sh
# Needs: the release binaries built, node, python3, curl, nft, ip netns,
#        setpriv (util-linux) for the unprivileged part; without it that part
#        runs as root and says so.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/test/guard.sh"
BIN="$HERE/../target/release"
BROWSER="$HERE/../../hidra-browser"
DRIVER="$BROWSER/test/vpn-live.js"
WORK=""
C="ip netns exec hv-client"
N="ip netns exec hv-node"
I="ip netns exec hv-inet"
PIDS=()
MADE_GROUP=0

ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok + 1)); }
fail() { echo "FAIL  $1"; bad=$((bad + 1)); }

cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  ip netns pids hv-client 2>/dev/null | xargs -r kill 2>/dev/null
  for ns in hv-client hv-node hv-inet; do ip netns del "$ns" 2>/dev/null; done
  rm -rf /etc/netns/hv-client /run/hidravpn/control.sock /run/hidravpn/control.token \
         /run/hidravpn/netcfg.json /run/hidravpn/peers.json /var/lib/hidravpn/peers.json /etc/hidravpn/client.key /etc/hidravpn/refill.json /etc/hidravpn/circuit.json
  [ "$MADE_GROUP" = 1 ] && groupdel hidravpn 2>/dev/null
  [ -n "${WORK:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT
cleanup
WORK="$(mktemp -d /tmp/hidravpn-browser.XXXXXX)"
chmod 755 "$WORK"

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
for b in hidravpn hidravpn-node hidravpn-service; do
  [ -x "$BIN/$b" ] || { echo "build first: cargo build --release --manifest-path hidravpn/Cargo.toml"; exit 1; }
done
command -v node >/dev/null || { echo "node is needed"; exit 1; }
[ -f "$DRIVER" ] || { echo "missing $DRIVER"; exit 1; }

# ── The group the browser relies on. Made here if the machine has none. ─────
if ! getent group hidravpn >/dev/null; then
  groupadd --system hidravpn && MADE_GROUP=1
fi
GID=$(getent group hidravpn | cut -d: -f3)
[ -n "$GID" ] && pass "the hidravpn group exists (gid $GID)" || { fail "no hidravpn group"; exit 1; }

# ── Network (same topology as test-service-netns.sh) ────────────────────────
ip netns add hv-client; ip netns add hv-node; ip netns add hv-inet
ip link add c-n type veth peer name n-c; ip link set c-n netns hv-client; ip link set n-c netns hv-node
ip link add n-i type veth peer name i-n; ip link set n-i netns hv-node; ip link set i-n netns hv-inet
$C ip addr add 10.200.0.2/24 dev c-n; $C ip link set c-n up; $C ip link set lo up; $C ip route add default via 10.200.0.1
$N ip addr add 10.200.0.1/24 dev n-c; $N ip link set n-c up; $N ip link set lo up
$N ip addr add 10.201.0.1/24 dev n-i; $N ip link set n-i up; $N ip route add default via 10.201.0.2
$I ip addr add 10.201.0.2/24 dev i-n; $I ip link set i-n up; $I ip link set lo up
mkdir -p /etc/netns/hv-client; echo "nameserver 10.200.0.1" > /etc/netns/hv-client/resolv.conf
ORIG_RESOLV="$(cat /etc/netns/hv-client/resolv.conf)"

# ── The "internet" ──────────────────────────────────────────────────────────
$I python3 -I "$HERE/test/whoami-http.py" > "$WORK/http.log" 2>&1 & PIDS+=($!)
$I python3 -I "$HERE/test/dns-stub.py" 10.201.0.2 > "$WORK/dns.log" 2>&1 & PIDS+=($!)
sleep 1

# ── Node ────────────────────────────────────────────────────────────────────
$N "$BIN/hidravpn-node" --config "$WORK/node.toml" init --endpoint 10.200.0.1:51820 --name test-node --dns udp://10.201.0.2 --out-interface n-i > "$WORK/init.log" 2>&1 || { cat "$WORK/init.log"; fail "node init"; exit 1; }
$N "$BIN/hidravpn-node" --config "$WORK/node.toml" run > "$WORK/node.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 50); do grep -q "DNS forwarder ready" "$WORK/node.log" && break; sleep 0.2; done
grep -q "DNS forwarder ready" "$WORK/node.log" && pass "node up" || { cat "$WORK/node.log"; fail "node did not come up"; exit 1; }

# ── Key, admission, and the invite goes into the POCKET, not to the browser ─
mkdir -p /etc/hidravpn
NODE_PUB=$(grep -o 'node public key: .*' "$WORK/init.log" | cut -d' ' -f4)
$C "$BIN/hidravpn" --key /etc/hidravpn/client.key keygen >/dev/null 2>&1
PUB=$($C "$BIN/hidravpn" --key /etc/hidravpn/client.key pubkey --node "$NODE_PUB" 2>/dev/null)
$N "$BIN/hidravpn-node" --config "$WORK/node.toml" admit --name laptop --pubkey "$PUB" > "$WORK/invite.json" 2>/dev/null
grep -q '"client_address": "10.77.0.2/16"' "$WORK/invite.json" && pass "client admitted" || { cat "$WORK/invite.json"; fail "admit"; }
"$BIN/hidravpn" nodes add --exit "$WORK/invite.json" > "$WORK/nodes-add.log" 2>&1 && pass "the invite is in the pocket as an exit ($(tr -d '\n' < "$WORK/nodes-add.log" | cut -c1-60))" || { cat "$WORK/nodes-add.log"; fail "nodes add"; }
[ -f /etc/hidravpn/circuit.json ] && pass "the pocket is where the service reads it (/etc/hidravpn/circuit.json)" || fail "no pocket file"

# ── The service, as root, in the client namespace ───────────────────────────
$C env RUST_LOG=hidravpn_service=info "$BIN/hidravpn-service" run > "$WORK/svc.log" 2>&1 & SVC=$!; PIDS+=($SVC)
for i in $(seq 1 50); do [ -S /run/hidravpn/control.sock ] && break; sleep 0.2; done
[ -S /run/hidravpn/control.sock ] && pass "the service is up" || { cat "$WORK/svc.log"; fail "the service did not start"; exit 1; }

# ── The access model: group-owned socket, token and directory ───────────────
st() { stat -c '%U:%G %a' "$1"; }
[ "$(st /run/hidravpn/control.sock)" = "root:hidravpn 660" ] && pass "the socket is root:hidravpn 0660" || fail "socket is $(st /run/hidravpn/control.sock)"
[ "$(st /run/hidravpn/control.token)" = "root:hidravpn 640" ] && pass "the token is root:hidravpn 0640" || fail "token is $(st /run/hidravpn/control.token)"
[ "$(stat -c '%G' /run/hidravpn)" = "hidravpn" ] && pass "the directory belongs to the group, so a member can enter it" || fail "directory is $(st /run/hidravpn)"
[ "$(st /etc/hidravpn/client.key)" = "root:root 600" ] && pass "the client key stays root-only" || fail "client key is $(st /etc/hidravpn/client.key)"

# ── Who runs the browser's side: an unprivileged member of the group ────────
AS_USER=""
if command -v setpriv >/dev/null && id nobody >/dev/null 2>&1 && setpriv --reuid=nobody --regid=nogroup --groups="$GID" --inh-caps=-all true 2>/dev/null \
   && setpriv --reuid=nobody --regid=nogroup --groups="$GID" --inh-caps=-all node -e "require('$BROWSER/src/main/vpn-manager.js')" 2>/dev/null; then
  AS_USER="setpriv --reuid=nobody --regid=nogroup --groups=$GID --inh-caps=-all"
  pass "the browser's side runs as 'nobody' in the hidravpn group, not as root"
  # And without the group it must be refused: the token is the group's.
  OUT=$(setpriv --reuid=nobody --regid=nogroup --clear-groups --inh-caps=-all node "$DRIVER" before 2>&1)
  echo "$OUT" | grep -q '"no-permission"' && pass "a user outside the group may not even read the token" || fail "outside the group: $OUT"
else
  echo "note  setpriv or a readable tree is missing; the browser's side runs as root here"
fi
drive() { $C $AS_USER node "$DRIVER" "$1"; }

# ── The sequence the page performs ──────────────────────────────────────────
OUT=$(drive before); echo "$OUT" | grep -q '"ok":true' && pass "before: disconnected, kill switch off, pocket lists exit:test-node without a key ($OUT)" || fail "before: $OUT"
OUT=$(drive connect-privado-refused); echo "$OUT" | grep -q '"ok":true' && pass "privado with no entry is refused by the service and changes nothing" || fail "privado: $OUT"
OUT=$(drive connect-rapido); echo "$OUT" | grep -q '"ok":true' && pass "rapido connects through the node the service picked ($OUT)" || { fail "rapido: $OUT"; cat "$WORK/svc.log" | tail -20; }
OUT=$(drive status); echo "$OUT" | grep -q '"ok":true' && pass "status: connected, kill switch armed, one exit hop ($OUT)" || fail "status: $OUT"

EXIT_IP=$($C curl -s --max-time 8 http://10.201.0.2/ 2>/dev/null)
[ "$EXIT_IP" = "10.201.0.1" ] && pass "the internet sees the node's address (10.201.0.1), not the client's" || fail "exit IP was '$EXIT_IP'"
$C nft list table inet hidravpn_ks >/dev/null 2>&1 && pass "the kill switch is armed in the kernel while connected" || fail "no kill switch table"
$C ip -4 route | grep -q "^0.0.0.0/1 dev hvpn0" && pass "default traffic routed into the tunnel" || fail "routes: $($C ip -4 route | tr '\n' ';')"
# The exit policy: port 25 from the tunnel is dropped by the node (the
# connection times out, curl 28), not refused by the host (curl 7).
$C curl -s --max-time 3 http://10.201.0.2:25/ >/dev/null 2>&1; RC=$?
[ "$RC" = 28 ] && pass "the node's exit policy drops mail (port 25) leaving the tunnel" || fail "port 25 from the tunnel: curl exit $RC (7 = reached the host)"

OUT=$(drive identity); echo "$OUT" | grep -q '"ok":true' && pass "new identity with one exit says the address did not change ($OUT)" || fail "identity: $OUT"
OUT=$(drive down); echo "$OUT" | grep -q '"ok":true' && pass "disconnect: disconnected, kill switch off" || fail "down: $OUT"
OUT=$(drive refill-off); echo "$OUT" | grep -q '"ok":true' && [ "$(stat -c %a /etc/hidravpn/refill.json 2>/dev/null)" = 600 ] && pass "the page's box reads automatic passes (on) and switches them off and on; the service keeps the setting root-only ($OUT)" || fail "refill from the page: $OUT"
# The command line, run by the same member of the group: `up --rapido` asks
# the service to pick, as the page does, and `down` takes it down.
if [ -n "$AS_USER" ]; then
  OUT=$($C $AS_USER "$BIN/hidravpn" up --rapido 2>&1); echo "$OUT" | grep -q "connected through the HidraVPN service" && pass "a member of the group connects from the command line too (up --rapido: $(echo "$OUT" | tail -1 | cut -c1-70))" || fail "member up --rapido: $OUT"
  OUT=$($C $AS_USER "$BIN/hidravpn" down 2>&1); [ $? -eq 0 ] && ! $C nft list table inet hidravpn_ks >/dev/null 2>&1 && pass "and down from the command line takes it down" || fail "member down: $OUT"
fi
$C nft list table inet hidravpn_ks >/dev/null 2>&1 && fail "the kill switch is still armed after down" || pass "the kill switch was lifted"
$C ip -4 route | grep -q "hvpn0" && fail "routes to hvpn0 remain" || pass "tunnel routes removed"
[ "$(cat /etc/netns/hv-client/resolv.conf)" = "$ORIG_RESOLV" ] && pass "resolv.conf restored" || fail "resolv.conf not restored"
$C curl -s --max-time 3 http://10.201.0.2/ >/dev/null 2>&1 && fail "still reaching the internet after down" || pass "after down the client is back to its own network"

# ── Nothing identifying in the logs, on either side ─────────────────────────
grep -qE "10\.200\.0\.2|10\.77\.0\.2|laptop" "$WORK/svc.log" "$WORK/node.log" && fail "a log names the client" || pass "no log names the client's address or name"

kill -INT $SVC 2>/dev/null; for i in $(seq 1 30); do kill -0 $SVC 2>/dev/null || break; sleep 0.2; done
kill -0 $SVC 2>/dev/null && fail "the service did not stop on SIGINT" || pass "the service stopped cleanly"

echo
echo "$ok passed, $bad failed"
[ $bad -eq 0 ]
