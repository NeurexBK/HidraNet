#!/usr/bin/env bash
# The whole client service, end to end, against a real node — the same three
# namespaces as test-netns.sh, but driven through the background service over
# its control channel instead of the direct command line. It proves the daemon,
# the IPC, the tunnel, the routing and the kill switch all work together:
# connect, check the exit address and that the kill switch is armed, then
# disconnect and check the machine is back as it was with nothing left armed.
#
# Run as root:  hidravpn/scripts/test-service-netns.sh
# Needs: the release binaries built, python3, curl, nft, ip netns.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/test/guard.sh"
BIN="$HERE/../target/release"
WORK=""
C="ip netns exec hv-client"
N="ip netns exec hv-node"
I="ip netns exec hv-inet"
PIDS=()

ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok + 1)); }
fail() { echo "FAIL  $1"; bad=$((bad + 1)); }

cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  ip netns pids hv-client 2>/dev/null | xargs -r kill 2>/dev/null
  for ns in hv-client hv-node hv-inet; do ip netns del "$ns" 2>/dev/null; done
  rm -rf /etc/netns/hv-client /run/hidravpn/control.sock /run/hidravpn/control.token \
         /run/hidravpn/netcfg.json /run/hidravpn/peers.json /var/lib/hidravpn/peers.json /etc/hidravpn/client.key
  [ -n "${WORK:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT
cleanup
WORK="$(mktemp -d /tmp/hidravpn-svc.XXXXXX)"

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
for b in hidravpn hidravpn-node hidravpn-service; do
  [ -x "$BIN/$b" ] || { echo "build first: cargo build --release --manifest-path hidravpn/Cargo.toml"; exit 1; }
done

# ── Network (same topology as test-netns.sh) ────────────────────────────────
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
# The "internet" here is a private range: the nodes are told to forward to it, which a public node never is.
$N "$BIN/hidravpn-node" --config "$WORK/node.toml" init --forward-private-destinations --endpoint 10.200.0.1:51820 --name test-node --dns udp://10.201.0.2 --out-interface n-i > "$WORK/init.log" 2>&1 || { cat "$WORK/init.log"; fail "node init"; exit 1; }
$N "$BIN/hidravpn-node" --config "$WORK/node.toml" run > "$WORK/node.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 50); do grep -q "DNS forwarder ready" "$WORK/node.log" && break; sleep 0.2; done
grep -q "DNS forwarder ready" "$WORK/node.log" && pass "node up" || { cat "$WORK/node.log"; fail "node did not come up"; exit 1; }

# ── Client key at the service's fixed path, admission, invite ───────────────
mkdir -p /etc/hidravpn
# The node admits the key derived for it (hidravpn pubkey --node), never the
# master key.
NODE_PUB=$(grep -o 'node public key: .*' "$WORK/init.log" | cut -d' ' -f4)
$C "$BIN/hidravpn" --key /etc/hidravpn/client.key keygen >/dev/null 2>&1
MASTER=$($C "$BIN/hidravpn" --key /etc/hidravpn/client.key pubkey 2>/dev/null)
PUB=$($C "$BIN/hidravpn" --key /etc/hidravpn/client.key pubkey --node "$NODE_PUB" 2>/dev/null)
[ ${#PUB} -eq 44 ] && [ "$PUB" != "$MASTER" ] && pass "client key generated at the service path; the key for this node derived from it" || fail "keygen: master '$MASTER' per-node '$PUB'"
$N "$BIN/hidravpn-node" --config "$WORK/node.toml" admit --name laptop --pubkey "$PUB" > "$WORK/invite.json" 2>/dev/null
grep -q '"client_address": "10.77.0.2/16"' "$WORK/invite.json" && pass "client admitted" || { cat "$WORK/invite.json"; fail "admit"; }

# ── Start the daemon in the client namespace ────────────────────────────────
$C env RUST_LOG=hidravpn_service=info "$BIN/hidravpn-service" run > "$WORK/svc.log" 2>&1 & SVC=$!; PIDS+=($SVC)
for i in $(seq 1 50); do [ -S /run/hidravpn/control.sock ] && break; sleep 0.2; done
[ -S /run/hidravpn/control.sock ] && pass "the service is up and its control channel is listening" || { cat "$WORK/svc.log"; fail "the service did not start"; exit 1; }

# Status before connecting.
$C "$BIN/hidravpn-service" status > "$WORK/st0.log" 2>&1
grep -q "not connected" "$WORK/st0.log" && grep -q "kill switch off" "$WORK/st0.log" && pass "status before: not connected, kill switch off" || { cat "$WORK/st0.log"; fail "unexpected starting status"; }

# A request with no token must be refused (the socket alone is not enough).
printf '{"token":"wrong","cmd":"status"}\n' | $C python3 -I -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect("/run/hidravpn/control.sock"); s.sendall(sys.stdin.buffer.read()); print(s.recv(4096).decode())' > "$WORK/noauth.log" 2>&1
grep -q "unauthorised" "$WORK/noauth.log" && pass "a request without the control token is refused" || { cat "$WORK/noauth.log"; fail "the service answered without a token"; }

# ── Up ──────────────────────────────────────────────────────────────────────
$C "$BIN/hidravpn-service" up "$WORK/invite.json" > "$WORK/up.log" 2>&1 && pass "service connected" || { cat "$WORK/up.log" "$WORK/svc.log"; fail "service up"; }

EXIT_IP=$($C curl -s --max-time 5 http://10.201.0.2/ 2>/dev/null)
[ "$EXIT_IP" = "10.201.0.1" ] && pass "exit address is the node (10.201.0.1)" || fail "exit IP was '$EXIT_IP'"
$C nft list table inet hidravpn_ks >/dev/null 2>&1 && pass "the kill switch is armed while connected" || fail "the kill switch was not armed"
$C ip -4 route | grep -q "^0.0.0.0/1 dev hvpn0" && pass "default traffic routed into the tunnel" || fail "routes: $($C ip -4 route | tr '\n' ';')"
BYNAME=$($C curl -s --max-time 5 http://whoami.test/ 2>/dev/null)
[ "$BYNAME" = "10.201.0.1" ] && pass "a request by name goes through the tunnel end to end" || fail "by name: '$BYNAME'"

$C "$BIN/hidravpn-service" status > "$WORK/st1.log" 2>&1
grep -q "connected through test-node" "$WORK/st1.log" && grep -q "kill switch on" "$WORK/st1.log" && pass "status while connected: connected, kill switch on" || { cat "$WORK/st1.log"; fail "unexpected connected status"; }

# ── Down ────────────────────────────────────────────────────────────────────
$C "$BIN/hidravpn-service" down > "$WORK/down.log" 2>&1 && pass "service disconnected" || { cat "$WORK/down.log"; fail "service down"; }
$C nft list table inet hidravpn_ks >/dev/null 2>&1 && fail "the kill switch is still armed after down" || pass "the kill switch was lifted"
$C ip -4 route | grep -q "hvpn0" && fail "routes to hvpn0 remain" || pass "tunnel routes removed"
[ "$(cat /etc/netns/hv-client/resolv.conf)" = "$ORIG_RESOLV" ] && pass "resolv.conf restored" || fail "resolv.conf not restored"
$C ip link show hvpn0 >/dev/null 2>&1 && fail "hvpn0 still exists" || pass "tunnel interface gone"
$C curl -s --max-time 3 http://10.201.0.2/ >/dev/null 2>&1 && fail "still reaching the internet after down" || pass "after down the client is back to its own network"

# ── Clean shutdown of the daemon ────────────────────────────────────────────
kill -INT $SVC; for i in $(seq 1 25); do kill -0 $SVC 2>/dev/null || break; sleep 0.2; done
kill -0 $SVC 2>/dev/null && fail "the service did not stop on SIGINT" || pass "the service stopped cleanly"

echo; echo "$ok passed, $bad failed"; [ $bad -eq 0 ]
