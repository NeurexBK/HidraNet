#!/bin/bash
# The whole phase-1 path, on one Linux machine, in three network namespaces:
#
#   hv-client ──veth── hv-node ──veth── hv-inet
#   10.200.0.2        10.200.0.1         10.201.0.2  (an "internet" host that
#                     10.201.0.1                      answers with your source IP
#                                                     and serves test DNS)
#
# hv-inet has no route back to the client's subnet, as the internet has none to
# a private address: the client reaches it only through the tunnel, where the
# node's NAT gives the packets the node's address. That is the "exit IP".
#
# Run as root:  hidravpn/scripts/test-netns.sh
# Needs: the release binaries built, python3, curl, nft, /dev/net/tun.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/test/guard.sh"
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
BIN="$HERE/../target/release"
WORK="$(mktemp -d /tmp/hidravpn-test.XXXXXX)"
PIDS=()
ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok+1)); }
fail() { echo "FAIL  $1"; bad=$((bad+1)); }
C="ip netns exec hv-client"; N="ip netns exec hv-node"; I="ip netns exec hv-inet"

cleanup() {
  set +e
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  sleep 1
  for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null; done
  ip netns del hv-client 2>/dev/null; ip netns del hv-node 2>/dev/null; ip netns del hv-inet 2>/dev/null
  rm -rf /etc/netns/hv-client /run/hidravpn/peers.json /var/lib/hidravpn/peers.json /run/hidravpn/netcfg.json /var/run/wireguard/hvpn0.sock
  rm -rf "$WORK"
}
trap cleanup EXIT
# What an interrupted run may have left: its namespaces and its files.
for ns in hv-client hv-node hv-inet; do ip netns del "$ns" 2>/dev/null; done
rm -rf /etc/netns/hv-client /run/hidravpn/peers.json /var/lib/hidravpn/peers.json /run/hidravpn/netcfg.json /var/run/wireguard/hvpn0.sock

for b in hidravpn hidravpn-node; do [ -x "$BIN/$b" ] || { echo "build first: cargo build --release"; exit 1; }; done

# ── Network ──────────────────────────────────────────────────────────────────
ip netns add hv-client; ip netns add hv-node; ip netns add hv-inet
ip link add c-n type veth peer name n-c; ip link set c-n netns hv-client; ip link set n-c netns hv-node
ip link add n-i type veth peer name i-n; ip link set n-i netns hv-node; ip link set i-n netns hv-inet
$C ip addr add 10.200.0.2/24 dev c-n; $C ip link set c-n up; $C ip link set lo up; $C ip route add default via 10.200.0.1
$N ip addr add 10.200.0.1/24 dev n-c; $N ip link set n-c up; $N ip link set lo up
$N ip addr add 10.201.0.1/24 dev n-i; $N ip link set n-i up; $N ip route add default via 10.201.0.2
$I ip addr add 10.201.0.2/24 dev i-n; $I ip link set i-n up; $I ip link set lo up
# The client gets its own resolv.conf (ip netns exec bind-mounts /etc/netns/NAME/* over /etc/*).
mkdir -p /etc/netns/hv-client; echo "nameserver 10.200.0.1" > /etc/netns/hv-client/resolv.conf
ORIG_RESOLV="$(cat /etc/netns/hv-client/resolv.conf)"

# ── The "internet": a whoami web server and a DNS server ─────────────────────
$I python3 -I "$HERE/test/whoami-http.py" > "$WORK/http.log" 2>&1 & PIDS+=($!)
$I python3 -I "$HERE/test/dns-stub.py" 10.201.0.2 > "$WORK/dns.log" 2>&1 & PIDS+=($!)
sleep 1

echo "── before the VPN"
if $C curl -s --max-time 3 http://10.201.0.2/ >/dev/null 2>&1; then fail "the client could reach the internet host without the tunnel (test network is wrong)"; else pass "without the tunnel the internet host is unreachable (no route back to a private address)"; fi

# ── Node ─────────────────────────────────────────────────────────────────────
$N "$BIN/hidravpn-node" --config "$WORK/node.toml" init --endpoint 10.200.0.1:51820 --name test-node --dns udp://10.201.0.2 --out-interface n-i > "$WORK/init.log" 2>&1 || { cat "$WORK/init.log"; fail "node init"; exit 1; }
pass "node settings written ($(grep -o 'node public key: .*' "$WORK/init.log" | cut -c1-40)...)"
$N "$BIN/hidravpn-node" --config "$WORK/node.toml" run > "$WORK/node.log" 2>&1 & NODE_PID=$!; PIDS+=($NODE_PID)
for i in $(seq 1 50); do grep -q "DNS forwarder ready" "$WORK/node.log" && break; sleep 0.2; done
grep -q "DNS forwarder ready" "$WORK/node.log" && pass "node up: $(grep -o 'tunnel interface.*' "$WORK/node.log" | head -1)" || { cat "$WORK/node.log"; fail "node did not come up"; exit 1; }
$N nft list table inet hidravpn >/dev/null 2>&1 && pass "NAT table present in the node" || fail "no NAT table"

# ── Client key, admission, invite ────────────────────────────────────────────
# The node admits the key derived for it, not the master key: the master key's
# public half reaches no node.
NODE_PUB=$(grep -o 'node public key: .*' "$WORK/init.log" | cut -d' ' -f4)
$C "$BIN/hidravpn" --key "$WORK/client.key" keygen >/dev/null 2>&1
MASTER=$($C "$BIN/hidravpn" --key "$WORK/client.key" pubkey 2>/dev/null)
PUB=$($C "$BIN/hidravpn" --key "$WORK/client.key" pubkey --node "$NODE_PUB" 2>/dev/null)
[ ${#MASTER} -eq 44 ] && [ ${#PUB} -eq 44 ] && pass "client key generated; the key for this node derived from it" || fail "client keygen: master '$MASTER' per-node '$PUB'"
[ "$PUB" != "$MASTER" ] && [ "$PUB" = "$($C "$BIN/hidravpn" --key "$WORK/client.key" pubkey --node "$NODE_PUB" 2>/dev/null)" ] && pass "the per-node key is not the master key, and derives the same twice" || fail "per-node key derivation"
$N "$BIN/hidravpn-node" --config "$WORK/node.toml" admit --name laptop --pubkey "$PUB" > "$WORK/invite.json" 2> "$WORK/admit.log"
grep -q '"client_address": "10.77.0.2/16"' "$WORK/invite.json" && pass "client admitted with 10.77.0.2 (invite: $(tr -d '\n ' < "$WORK/invite.json" | cut -c1-70)...)" || { cat "$WORK/invite.json" "$WORK/admit.log"; fail "admit"; }

# ── Up ───────────────────────────────────────────────────────────────────────
$C "$BIN/hidravpn" --key "$WORK/client.key" up "$WORK/invite.json" > "$WORK/client.log" 2>&1 & UP=$!; PIDS+=($UP)
for i in $(seq 1 100); do grep -q "^connected" "$WORK/client.log" && break; sleep 0.2; done
grep -q "^connected" "$WORK/client.log" && pass "client connected (handshake done) in under $((i/5))s" || { cat "$WORK/client.log"; fail "no handshake"; }

echo "── through the tunnel"
EXIT_IP=$($C curl -s --max-time 5 http://10.201.0.2/ 2>/dev/null)
[ "$EXIT_IP" = "10.201.0.1" ] && pass "the internet host sees the node's address, 10.201.0.1 (curl ifconfig.me shows the node)" || fail "exit IP was '$EXIT_IP'"
RES=$($C python3 -I -c "import socket;print(socket.gethostbyname('whoami.test'))" 2>&1)
[ "$RES" = "10.201.0.2" ] && pass "DNS resolves inside the tunnel (whoami.test -> $RES)" || fail "DNS: $RES"
sleep 0.3
if grep -q "query from 10.201.0.1 for whoami.test" "$WORK/dns.log"; then pass "the DNS server saw the query come from the node, not the client"; else fail "DNS query source: $(grep -o 'query from [0-9.]*' "$WORK/dns.log" | sort -u | tr '\n' ' ')"; fi
BYNAME=$($C curl -s --max-time 5 http://whoami.test/ 2>/dev/null)
[ "$BYNAME" = "10.201.0.1" ] && pass "a request by name goes through the tunnel end to end" || fail "by name: '$BYNAME'"
$C ip -4 route | grep -q "^0.0.0.0/1 dev hvpn0" && $C ip -4 route | grep -q "^128.0.0.0/1 dev hvpn0" && pass "default traffic routed into hvpn0" || fail "routes: $($C ip -4 route | tr '\n' ';')"
$C ip -4 route | grep -q "^10.200.0.1 " && pass "the node itself stays reachable outside the tunnel" || fail "no host route to the node"
grep -q "nameserver 10.77.0.1" /etc/netns/hv-client/resolv.conf && pass "resolv.conf points at the node's tunnel address" || fail "resolv.conf: $(cat /etc/netns/hv-client/resolv.conf)"
# A bigger transfer, to exercise fragmentation-free MTU: 2 MB through the tunnel.
$C dd if=/dev/urandom of="$WORK/blob" bs=1M count=2 status=none
$I python3 -I -m http.server 8080 --directory "$WORK" > /dev/null 2>&1 & PIDS+=($!); sleep 1
SUM1=$(sha256sum "$WORK/blob" | cut -c1-64); SUM2=$($C curl -s --max-time 20 http://10.201.0.2:8080/blob | sha256sum | cut -c1-64)
[ "$SUM1" = "$SUM2" ] && pass "2 MB transferred through the tunnel intact" || fail "transfer corrupted or failed"
$N "$BIN/hidravpn-node" --config "$WORK/node.toml" status > "$WORK/status.log" 2>&1
grep -q "laptop" "$WORK/status.log" && ! grep "laptop" "$WORK/status.log" | grep -q "never" && pass "node status shows the client with a handshake: $(grep laptop "$WORK/status.log" | tr -s ' ')" || { cat "$WORK/status.log"; fail "status"; }
grep -qE "10\.200\.0\.2|10\.77\.0\.2" "$WORK/node.log" && fail "the node log contains a client address" || pass "the node log names no client address"

echo "── the node restarts"
# While it is away the client's datagrams draw ICMP "port unreachable", which
# the socket reports on its next read; that must not end the tunnel.
kill -INT $NODE_PID; for i in $(seq 1 25); do kill -0 $NODE_PID 2>/dev/null || break; sleep 0.2; done
for i in 1 2 3; do $C curl -s --max-time 1 http://10.201.0.2/ >/dev/null 2>&1; done
$N "$BIN/hidravpn-node" --config "$WORK/node.toml" run > "$WORK/node2.log" 2>&1 & NODE_PID=$!; PIDS+=($NODE_PID)
for i in $(seq 1 50); do grep -q "DNS forwarder ready" "$WORK/node2.log" && break; sleep 0.2; done
BACK=""
for i in $(seq 1 20); do BACK=$($C curl -s --max-time 2 http://10.201.0.2/ 2>/dev/null); [ "$BACK" = "10.201.0.1" ] && break; sleep 0.5; done
[ "$BACK" = "10.201.0.1" ] && kill -0 $UP 2>/dev/null && pass "after the node restarted the tunnel came back by itself" || { tail -3 "$WORK/client.log"; fail "the tunnel did not survive the node restarting"; }

echo "── down"
kill -INT $UP; for i in $(seq 1 50); do kill -0 $UP 2>/dev/null || break; sleep 0.2; done
grep -q "network restored" "$WORK/client.log" && pass "client disconnected cleanly" || { tail -5 "$WORK/client.log"; fail "disconnect"; }
$C ip -4 route | grep -q "hvpn0" && fail "routes to hvpn0 remain" || pass "tunnel routes removed"
[ "$(cat /etc/netns/hv-client/resolv.conf)" = "$ORIG_RESOLV" ] && pass "resolv.conf restored" || fail "resolv.conf not restored: $(cat /etc/netns/hv-client/resolv.conf)"
$C ip link show hvpn0 >/dev/null 2>&1 && fail "hvpn0 still exists" || pass "tunnel interface gone"
[ -f /run/hidravpn/netcfg.json ] && fail "a network plan was left behind" || pass "no network plan left behind"
$C curl -s --max-time 3 http://10.201.0.2/ >/dev/null 2>&1 && fail "still reaching the internet host after down" || pass "after down the client is back to its own network"

echo; echo "$ok passed, $bad failed"; [ $bad -eq 0 ]
