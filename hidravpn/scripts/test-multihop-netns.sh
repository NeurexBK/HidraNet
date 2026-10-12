#!/usr/bin/env bash
# Phase 3, end to end, on one Linux machine, in five network namespaces:
#
#   hv-client ──veth── hv-entry ──bridge──┬── hv-exit  ──veth── hv-inet
#   10.200.0.2        10.200.0.1          │   10.202.0.1        10.201.0.2
#                     10.202.0.2 (br-x)   │   10.201.0.1
#                                         └── hv-exit2 ──veth── hv-inet
#                                             10.202.0.3        10.204.0.2
#                                             10.204.0.1
#
# The entry's whole "internet" is the link to the two exits: it has no route to
# hv-inet at all, so anything that reaches the internet host went through an
# exit. hv-inet has no route back to a private address, so it is reachable
# only through an exit's NAT, and it answers with the address it saw — the
# exit's. The daemon runs in the client namespace, as test-service-netns.sh
# does; the three nodes run on this one host side by side (HIDRAVPN_RUN_DIR
# and a different interface name each).
#
# What it proves: the internet sees the exit's address, not the entry's; the
# entry never carried plaintext (an observation counter in its namespace); DNS
# goes out from the exit; 2 MB arrive intact through both hops; the kill
# switch is armed and blocks a leak path; status says privado, 2 hops;
# new-identity moves the exit (the address the internet sees changes) and,
# with no alternate, reconnects and says so; down leaves nothing behind.
#
# Run as root:  hidravpn/scripts/test-multihop-netns.sh
# Needs: the release binaries built, python3, curl, nft, ip netns, /dev/net/tun.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/../target/release"
WORK=""
C="ip netns exec hv-client"
E="ip netns exec hv-entry"
X="ip netns exec hv-exit"
X2="ip netns exec hv-exit2"
I="ip netns exec hv-inet"
PIDS=()
SVC=""

ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok + 1)); }
fail() { echo "FAIL  $1"; bad=$((bad + 1)); }

cleanup() {
  set +e
  [ -n "$SVC" ] && kill -INT "$SVC" 2>/dev/null
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  sleep 1
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null; done
  for ns in hv-client hv-entry hv-exit hv-exit2 hv-inet; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null
    ip netns del "$ns" 2>/dev/null
  done
  rm -rf /etc/netns/hv-client /run/hidravpn/control.sock /run/hidravpn/control.token \
         /run/hidravpn/netcfg.json /run/hidravpn/peers.json /etc/hidravpn/client.key \
         /var/run/wireguard/hvpn0.sock /var/run/wireguard/hvx0.sock /var/run/wireguard/hvx1.sock
  [ -n "${WORK:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT
cleanup
WORK="$(mktemp -d /tmp/hidravpn-mh.XXXXXX)"

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
for b in hidravpn hidravpn-node hidravpn-service; do
  [ -x "$BIN/$b" ] || { echo "build first: cargo build --release --manifest-path hidravpn/Cargo.toml"; exit 1; }
done

# ── Network ─────────────────────────────────────────────────────────────────
for ns in hv-client hv-entry hv-exit hv-exit2 hv-inet; do ip netns add "$ns"; ip netns exec "$ns" ip link set lo up; done
# client ── entry
ip link add c-e type veth peer name e-c; ip link set c-e netns hv-client; ip link set e-c netns hv-entry
$C ip addr add 10.200.0.2/24 dev c-e; $C ip link set c-e up; $C ip route add default via 10.200.0.1
$E ip addr add 10.200.0.1/24 dev e-c; $E ip link set e-c up
# entry ── bridge ── the two exits
$E ip link add br-x type bridge; $E ip addr add 10.202.0.2/24 dev br-x; $E ip link set br-x up
ip link add e-x type veth peer name x-e; ip link set e-x netns hv-entry; ip link set x-e netns hv-exit
ip link add e-x2 type veth peer name x2-e; ip link set e-x2 netns hv-entry; ip link set x2-e netns hv-exit2
$E ip link set e-x master br-x; $E ip link set e-x up
$E ip link set e-x2 master br-x; $E ip link set e-x2 up
$X ip addr add 10.202.0.1/24 dev x-e; $X ip link set x-e up
$X2 ip addr add 10.202.0.3/24 dev x2-e; $X2 ip link set x2-e up
# exits ── inet
ip link add x-i type veth peer name i-x; ip link set x-i netns hv-exit; ip link set i-x netns hv-inet
ip link add x2-i type veth peer name i-x2; ip link set x2-i netns hv-exit2; ip link set i-x2 netns hv-inet
$X ip addr add 10.201.0.1/24 dev x-i; $X ip link set x-i up; $X ip route add default via 10.201.0.2
$X2 ip addr add 10.204.0.1/24 dev x2-i; $X2 ip link set x2-i up; $X2 ip route add default via 10.204.0.2
$I ip addr add 10.201.0.2/24 dev i-x; $I ip link set i-x up
$I ip addr add 10.204.0.2/24 dev i-x2; $I ip link set i-x2 up
# The client gets its own resolv.conf (ip netns exec bind-mounts /etc/netns/NAME/* over /etc/*).
mkdir -p /etc/netns/hv-client; echo "nameserver 10.200.0.1" > /etc/netns/hv-client/resolv.conf
ORIG_RESOLV="$(cat /etc/netns/hv-client/resolv.conf)"

# An observation table in the entry: what the entry forwards out of its tunnel.
# Counters only; nothing is logged or dropped. If the entry ever forwarded a
# plaintext HTTP or DNS packet, these would count it.
$E nft -f - <<'EOF'
table inet hv_observe {
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "hvpn0" tcp dport 80 counter comment "plain-http"
    iifname "hvpn0" udp dport 53 counter comment "plain-dns"
    iifname "hvpn0" meta l4proto tcp counter comment "any-tcp"
    iifname "hvpn0" ip daddr 10.202.0.1 udp dport 51820 counter comment "to-exit"
    iifname "hvpn0" ip daddr 10.202.0.3 udp dport 51820 counter comment "to-exit2"
  }
}
EOF
obs() { $E nft list table inet hv_observe | grep "comment \"$1\"" | sed -E 's/.*packets ([0-9]+).*/\1/'; }

# ── The "internet", and a host on the client's own link (a leak target) ────
$I python3 -I "$HERE/test/whoami-http.py" > "$WORK/http.log" 2>&1 & PIDS+=($!)
$I python3 -I "$HERE/test/dns-stub.py" 10.201.0.2 > "$WORK/dns.log" 2>&1 & PIDS+=($!)
$C dd if=/dev/urandom of="$WORK/blob" bs=1M count=2 status=none
$I python3 -I -m http.server 8080 --directory "$WORK" > /dev/null 2>&1 & PIDS+=($!)
mkdir -p "$WORK/leak"; echo leak > "$WORK/leak/index.html"
$E python3 -I -m http.server 8081 --bind 10.200.0.1 --directory "$WORK/leak" > /dev/null 2>&1 & PIDS+=($!)
sleep 1

echo "── before the VPN"
$C curl -s --max-time 3 http://10.201.0.2/ >/dev/null 2>&1 && fail "the client could reach the internet host without a tunnel (test network is wrong)" || pass "without a tunnel the internet host is unreachable"
[ "$($C curl -s --max-time 3 http://10.200.0.1:8081/ 2>/dev/null)" = "leak" ] && pass "a host on the client's own link answers (the leak path the kill switch must close)" || fail "the leak-path host did not answer before the VPN"

# ── Three nodes on one host ─────────────────────────────────────────────────
# Each has its own run directory and interface name; the entry keeps the
# default 10.77.0.0/16 on purpose, the same as the exits, to prove the client
# copes with both hops handing it the same subnet.
mkdir -p "$WORK/run-entry" "$WORK/run-exit" "$WORK/run-exit2"
$E "$BIN/hidravpn-node" --config "$WORK/entry.toml" init --endpoint 10.200.0.1:51820 --name entry-node --dns udp://10.201.0.2 --out-interface br-x > "$WORK/init-entry.log" 2>&1 || { cat "$WORK/init-entry.log"; fail "entry init"; exit 1; }
$X "$BIN/hidravpn-node" --config "$WORK/exit.toml" init --endpoint 10.202.0.1:51820 --name exit-node --dns udp://10.201.0.2 --out-interface x-i > "$WORK/init-exit.log" 2>&1 || { cat "$WORK/init-exit.log"; fail "exit init"; exit 1; }
$X2 "$BIN/hidravpn-node" --config "$WORK/exit2.toml" init --endpoint 10.202.0.3:51820 --name exit-two --dns udp://10.204.0.2 --out-interface x2-i > "$WORK/init-exit2.log" 2>&1 || { cat "$WORK/init-exit2.log"; fail "exit2 init"; exit 1; }
sed -i 's/^interface = "hvpn0"/interface = "hvx0"/' "$WORK/exit.toml"
sed -i 's/^interface = "hvpn0"/interface = "hvx1"/' "$WORK/exit2.toml"
grep -q '^interface = "hvx0"' "$WORK/exit.toml" && grep -q '^interface = "hvx1"' "$WORK/exit2.toml" && pass "three nodes set up: entry on hvpn0, exits on hvx0 and hvx1" || fail "could not give the exits their own interface names"

$E env HIDRAVPN_RUN_DIR="$WORK/run-entry" "$BIN/hidravpn-node" --config "$WORK/entry.toml" run > "$WORK/entry.log" 2>&1 & PIDS+=($!)
$X env HIDRAVPN_RUN_DIR="$WORK/run-exit" "$BIN/hidravpn-node" --config "$WORK/exit.toml" run > "$WORK/exit.log" 2>&1 & PIDS+=($!)
$X2 env HIDRAVPN_RUN_DIR="$WORK/run-exit2" "$BIN/hidravpn-node" --config "$WORK/exit2.toml" run > "$WORK/exit2.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 50); do grep -q "DNS forwarder ready" "$WORK/entry.log" && grep -q "DNS forwarder ready" "$WORK/exit.log" && grep -q "DNS forwarder ready" "$WORK/exit2.log" && break; sleep 0.2; done
if grep -q "DNS forwarder ready" "$WORK/entry.log" && grep -q "DNS forwarder ready" "$WORK/exit.log" && grep -q "DNS forwarder ready" "$WORK/exit2.log"; then
  pass "entry, exit and exit2 are up"
else
  cat "$WORK/entry.log" "$WORK/exit.log" "$WORK/exit2.log"; fail "a node did not come up"; exit 1
fi

# ── One client key, admitted on all three ───────────────────────────────────
mkdir -p /etc/hidravpn
PUB=$($C "$BIN/hidravpn" --key /etc/hidravpn/client.key keygen 2>/dev/null)
$E env HIDRAVPN_RUN_DIR="$WORK/run-entry" "$BIN/hidravpn-node" --config "$WORK/entry.toml" admit --name laptop --pubkey "$PUB" > "$WORK/entry.json" 2>/dev/null
$X env HIDRAVPN_RUN_DIR="$WORK/run-exit" "$BIN/hidravpn-node" --config "$WORK/exit.toml" admit --name laptop --pubkey "$PUB" > "$WORK/exit.json" 2>/dev/null
$X2 env HIDRAVPN_RUN_DIR="$WORK/run-exit2" "$BIN/hidravpn-node" --config "$WORK/exit2.toml" admit --name laptop --pubkey "$PUB" > "$WORK/exit2.json" 2>/dev/null
if grep -q '"client_address": "10.77.0.2/16"' "$WORK/entry.json" "$WORK/exit.json" "$WORK/exit2.json" && [ "$(grep -l '"client_address"' "$WORK"/*.json | wc -l)" = 3 ]; then
  pass "the client is admitted on all three nodes, with the same subnet on each"
else
  cat "$WORK/entry.json" "$WORK/exit.json" "$WORK/exit2.json"; fail "admission"
fi

# ── The service, in the client namespace ────────────────────────────────────
$C env RUST_LOG=hidravpn_service=info "$BIN/hidravpn-service" run > "$WORK/svc.log" 2>&1 & SVC=$!
for i in $(seq 1 50); do [ -S /run/hidravpn/control.sock ] && break; sleep 0.2; done
[ -S /run/hidravpn/control.sock ] && pass "the service is up" || { cat "$WORK/svc.log"; fail "the service did not start"; exit 1; }

wait_connected() {
  for i in $(seq 1 100); do
    $C "$BIN/hidravpn" status > "$WORK/st.log" 2>&1
    grep -q "^connected:" "$WORK/st.log" && return 0
    sleep 0.2
  done
  return 1
}

echo "── up: privado, two hops, with an alternate exit"
$C "$BIN/hidravpn" up "$WORK/exit.json" --via "$WORK/entry.json" --alternate "$WORK/exit2.json" > "$WORK/up.log" 2>&1 && grep -q "privado, 2 hops" "$WORK/up.log" && pass "up through the service: $(cat "$WORK/up.log")" || { cat "$WORK/up.log" "$WORK/svc.log"; fail "up"; }
wait_connected && pass "both hops have a session (in under $((i/5))s): $(cat "$WORK/st.log" | cut -c1-110)" || { cat "$WORK/st.log" "$WORK/svc.log"; fail "no session on every hop"; }
grep -q "privado, 2 hops: entry entry-node then exit exit-node" "$WORK/st.log" && pass "status says privado, 2 hops, entry-node then exit-node" || fail "status: $(cat "$WORK/st.log")"
$C "$BIN/hidravpn-service" status > "$WORK/st-svc.log" 2>&1
grep -q "connected through entry-node then exit-node (10.202.0.1:51820), privado, 2 hops" "$WORK/st-svc.log" && pass "the service's own status line agrees" || fail "service status: $(cat "$WORK/st-svc.log")"

echo "── the two interfaces and the routes"
$C ip link show hvpn0 >/dev/null 2>&1 && $C ip link show hvpn1 >/dev/null 2>&1 && pass "hvpn0 (outer) and hvpn1 (inner) exist" || fail "interfaces: $($C ip -br link | tr '\n' ';')"
MTU1=$($C ip link show hvpn1 | grep -o 'mtu [0-9]*' | cut -d' ' -f2)
[ "$MTU1" = 1340 ] && pass "the inner MTU is 1340 (1420 − 80)" || fail "inner MTU is $MTU1"
$C ip -4 route | grep -q "^0.0.0.0/1 dev hvpn1" && $C ip -4 route | grep -q "^128.0.0.0/1 dev hvpn1" && pass "default traffic goes into the inner tunnel" || fail "routes: $($C ip -4 route | tr '\n' ';')"
$C ip -4 route | grep -q "^10.202.0.1 dev hvpn0" && pass "the exit's endpoint is routed through the outer tunnel" || fail "no via route: $($C ip -4 route | tr '\n' ';')"
$C ip -4 route | grep -q "^10.200.0.1 " && pass "the entry's endpoint stays on the physical link" || fail "no host route to the entry"

echo "── through both hops"
EXIT_IP=$($C curl -s --max-time 8 http://10.201.0.2/ 2>/dev/null)
[ "$EXIT_IP" = "10.201.0.1" ] && pass "the internet host sees the exit's address, 10.201.0.1 — not the entry's" || fail "exit IP was '$EXIT_IP'"
RES=$($C python3 -I -c "import socket;print(socket.gethostbyname('whoami.test'))" 2>&1)
[ "$RES" = "10.201.0.2" ] && pass "DNS resolves through the circuit (whoami.test -> $RES)" || fail "DNS: $RES"
sleep 0.3
grep -q "query from 10.201.0.1 for whoami.test" "$WORK/dns.log" && pass "the resolver saw the query come from the exit, not the client or the entry" || fail "DNS query source: $(grep -o 'query from [0-9.]*' "$WORK/dns.log" | sort -u | tr '\n' ' ')"
BYNAME=$($C curl -s --max-time 8 http://whoami.test/ 2>/dev/null)
[ "$BYNAME" = "10.201.0.1" ] && pass "a request by name goes through both hops end to end" || fail "by name: '$BYNAME'"
SUM1=$(sha256sum "$WORK/blob" | cut -c1-64); SUM2=$($C curl -s --max-time 40 http://10.201.0.2:8080/blob | sha256sum | cut -c1-64)
[ "$SUM1" = "$SUM2" ] && pass "2 MB transferred intact through both hops" || fail "transfer corrupted or failed"

echo "── what the entry saw"
[ "$(obs plain-http)" = 0 ] && [ "$(obs plain-dns)" = 0 ] && [ "$(obs any-tcp)" = 0 ] && pass "the entry forwarded no plaintext: 0 TCP packets, 0 HTTP, 0 DNS out of its tunnel" || fail "entry forwarded plaintext: http=$(obs plain-http) dns=$(obs plain-dns) tcp=$(obs any-tcp)"
[ "$(obs to-exit)" -gt 0 ] && pass "the entry forwarded $(obs to-exit) encrypted WireGuard packets to the exit" || fail "no WireGuard packets to the exit through the entry"
$E env HIDRAVPN_RUN_DIR="$WORK/run-entry" "$BIN/hidravpn-node" --config "$WORK/entry.toml" status > "$WORK/entry-status.log" 2>&1
$X env HIDRAVPN_RUN_DIR="$WORK/run-exit" "$BIN/hidravpn-node" --config "$WORK/exit.toml" status > "$WORK/exit-status.log" 2>&1
grep -q "laptop" "$WORK/entry-status.log" && ! grep -q "never" "$WORK/entry-status.log" && grep -q "laptop" "$WORK/exit-status.log" && ! grep -q "never" "$WORK/exit-status.log" && pass "both nodes show the client with a handshake" || { cat "$WORK/entry-status.log" "$WORK/exit-status.log"; fail "node status"; }

echo "── the kill switch"
$C nft list table inet hidravpn_ks > "$WORK/ks.log" 2>&1 && pass "the kill switch is armed" || fail "the kill switch is not armed"
grep -q 'ip daddr 10.200.0.1 udp dport 51820 accept' "$WORK/ks.log" && ! grep -q 'ip daddr 10.202.0.1' "$WORK/ks.log" && pass "the entry's endpoint is the only address allowed off-tunnel" || fail "kill switch rules: $(grep -c accept "$WORK/ks.log") accepts"
grep -q 'oifname "hvpn1" accept' "$WORK/ks.log" && grep -q 'oifname "hvpn0" accept' "$WORK/ks.log" && pass "both tunnel interfaces are allowed" || fail "an interface is missing from the kill switch"
$C curl -s --max-time 3 http://10.200.0.1:8081/ >/dev/null 2>&1 && fail "a plain request to the physical link got through the kill switch" || pass "a plain request to a host on the physical link is blocked"

echo "── new identity: the exit changes"
$C "$BIN/hidravpn" new-identity > "$WORK/ni.log" 2>&1 && grep -q "the exit is now exit-two (was exit-node)" "$WORK/ni.log" && pass "new-identity: $(head -1 "$WORK/ni.log")" || { cat "$WORK/ni.log" "$WORK/svc.log"; fail "new-identity"; }
wait_connected && grep -q "entry entry-node then exit exit-two" "$WORK/st.log" && pass "both hops have a session again, now through exit-two" || { cat "$WORK/st.log"; fail "not connected through exit-two"; }
EXIT_IP2=$($C curl -s --max-time 8 http://10.201.0.2/ 2>/dev/null)
[ "$EXIT_IP2" = "10.204.0.1" ] && pass "the internet host now sees a different address, 10.204.0.1" || fail "exit IP after new-identity was '$EXIT_IP2'"
[ "$(obs to-exit2)" -gt 0 ] && [ "$(obs any-tcp)" = 0 ] && pass "the entry forwarded $(obs to-exit2) encrypted packets to exit-two and still no plaintext" || fail "entry after rotation: to-exit2=$(obs to-exit2) tcp=$(obs any-tcp)"
$C ip -4 route | grep -q "^10.202.0.3 dev hvpn0" && ! $C ip -4 route | grep -q "^10.202.0.1 " && pass "the via route moved to the new exit; the old one is gone" || fail "routes after rotation: $($C ip -4 route | tr '\n' ';')"
$C nft list table inet hidravpn_ks >/dev/null 2>&1 && pass "the kill switch stayed armed across the rotation" || fail "the kill switch was lost in the rotation"

echo "── down"
$C "$BIN/hidravpn" down > "$WORK/down.log" 2>&1 && pass "down through the service" || { cat "$WORK/down.log"; fail "down"; }
$C nft list table inet hidravpn_ks >/dev/null 2>&1 && fail "the kill switch is still armed" || pass "the kill switch was lifted"
$C ip link show hvpn0 >/dev/null 2>&1 || $C ip link show hvpn1 >/dev/null 2>&1 && fail "a tunnel interface remains" || pass "both tunnel interfaces are gone"
$C ip -4 route | grep -qE "hvpn|10.202" && fail "routes remain: $($C ip -4 route | tr '\n' ';')" || pass "all tunnel and via routes removed"
[ "$(cat /etc/netns/hv-client/resolv.conf)" = "$ORIG_RESOLV" ] && pass "resolv.conf restored" || fail "resolv.conf not restored"
[ -f /run/hidravpn/netcfg.json ] && fail "a network plan was left behind" || pass "no network plan left behind"
$C curl -s --max-time 3 http://10.201.0.2/ >/dev/null 2>&1 && fail "still reaching the internet after down" || pass "after down the client is back on its own network"
[ "$($C curl -s --max-time 3 http://10.200.0.1:8081/ 2>/dev/null)" = "leak" ] && pass "the physical link works again" || fail "the physical link is still blocked"

echo "── new identity with a single exit: honest"
$C "$BIN/hidravpn" up "$WORK/exit.json" --via "$WORK/entry.json" > "$WORK/up2.log" 2>&1 && wait_connected && pass "up again, two hops, no alternate" || { cat "$WORK/up2.log"; fail "second up"; }
$C "$BIN/hidravpn" new-identity > "$WORK/ni2.log" 2>&1 && grep -q "only one exit node is configured; reconnected to the same one" "$WORK/ni2.log" && pass "new-identity says so: $(head -1 "$WORK/ni2.log" | cut -c1-80)..." || { cat "$WORK/ni2.log"; fail "new-identity with one exit"; }
wait_connected && [ "$($C curl -s --max-time 8 http://10.201.0.2/ 2>/dev/null)" = "10.201.0.1" ] && pass "reconnected through the same exit; the internet sees 10.201.0.1 again" || fail "not back through exit-node"
$C "$BIN/hidravpn" down > /dev/null 2>&1 && ! $C ip link show hvpn1 >/dev/null 2>&1 && pass "down again, clean" || fail "second down"

echo "── the same circuit held directly, without the service"
$C "$BIN/hidravpn" --direct --key /etc/hidravpn/client.key up "$WORK/exit.json" --via "$WORK/entry.json" > "$WORK/direct.log" 2>&1 & UP=$!; PIDS+=($UP)
for i in $(seq 1 100); do grep -q "^connected" "$WORK/direct.log" && break; sleep 0.2; done
grep -q "^connected" "$WORK/direct.log" && grep -q "Privado (2 hops)" "$WORK/direct.log" && pass "direct up: two hops, connected" || { cat "$WORK/direct.log"; fail "direct up"; }
[ "$($C curl -s --max-time 8 http://10.201.0.2/ 2>/dev/null)" = "10.201.0.1" ] && pass "the internet sees the exit's address through the direct circuit" || fail "direct exit IP"
kill -INT $UP; for i in $(seq 1 50); do kill -0 $UP 2>/dev/null || break; sleep 0.2; done
grep -q "network restored" "$WORK/direct.log" && ! $C ip link show hvpn0 >/dev/null 2>&1 && [ ! -f /run/hidravpn/netcfg.json ] && pass "direct down: network restored, interfaces gone, no plan" || { tail -3 "$WORK/direct.log"; fail "direct down"; }

echo "── privacy of the logs"
grep -qE "10\.200\.0\.2|10\.77\.0\.2|whoami" "$WORK/entry.log" "$WORK/exit.log" "$WORK/exit2.log" "$WORK/svc.log" && fail "a log names a client address or a name looked up" || pass "no node or service log names an address or a name looked up"

# ── Clean shutdown of the daemon ────────────────────────────────────────────
kill -INT $SVC; for i in $(seq 1 25); do kill -0 $SVC 2>/dev/null || break; sleep 0.2; done
kill -0 $SVC 2>/dev/null && fail "the service did not stop on SIGINT" || pass "the service stopped cleanly"
SVC=""

echo; echo "$ok passed, $bad failed"; [ $bad -eq 0 ]
