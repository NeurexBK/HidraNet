#!/bin/bash
# IPv6 through the tunnel, in four network namespaces with both families:
#
#   h6-client ──veth── h6-entry ──veth── h6-exit ──veth── h6-inet
#   10.220.0.2         10.220.0.1        10.222.0.1       10.221.0.2
#   2001:db8:220::2    2001:db8:220::1   2001:db8:222::1  2001:db8:221::2
#                      10.222.0.2        10.221.0.1       (answers with your
#                      2001:db8:222::2   2001:db8:221::1   source address)
#
# h6-entry is the client's router, and on two hops the entry node (role
# entry); h6-exit runs the exit node (role exit), with IPv6 out to h6-inet.
# h6-inet has no route back to the client: it is reached only through the
# exit, and sees the exit's addresses. 2001:db8:220::2 is the client's own
# IPv6 address: whoever sees it knows who the client is.
#
# What it proves:
#   - one hop: the exit gives the client an address of its unique local
#     subnet; IPv6 goes through the tunnel and the internet sees the exit's
#     own IPv6 address; no packet carries the client's own address into the
#     tunnel or out on its link; status says so.
#   - two hops: IPv6 goes through the exit, never through the entry, which
#     carries none (it is given no address, and its tunnel sees no IPv6).
#   - an exit with ipv6 = "off", and one whose host has no IPv6 route: the
#     invite carries no IPv6 address, IPv6 is blocked, nothing leaks.
#
# Run as root:  hidravpn/scripts/test-ipv6-netns.sh
# Needs: the release binaries built, python3, curl, nft, tcpdump, wg where
# the kernel has WireGuard, and a kernel with IPv6.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/test/guard.sh"
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
BIN="$HERE/../target/release"
WORK="$(mktemp -d /tmp/hidravpn-v6.XXXXXX)"
PIDS=(); SVC=""
ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok+1)); }
fail() { echo "FAIL  $1"; bad=$((bad+1)); }
C="ip netns exec h6-client"; E="ip netns exec h6-entry"; X="ip netns exec h6-exit"; I="ip netns exec h6-inet"
NSS="h6-client h6-entry h6-exit h6-inet"
CLIENT6=2001:db8:220::2; EXIT6=2001:db8:221::1; ULA=fd68:6964:7261:7670

cleanup() {
  set +e
  [ -n "$SVC" ] && kill -INT "$SVC" 2>/dev/null && sleep 1
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  sleep 1
  for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null; done
  for ns in $NSS; do ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null; ip netns del "$ns" 2>/dev/null; done
  rm -rf /etc/netns/h6-client /run/hidravpn/control.sock /run/hidravpn/control.token /run/hidravpn/netcfg.json \
         /etc/hidravpn/client.key /etc/hidravpn/circuit.json /var/run/wireguard/hvpn0.sock /var/run/wireguard/hvx0.sock
  [ -z "${KEEP:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT
SVC=""; for ns in $NSS; do ip netns del "$ns" 2>/dev/null; done
rm -rf /etc/netns/h6-client /run/hidravpn/control.sock /run/hidravpn/control.token /run/hidravpn/netcfg.json /etc/hidravpn/client.key /etc/hidravpn/circuit.json
for b in hidravpn hidravpn-node hidravpn-service; do [ -x "$BIN/$b" ] || { echo "build first: cargo build --release"; exit 1; }; done
command -v tcpdump >/dev/null || { echo "needs tcpdump"; exit 1; }

# ── Network ──────────────────────────────────────────────────────────────────
for ns in $NSS; do ip netns add "$ns"; ip netns exec "$ns" ip link set lo up; done
if ! $C ip -6 addr show dev lo 2>/dev/null | grep -q '::1'; then
  if [ "${HIDRAVPN_REQUIRE_IPV6:-}" = 1 ]; then echo "FAIL  this kernel has no IPv6, and HIDRAVPN_REQUIRE_IPV6=1 says these checks must run"; exit 1; fi
  echo "SKIP  this kernel has no IPv6: nothing here can run"; exit 0
fi
link() { ip link add "$1" type veth peer name "$2"; ip link set "$1" netns "$3"; ip link set "$2" netns "$4"; }
link c-e e-c h6-client h6-entry
link e-x x-e h6-entry h6-exit
link x-i i-x h6-exit h6-inet
addr() { ip netns exec "$1" ip addr add "$3" dev "$2"; ip netns exec "$1" ip -6 addr add "$4" dev "$2" nodad; ip netns exec "$1" ip link set "$2" up; }
addr h6-client c-e 10.220.0.2/24 $CLIENT6/64
addr h6-entry e-c 10.220.0.1/24 2001:db8:220::1/64
addr h6-entry e-x 10.222.0.2/24 2001:db8:222::2/64
addr h6-exit x-e 10.222.0.1/24 2001:db8:222::1/64
addr h6-exit x-i 10.221.0.1/24 $EXIT6/64
addr h6-inet i-x 10.221.0.2/24 2001:db8:221::2/64
$C ip route add default via 10.220.0.1; $C ip -6 route add default via 2001:db8:220::1
# The entry namespace is the client's router to the exit, as an ISP is.
$E sysctl -qw net.ipv4.ip_forward=1; $E sysctl -qw net.ipv6.conf.all.forwarding=1
$E ip route add default via 10.222.0.1; $E ip -6 route add default via 2001:db8:222::1
$X ip route add 10.220.0.0/24 via 10.222.0.2; $X ip -6 route add 2001:db8:220::/64 via 2001:db8:222::2
$X ip route add default via 10.221.0.2; $X ip -6 route add default via 2001:db8:221::2
mkdir -p /etc/netns/h6-client; echo "nameserver 10.220.0.1" > /etc/netns/h6-client/resolv.conf

$I python3 -I "$HERE/test/whoami6-http.py" > "$WORK/http.log" 2>&1 & PIDS+=($!)
$I python3 -I "$HERE/test/dns-stub.py" 10.221.0.2 > "$WORK/dns.log" 2>&1 & PIDS+=($!)
sleep 1

echo "── before the VPN"
[ "$($X curl -6 -s --max-time 3 'http://[2001:db8:221::2]/')" = $EXIT6 ] && pass "the internet host answers on IPv6 with the address it sees" || fail "no IPv6 internet host"
$C curl -6 -s --max-time 3 'http://[2001:db8:221::2]/' >/dev/null 2>&1 && fail "the client reaches the internet host without the tunnel (test network is wrong)" || pass "without the tunnel the client cannot reach it (no route back)"

# ── Nodes ────────────────────────────────────────────────────────────────────
mkdir -p "$WORK/run-entry" "$WORK/run-exit"
$E "$BIN/hidravpn-node" --config "$WORK/entry.toml" init --endpoint 10.220.0.1:51820 --name v6-entry --operator op-a --role entry --dns udp://10.221.0.2 --out-interface e-x > "$WORK/init-e.log" 2>&1 || { cat "$WORK/init-e.log"; fail "entry init"; exit 1; }
$X "$BIN/hidravpn-node" --config "$WORK/exit.toml" init --endpoint 10.222.0.1:51820 --name v6-exit --operator op-b --role exit --dns udp://10.221.0.2 --out-interface x-i > "$WORK/init-x.log" 2>&1 || { cat "$WORK/init-x.log"; fail "exit init"; exit 1; }
sed -i 's/^interface = "hvpn0"/interface = "hvx0"/' "$WORK/exit.toml"
start_exit() {
  $X env HIDRAVPN_RUN_DIR="$WORK/run-exit" "$BIN/hidravpn-node" --config "$WORK/exit.toml" run > "$WORK/exit.log" 2>&1 & NODE_X=$!; PIDS+=("$NODE_X")
  for _ in $(seq 1 50); do grep -q "DNS forwarder ready" "$WORK/exit.log" && return 0; sleep 0.2; done
  cat "$WORK/exit.log"; return 1
}
stop_exit() { kill -INT "$NODE_X"; for _ in $(seq 1 25); do kill -0 "$NODE_X" 2>/dev/null || break; sleep 0.2; done; }
$E env HIDRAVPN_RUN_DIR="$WORK/run-entry" "$BIN/hidravpn-node" --config "$WORK/entry.toml" run > "$WORK/entry.log" 2>&1 & PIDS+=($!)
start_exit || { fail "the exit did not come up"; exit 1; }
for _ in $(seq 1 50); do grep -q "DNS forwarder ready" "$WORK/entry.log" && break; sleep 0.2; done
grep -q "DNS forwarder ready" "$WORK/entry.log" && pass "entry and exit are up" || { cat "$WORK/entry.log"; fail "the entry did not come up"; exit 1; }
grep -q "IPv6 for clients: yes" "$WORK/exit.log" && pass "the exit carries IPv6 for its clients" || fail "the exit does not offer IPv6: $(grep -i ipv6 "$WORK/exit.log")"
grep -q "IPv6 for clients: no" "$WORK/entry.log" && pass "the entry carries none, though its host has IPv6" || fail "entry: $(grep -i ipv6 "$WORK/entry.log")"
$X nft list table inet hidravpn 2>/dev/null | grep -q "ip6 saddr $ULA::/64 oifname \"x-i\" masquerade" && pass "the exit translates its clients' IPv6 to its own" || fail "no IPv6 translation on the exit"

# ── Client ───────────────────────────────────────────────────────────────────
mkdir -p /etc/hidravpn
$C "$BIN/hidravpn" --key /etc/hidravpn/client.key keygen >/dev/null 2>&1
NODE_E=$(grep -o 'node public key: .*' "$WORK/init-e.log" | cut -d' ' -f4)
NODE_X_PUB=$(grep -o 'node public key: .*' "$WORK/init-x.log" | cut -d' ' -f4)
PUB_E=$($C "$BIN/hidravpn" --key /etc/hidravpn/client.key pubkey --node "$NODE_E" 2>/dev/null)
PUB_X=$($C "$BIN/hidravpn" --key /etc/hidravpn/client.key pubkey --node "$NODE_X_PUB" 2>/dev/null)
PUB_XB=$($C "$BIN/hidravpn" --key /etc/hidravpn/client.key pubkey --node "$NODE_X_PUB" --behind 2>/dev/null)
admit_x() { $X env HIDRAVPN_RUN_DIR="$WORK/run-exit" "$BIN/hidravpn-node" --config "$WORK/exit.toml" admit --name "$1" --pubkey "$2" 2>/dev/null; }
$E env HIDRAVPN_RUN_DIR="$WORK/run-entry" "$BIN/hidravpn-node" --config "$WORK/entry.toml" admit --name laptop --pubkey "$PUB_E" > "$WORK/entry.json" 2>/dev/null
admit_x laptop "$PUB_X" > "$WORK/exit.json"
admit_x laptop-behind "$PUB_XB" > "$WORK/exit-behind.json"
grep -q "\"client_address6\": \"$ULA::a4d:2/64\"" "$WORK/exit.json" && pass "the exit's invite gives the client $ULA::a4d:2/64" || fail "exit invite: $(tr -d '\n ' < "$WORK/exit.json" | cut -c1-200)"
grep -q client_address6 "$WORK/entry.json" && fail "the entry's invite gives an IPv6 address" || pass "the entry's invite gives no IPv6 address"
$X wg show hvx0 allowed-ips 2>/dev/null | grep -q "$ULA::a4d:2/128" && pass "the exit lets the client send from its IPv6 address and no other" || fail "allowed IPs: $($X wg show hvx0 allowed-ips 2>&1 | tr '\n' ';')"

$C env RUST_LOG=hidravpn_service=info "$BIN/hidravpn-service" run > "$WORK/svc.log" 2>&1 & SVC=$!
for _ in $(seq 1 50); do [ -S /run/hidravpn/control.sock ] && break; sleep 0.2; done
[ -S /run/hidravpn/control.sock ] && pass "the service is up" || { cat "$WORK/svc.log"; fail "the service did not start"; exit 1; }
wait_connected() {
  for _ in $(seq 1 100); do $C "$BIN/hidravpn" status > "$WORK/st.log" 2>&1; grep -q "^connected:" "$WORK/st.log" && return 0; sleep 0.2; done
  cat "$WORK/st.log"; return 1
}

# The client's IPv6 seen while connected: what comes back, what went into
# the tunnel, what left on the link. $1 names the round, $2 the tunnel
# interface that carries the traffic.
probe6() {
  $C tcpdump -n -U -i "$2" -w "$WORK/tun-$1.pcap" ip6 > /dev/null 2>&1 & local td=$!
  sleep 0.5
  GOT6=$($C curl -6 -s --max-time 4 'http://[2001:db8:221::2]/' 2>/dev/null)
  sleep 0.5; kill $td 2>/dev/null; wait $td 2>/dev/null
  OWN=$(tcpdump -n -r "$WORK/tun-$1.pcap" "src host $CLIENT6" 2>/dev/null | wc -l)
}
start_link_capture() { $C tcpdump -n -U -i c-e -w "$WORK/link-$1.pcap" "ip6 and src host $CLIENT6" > /dev/null 2>&1 & LINKCAP=$!; PIDS+=("$LINKCAP"); sleep 0.5; }
link_count() { kill "$LINKCAP" 2>/dev/null; sleep 0.3; tcpdump -n -r "$WORK/link-$1.pcap" 2>/dev/null | wc -l; }

echo "── one hop through an exit that carries IPv6"
start_link_capture one
$C "$BIN/hidravpn" up "$WORK/exit.json" > "$WORK/up1.log" 2>&1 && wait_connected && pass "connected, one hop" || { cat "$WORK/up1.log" "$WORK/svc.log"; fail "up, one hop"; }
grep -q "IPv6 through the tunnel" "$WORK/st.log" && pass "status says IPv6 goes through the tunnel" || fail "status: $(cat "$WORK/st.log")"
$C ip -6 addr show dev hvpn0 | grep -q "inet6 $ULA::a4d:2/64" && pass "the tunnel interface holds the exit's address for the client" || fail "hvpn0: $($C ip -6 addr show dev hvpn0 | grep inet6 | tr '\n' ';')"
[ "$($C curl -4 -s --max-time 5 http://10.221.0.2/)" = 10.221.0.1 ] && pass "IPv4 leaves from the exit" || fail "IPv4 through the tunnel"
probe6 one hvpn0
[ "$GOT6" = $EXIT6 ] && pass "IPv6 goes through the tunnel: the internet sees the exit's IPv6 address" || fail "IPv6 request got '$GOT6'"
[ "$OWN" = 0 ] && pass "no packet carried the client's own IPv6 address into the tunnel" || fail "$OWN packet(s) carried $CLIENT6 into the tunnel"
$C dd if=/dev/urandom of="$WORK/blob" bs=1M count=1 status=none 2>/dev/null; cp "$WORK/blob" "$WORK/blobsrv"
$I python3 -I -m http.server 8080 --bind :: --directory "$WORK" > /dev/null 2>&1 & PIDS+=($!); sleep 1
[ "$(sha256sum < "$WORK/blob")" = "$($C curl -6 -s --max-time 20 'http://[2001:db8:221::2]:8080/blobsrv' | sha256sum)" ] && pass "1 MB over IPv6 through the tunnel, intact" || fail "the IPv6 transfer was corrupted or failed"
$C "$BIN/hidravpn" down > /dev/null 2>&1
N=$(link_count one); [ "$N" = 0 ] && pass "no IPv6 packet with the client's own address left on its link while connected" || fail "$N IPv6 packet(s) left on the link"
$C ip -6 route | grep -q hvpn0 && fail "IPv6 routes to the tunnel remain" || pass "down: the IPv6 routes are gone"

echo "── two hops: IPv6 through the exit, never through the entry"
$E tcpdump -n -U -i hvpn0 -w "$WORK/entry-tun.pcap" ip6 > /dev/null 2>&1 & ETD=$!; PIDS+=("$ETD")
start_link_capture two
$C "$BIN/hidravpn" up "$WORK/exit-behind.json" --via "$WORK/entry.json" > "$WORK/up2.log" 2>&1 && wait_connected && grep -q "privado, 2 hops" "$WORK/st.log" && pass "connected, two hops" || { cat "$WORK/up2.log" "$WORK/st.log" "$WORK/svc.log"; fail "up, two hops"; }
grep -q "IPv6 through the tunnel" "$WORK/st.log" && pass "status says IPv6 goes through the tunnel" || fail "status: $(cat "$WORK/st.log")"
$C ip -6 addr show dev hvpn1 | grep -q "inet6 $ULA::" && pass "the inner tunnel holds the exit's address for the client" || fail "hvpn1: $($C ip -6 addr show dev hvpn1 2>&1 | grep inet6 | tr '\n' ';')"
$C ip -6 addr show dev hvpn0 | grep -q "scope global" && fail "the outer tunnel, to the entry, has a global IPv6 address" || pass "the outer tunnel, to the entry, has no IPv6 address of its own"
probe6 two hvpn1
[ "$GOT6" = $EXIT6 ] && pass "IPv6 goes through both hops: the internet sees the exit's IPv6 address" || fail "IPv6 request got '$GOT6'"
[ "$OWN" = 0 ] && pass "no packet carried the client's own IPv6 address into the inner tunnel" || fail "$OWN packet(s) carried $CLIENT6 into the inner tunnel"
sleep 0.5; kill "$ETD" 2>/dev/null; sleep 0.3
EN=$(tcpdump -n -r "$WORK/entry-tun.pcap" 2>/dev/null | grep -vc "fe80::")
[ "$EN" = 0 ] && pass "the entry's tunnel carried no IPv6 at all" || fail "the entry's tunnel carried $EN IPv6 packet(s)"
$C "$BIN/hidravpn" down > /dev/null 2>&1
N=$(link_count two); [ "$N" = 0 ] && pass "no IPv6 packet with the client's own address left on its link" || fail "$N IPv6 packet(s) left on the link"

blocked_round() {  # $1 round, $2 invite file
  start_link_capture "$1"
  $C "$BIN/hidravpn" up "$2" > "$WORK/up-$1.log" 2>&1 && wait_connected && pass "connected" || { cat "$WORK/up-$1.log" "$WORK/svc.log"; fail "up"; }
  grep -q "IPv6 blocked" "$WORK/st.log" && pass "status says IPv6 is blocked" || fail "status: $(cat "$WORK/st.log")"
  [ "$($C curl -4 -s --max-time 5 http://10.221.0.2/)" = 10.221.0.1 ] && pass "IPv4 still goes through the exit" || fail "IPv4 through the tunnel"
  probe6 "$1" hvpn0
  [ -z "$GOT6" ] && pass "an IPv6 request gets nothing" || fail "an IPv6 request got '$GOT6'"
  [ "$OWN" = 0 ] && pass "no packet carried the client's own IPv6 address into the tunnel" || fail "$OWN packet(s) carried $CLIENT6 into the tunnel"
  $C "$BIN/hidravpn" down > /dev/null 2>&1
  N=$(link_count "$1"); [ "$N" = 0 ] && pass "no IPv6 packet with the client's own address left on its link" || fail "$N IPv6 packet(s) left on the link"
}

echo "── an exit with ipv6 = \"off\""
stop_exit
sed -i 's/^ipv6 = "auto"$/ipv6 = "off"/' "$WORK/exit.toml"
grep -q '^ipv6 = "off"$' "$WORK/exit.toml" || fail "could not set ipv6 = \"off\" in the exit's settings"
start_exit || { fail "the exit did not come back"; exit 1; }
grep -q "IPv6 for clients: no" "$WORK/exit.log" && pass "the exit carries no IPv6" || fail "exit: $(grep -i ipv6 "$WORK/exit.log")"
admit_x laptop-off "$($C "$BIN/hidravpn" --key /etc/hidravpn/client.key pubkey --node "$NODE_X_PUB" 2>/dev/null)" > "$WORK/exit-off.json"
grep -q client_address6 "$WORK/exit-off.json" && fail "its invite still gives an IPv6 address" || pass "its invite gives no IPv6 address"
blocked_round off "$WORK/exit-off.json"

echo "── an exit whose host has no IPv6 route"
stop_exit
sed -i 's/^ipv6 = "off"$/ipv6 = "auto"/' "$WORK/exit.toml"
$X ip -6 route del default
start_exit || { fail "the exit did not come back"; exit 1; }
grep -q "no IPv6 default route" "$WORK/exit.log" && pass "the exit says its host has no IPv6 route, and carries none" || fail "exit: $(grep -i ipv6 "$WORK/exit.log")"
admit_x laptop-noroute "$($C "$BIN/hidravpn" --key /etc/hidravpn/client.key pubkey --node "$NODE_X_PUB" 2>/dev/null)" > "$WORK/exit-noroute.json"
grep -q client_address6 "$WORK/exit-noroute.json" && fail "its invite still gives an IPv6 address" || pass "its invite gives no IPv6 address"
blocked_round noroute "$WORK/exit-noroute.json"

echo "── the logs"
grep -qE "10\.220\.0\.2|$CLIENT6|$ULA::a4d|whoami" "$WORK/entry.log" "$WORK/exit.log" "$WORK/svc.log" && fail "a log names a client address" || pass "no node or service log names a client address, IPv4 or IPv6"

kill -INT "$SVC"; for _ in $(seq 1 25); do kill -0 "$SVC" 2>/dev/null || break; sleep 0.2; done; SVC=""
echo; echo "$ok passed, $bad failed"; [ $bad -eq 0 ]
