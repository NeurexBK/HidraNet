#!/bin/bash
# IPv6 and the tunnel, in three network namespaces with both families:
#
#   h6-client ──veth── h6-node ──veth── h6-inet
#   10.220.0.2         10.220.0.1        10.221.0.2
#   2001:db8:220::2    2001:db8:220::1   2001:db8:221::2   (answers with your
#                      10.221.0.1                            source address)
#                      2001:db8:221::1
#
# 2001:db8:220::2 is the client's own IPv6 address: whoever sees it knows
# who the client is. It must never leave the machine while connected, and
# never travel inside the tunnel either, where the node would read it.
#
# Run as root:  hidravpn/scripts/test-ipv6-netns.sh
# Needs: the release binaries built, python3, curl, nft, tcpdump, a kernel
# with IPv6.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/test/guard.sh"
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
BIN="$HERE/../target/release"
WORK="$(mktemp -d /tmp/hidravpn-v6.XXXXXX)"
PIDS=()
ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok+1)); }
fail() { echo "FAIL  $1"; bad=$((bad+1)); }
C="ip netns exec h6-client"; N="ip netns exec h6-node"; I="ip netns exec h6-inet"
NSS="h6-client h6-node h6-inet"
CLIENT6=2001:db8:220::2

cleanup() {
  set +e
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  sleep 1
  for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null; done
  for ns in $NSS; do ip netns del "$ns" 2>/dev/null; done
  rm -rf /etc/netns/h6-client /run/hidravpn/netcfg.json /var/run/wireguard/hvpn0.sock
  [ -z "${KEEP:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT
for ns in $NSS; do ip netns del "$ns" 2>/dev/null; done
rm -rf /etc/netns/h6-client /run/hidravpn/netcfg.json /var/run/wireguard/hvpn0.sock
for b in hidravpn hidravpn-node; do [ -x "$BIN/$b" ] || { echo "build first: cargo build --release"; exit 1; }; done
command -v tcpdump >/dev/null || { echo "needs tcpdump"; exit 1; }

# ── Network ──────────────────────────────────────────────────────────────────
for ns in $NSS; do ip netns add "$ns"; ip netns exec "$ns" ip link set lo up; done
if ! $C ip -6 addr add ::1/128 dev lo 2>/dev/null && ! $C ip -6 addr show dev lo | grep -q '::1'; then
  if [ "${HIDRAVPN_REQUIRE_IPV6:-}" = 1 ]; then echo "FAIL  this kernel has no IPv6"; exit 1; fi
  echo "SKIP  this kernel has no IPv6: nothing here can run"; exit 0
fi
ip link add c-n type veth peer name n-c; ip link set c-n netns h6-client; ip link set n-c netns h6-node
ip link add n-i type veth peer name i-n; ip link set n-i netns h6-node; ip link set i-n netns h6-inet
$C ip addr add 10.220.0.2/24 dev c-n; $C ip -6 addr add $CLIENT6/64 dev c-n nodad; $C ip link set c-n up
$C ip route add default via 10.220.0.1; $C ip -6 route add default via 2001:db8:220::1
$N ip addr add 10.220.0.1/24 dev n-c; $N ip -6 addr add 2001:db8:220::1/64 dev n-c nodad; $N ip link set n-c up
$N ip addr add 10.221.0.1/24 dev n-i; $N ip -6 addr add 2001:db8:221::1/64 dev n-i nodad; $N ip link set n-i up
$N ip route add default via 10.221.0.2; $N ip -6 route add default via 2001:db8:221::2
$I ip addr add 10.221.0.2/24 dev i-n; $I ip -6 addr add 2001:db8:221::2/64 dev i-n nodad; $I ip link set i-n up
mkdir -p /etc/netns/h6-client; echo "nameserver 10.220.0.1" > /etc/netns/h6-client/resolv.conf

$I python3 -I "$HERE/test/whoami6-http.py" > "$WORK/http.log" 2>&1 & PIDS+=($!)
$I python3 -I "$HERE/test/dns-stub.py" 10.221.0.2 > "$WORK/dns.log" 2>&1 & PIDS+=($!)
sleep 1

echo "── before the VPN"
[ "$($N curl -6 -s --max-time 3 'http://[2001:db8:221::2]/')" = 2001:db8:221::1 ] && pass "the internet host answers on IPv6 with the address it sees" || fail "no IPv6 internet host"
$C curl -6 -s --max-time 3 'http://[2001:db8:221::2]/' >/dev/null 2>&1 && fail "the client reaches the internet host without the tunnel (test network is wrong)" || pass "without the tunnel the client cannot reach it (no route back)"

# ── Node and client ──────────────────────────────────────────────────────────
$N "$BIN/hidravpn-node" --config "$WORK/node.toml" init --endpoint 10.220.0.1:51820 --name v6-node --dns udp://10.221.0.2 --out-interface n-i > "$WORK/init.log" 2>&1 || { cat "$WORK/init.log"; fail "node init"; exit 1; }
$N "$BIN/hidravpn-node" --config "$WORK/node.toml" run > "$WORK/node.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 50); do grep -q "DNS forwarder ready" "$WORK/node.log" && break; sleep 0.2; done
grep -q "DNS forwarder ready" "$WORK/node.log" && pass "node up" || { cat "$WORK/node.log"; fail "node did not come up"; exit 1; }
NODE_PUB=$(grep -o 'node public key: .*' "$WORK/init.log" | cut -d' ' -f4)
$C "$BIN/hidravpn" --key "$WORK/client.key" keygen >/dev/null 2>&1
PUB=$($C "$BIN/hidravpn" --key "$WORK/client.key" pubkey --node "$NODE_PUB" 2>/dev/null)
$N "$BIN/hidravpn-node" --config "$WORK/node.toml" admit --name laptop --pubkey "$PUB" > "$WORK/invite.json" 2> "$WORK/admit.log" || { cat "$WORK/admit.log"; fail "admit"; exit 1; }

$C tcpdump -n -U -i c-n -w "$WORK/link.pcap" ip6 and not icmp6 > /dev/null 2>&1 & PIDS+=($!)
sleep 0.5
$C "$BIN/hidravpn" --key "$WORK/client.key" up "$WORK/invite.json" > "$WORK/client.log" 2>&1 & UP=$!; PIDS+=("$UP")
for _ in $(seq 1 100); do grep -q "^connected" "$WORK/client.log" && break; sleep 0.2; done
grep -q "^connected" "$WORK/client.log" && pass "connected" || { cat "$WORK/client.log"; fail "no handshake"; exit 1; }
[ "$($C curl -s --max-time 5 http://10.221.0.2/)" = 10.221.0.1 ] && pass "IPv4 goes through the tunnel and leaves from the node" || fail "IPv4 through the tunnel"

echo "── IPv6 while connected"
$C tcpdump -n -U -i hvpn0 -w "$WORK/tun.pcap" ip6 > /dev/null 2>&1 & TD=$!; PIDS+=("$TD")
sleep 0.5
for _ in 1 2 3; do $C curl -6 -s --max-time 2 'http://[2001:db8:221::2]/' > "$WORK/v6.out" 2>/dev/null; done
sleep 0.5; kill $TD 2>/dev/null; sleep 0.3
echo "      what the IPv6 request got back: '$(cat "$WORK/v6.out")'"
echo "      sources of IPv6 packets written into the tunnel: $(tcpdump -n -r "$WORK/tun.pcap" 2>/dev/null | awk '{print $3}' | sed 's/\.[0-9]*$//' | sort -u | tr '\n' ' ')"
N_OWN=$(tcpdump -n -r "$WORK/tun.pcap" "src host $CLIENT6" 2>/dev/null | wc -l)
[ "$N_OWN" = 0 ] && pass "no IPv6 packet carries the client's own address into the tunnel" || fail "$N_OWN IPv6 packet(s) carried the client's own address $CLIENT6 into the tunnel, where the node decrypts them"
N_LINK=$(tcpdump -n -r "$WORK/link.pcap" "src host $CLIENT6" 2>/dev/null | wc -l)
[ "$N_LINK" = 0 ] && pass "no IPv6 packet left on the client's own link" || fail "$N_LINK IPv6 packet(s) left on the client's own link"

echo "── down"
kill -INT $UP; for _ in $(seq 1 50); do kill -0 $UP 2>/dev/null || break; sleep 0.2; done
grep -q "network restored" "$WORK/client.log" && pass "disconnected cleanly" || { tail -5 "$WORK/client.log"; fail "disconnect"; }
$C ip -6 route | grep -q hvpn0 && fail "IPv6 routes to hvpn0 remain" || pass "IPv6 routes removed"

echo; echo "$ok passed, $bad failed"; [ $bad -eq 0 ]
