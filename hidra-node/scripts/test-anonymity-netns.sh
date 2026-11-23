#!/usr/bin/env bash
# The client reaches the entry relay and nothing else.
#
#   hn-client ── hn-core (router, firewall, capture) ──┬── hn-entry   198.51.100.1
#   192.0.2.2    192.0.2.1 / 198.51.100.254 /          ├── hn-middle  198.51.100.2
#   hn-proxy                                           │
#   192.0.2.130                                          │
#                203.0.113.1                           ├── hn-exit    198.51.100.3
#                                                      ├── hn-relay4  198.51.100.4
#                                                      └── hn-target  203.0.113.2
#
# The core routes between all of them, so the client COULD reach the middle,
# the exit or the target: the network does not hide the path. The core's
# firewall lets the client open connections to the entry relay only, and
# counts (then rejects) every packet the client sends anywhere else. A packet
# capture on the client's link is checked the same way.
#
# Each relay signs a descriptor for the address and key it serves circuits
# with; the client is given the three descriptors, verifies them, and builds
# its circuit through them by telescoping.
#
# Pass means: a 3-hop circuit is built, real data goes through it and comes
# back intact, it is torn down and a second one is built and used; a relay
# whose descriptor names a key it does not hold, a descriptor altered after
# signing, and a middle relay that is down each make the circuit fail, with
# no other way tried; and through all of it the counters and the capture show
# zero packets from the client to the middle, the exit or the target.
#
# The relays also run DHT nodes, and a fourth relay is known only to the
# DHT. The real `hidra-node --proxy` runs in its own namespace, hn-proxy,
# with the first three relays pinned. Through its SOCKS port it must reach
# the target and a .hidra service whose descriptor is only in the DHT, and
# it must learn of the fourth relay. Its firewall lets it open TCP to a
# relay's circuit port and nothing else: no UDP (the DHT), no DNS, no target.
# It may use any relay as its first hop, so which relay that is is not
# checked here.
#
# Run as root from the repository root:  sudo bash hidra-node/scripts/test-anonymity-netns.sh
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
CRATE="$HERE/.."
BIN="$CRATE/target/debug/examples/netns_harness"
NODE="$CRATE/target/debug/hidra-node"
WORK=""
NS=(hn-client hn-proxy hn-core hn-entry hn-middle hn-exit hn-relay4 hn-target)
PIDS=()

ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok + 1)); }
fail() { echo "FAIL  $1"; bad=$((bad + 1)); }

cleanup() {
  set +e
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  sleep 0.5
  for ns in "${NS[@]}"; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null
    ip netns del "$ns" 2>/dev/null
  done
  rm -rf /etc/netns/hn-exit
  [ -n "${WORK:-}" ] && [ -z "${KEEP_WORK:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
for tool in ip nft tcpdump; do
  command -v "$tool" >/dev/null || { echo "missing $tool: install iproute2, nftables and tcpdump"; exit 1; }
done
cleanup
WORK="$(mktemp -d /tmp/hidra-anon.XXXXXX)"

# sudo resets PATH, so build first as yourself if cargo is not root's:
#   cargo build --manifest-path hidra-node/Cargo.toml --example netns_harness --bin hidra-node
if command -v cargo >/dev/null; then
  cargo build --quiet --manifest-path "$CRATE/Cargo.toml" --example netns_harness --bin hidra-node || exit 1
fi
[ -x "$BIN" ] && [ -x "$NODE" ] || { echo "build first: cargo build --manifest-path hidra-node/Cargo.toml --example netns_harness --bin hidra-node"; exit 1; }

# ── Network ─────────────────────────────────────────────────────────────────
for ns in "${NS[@]}"; do ip netns add "$ns"; ip netns exec "$ns" ip link set lo up; done
CORE="ip netns exec hn-core"
$CORE sysctl -qw net.ipv4.ip_forward=1
$CORE ip link add br-r type bridge
$CORE ip addr add 198.51.100.254/24 dev br-r
$CORE ip link set br-r up

link() { # ns, ifname-in-ns, addr/len, gateway
  ip link add "$2" type veth peer name "core-$2"
  ip link set "$2" netns "$1"
  ip link set "core-$2" netns hn-core
  ip netns exec "$1" ip addr add "$3" dev "$2"
  ip netns exec "$1" ip link set "$2" up
  ip netns exec "$1" ip route add default via "$4"
  $CORE ip link set "core-$2" up
}
link hn-client c0 192.0.2.2/25 192.0.2.1
$CORE ip addr add 192.0.2.1/25 dev core-c0
link hn-proxy  p0 192.0.2.130/25 192.0.2.129
$CORE ip addr add 192.0.2.129/25 dev core-p0
link hn-target t0 203.0.113.2/24 203.0.113.1
$CORE ip addr add 203.0.113.1/24 dev core-t0
link hn-entry  r1 198.51.100.1/24 198.51.100.254
link hn-middle r2 198.51.100.2/24 198.51.100.254
link hn-exit   r3 198.51.100.3/24 198.51.100.254
link hn-relay4 r4 198.51.100.4/24 198.51.100.254
for i in r1 r2 r3 r4; do $CORE ip link set "core-$i" master br-r; done

$CORE nft -f - <<'EOF'
table inet anon {
  counter client_to_entry {}
  counter client_to_middle {}
  counter client_to_exit {}
  counter client_to_target {}
  counter client_to_other {}
  counter proxy_to_relays {}
  counter proxy_to_other {}
  chain forward {
    type filter hook forward priority 0; policy accept;
    ip saddr 192.0.2.130 ip daddr 198.51.100.0/24 tcp dport 9001 counter name proxy_to_relays accept
    ip saddr 192.0.2.130 counter name proxy_to_other drop
    ip saddr 192.0.2.2 ip daddr 198.51.100.1 tcp dport 9001 counter name client_to_entry accept
    ip saddr 192.0.2.2 ip daddr 198.51.100.2 counter name client_to_middle reject with tcp reset
    ip saddr 192.0.2.2 ip daddr 198.51.100.3 counter name client_to_exit reject with tcp reset
    ip saddr 192.0.2.2 ip daddr 203.0.113.2 counter name client_to_target reject with tcp reset
    ip saddr 192.0.2.2 counter name client_to_other drop
  }
}
EOF
counter() { $CORE nft list counter inet anon "$1" | awk '/packets/ {print $2}'; }

$CORE tcpdump -U -n -i core-c0 -w "$WORK/client.pcap" >/dev/null 2>&1 &
PIDS+=($!)
$CORE tcpdump -U -n -i core-p0 -w "$WORK/proxy.pcap" >/dev/null 2>&1 &
PIDS+=($!)
sleep 1

# A payload and a hostname nobody else could produce. The exit resolves the
# name to the target through its namespace's own hosts file.
TAG="$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export HIDRA_CANARY="payload-canary-$TAG"
export HIDRA_CANARY_HOST="host-canary-$TAG.test"
mkdir -p /etc/netns/hn-exit
echo "203.0.113.2 $HIDRA_CANARY_HOST" >/etc/netns/hn-exit/hosts

# ── Nodes ───────────────────────────────────────────────────────────────────
start() { # ns, log, args...
  local ns="$1" log="$2"; shift 2
  ip netns exec "$ns" "$BIN" "$@" >"$WORK/$log" 2>&1 &
  PIDS+=($!)
}
start hn-target echo.log    echo  203.0.113.2:7000
BOOT=198.51.100.1:7000
start hn-entry  entry.log   relay 198.51.100.1:9001 "$WORK/entry.json"  --dht 198.51.100.1:7000
start hn-middle middle.log  relay 198.51.100.2:9001 "$WORK/middle.json" --dht 198.51.100.2:7000 --bootstrap $BOOT
MIDDLE_PID="${PIDS[-1]}"
start hn-exit   exit.log    relay 198.51.100.3:9001 "$WORK/exit.json"   --dht 198.51.100.3:7000 --bootstrap $BOOT
# Known only to the DHT: the client is not told about it.
start hn-relay4 relay4.log  relay 198.51.100.4:9001 "$WORK/relay4.json" --dht 198.51.100.4:7000 --bootstrap $BOOT
# A relay that signs a key it does not hold, on a second port of the exit.
start hn-exit   liar.log    relay 198.51.100.3:9002 "$WORK/liar.json" --lie
for _ in $(seq 120); do
  [ -s "$WORK/entry.json" ] && [ -s "$WORK/middle.json" ] && [ -s "$WORK/exit.json" ] \
    && [ -s "$WORK/relay4.json" ] && [ -s "$WORK/liar.json" ] && break
  sleep 1
done
sleep 1
"$BIN" tamper "$WORK/exit.json" "$WORK/tampered.json" >/dev/null

client() { # log, middle descriptor, exit descriptor, [expect-fail]
  local log="$1"; shift
  ip netns exec hn-client timeout 120 "$BIN" client "$WORK/entry.json" "$@" \
    >"$WORK/$log" 2>&1
}
result() { grep '^RESULT' "$WORK/$1" | tail -n1 | cut -c8-; }

# ── Circuit, data, teardown, rebuild ────────────────────────────────────────
if client client.log "$WORK/middle.json" "$WORK/exit.json" 203.0.113.2:7000; then
  pass "two circuits built in turn, 64 KiB echoed intact through each"
else
  fail "circuit through entry → middle → exit ($(result client.log))"
fi

# ── The proxy: relays and .hidra services from the DHT, through circuits ────
# A hidden service in the target's namespace, registered at the exit and
# announced in the DHT. (Its own anonymity is not what this test is about.)
start hn-target service.log service "$WORK/entry.json" "$WORK/middle.json" "$WORK/exit.json" \
  203.0.113.2:7100 $BOOT "$WORK/service.name"
for _ in $(seq 90); do [ -s "$WORK/service.name" ] && break; sleep 1; done
sleep 3

mkdir -p "$WORK/client-keys"
cat >"$WORK/client.toml" <<CONFIG
[node]
name = "anonymity-test-client"
[network]
listen_addr = "127.0.0.1"
listen_port = 9150
[logging]
level = "debug"
format = "pretty"
[paths]
keys_dir = "$WORK/client-keys"
[dht]
bootstrap_nodes = ["$BOOT"]
[proxy]
listen_addr = "127.0.0.1"
port = 9050
CONFIG
for r in entry middle exit; do
  printf '[[relays]]\nname = "%s"\naddr = "%s"\nnoise_pubkey = "%s"\n' "$r" \
    "$(grep -o '"addr":"[^"]*"' "$WORK/$r.json" | cut -d'"' -f4)" \
    "$("$BIN" pin "$WORK/$r.json" 2>/dev/null | tail -n1)" >>"$WORK/client.toml"
done
ip netns exec hn-proxy "$NODE" --proxy --config "$WORK/client.toml" >"$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
PIDS+=($PROXY_PID)

socks() { # log, host, port
  ip netns exec hn-proxy timeout 120 "$BIN" socks 127.0.0.1:9050 "$2" "$3" >"$WORK/$1" 2>&1
}
if socks socks-web.log 203.0.113.2 7000; then
  pass "proxy: the target reached through the real SOCKS proxy ($(result socks-web.log))"
else
  fail "proxy: the target through SOCKS ($(result socks-web.log))"
fi
HIDRA_NAME="$(cat "$WORK/service.name" 2>/dev/null)"
if [ -n "$HIDRA_NAME" ] && socks socks-hidra.log "$HIDRA_NAME" 80; then
  pass "proxy: a .hidra service found in the DHT and reached ($(result socks-hidra.log))"
else
  fail "proxy: the .hidra service ($(result socks-hidra.log 2>/dev/null))"
fi
if sed 's/\x1b\[[0-9;]*m//g' "$WORK/proxy.log" | grep -qE "usable(:|=) ?4\b"; then
  pass "proxy: learned of the relay known only to the DHT"
else
  fail "proxy: never learned of the relay known only to the DHT"
fi
kill "$PROXY_PID" 2>/dev/null

# ── Failures abort; nothing else is tried ───────────────────────────────────
if client wrongkey.log "$WORK/middle.json" "$WORK/liar.json" 203.0.113.2:7000 expect-fail; then
  pass "exit with a signed but wrong key: circuit refused ($(result wrongkey.log))"
else
  fail "exit with a signed but wrong key ($(result wrongkey.log))"
fi
if client tampered.log "$WORK/middle.json" "$WORK/tampered.json" 203.0.113.2:7000 expect-fail; then
  pass "descriptor altered after signing: refused ($(result tampered.log))"
else
  fail "descriptor altered after signing ($(result tampered.log))"
fi
kill "$MIDDLE_PID" 2>/dev/null; sleep 0.5
if client deadmiddle.log "$WORK/middle.json" "$WORK/exit.json" 203.0.113.2:7000 expect-fail; then
  pass "middle relay down: extension failed, circuit abandoned ($(result deadmiddle.log))"
else
  fail "middle relay down ($(result deadmiddle.log))"
fi

# ── What the network saw ────────────────────────────────────────────────────
sleep 1
kill "${PIDS[0]}" "${PIDS[1]}" 2>/dev/null; sleep 0.5
[ "$(counter client_to_entry)" -gt 0 ] && pass "the client spoke to the entry relay ($(counter client_to_entry) packets)" \
  || fail "the client never reached the entry relay"
for c in client_to_middle client_to_exit client_to_target client_to_other; do
  n="$(counter "$c")"
  [ "$n" = 0 ] && pass "firewall: 0 packets $c" || fail "firewall: $n packets $c"
done
syns() { tcpdump -n -r "$WORK/client.pcap" "$1" 2>/dev/null | wc -l; }
SYN='tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and src host 192.0.2.2'
n="$(tcpdump -n -r "$WORK/client.pcap" "udp and src host 192.0.2.2" 2>/dev/null | wc -l)"
[ "$n" = 0 ] && pass "capture: 0 UDP packets from the client (no DHT, no DNS)" \
  || fail "capture: $n UDP packets from the client: $(tcpdump -n -r "$WORK/client.pcap" "udp and src host 192.0.2.2" 2>/dev/null | awk '{print $5}' | sort | uniq -c | tr '\n' ' ')"
n="$(syns "$SYN and not dst host 198.51.100.1")"
[ "$n" = 0 ] && pass "capture: 0 connection attempts from the client to anything but the entry" \
  || fail "capture: $n connection attempts from the client to something other than the entry: $(tcpdump -n -r "$WORK/client.pcap" "$SYN and not dst host 198.51.100.1" 2>/dev/null | awk '{print $5}' | sort | uniq -c | tr '\n' ' ')"

n="$(counter proxy_to_relays)"
[ "$n" -gt 0 ] && pass "proxy: spoke to relays' circuit ports ($n packets)" || fail "proxy: never reached a relay"
n="$(counter proxy_to_other)"
[ "$n" = 0 ] && pass "firewall: 0 packets from the proxy to anything but a relay's circuit port" \
  || fail "firewall: $n packets from the proxy to something other than a relay's circuit port"
n="$(tcpdump -n -r "$WORK/proxy.pcap" "udp and src host 192.0.2.130" 2>/dev/null | wc -l)"
[ "$n" = 0 ] && pass "capture: 0 UDP packets from the proxy (no DHT, no DNS)" \
  || fail "capture: $n UDP packets from the proxy: $(tcpdump -n -r "$WORK/proxy.pcap" "udp and src host 192.0.2.130" 2>/dev/null | awk '{print $5}' | sort | uniq -c | tr '\n' ' ')"

# ── What the logs say ───────────────────────────────────────────────────────
# Every process logs at DEBUG, failure paths included. None may write the
# canary payload, the canary hostname, or the client's address — the client
# itself included: its log is on the user's disk.
for f in client wrongkey tampered deadmiddle entry middle exit relay4 liar echo proxy; do
  [ -s "$WORK/$f.log" ] || [ "$f" = echo ] || fail "log $f.log is empty: the capture missed it"
done
grep -q "circuit extended" "$WORK/entry.log" && grep -q "extend failed" "$WORK/entry.log" \
  || fail "the entry's log lacks the circuit's own lines: the capture missed it"
leaks="$(grep -lE "$TAG|192\.0\.2\.(2|130)\b" "$WORK"/*.log 2>/dev/null | xargs -r -n1 basename | tr '\n' ' ')"
[ -z "$leaks" ] && pass "logs at DEBUG: no canary payload, no canary hostname, no client address" \
  || fail "the canary or the client's address is in: $leaks"

echo
echo "passed $ok, failed $bad"
[ "$bad" = 0 ]
