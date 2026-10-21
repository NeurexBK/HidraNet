#!/usr/bin/env bash
# The client reaches the entry relay and nothing else.
#
#   hn-client ── hn-core (router, firewall, capture) ──┬── hn-entry   198.51.100.1
#   192.0.2.2    192.0.2.1 / 198.51.100.254 /          ├── hn-middle  198.51.100.2
#                203.0.113.1                           ├── hn-exit    198.51.100.3
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
# Run as root from the repository root:  sudo bash hidra-node/scripts/test-anonymity-netns.sh
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
CRATE="$HERE/.."
BIN="$CRATE/target/debug/examples/netns_harness"
WORK=""
NS=(hn-client hn-core hn-entry hn-middle hn-exit hn-target)
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
  [ -n "${WORK:-}" ] && [ -z "${KEEP_WORK:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
cleanup
WORK="$(mktemp -d /tmp/hidra-anon.XXXXXX)"

# sudo resets PATH, so build first as yourself if cargo is not root's:
#   cargo build --manifest-path hidra-node/Cargo.toml --example netns_harness
if command -v cargo >/dev/null; then
  cargo build --quiet --manifest-path "$CRATE/Cargo.toml" --example netns_harness || exit 1
fi
[ -x "$BIN" ] || { echo "build first: cargo build --manifest-path hidra-node/Cargo.toml --example netns_harness"; exit 1; }

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
link hn-client c0 192.0.2.2/24 192.0.2.1
$CORE ip addr add 192.0.2.1/24 dev core-c0
link hn-target t0 203.0.113.2/24 203.0.113.1
$CORE ip addr add 203.0.113.1/24 dev core-t0
link hn-entry  r1 198.51.100.1/24 198.51.100.254
link hn-middle r2 198.51.100.2/24 198.51.100.254
link hn-exit   r3 198.51.100.3/24 198.51.100.254
for i in r1 r2 r3; do $CORE ip link set "core-$i" master br-r; done

$CORE nft -f - <<'EOF'
table inet anon {
  counter client_to_entry {}
  counter client_to_middle {}
  counter client_to_exit {}
  counter client_to_target {}
  counter client_to_other {}
  chain forward {
    type filter hook forward priority 0; policy accept;
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
sleep 1

# ── Nodes ───────────────────────────────────────────────────────────────────
start() { # ns, log, args...
  local ns="$1" log="$2"; shift 2
  ip netns exec "$ns" "$BIN" "$@" >"$WORK/$log" 2>&1 &
  PIDS+=($!)
}
start hn-target echo.log    echo  203.0.113.2:7000
start hn-entry  entry.log   relay 198.51.100.1:9001 "$WORK/entry.json"
start hn-middle middle.log  relay 198.51.100.2:9001 "$WORK/middle.json"
MIDDLE_PID="${PIDS[-1]}"
start hn-exit   exit.log    relay 198.51.100.3:9001 "$WORK/exit.json"
# A relay that signs a key it does not hold, on a second port of the exit.
start hn-exit   liar.log    relay 198.51.100.3:9002 "$WORK/liar.json" --lie
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
kill "${PIDS[0]}" 2>/dev/null; sleep 0.5
[ "$(counter client_to_entry)" -gt 0 ] && pass "the client spoke to the entry relay ($(counter client_to_entry) packets)" \
  || fail "the client never reached the entry relay"
for c in client_to_middle client_to_exit client_to_target client_to_other; do
  n="$(counter "$c")"
  [ "$n" = 0 ] && pass "firewall: 0 packets $c" || fail "firewall: $n packets $c"
done
syns() { tcpdump -n -r "$WORK/client.pcap" "$1" 2>/dev/null | wc -l; }
SYN='tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and src host 192.0.2.2'
n="$(syns "$SYN and not dst host 198.51.100.1")"
[ "$n" = 0 ] && pass "capture: 0 connection attempts from the client to anything but the entry" \
  || fail "capture: $n connection attempts from the client to something other than the entry: $(tcpdump -n -r "$WORK/client.pcap" "$SYN and not dst host 198.51.100.1" 2>/dev/null | awk '{print $5}' | sort | uniq -c | tr '\n' ' ')"

echo
echo "passed $ok, failed $bad"
[ "$bad" = 0 ]
