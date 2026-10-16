#!/usr/bin/env bash
# Anonymity, not just encryption: who can see what, proved with packet
# captures, firewall counters and the nodes' own view of their peers.
# Seven network namespaces:
#
#   hv-client ──veth── hv-isp ──bridge br-pub──┬── hv-entry  10.210.0.10  (role entry, operator op-a)
#   10.200.0.2         10.200.0.1               ├── hv-exit   10.210.0.20  (role exit,  operator op-b) ──veth── hv-inet
#   fd00:200::2        fd00:200::1              └── hv-exit2  10.210.0.30  (role exit,  operator op-a) ──veth── hv-inet
#                      10.210.0.1                   (exits reach hv-inet at 10.201.0.2 and 10.204.0.2)
#
# hv-isp is the client's own network: a router with no NAT, so whoever the
# client talks to directly sees 10.200.0.2. The exits can reach the client
# (that is how one hop works), so an exit that learned the client's address
# would be caught here. hv-inet ("the internet") is reachable only through an
# exit's NAT and runs the resolver every exit uses.
#
# What it proves:
#   - Privado from a pocket that only knows the nodes: the client never
#     sends a packet to an exit; the exit never receives one from the client;
#     the exit's own peer table shows the session coming from the entry.
#   - The exit is shown a fresh key on every Privado connection and a new
#     identity, never the key it knows from a one-hop session, and the key it
#     was shown lapses on the exit soon after the session ends.
#   - The entry never learns the destination: it forwards nothing but
#     WireGuard and the admission request to the exit, its resolver is never
#     asked, and even a program bound to the outer tunnel cannot reach it.
#   - Two hops under one operator are refused unless the person says yes,
#     and a new identity never moves to such a pair by itself.
#   - Nothing leaves the machine outside the tunnel while connected, while
#     the circuit rotates, while it reconnects, and while the exit is dead;
#     no DNS and no IPv6 at all.
#   - With every component logging at DEBUG, including failures, no log
#     names the client's address, its tunnel addresses, a key it presented,
#     a name it looked up or a byte it sent.
#
# Run as root:  sudo bash hidravpn/scripts/test-anonymity-netns.sh
# Needs: the release binaries built, python3, curl, nft, tcpdump, ip netns, /dev/net/tun,
# and wg (wireguard-tools) where the kernel has WireGuard.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/../target/release"
WORK=""
C="ip netns exec hv-client"; P="ip netns exec hv-isp"; E="ip netns exec hv-entry"
X="ip netns exec hv-exit"; X2="ip netns exec hv-exit2"; I="ip netns exec hv-inet"
PIDS=(); CAPS=(); SVC=""; NODE_X=""
export RUST_BACKTRACE=0
ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok + 1)); }
fail() { echo "FAIL  $1"; bad=$((bad + 1)); }
NSS="hv-client hv-isp hv-entry hv-exit hv-exit2 hv-inet"
cleanup() {
  set +e
  [ -n "$SVC" ] && kill -INT "$SVC" 2>/dev/null && sleep 1
  for p in "${CAPS[@]:-}" "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  sleep 0.5
  for ns in $NSS; do ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null; ip netns del "$ns" 2>/dev/null; done
  rm -rf /etc/netns/hv-client /run/hidravpn/control.sock /run/hidravpn/control.token /run/hidravpn/netcfg.json \
         /var/lib/hidravpn/peers.json /etc/hidravpn/client.key /etc/hidravpn/circuit.json \
         /var/run/wireguard/hve0.sock /var/run/wireguard/hvx0.sock /var/run/wireguard/hvx1.sock
  [ -n "${WORK:-}" ] && [ -z "${KEEP:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT
cleanup
WORK="$(mktemp -d /tmp/hidravpn-anon.XXXXXX)"
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
for b in hidravpn hidravpn-node hidravpn-service hidravpn-sign; do [ -x "$BIN/$b" ] || { echo "build first: cargo build --release --manifest-path hidravpn/Cargo.toml"; exit 1; }; done
command -v tcpdump >/dev/null || { echo "needs tcpdump"; exit 1; }

CANARY="canary-$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
CLIENT=10.200.0.2; ISP=10.200.0.1; ENTRY=10.210.0.10; EXIT=10.210.0.20; EXIT2=10.210.0.30

# ── Network ─────────────────────────────────────────────────────────────────
for ns in $NSS; do ip netns add "$ns"; ip netns exec "$ns" ip link set lo up; done
$P sysctl -qw net.ipv4.ip_forward=1
ip link add c-i type veth peer name i-c; ip link set c-i netns hv-client; ip link set i-c netns hv-isp
$C ip addr add $CLIENT/24 dev c-i; $C ip link set c-i up; $C ip route add default via $ISP
$P ip addr add $ISP/24 dev i-c; $P ip link set i-c up
$P ip link add br-pub type bridge; $P ip addr add 10.210.0.1/24 dev br-pub; $P ip link set br-pub up
for pair in "hv-entry en-p p-en $ENTRY" "hv-exit ex-p p-ex $EXIT" "hv-exit2 ex2-p p-ex2 $EXIT2"; do
  set -- $pair
  ip link add "$2" type veth peer name "$3"; ip link set "$2" netns "$1"; ip link set "$3" netns hv-isp
  $P ip link set "$3" master br-pub; $P ip link set "$3" up
  ip netns exec "$1" ip addr add "$4/24" dev "$2"; ip netns exec "$1" ip link set "$2" up
done
$E ip route add default via 10.210.0.1
ip link add x-i type veth peer name i-x; ip link set x-i netns hv-exit; ip link set i-x netns hv-inet
ip link add x2-i type veth peer name i-x2; ip link set x2-i netns hv-exit2; ip link set i-x2 netns hv-inet
$X ip addr add 10.201.0.1/24 dev x-i; $X ip link set x-i up; $X ip route add default via 10.201.0.2; $X ip route add 10.200.0.0/24 via 10.210.0.1
$X2 ip addr add 10.204.0.1/24 dev x2-i; $X2 ip link set x2-i up; $X2 ip route add default via 10.204.0.2; $X2 ip route add 10.200.0.0/24 via 10.210.0.1
$I ip addr add 10.201.0.2/24 dev i-x; $I ip link set i-x up
$I ip addr add 10.204.0.2/24 dev i-x2; $I ip link set i-x2 up
# IPv6 on the client's own link only, so an IPv6 leak would have somewhere to go.
# A kernel built without IPv6 cannot leak it; the IPv6 checks then say SKIP.
V6=1
{ $C ip -6 addr add fd00:200::2/64 dev c-i nodad && $P ip -6 addr add fd00:200::1/64 dev i-c nodad; } 2>/dev/null || V6=0
skip() { echo "SKIP  $1"; }
mkdir -p /etc/netns/hv-client; echo "nameserver $ISP" > /etc/netns/hv-client/resolv.conf

$I python3 -I "$HERE/test/whoami-http.py" > "$WORK/http.log" 2>&1 & PIDS+=($!)
$I python3 -I "$HERE/test/dns-stub.py" 10.201.0.2 > "$WORK/dns.log" 2>&1 & PIDS+=($!)
mkdir -p "$WORK/leak"; echo leak > "$WORK/leak/index.html"
BIND=0.0.0.0; [ $V6 = 1 ] && BIND=::
$P python3 -I -m http.server 8081 --bind $BIND --directory "$WORK/leak" > /dev/null 2>&1 & PIDS+=($!)
sleep 1
[ "$($C curl -s --max-time 3 http://$ISP:8081/ 2>/dev/null)" = leak ] && pass "before the VPN the client's own network answers (the leak target)" || fail "the test network is wrong: no leak target"
if [ $V6 = 1 ]; then
  [ "$($C curl -6 -s --max-time 3 'http://[fd00:200::1]:8081/' 2>/dev/null)" = leak ] && pass "before the VPN it answers on IPv6 too" || fail "no IPv6 leak target"
elif [ "${HIDRAVPN_REQUIRE_IPV6:-}" = 1 ]; then
  fail "this kernel has no IPv6, and HIDRAVPN_REQUIRE_IPV6=1 says the IPv6 checks must run"
else
  skip "this kernel has no IPv6: the IPv6 checks cannot run here"
fi
$C curl -s --max-time 3 http://10.201.0.2/ >/dev/null 2>&1 && fail "the internet host is reachable without an exit (test network is wrong)" || pass "the internet host is reachable only through an exit"

# Captures: the client's own link, and everything that reaches the exit from outside.
cap() { $1 tcpdump -i "$2" -U -n -w "$3" ${4:-} >/dev/null 2>&1 & CAPS+=($!); }
count() { tcpdump -n -r "$1" "$2" 2>/dev/null | wc -l; }
cap "$P" i-c "$WORK/isp-all.pcap"
cap "$X" ex-p "$WORK/exit-all.pcap"
sleep 1

# ── Three nodes, all admitting openly ───────────────────────────────────────
mkdir -p "$WORK/run-e" "$WORK/run-x" "$WORK/run-x2"
$E "$BIN/hidravpn-node" --config "$WORK/e.toml" init --endpoint $ENTRY:51820 --tunnel 10.78.0.0/16 --name entry-a --role entry --operator op-a --open-admission --dns udp://10.201.0.2 --out-interface en-p > "$WORK/init-e.log" 2>&1 || { cat "$WORK/init-e.log"; exit 1; }
$X "$BIN/hidravpn-node" --config "$WORK/x.toml" init --endpoint $EXIT:51820 --name exit-b --role exit --operator op-b --open-admission --dns udp://10.201.0.2 --out-interface x-i > "$WORK/init-x.log" 2>&1 || { cat "$WORK/init-x.log"; exit 1; }
$X2 "$BIN/hidravpn-node" --config "$WORK/x2.toml" init --endpoint $EXIT2:51820 --tunnel 10.79.0.0/16 --name exit-a2 --role exit --operator op-a --open-admission --dns udp://10.204.0.2 --out-interface x2-i > "$WORK/init-x2.log" 2>&1 || { cat "$WORK/init-x2.log"; exit 1; }
sed -i 's/^interface = "hvpn0"/interface = "hve0"/' "$WORK/e.toml"
sed -i 's/^interface = "hvpn0"/interface = "hvx0"/' "$WORK/x.toml"
sed -i 's/^interface = "hvpn0"/interface = "hvx1"/' "$WORK/x2.toml"
LOGENV="RUST_LOG=debug HIDRAVPN_SESSION_IDLE_SECS=40"
start_exit() { $X env HIDRAVPN_RUN_DIR="$WORK/run-x" $LOGENV ${1:-} "$BIN/hidravpn-node" --config "$WORK/x.toml" run >> "$WORK/x.log" 2>&1 & NODE_X=$!; PIDS+=($NODE_X); }
$E env HIDRAVPN_RUN_DIR="$WORK/run-e" $LOGENV "$BIN/hidravpn-node" --config "$WORK/e.toml" run > "$WORK/e.log" 2>&1 & PIDS+=($!)
start_exit
$X2 env HIDRAVPN_RUN_DIR="$WORK/run-x2" $LOGENV "$BIN/hidravpn-node" --config "$WORK/x2.toml" run > "$WORK/x2.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 100); do grep -q "DNS forwarder ready" "$WORK/e.log" && grep -q "DNS forwarder ready" "$WORK/x.log" && grep -q "DNS forwarder ready" "$WORK/x2.log" && break; sleep 0.2; done
grep -q "admission service on TCP 51821 (open" "$WORK/e.log" && grep -q "admission service on TCP 51821 (open" "$WORK/x.log" && grep -q "admission service on TCP 51821 (open" "$WORK/x2.log" && pass "three nodes up, each admitting openly, at DEBUG" || { tail -n 5 "$WORK/e.log" "$WORK/x.log" "$WORK/x2.log"; fail "nodes did not come up"; exit 1; }

# What the entry does with what it receives from its tunnel: counters only.
$E nft -f - <<'EOF'
table inet hv_observe {
  chain input {
    type filter hook input priority -10; policy accept;
    iifname "hve0" udp dport 53 counter comment "entry-resolver-udp"
    iifname "hve0" tcp dport 53 counter comment "entry-resolver-tcp"
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "hve0" udp dport 53 counter comment "fwd-dns"
    iifname "hve0" tcp dport 80 counter comment "fwd-http"
    iifname "hve0" udp dport 51820 counter comment "fwd-wireguard"
    iifname "hve0" tcp dport 51821 counter comment "fwd-admission"
    iifname "hve0" counter comment "fwd-all"
  }
}
EOF
obs() { $E nft list table inet hv_observe | grep "comment \"$1\"" | sed -E 's/.*packets ([0-9]+).*/\1/'; }

# A node's own peer table, as its operator can read it: "key endpoint
# handshake" lines. A node on userspace WireGuard answers on its control
# socket; one on the kernel's (as on a CI runner) through `wg`. Arguments:
# the interface, then the namespace prefix it lives in.
peers() {
  if [ -S "/var/run/wireguard/$1.sock" ]; then peers_uapi "/var/run/wireguard/$1.sock"
  else $2 wg show "$1" dump 2>/dev/null | awk 'NR > 1 { ep = $3; if (ep == "(none)") ep = "-"; else sub(/:[0-9]+$/, "", ep); print $1, ep, $5 }'
  fi
}
peers_uapi() { python3 -I - "$1" <<'PY'
import socket, sys, base64
s = socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect(sys.argv[1]); s.sendall(b"get=1\n\n")
buf = b""
while not buf.endswith(b"\n\n"):
    c = s.recv(65536)
    if not c: break
    buf += c
key = None; ep = "-"; hs = 0; out = []
def flush():
    if key: out.append(f"{key} {ep} {hs}")
for line in buf.decode().splitlines():
    k, _, v = line.partition("=")
    if k == "public_key":
        flush(); key = base64.b64encode(bytes.fromhex(v)).decode(); ep = "-"; hs = 0
    elif k == "endpoint": ep = v.rsplit(":", 1)[0]
    elif k == "last_handshake_time_sec": hs = int(v)
flush(); print("\n".join(out))
PY
}
# Every key the exit has ever seen arrive from an address, appended over the run.
# The same for the entry.
watch_exit() { while true; do peers hvx0 "$X" >> "$WORK/exit-seen.txt" 2>/dev/null; peers hve0 "$E" >> "$WORK/entry-seen.txt" 2>/dev/null; sleep 0.5; done; }
watch_exit & PIDS+=($!)
# How many different keys a node's table ever showed arriving from an address, with a handshake.
keys_from() { python3 -I -c "
import sys
print(len({l.split()[0] for l in open(sys.argv[1]) if len(l.split()) == 3 and l.split()[1] == sys.argv[2] and l.split()[2] != '0'}))" "$1" "$2" 2>/dev/null || echo 0; }

# ── The list, the client, the service ───────────────────────────────────────
$E "$BIN/hidravpn-node" --config "$WORK/e.toml" record > "$WORK/rec-e.json" 2>/dev/null
$X "$BIN/hidravpn-node" --config "$WORK/x.toml" record > "$WORK/rec-x.json" 2>/dev/null
$X2 "$BIN/hidravpn-node" --config "$WORK/x2.toml" record > "$WORK/rec-x2.json" 2>/dev/null
LISTPUB=$("$BIN/hidravpn-sign" keygen --out "$WORK/list.key" 2>/dev/null)
HIDRAVPN_SIGN="$BIN/hidravpn-sign" bash "$HERE/make-node-list.sh" --key "$WORK/list.key" --out "$WORK/nodes.json" --sequence 1 "$WORK/rec-e.json" "$WORK/rec-x.json" "$WORK/rec-x2.json" > /dev/null 2>&1
mkdir -p /etc/hidravpn
$C "$BIN/hidravpn" --key /etc/hidravpn/client.key keygen >/dev/null 2>&1
"$BIN/hidravpn" nodes import "$WORK/nodes.json" --pubkey "$LISTPUB" > "$WORK/import.log" 2>&1 && grep -q "added 3 node(s)" "$WORK/import.log" && pass "the signed list makes three nodes known" || { cat "$WORK/import.log"; fail "import"; }
cp /etc/hidravpn/circuit.json "$WORK/known-only.json"
MASTER=$($C "$BIN/hidravpn" --key /etc/hidravpn/client.key pubkey 2>/dev/null)

$C env RUST_LOG=debug "$BIN/hidravpn-service" run > "$WORK/svc.log" 2>&1 & SVC=$!
for i in $(seq 1 50); do [ -S /run/hidravpn/control.sock ] && break; sleep 0.2; done
[ -S /run/hidravpn/control.sock ] && pass "the service is up, at DEBUG" || { cat "$WORK/svc.log"; fail "service"; exit 1; }
svc() { python3 -I - "$1" <<'PY'
import socket, sys, json
tok = open('/run/hidravpn/control.token').read().strip()
req = json.loads(sys.argv[1]); req['token'] = tok
s = socket.socket(socket.AF_UNIX); s.settimeout(90); s.connect('/run/hidravpn/control.sock'); s.sendall((json.dumps(req) + '\n').encode())
buf = b''
while b'\n' not in buf:
    c = s.recv(65536)
    if not c: break
    buf += c
print(buf.decode().strip())
PY
}
wait_connected() { for i in $(seq 1 60); do svc '{"cmd":"status"}' | grep -q '"connected":true' && return 0; sleep 0.3; done; return 1; }
exit_of() { svc '{"cmd":"status"}' | python3 -I -c "import json,sys; print(json.load(sys.stdin)['status']['node_name'])" 2>/dev/null; }
# The key the exit is shown right now: of the keys not seen before in this
# run, the one with the newest handshake ("key endpoint handshake").
SEEN_KEYS=()
current_exit_key() {
  sleep 1
  peers hvx0 "$X" | awk '$3 > 0' | sort -k3 -n | python3 -I -c "
import sys
seen = set(sys.argv[1:])
rows = [l.split() for l in sys.stdin if l.split() and l.split()[0] not in seen]
print(' '.join(rows[-1]) if rows else '- - 0')" "${SEEN_KEYS[@]}"
}

# ── A. Privado from a pocket that only knows the nodes ──────────────────────
echo "── A. privado, first connection"
cap "$P" i-c "$WORK/isp-a.pcap"; cap "$X" ex-p "$WORK/exit-a.pcap"; sleep 1
R=$(svc '{"cmd":"connect","mode":"privado"}')
echo "$R" | grep -q '"ok":true' && echo "$R" | grep -q '"hops":2' && pass "connect privado from a pocket that only knew the nodes" || { echo "$R" | cut -c1-400; tail -5 "$WORK/svc.log"; fail "connect privado"; }
wait_connected && pass "both hops have a session" || fail "no session"
[ "$(exit_of)" = exit-b ] && pass "the exit is exit-b (op-b), not exit-a2 run by the entry's operator" || fail "exit was '$(exit_of)'"
EXIT_SEEN=$($C curl -s --max-time 8 http://10.201.0.2/ 2>/dev/null)
[ "$EXIT_SEEN" = 10.201.0.1 ] && pass "the internet sees the exit's address" || fail "internet saw '$EXIT_SEEN'"
RES=$($C python3 -I -c "import socket;print(socket.gethostbyname('$CANARY.test'))" 2>&1)
$C curl -s --max-time 8 -o /dev/null --data "payload-$CANARY" "http://10.201.0.2/$CANARY" 2>/dev/null
sleep 0.5
[ "$RES" = 10.201.0.2 ] && grep -q "query from 10.201.0.1 for $CANARY.test" "$WORK/dns.log" && pass "DNS goes through both hops: the resolver saw the canary name asked by the exit" || fail "DNS: '$RES' $(grep -c "$CANARY" "$WORK/dns.log")"
read -r KP1 EP1 _ <<< "$(current_exit_key)"; SEEN_KEYS+=("$KP1")
[ "$EP1" = $ENTRY ] && pass "the exit's own peer table shows the session coming from the entry ($EP1)" || fail "the exit sees the session from '$EP1'"
sleep 1; kill "${CAPS[-1]}" "${CAPS[-2]}" 2>/dev/null; sleep 0.5
N=$(count "$WORK/isp-a.pcap" "ip and src host $CLIENT and (dst host $EXIT or dst host $EXIT2)")
[ "$N" = 0 ] && pass "the client sent 0 packets to an exit while connecting (the admission went through the entry)" || fail "the client sent $N packet(s) straight to an exit while connecting privado"
N=$(count "$WORK/exit-a.pcap" "ip and src host $CLIENT")
[ "$N" = 0 ] && pass "the exit received 0 packets from the client's address" || fail "the exit received $N packet(s) from the client's address"
N=$(count "$WORK/isp-a.pcap" "ip and src host $CLIENT and not (udp and dst host $ENTRY and dst port 51820) and not (tcp and host $ENTRY and port 51821) and not (icmp[icmptype] == icmp-unreach and dst host $ENTRY)")
[ "$N" = 0 ] && pass "everything the client sent went to the entry: WireGuard, and its admission request" || fail "$N packet(s) left the client for somewhere else than the entry"

echo "── A. what the entry saw"
[ "$(obs fwd-dns)" = 0 ] && [ "$(obs fwd-http)" = 0 ] && [ "$(obs entry-resolver-udp)" = 0 ] && [ "$(obs entry-resolver-tcp)" = 0 ] && pass "the entry forwarded no DNS and no HTTP, and its resolver was asked nothing" || fail "entry: dns=$(obs fwd-dns) http=$(obs fwd-http) resolver=$(obs entry-resolver-udp)/$(obs entry-resolver-tcp)"
[ "$(obs fwd-all)" = "$(( $(obs fwd-wireguard) + $(obs fwd-admission) ))" ] && [ "$(obs fwd-wireguard)" -gt 0 ] && pass "the entry forwarded only WireGuard ($(obs fwd-wireguard)) and the admission request ($(obs fwd-admission)) to the exit" || fail "entry forwarded other traffic: all=$(obs fwd-all) wg=$(obs fwd-wireguard) adm=$(obs fwd-admission)"
# A program that binds to the outer tunnel on purpose: its packets must not
# reach the entry (whose resolver would see the name, whose firewall would
# see the destination).
OUTER_DNS=10.78.0.1  # the entry's resolver: its tunnel is 10.78.0.0/16
$C python3 -I - "$OUTER_DNS" "$CANARY" > "$WORK/bound.log" 2>&1 <<'PY'
import socket, sys, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, 25, b"hvpn0\0")  # SO_BINDTODEVICE
s.settimeout(2)
q = struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(p)]) + p.encode() for p in (sys.argv[2] + "-bound", "test")) + b"\0\0\1\0\1"
try:
    s.sendto(q, (sys.argv[1], 53)); s.recvfrom(512); print("answered")
except Exception as e:
    print("no answer:", type(e).__name__)
PY
$C curl -s --max-time 3 --interface hvpn0 http://10.201.0.2/ > /dev/null 2>&1
[ -n "$OUTER_DNS" ] && grep -q "no answer" "$WORK/bound.log" && [ "$(obs entry-resolver-udp)" = 0 ] && [ "$(obs fwd-http)" = 0 ] && pass "a program bound to the outer tunnel reaches neither the entry's resolver nor, through it, the internet" || fail "bound to the outer tunnel: $(cat "$WORK/bound.log") resolver=$(obs entry-resolver-udp) http=$(obs fwd-http) (dns '$OUTER_DNS')"

echo "── A. IPv6"
if [ $V6 = 1 ]; then
  $C curl -6 -s --max-time 3 'http://[fd00:200::1]:8081/' >/dev/null 2>&1 && fail "IPv6 got out while connected" || pass "an IPv6 request is blocked while connected"
else skip "IPv6 request while connected (no IPv6 in this kernel)"; fi

# ── B. one hop, then two: the exit cannot join them ─────────────────────────
echo "── B. the exit cannot link a one-hop session to a two-hop one"
svc '{"cmd":"down"}' > /dev/null
rapido_through_exit_b() { for i in $(seq 1 12); do R=$(svc '{"cmd":"connect","mode":"rapido"}'); [ "$(exit_of)" = exit-b ] && return 0; done; return 1; }
for i in $(seq 1 12); do
  R=$(svc '{"cmd":"connect","mode":"rapido"}'); [ "$(exit_of)" = exit-b ] && break
done
wait_connected && [ "$(exit_of)" = exit-b ] && pass "one hop through exit-b" || fail "rapido through exit-b: $(echo "$R" | cut -c1-300)"
$C curl -s --max-time 8 http://10.201.0.2/ > /dev/null 2>&1
read -r KD EPD _ <<< "$(current_exit_key)"; SEEN_KEYS+=("$KD")
[ "$EPD" = $CLIENT ] && pass "in one hop the exit sees the client's address, as it must ($EPD)" || fail "rapido: exit sees '$EPD'"
svc '{"cmd":"down"}' > /dev/null
rapido_through_exit_b && wait_connected && $C curl -s --max-time 8 http://10.201.0.2/ > /dev/null 2>&1
read -r KD2 EPD2 _ <<< "$(current_exit_key)"; SEEN_KEYS+=("$KD2")
[ "$KD2" != - ] && [ "$KD2" != "$KD" ] && [ "$EPD2" = $CLIENT ] && pass "a second one-hop connection shows the same node a fresh key: it cannot tell it is the same person by key" || fail "one hop twice: '$KD' then '$KD2' (from $EPD2)"
svc '{"cmd":"down"}' > /dev/null
R=$(svc '{"cmd":"connect","mode":"privado"}'); wait_connected && [ "$(exit_of)" = exit-b ] || fail "second privado: $(echo "$R" | cut -c1-300)"
$C curl -s --max-time 8 http://10.201.0.2/ > /dev/null 2>&1
read -r KP2 EP2 _ <<< "$(current_exit_key)"; SEEN_KEYS+=("$KP2")
[ "$EP2" = $ENTRY ] && [ "$KP2" != "$KD" ] && [ "$KP2" != - ] && pass "two hops show the exit a key it never saw in the one-hop session" || fail "privado key '$KP2' (from $EP2) vs one-hop key '$KD'"
[ "$KP2" != - ] && [ "$KP2" != "$KP1" ] && pass "every privado connection shows the exit a fresh key" || fail "the exit saw the same key on two privado connections"
python3 -I - "$WORK/exit-seen.txt" "$CLIENT" > "$WORK/linked.txt" <<'PY'
import sys
direct, via = set(), set()
for line in open(sys.argv[1]):
    p = line.split()
    if len(p) < 2 or p[1] == "-": continue
    (direct if p[1] == sys.argv[2] else via).add(p[0])
print(len(direct & via))
PY
[ "$(cat "$WORK/linked.txt")" = 0 ] && pass "no key the exit ever saw from the client's address appeared from anywhere else" || fail "$(cat "$WORK/linked.txt") key(s) seen by the exit both from the client and through the entry"
N=$(keys_from "$WORK/entry-seen.txt" $CLIENT)
[ "$N" -ge 2 ] && pass "the entry was shown a different key on each of the $N two-hop connections so far" || fail "the entry saw $N key(s) over two connections"

# ── C. one operator for both hops ───────────────────────────────────────────
echo "── C. one operator on both hops"
NI=$(svc '{"cmd":"new_identity"}')
wait_connected; [ "$(exit_of)" = exit-b ] && echo "$NI" | grep -qi "operator" && pass "new identity does not move to exit-a2, run by the entry's operator, and says why" || fail "new identity: exit '$(exit_of)'; $(echo "$NI" | grep -o '"note":"[^"]*"')"
read -r KP3 _ _ <<< "$(current_exit_key)"; SEEN_KEYS+=("$KP3")
[ "$KP3" != - ] && [ "$KP3" != "$KP2" ] && pass "a new identity shows even the same exit a fresh key" || fail "same key after new identity"
svc '{"cmd":"down"}' > /dev/null
python3 -I -c "import json; p=json.load(open('/etc/hidravpn/circuit.json')); p['exits']=[x for x in p['exits'] if x['node_name']!='exit-b']; p['known']=[k for k in p.get('known',[]) if k['node_name']!='exit-b']; json.dump(p,open('/etc/hidravpn/circuit.json','w'))"
R=$(svc '{"cmd":"connect","mode":"privado"}')
echo "$R" | grep -q '"ok":false' && echo "$R" | grep -qi "operator" && ! $C ip link show hvpn0 >/dev/null 2>&1 && pass "privado with only one operator's nodes is refused, says why, and changes nothing" || fail "same-operator privado: $(echo "$R" | cut -c1-300)"
R=$(svc '{"cmd":"connect","mode":"privado","allow_same_operator":true}')
wait_connected && svc '{"cmd":"status"}' | grep -q '"same_operator":true' && pass "with the person's explicit yes it connects, and status says one operator runs both" || fail "consented same-operator privado: $(echo "$R" | cut -c1-300)"
svc '{"cmd":"down"}' > /dev/null
"$BIN/hidravpn" nodes import "$WORK/nodes.json" --pubkey "$LISTPUB" > /dev/null 2>&1

# ── D. nothing leaves outside the tunnel: rotation, reconnect, a dead exit ──
echo "── D. rotation, reconnect, a dead exit"
R=$(svc '{"cmd":"connect","mode":"privado"}'); wait_connected && pass "privado again" || fail "privado for D: $(echo "$R" | cut -c1-300)"
sleep 1
cap "$P" i-c "$WORK/isp-d.pcap"; sleep 1
# Knock on the client's own network, look up names and try IPv6 throughout.
$C bash -c 'end=$((SECONDS+40)); while [ $SECONDS -lt $end ]; do curl -s --connect-timeout 0.2 --max-time 0.4 -o /dev/null http://10.200.0.1:8081/; curl -6 -s --connect-timeout 0.2 --max-time 0.4 -o /dev/null "http://[fd00:200::1]:8081/"; getent hosts "knock-'"$CANARY"'.test" >/dev/null; done' >/dev/null 2>&1 & KNOCK=$!
sleep 2
svc '{"cmd":"new_identity"}' > /dev/null; wait_connected || fail "no session after a new identity"
svc '{"cmd":"connect","mode":"privado"}' > /dev/null; wait_connected || fail "no session after a reconnect"
kill -9 "$NODE_X" 2>/dev/null; sleep 6
svc '{"cmd":"status"}' | grep -q '"killswitch":true' && pass "with the exit dead, the kill switch is still armed" || fail "kill switch lost when the exit died"
# Back with a session window longer than the outage, as in real life (ten
# minutes): the client's lease must still be there.
start_exit HIDRAVPN_SESSION_IDLE_SECS=60; sleep 2
for i in $(seq 1 60); do [ "$($C curl -s --max-time 2 http://10.201.0.2/ 2>/dev/null)" = 10.201.0.1 ] && break; sleep 0.5; done
[ "$($C curl -s --max-time 3 http://10.201.0.2/ 2>/dev/null)" = 10.201.0.1 ] && pass "when the exit comes back, the session resumes through it" || fail "no traffic after the exit came back: exit peers $(peers hvx0 "$X" | tr '\n' ';') status $(svc '{"cmd":"status"}' | cut -c1-600)"
wait $KNOCK 2>/dev/null
sleep 1; kill "${CAPS[-1]}" 2>/dev/null; sleep 0.5
N=$(count "$WORK/isp-d.pcap" "ip and src host $CLIENT and not (udp and dst host $ENTRY and dst port 51820) and not (tcp and host $ENTRY and port 51821) and not (icmp[icmptype] == icmp-unreach and dst host $ENTRY)")
[ "$N" = 0 ] && pass "0 IPv4 packets left the client outside the tunnel through a new identity, a reconnect and a dead exit" || fail "$N packet(s) left the client outside the tunnel"
N=$(count "$WORK/isp-d.pcap" "udp port 53 or tcp port 53")
[ "$N" = 0 ] && pass "0 DNS packets on the client's own link" || fail "$N DNS packet(s) on the client's own link"
if [ $V6 = 1 ]; then
  N=$(count "$WORK/isp-d.pcap" "ip6 and src host fd00:200::2")
  [ "$N" = 0 ] && pass "0 IPv6 packets from the client" || fail "$N IPv6 packet(s) left the client"
else skip "IPv6 packets during rotation (no IPv6 in this kernel)"; fi
read -r KP4 _ _ <<< "$(current_exit_key)"; SEEN_KEYS+=("$KP4")
INNER=$($C ip -4 -o addr show 2>/dev/null | grep -oE 'hvpn[01] +inet [0-9.]+' | awk '{print $3}' | tr '\n' ' ')
svc '{"cmd":"down"}' > /dev/null

# ── E. the key the exit was shown does not outlive the session ──────────────
echo "── E. what the exit keeps"
sleep 1
# A failure path for the logs: an admission request that is not one, and a
# connection to an exit that is gone.
$E curl -s --max-time 3 -X POST --data "{\"public_key\":\"$CANARY\"}" http://$EXIT:51821/admit > /dev/null 2>&1
for i in $(seq 1 150); do
  python3 -I -c "import json,sys; ls=json.load(open('$WORK/run-x/peers.json'))['leases']; sys.exit(0 if all(l['source'] != 'session' for l in ls) else 1)" 2>/dev/null && break; sleep 1
done
python3 -I - "$WORK/run-x/peers.json" "${SEEN_KEYS[@]}" > "$WORK/kept.txt" <<'PY'
import json, sys
leases = json.load(open(sys.argv[1]))["leases"]
privado = {sys.argv[2]} | set(sys.argv[5:])  # KP1, not KD or KD2, then KP2 KP3 KP4
print(sum(1 for l in leases if l["public_key"] in privado))
PY
[ "$(cat "$WORK/kept.txt")" = 0 ] && pass "the exit no longer holds any key a two-hop session showed it" || fail "the exit still holds $(cat "$WORK/kept.txt") two-hop session key(s): $(tr -d '\n ' < "$WORK/run-x/peers.json" | cut -c1-200)"

# ── G. the same, held by the command line without the service ───────────────
echo "── G. two hops held directly, without the service"
cp "$WORK/known-only.json" "$WORK/direct-pocket.json"
cap "$P" i-c "$WORK/isp-g.pcap"; sleep 1
$C "$BIN/hidravpn" --direct --key /etc/hidravpn/client.key up --privado --pocket "$WORK/direct-pocket.json" > "$WORK/direct.log" 2>&1 & UP=$!
for i in $(seq 1 100); do grep -q "^connected" "$WORK/direct.log" && break; sleep 0.2; done
DIRECT_SEEN=$($C curl -s --max-time 8 http://10.201.0.2/ 2>/dev/null)
read -r KG EPG _ <<< "$(current_exit_key)"; SEEN_KEYS+=("$KG")
kill -TERM $UP 2>/dev/null; wait $UP 2>/dev/null
sleep 1; kill "${CAPS[-1]}" 2>/dev/null; sleep 0.5
grep -q "^connected" "$WORK/direct.log" && [ "$DIRECT_SEEN" = 10.201.0.1 ] && grep -q "asking exit-b for a key for this connection, through entry-a" "$WORK/direct.log" && pass "the command line alone asks the exit through the entry and connects" || { tail -5 "$WORK/direct.log"; fail "direct privado"; }
[ "$EPG" = $ENTRY ] && [ "$KG" != - ] && pass "the exit sees that session from the entry, under a key it has not seen before" || fail "direct privado: exit sees '$KG' from '$EPG'"
N=$(count "$WORK/isp-g.pcap" "ip and src host $CLIENT and (dst host $EXIT or dst host $EXIT2)")
[ "$N" = 0 ] && pass "the command line sent 0 packets to an exit" || fail "the command line sent $N packet(s) straight to an exit"
$C ip link show hvpn0 >/dev/null 2>&1 || $C nft list table inet hidravpn_ks >/dev/null 2>&1 && fail "SIGTERM left a tunnel or the kill switch behind" || pass "SIGTERM put the network back"

# ── H. what a session admission costs, and nodes not yet updated ───────────
echo "── H. proof of work instead of counting addresses; nodes not yet updated"
post() { $C curl -s -o "$WORK/post.out" -w '%{http_code}' --max-time 5 -X POST -H 'Content-Type: application/json' --data "$1" "http://$ENTRY:51821/admit" 2>/dev/null; }
K=$("$BIN/hidravpn-sign" keygen --out "$WORK/kh" 2>/dev/null)
[ "$(post "{\"public_key\":\"$K\",\"session\":true}")" = 428 ] && grep -q '"work_bits":20' "$WORK/post.out" && pass "a session admission with no proof of work is refused (428) with the work the node wants" || fail "no work: $(cat "$WORK/post.out")"
[ "$(post "{\"public_key\":\"$K\",\"session\":true,\"work\":{\"minute\":1,\"nonce\":1}}")" = 428 ] && pass "a proof that is not one is refused (428)" || fail "bad work: $(cat "$WORK/post.out")"
# One honest proof, sent again and again: the node answers with the lease it
# already gave that key, and the replays take no room from anyone else.
WORKED=$(python3 -I -c '
import base64, hashlib, json, sys, time
node = base64.b64decode(json.load(open(sys.argv[1]))["node_public_key"])
client = base64.b64decode(sys.argv[2])
minute = int(time.time()) // 60
nonce = 0
while True:
    d = hashlib.sha256(b"HidraVPN admission work v1" + node + client + minute.to_bytes(8, "big") + nonce.to_bytes(8, "big")).digest()
    if int.from_bytes(d[:4], "big") >> 12 == 0:
        break
    nonce += 1
print(json.dumps({"public_key": sys.argv[2], "session": True, "work": {"minute": minute, "nonce": nonce}}))
' "$WORK/rec-e.json" "$K")
CODES=$(for i in $(seq 1 650); do post "$WORKED"; echo; done | sort | uniq -c | tr -s ' ' | tr '\n' ';')
[ "$CODES" = " 650 200;" ] && pass "one proof of work sent 650 times (more than the node-wide ceiling of 600): every replay gets the same lease" || fail "replays answered: $CODES $(cat "$WORK/post.out")"
OKS=0
for i in 1 2 3 4 5 6; do
  R=$(svc '{"cmd":"connect","mode":"privado"}'); echo "$R" | grep -q '"ok":true' && OKS=$((OKS+1))
  svc '{"cmd":"down"}' > /dev/null
done
[ "$OKS" = 6 ] && pass "six two-hop connections in a row from one address after the replays: none throttled (the old limit was three per ten minutes)" || fail "only $OKS of 6 connections went through: $(echo "$R" | cut -c1-200)"
# A list in which the entry's record does not say `sessions`: as published
# for a node not yet updated.
python3 -I -c "import json; r=json.load(open('$WORK/rec-e.json')); r.pop('features', None); json.dump(r, open('$WORK/rec-e-old.json','w'))"
HIDRAVPN_SIGN="$BIN/hidravpn-sign" bash "$HERE/make-node-list.sh" --key "$WORK/list.key" --out "$WORK/nodes-old.json" --sequence 2 "$WORK/rec-e-old.json" "$WORK/rec-x.json" > /dev/null 2>&1
"$BIN/hidravpn" nodes import --pocket "$WORK/old-pocket.json" "$WORK/nodes-old.json" --pubkey "$LISTPUB" > /dev/null 2>&1
cap "$P" i-c "$WORK/isp-h.pcap"; sleep 1
OUT=$($C "$BIN/hidravpn" --direct --key /etc/hidravpn/client.key up --privado --pocket "$WORK/old-pocket.json" 2>&1)
sleep 1; kill "${CAPS[-1]}" 2>/dev/null; sleep 0.5
echo "$OUT" | grep -q "older than per-connection keys" && pass "an entry whose software is older than per-connection keys is not used, and the person is told why" || fail "old entry: $(echo "$OUT" | tail -2)"
N=$(count "$WORK/isp-h.pcap" "ip and src host $CLIENT and tcp")
[ "$N" = 0 ] && pass "nothing was asked of it: 0 TCP packets left the client" || fail "$N TCP packet(s) left the client for an old node"
# An exit that takes admission requests on another port than the one entries
# relay: never tried behind an entry, and nothing is spent on the entry first.
python3 -I -c "import json; r=json.load(open('$WORK/rec-x2.json')); r['admission_port']=51900; json.dump(r, open('$WORK/rec-x2-port.json','w'))"
HIDRAVPN_SIGN="$BIN/hidravpn-sign" bash "$HERE/make-node-list.sh" --key "$WORK/list.key" --out "$WORK/nodes-port.json" --sequence 3 "$WORK/rec-e.json" "$WORK/rec-x2-port.json" > /dev/null 2>&1
"$BIN/hidravpn" nodes import --pocket "$WORK/port-pocket.json" "$WORK/nodes-port.json" --pubkey "$LISTPUB" > /dev/null 2>&1
cap "$P" i-c "$WORK/isp-port.pcap"; sleep 1
OUT=$($C "$BIN/hidravpn" --direct --key /etc/hidravpn/client.key up --privado --allow-same-operator --pocket "$WORK/port-pocket.json" 2>&1)
sleep 1; kill "${CAPS[-1]}" 2>/dev/null; sleep 0.5
echo "$OUT" | grep -q "a port other than 51821" && pass "an exit on another admission port is not used behind an entry, and the person is told why" || fail "exit on port 51900: $(echo "$OUT" | tail -2)"
N=$(count "$WORK/isp-port.pcap" "ip and src host $CLIENT and tcp")
[ "$N" = 0 ] && pass "nothing was asked of the entry for it: 0 TCP packets left the client" || fail "$N TCP packet(s) left the client for an exit no entry relays to"

# ── I. switching off a connection still being made ─────────────────────────
echo "── I. switching off a connection still being made"
svc '{"cmd":"down"}' > /dev/null
ms() { echo $(( ($(date +%s%N) - $1) / 1000000 )); }
# The exit stops answering: its kernel still takes the connection, and the
# admission request through the entry waits for a reply that never comes.
kill -STOP "$NODE_X"
svc '{"cmd":"connect","mode":"privado"}' > "$WORK/hung.out" 2>&1 & HUNG=$!
sleep 2.5
T=$(date +%s%N); ST=$(svc '{"cmd":"status"}'); TS=$(ms "$T")
[ "$TS" -lt 1000 ] && echo "$ST" | grep -q '"connected":false' && echo "$ST" | grep -q '"hops":2' && pass "while the exit does not answer, status answers at once: two hops being built, not connected (${TS} ms)" || fail "status while connecting took ${TS} ms: $(echo "$ST" | cut -c1-200)"
T=$(date +%s%N); D=$(svc '{"cmd":"down"}'); TD=$(ms "$T")
[ "$TD" -lt 3000 ] && echo "$D" | grep -q '"ok":true' && pass "Disconnect stops it without waiting on the exit (${TD} ms)" || fail "down while connecting took ${TD} ms: $(echo "$D" | cut -c1-200)"
wait "$HUNG"
grep -q "switched off while the connection was being made" "$WORK/hung.out" && pass "the connection that was stopped says so" || fail "the stopped connect answered: $(cut -c1-200 "$WORK/hung.out")"
kill -CONT "$NODE_X"
{ $C ip link show hvpn0 || $C ip link show hvpn1 || $C nft list table inet hidravpn_ks; } >/dev/null 2>&1 && fail "a tunnel or the kill switch was left behind" || pass "nothing left behind: no tunnel, no kill switch"
[ "$($C curl -s --max-time 3 http://$ISP:8081/ 2>/dev/null)" = leak ] && pass "the machine's own network is back" || fail "the network was not put back"
svc '{"cmd":"connect","mode":"privado"}' > /dev/null; wait_connected && pass "with the exit answering again, the next connect works" || fail "no connection after the exit came back"
svc '{"cmd":"down"}' > /dev/null

# ── F. the logs, at DEBUG, failures included ────────────────────────────────
echo "── F. the logs"
kill -9 $(pgrep -f "x2.toml run") 2>/dev/null
svc '{"cmd":"connect","mode":"privado","allow_same_operator":true}' > /dev/null
svc '{"cmd":"down"}' > /dev/null
kill -INT $SVC; for i in $(seq 1 25); do kill -0 $SVC 2>/dev/null || break; sleep 0.2; done; SVC=""
for p in "${PIDS[@]}"; do kill -INT "$p" 2>/dev/null; done; sleep 1
LOGS=("$WORK/e.log" "$WORK/x.log" "$WORK/x2.log" "$WORK/svc.log")
[ "$(cat "${LOGS[@]}" | wc -l)" -gt 20 ] && pass "every node and the service ran with RUST_LOG=debug, failures included ($(cat "${LOGS[@]}" | wc -l) log lines)" || fail "the logs are nearly empty"
NEEDLES=("$CANARY" "$CLIENT" "fd00:200::2" "$MASTER")
for a in $INNER; do NEEDLES+=("$a"); done
for k in "${SEEN_KEYS[@]}"; do [ -n "$k" ] && [ "$k" != - ] && NEEDLES+=("$k" "$(python3 -I -c "import base64,sys; print(base64.b64decode(sys.argv[1]).hex())" "$k")"); done
LEAKED=""
for n in "${NEEDLES[@]}"; do grep -qF -- "$n" "${LOGS[@]}" && LEAKED="$LEAKED $n"; done
[ -z "$LEAKED" ] && pass "no log names the client's address, its tunnel addresses, a key it presented, the canary name or payload (${#NEEDLES[@]} needles)" || fail "the logs name:$LEAKED"
grep -qF "$ENTRY" "$WORK/x.log" "$WORK/x2.log" && fail "an exit's log names the address its clients came from" || pass "no exit's log names the address a client came from"

echo; echo "$ok passed, $bad failed"; [ $bad -eq 0 ]
