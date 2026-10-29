#!/usr/bin/env bash
# Passes that top themselves up (phase 6): the service fetches more when a
# pass node's count runs low, only while connected, so the request goes
# through the tunnel. Four namespaces:
#
#   hv-client ──veth── hv-node ──veth── hv-inet
#   10.200.0.2        10.200.0.1        10.201.0.2  (the "internet"; the
#                     10.201.0.1        issuer on TCP 8730, a whoami on 80)
#                     node-p: exit, admission "pass"
#   hv-client ──veth── hv-inet: 10.209.0.2 / 10.209.0.1, a side door used
#   once, to get the first passes, then shut: from then on the issuer is
#   reachable through the tunnel only.
#   hv-e, hv-x ──veth── hv-inet: node-e (entry, open) and node-x (exit,
#   pass), 10.206.0.2 and 10.205.0.2, for two hops.
#
# It proves: `passes auto` keeps its settings root-only and says them; with
# auto on, a connection that leaves a node low gets it topped up to the
# count, and the issuer could only have been reached through the tunnel;
# with auto off nothing is fetched; while disconnected nothing is fetched
# even when low; with two hops up nothing is fetched either, by itself or by
# hand, since it would leave through the exit, whether the service or the
# command line holds them; and no log names the client's address or the
# token.
#
# Run as root:  hidravpn/scripts/test-refill-netns.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/test/guard.sh"
BIN="$HERE/../target/release"
WORK=""
C="ip netns exec hv-client"; N="ip netns exec hv-node"; I="ip netns exec hv-inet"; E="ip netns exec hv-e"; X="ip netns exec hv-x"
PIDS=()
export RUST_BACKTRACE=0
export HIDRAVPN_PLAIN_HTTP_ISSUER=1
ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok + 1)); }
fail() { echo "FAIL  $1"; bad=$((bad + 1)); }
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  ip netns pids hv-client 2>/dev/null | xargs -r kill 2>/dev/null
  sleep 0.5
  for ns in hv-client hv-node hv-inet hv-e hv-x; do ip netns del "$ns" 2>/dev/null; done
  rm -rf /etc/netns/hv-client /run/hidravpn/control.sock /run/hidravpn/control.token /run/hidravpn/netcfg.json \
         /etc/hidravpn/client.key /etc/hidravpn/circuit.json /etc/hidravpn/passes.json /etc/hidravpn/pass.token \
         /etc/hidravpn/refill.json /var/run/wireguard/hvp0.sock /var/run/wireguard/hve0.sock /var/run/wireguard/hvx0.sock
  [ -n "${WORK:-}" ] && rm -rf "$WORK"
}
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
trap cleanup EXIT
cleanup
WORK="$(mktemp -d /tmp/hidravpn-refill.XXXXXX)"
for b in hidravpn hidravpn-node hidravpn-service hidravpn-sign hidravpn-issuer; do [ -x "$BIN/$b" ] || { echo "build first: cargo build --release --manifest-path hidravpn/Cargo.toml"; exit 1; }; done

# ── Network ─────────────────────────────────────────────────────────────────
ip netns add hv-client; ip netns add hv-node; ip netns add hv-inet
ip link add c-n type veth peer name n-c; ip link set c-n netns hv-client; ip link set n-c netns hv-node
ip link add n-i type veth peer name i-n; ip link set n-i netns hv-node; ip link set i-n netns hv-inet
ip link add c-i type veth peer name i-c; ip link set c-i netns hv-client; ip link set i-c netns hv-inet
$C ip addr add 10.200.0.2/24 dev c-n; $C ip link set c-n up; $C ip link set lo up; $C ip route add default via 10.200.0.1
$N ip addr add 10.200.0.1/24 dev n-c; $N ip link set n-c up; $N ip link set lo up
$N ip addr add 10.201.0.1/24 dev n-i; $N ip link set n-i up; $N ip route add default via 10.201.0.2
$I ip addr add 10.201.0.2/24 dev i-n; $I ip link set i-n up; $I ip link set lo up
$C ip addr add 10.209.0.2/24 dev c-i; $C ip link set c-i up; $C ip route add 10.201.0.2/32 via 10.209.0.1
$I ip addr add 10.209.0.1/24 dev i-c; $I ip link set i-c up
mkdir -p /etc/netns/hv-client; echo "nameserver 10.200.0.1" > /etc/netns/hv-client/resolv.conf
$I python3 -I "$HERE/test/whoami-http.py" > "$WORK/http.log" 2>&1 & PIDS+=($!)
$I python3 -I "$HERE/test/dns-stub.py" 10.201.0.2 > "$WORK/dns.log" 2>&1 & PIDS+=($!)
sleep 1

# ── The issuer, on the internet side ────────────────────────────────────────
ISS="$BIN/hidravpn-issuer --accounts $WORK/accounts.json"
$ISS keygen --out "$WORK/issuer-key.json" --days 30 > "$WORK/pass-key.json" 2>/dev/null || { fail "issuer keygen"; exit 1; }
TOKEN=$($ISS account add --name someone --quota 40 2>/dev/null)
$I $ISS run --key "$WORK/issuer-key.json" --listen 10.201.0.2:8730 --plain-http-public > "$WORK/issuer.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 50); do grep -q "pass issuer on TCP 8730" "$WORK/issuer.log" && break; sleep 0.2; done
grep -q "pass issuer on TCP 8730" "$WORK/issuer.log" && pass "the issuer is up, on the internet side" || { cat "$WORK/issuer.log"; fail "issuer"; exit 1; }

# ── A pass node ─────────────────────────────────────────────────────────────
$N "$BIN/hidravpn-node" --config "$WORK/p.toml" init --endpoint 10.200.0.1:51820 --name node-p --role exit --operator maintainers --pass-admission --dns udp://10.201.0.2 --out-interface n-i > "$WORK/init.log" 2>&1 || { cat "$WORK/init.log"; fail "node init"; exit 1; }
sed -i 's/^interface = "hvpn0"/interface = "hvp0"/' "$WORK/p.toml"
$N "$BIN/hidravpn-node" --config "$WORK/p.toml" pass-key add "$WORK/pass-key.json" > /dev/null 2>&1
mkdir -p "$WORK/run"
$N env HIDRAVPN_RUN_DIR="$WORK/run" "$BIN/hidravpn-node" --config "$WORK/p.toml" run > "$WORK/node.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 100); do grep -q "DNS forwarder ready" "$WORK/node.log" && grep -q "admission service on" "$WORK/node.log" && break; sleep 0.2; done
grep -q "admission service on TCP 51821 (with a pass" "$WORK/node.log" && pass "node-p is up, admitting with passes" || { tail -5 "$WORK/node.log"; fail "node"; exit 1; }
$N "$BIN/hidravpn-node" --config "$WORK/p.toml" record > "$WORK/rec.json" 2>/dev/null
LISTPUB=$("$BIN/hidravpn-sign" keygen --out "$WORK/list.key" 2>/dev/null)
HIDRAVPN_SIGN="$BIN/hidravpn-sign" bash "$HERE/make-node-list.sh" --key "$WORK/list.key" --out "$WORK/nodes.json" --sequence 1 \
  --issuer-url http://10.201.0.2:8730 --pass-key "$WORK/pass-key.json" "$WORK/rec.json" > /dev/null 2>&1

# ── The client: the list, the token, two passes through the side door ───────
mkdir -p /etc/hidravpn
$C "$BIN/hidravpn" keygen >/dev/null 2>&1
"$BIN/hidravpn" nodes import "$WORK/nodes.json" --pubkey "$LISTPUB" > /dev/null 2>&1
echo "$TOKEN" | "$BIN/hidravpn" passes token - > /dev/null 2>&1
OUT=$($C "$BIN/hidravpn" passes get --count 2 2>&1); echo "$OUT" | grep -q "2 pass(es)" && pass "two passes, through the side door" || { fail "passes get: $OUT"; exit 1; }
$C ip link set c-i down
$C curl -s --max-time 3 http://10.201.0.2:8730/keys >/dev/null 2>&1 && fail "the issuer is still reachable without the tunnel" || pass "the side door is shut: the issuer is not reachable without the tunnel"

OUT=$("$BIN/hidravpn" passes list 2>&1); echo "$OUT" | grep -q "automatic passes on: a pass node with fewer than 3 left gets topped up to 10" && pass "automatic passes are on by default (3, 10), and passes list says so" || fail "default: $OUT"
OUT=$("$BIN/hidravpn" passes auto on --low 3 --count 6 2>&1); echo "$OUT" | grep -q "fewer than 3 left gets topped up to 6" && [ "$(stat -c %a /etc/hidravpn/refill.json)" = 600 ] && pass "passes auto on --low 3 --count 6: kept root-only, and said back" || fail "auto on: $OUT"
OUT=$("$BIN/hidravpn" passes auto --low 7 --count 6 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "below --count" && pass "a low that is not below the count is refused" || fail "bad auto: $OUT"

# ── The service, checking every 2 seconds ───────────────────────────────────
start_service() {
  $C env RUST_LOG=hidravpn_service=info HIDRAVPN_REFILL_SECS=2 "$BIN/hidravpn-service" run >> "$WORK/svc.log" 2>&1 & SVC=$!; PIDS+=($SVC)
  for i in $(seq 1 50); do [ -S /run/hidravpn/control.sock ] && break; sleep 0.2; done
}
start_service
svc() { python3 -I - "$1" <<'PY'
import socket, sys, json
tok = open('/run/hidravpn/control.token').read().strip()
req = json.loads(sys.argv[1]); req['token'] = tok
s = socket.socket(socket.AF_UNIX); s.settimeout(60); s.connect('/run/hidravpn/control.sock'); s.sendall((json.dumps(req) + '\n').encode())
buf = b''
while True:
    c = s.recv(65536)
    if not c: break
    buf += c
    if b'\n' in buf: break
print(buf.decode().strip())
PY
}
count() { svc '{"cmd":"nodes"}' | grep -o '"passes":[0-9]*' | head -1 | cut -d: -f2; }
wait_count() { for i in $(seq 1 "$2"); do [ "$(count)" = "$1" ] && return 0; sleep 1; done; return 1; }
connected() { for _ in $(seq 1 25); do svc '{"cmd":"status"}' | grep -q '"connected":true' && return 0; sleep 0.4; done; return 1; }

R=$(svc '{"cmd":"connect","mode":"rapido"}'); echo "$R" | grep -q '"ok":true' && connected && pass "connected: a pass redeemed on node-p for this connection, no join first (1 left)" || { echo "$R"; fail "connect"; }
wait_count 6 20 && pass "the service topped node-p up to 6 by itself while connected" || fail "no top-up: $(count) pass(es)"
grep -q "issued 5 pass(es)" "$WORK/issuer.log" && pass "the issuer counted five, asked through the tunnel (the only way to reach it now)" || fail "issuer: $(cat "$WORK/issuer.log")"
grep -q "passes topped up by themselves" "$WORK/svc.log" && pass "the service logged that it topped up" || fail "svc log"
EXIT_IP=$($C curl -s --max-time 5 http://10.201.0.2/ 2>/dev/null); [ "$EXIT_IP" = "10.201.0.1" ] && pass "the internet sees the node's address" || fail "exit IP '$EXIT_IP'"

# ── Off: nothing is fetched ─────────────────────────────────────────────────
"$BIN/hidravpn" passes auto off > /dev/null 2>&1
svc '{"cmd":"down"}' >/dev/null; R=$(svc '{"cmd":"connect","mode":"rapido"}'); connected || fail "reconnect: $R"
BEFORE=$(count); sleep 6
[ "$(count)" = "$BEFORE" ] && [ "$BEFORE" -lt 6 ] && pass "with automatic passes off, the wallet stays as it is ($BEFORE)" || fail "off: $BEFORE -> $(count)"

# ── Disconnected: nothing is fetched, even when low ─────────────────────────
svc '{"cmd":"down"}' >/dev/null
"$BIN/hidravpn" passes auto on --low 8 --count 9 > /dev/null 2>&1
# The side door open again: disconnected, the issuer is reachable from this
# machine's own address, and must still not be asked.
$C ip link set c-i up; $C ip route add 10.201.0.2/32 via 10.209.0.1 2>/dev/null
$C curl -s --max-time 3 -o /dev/null http://10.201.0.2:8730/keys && pass "disconnected, the issuer can be reached directly (the side door is open for this step)" || fail "the side door did not open"
ISSUED_BEFORE=$(grep -c "issued" "$WORK/issuer.log")
BEFORE=$(count); sleep 6
[ "$(count)" = "$BEFORE" ] && [ "$(grep -c "issued" "$WORK/issuer.log")" = "$ISSUED_BEFORE" ] && pass "disconnected, nothing is fetched though the node is low ($BEFORE < 8) and the issuer is reachable: it would go out of this machine's own address" || fail "disconnected: $BEFORE -> $(count)"
$C ip link set c-i down
R=$(svc '{"cmd":"connect","mode":"rapido"}'); connected || fail "connect again: $R"
wait_count 9 20 && pass "connected again, topped up to 9" || fail "second top-up: $(count)"

# ── Two hops: never through the exit ───────────────────────────────────────
# node-e, an entry that admits openly, and node-x, an exit that admits with
# a pass, hang off the "internet". With two hops up, a request with the
# account token would leave through node-x, and the issuer (run by the
# exits' operator) could tie the session to the account: no top-up, and
# passes asked for by hand are refused, by the service and by the command
# line, until they are down.
svc '{"cmd":"down"}' >/dev/null
$I ip route add 10.200.0.0/24 via 10.201.0.1; $I sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
ip netns add hv-e; ip netns add hv-x
ip link add e-i type veth peer name i-e; ip link set e-i netns hv-e; ip link set i-e netns hv-inet
ip link add x-i type veth peer name i-x; ip link set x-i netns hv-x; ip link set i-x netns hv-inet
$E ip addr add 10.206.0.2/24 dev e-i; $E ip link set e-i up; $E ip link set lo up; $E ip route add default via 10.206.0.1
$I ip addr add 10.206.0.1/24 dev i-e; $I ip link set i-e up
$X ip addr add 10.205.0.2/24 dev x-i; $X ip link set x-i up; $X ip link set lo up; $X ip route add default via 10.205.0.1
$I ip addr add 10.205.0.1/24 dev i-x; $I ip link set i-x up
$E "$BIN/hidravpn-node" --config "$WORK/e.toml" init --forward-private-destinations --endpoint 10.206.0.2:51820 --tunnel 10.79.0.0/16 --name node-e --role entry --operator others --open-admission --dns udp://10.201.0.2 --out-interface e-i > "$WORK/init-e.log" 2>&1 || { cat "$WORK/init-e.log"; fail "node-e init"; }
sed -i 's/^interface = "hvpn0"/interface = "hve0"/' "$WORK/e.toml"
$X "$BIN/hidravpn-node" --config "$WORK/x.toml" init --forward-private-destinations --endpoint 10.205.0.2:51820 --tunnel 10.78.0.0/16 --name node-x --role exit --operator maintainers --pass-admission --dns udp://10.201.0.2 --out-interface x-i > "$WORK/init-x.log" 2>&1 || { cat "$WORK/init-x.log"; fail "node-x init"; }
sed -i 's/^interface = "hvpn0"/interface = "hvx0"/' "$WORK/x.toml"
$X "$BIN/hidravpn-node" --config "$WORK/x.toml" pass-key add "$WORK/pass-key.json" > /dev/null 2>&1
mkdir -p "$WORK/run-e" "$WORK/run-x"
$E env HIDRAVPN_RUN_DIR="$WORK/run-e" "$BIN/hidravpn-node" --config "$WORK/e.toml" run > "$WORK/node-e.log" 2>&1 & PIDS+=($!)
$X env HIDRAVPN_RUN_DIR="$WORK/run-x" "$BIN/hidravpn-node" --config "$WORK/x.toml" run > "$WORK/node-x.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 100); do grep -q "admission service on" "$WORK/node-e.log" && grep -q "admission service on" "$WORK/node-x.log" && break; sleep 0.2; done
$E "$BIN/hidravpn-node" --config "$WORK/e.toml" record > "$WORK/rec-e.json" 2>/dev/null
$X "$BIN/hidravpn-node" --config "$WORK/x.toml" record > "$WORK/rec-x.json" 2>/dev/null
HIDRAVPN_SIGN="$BIN/hidravpn-sign" bash "$HERE/make-node-list.sh" --key "$WORK/list.key" --out "$WORK/nodes2.json" --sequence 2 \
  --issuer-url http://10.201.0.2:8730 --pass-key "$WORK/pass-key.json" "$WORK/rec.json" "$WORK/rec-e.json" "$WORK/rec-x.json" > /dev/null 2>&1
OUT=$("$BIN/hidravpn" nodes import "$WORK/nodes2.json" --pubkey "$LISTPUB" 2>&1); echo "$OUT" | grep -q "added 2 node(s)" || fail "import with node-e and node-x: $OUT"
# node-x's first passes through the side door, disconnected.
$C ip link set c-i up; $C ip route add 10.201.0.2/32 via 10.209.0.1 2>/dev/null
OUT=$($C "$BIN/hidravpn" passes get --node node-x --count 2 2>&1); echo "$OUT" | grep -q "2 pass(es)" || fail "passes for node-x: $OUT"
$C ip link set c-i down
count_of() { svc '{"cmd":"nodes"}' | python3 -I -c "import json,sys; print([n.get('passes') for n in json.load(sys.stdin)['nodes'] if n['node_name']==sys.argv[1]][0])" "$1"; }
# Low enough that a top-up would fire at once for node-x once it has spent one.
"$BIN/hidravpn" passes auto on --low 9 --count 10 > /dev/null 2>&1
# node-x is the one exit meanwhile: node-p sits on the client's own link.
cp /etc/hidravpn/circuit.json "$WORK/pocket-with-node-p.json"
"$BIN/hidravpn" nodes remove node-p > /dev/null 2>&1
R=$(svc '{"cmd":"connect","mode":"privado"}')
for _ in $(seq 1 25); do svc '{"cmd":"status"}' | grep -q '"status":{"connected":true' && break; sleep 0.4; done
ST=$(svc '{"cmd":"status"}')
echo "$ST" | grep -q '"status":{"connected":true' && echo "$ST" | grep -q '"entry_name":"node-e"' && echo "$ST" | grep -q '"node_name":"node-x"' && pass "two hops: node-e, then node-x as the exit (a pass redeemed through node-e)" || fail "privado: $R $ST"
echo "$ST" | grep -q '"account_one_hop_only":true' && pass "the status says the service keeps the account token off two hops, which the VPN page tells an older service by" || fail "status lacks account_one_hop_only: $ST"
EXIT_IP=""
for _ in $(seq 1 10); do EXIT_IP=$($C curl -s --max-time 3 http://10.201.0.2/ 2>/dev/null); [ "$EXIT_IP" = "10.205.0.2" ] && break; sleep 0.5; done
[ "$EXIT_IP" = "10.205.0.2" ] && $C curl -s --max-time 3 -o /dev/null http://10.201.0.2:8730/keys && pass "through the two hops the issuer can be reached, through the exit" || fail "two hops do not reach the issuer: '$EXIT_IP'"
ISSUED_BEFORE=$(grep -c "issued" "$WORK/issuer.log")
BEFORE=$(count_of node-x); sleep 6
[ "$(count_of node-x)" = "$BEFORE" ] && [ "$BEFORE" -lt 9 ] && [ "$(grep -c "issued" "$WORK/issuer.log")" = "$ISSUED_BEFORE" ] && pass "with two hops up, nothing is topped up though node-x is low ($BEFORE < 9): it would go out through the exit" || fail "privado top-up: node-x $BEFORE -> $(count_of node-x), issued $ISSUED_BEFORE -> $(grep -c "issued" "$WORK/issuer.log")"
R=$(svc '{"cmd":"get_passes","count":1}')
echo "$R" | grep -q '"ok":false' && echo "$R" | grep -q "not while two hops (privado) are up" && [ "$(grep -c "issued" "$WORK/issuer.log")" = "$ISSUED_BEFORE" ] && pass "passes asked of the service by hand are refused while two hops are up, and say why" || fail "get_passes in privado: $R"
OUT=$($C "$BIN/hidravpn" passes get --count 1 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "not while two hops (privado) are up" && [ "$(grep -c "issued" "$WORK/issuer.log")" = "$ISSUED_BEFORE" ] && pass "and so are they from the command line" || fail "passes get in privado: $OUT"
OUT=$($C "$BIN/hidravpn" --direct passes get --count 1 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "not while two hops (privado) are up" && [ "$(grep -c "issued" "$WORK/issuer.log")" = "$ISSUED_BEFORE" ] && pass "and with --direct too: the service is still asked whether two hops are up" || fail "--direct passes get in privado: $OUT"
OUT=$("$BIN/hidravpn" passes list 2>&1); echo "$OUT" | grep -q "never in privado" && pass "passes list says automatic passes never go through two hops" || fail "list: $OUT"
# Joining node-x now would redeem a pass through node-x itself, the exit,
# and the key it admitted would later be shown to it from this machine's
# own address in one hop: no join while two hops are up, of a pass node or
# an open one, asked of the service or of the command line.
LEFT=$(count_of node-x)
R=$(svc '{"cmd":"join","name":"node-x"}')
echo "$R" | grep -q '"ok":false' && echo "$R" | grep -q "not while two hops (privado) are up: the node would be asked for admission through the exit" && [ "$(count_of node-x)" = "$LEFT" ] && pass "joining a pass node through the service is refused while two hops are up, and no pass is spent" || fail "join in privado: $R (node-x $LEFT -> $(count_of node-x))"
OUT=$($C "$BIN/hidravpn" nodes join --all 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "not while two hops (privado) are up: the node would be asked for admission" && [ "$(count_of node-x)" = "$LEFT" ] && pass "and from the command line" || fail "nodes join in privado: $OUT"
svc '{"cmd":"down"}' >/dev/null

# ── Two hops held by the command line, with no service ─────────────────────
# `hidravpn up --privado` in another terminal holds the circuit itself: no
# service can tell, but the network plan it wrote says two hops. Passes,
# an order and a claim are all refused, with or without --direct.
kill "$SVC"; wait "$SVC" 2>/dev/null
for i in $(seq 1 25); do [ -S /run/hidravpn/control.sock ] || break; sleep 0.2; done
$C "$BIN/hidravpn" up --privado > "$WORK/fg.log" 2>&1 & FG=$!; PIDS+=($FG)
for i in $(seq 1 50); do grep -q "routes and DNS set" "$WORK/fg.log" && break; sleep 0.2; done
grep -qi "everything now goes through the privado (2 hops)" "$WORK/fg.log" && grep -q '"hops": 2' /run/hidravpn/netcfg.json && pass "two hops held by the command line, no service; its network plan says two hops" || fail "foreground privado: $(cat "$WORK/fg.log")"
EXIT_IP=$($C curl -s --max-time 5 http://10.201.0.2/ 2>/dev/null); [ "$EXIT_IP" = "10.205.0.2" ] || fail "foreground privado exit IP '$EXIT_IP'"
for args in "passes get --count 1" "--direct passes get --count 1" "passes buy 5" "passes claim 5VERv8NMvzbJMEkV8xnrLkEaWRtSz2CosKDYVCJjrRo" "nodes join --all"; do
  OUT=$($C "$BIN/hidravpn" $args 2>&1); RC=$?
  [ $RC -ne 0 ] && echo "$OUT" | grep -q "not while two hops (privado) are up" || fail "$args with two hops held by the command line: $OUT"
done
[ "$(grep -c "issued" "$WORK/issuer.log")" = "$ISSUED_BEFORE" ] && pass "passes get (with or without --direct), passes buy, passes claim and nodes join are refused while it holds them, and nothing reached the issuer" || fail "issued while the command line held two hops"
kill -INT "$FG"; wait "$FG" 2>/dev/null
[ ! -e /run/hidravpn/netcfg.json ] || fail "the foreground circuit left its plan behind"
start_service
# Back to one hop through node-p alone: topped up again.
cp "$WORK/pocket-with-node-p.json" /etc/hidravpn/circuit.json
"$BIN/hidravpn" nodes remove node-x > /dev/null 2>&1
R=$(svc '{"cmd":"connect","mode":"rapido"}'); connected || fail "rapido after privado: $R"
for _ in $(seq 1 20); do [ "$(count_of node-p)" = 10 ] && break; sleep 1; done
[ "$(count_of node-p)" = 10 ] && pass "back in one hop, node-p is topped up to 10" || fail "top-up after privado: $(count_of node-p)"
# In one hop a join goes ahead: node-x, known again from the list, gets a
# pass (its two went on the two-hop connections) and is joined with it,
# redeemed from this machine (through node-p, not behind an entry), and
# written down so, to be shown from here again.
"$BIN/hidravpn" nodes import "$WORK/nodes2.json" --pubkey "$LISTPUB" > /dev/null 2>&1
R=$(svc '{"cmd":"get_passes","name":"node-x","count":1}'); echo "$R" | grep -q '"ok":true' || fail "a pass for node-x in rapido: $R"
R=$(svc '{"cmd":"join","name":"node-x"}')
BEHIND=$(python3 -I -c "import json; print([x.get('pass', {}).get('behind') for x in json.load(open('/etc/hidravpn/circuit.json'))['exits'] if x['node_name']=='node-x'])")
echo "$R" | grep -q '"ok":true' && echo "$R" | grep -q "node-x: admitted with a pass" && [ "$BEHIND" = "[False]" ] && pass "in rapido node-x is joined with a pass, written down as redeemed from here" || fail "join in rapido: $R (behind $BEHIND)"
svc '{"cmd":"down"}' >/dev/null

# ── Nothing in the logs ─────────────────────────────────────────────────────
grep -F -e "$TOKEN" "$WORK"/*.log >/dev/null && fail "a log holds the token" || pass "no log holds the token"
grep -E "10\.200\.0\.2|10\.209\.0\.2" "$WORK/svc.log" "$WORK/issuer.log" "$WORK/node.log" >/dev/null && fail "a log names the client's address" || pass "no log names the client's address"

echo; echo "$ok passed, $bad failed"; [ $bad -eq 0 ]
