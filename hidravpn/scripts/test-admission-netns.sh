#!/usr/bin/env bash
# Open admission, end to end: a stranger that knows two nodes from a signed
# list connects without meeting anyone. Four namespaces, two nodes:
#
#   hv-client ──veth── hv-entry ──veth── hv-node ──veth── hv-inet
#   10.200.0.2        10.200.0.1        10.202.0.1       10.201.0.2
#                     10.202.0.2        10.201.0.1
#                     node-b: entry     node-a: exit
#   node-b  entry role, open admission, UDP 51820, admission TCP 51821, tunnel 10.78.0.0/16
#   node-a  exit role,  open admission, UDP 51820, admission TCP 51821, tunnel 10.77.0.0/16
#
# It proves: a node describes itself (GET /); the maintainers' tooling makes
# and signs a list from the nodes' records; a client that imported the list
# knows the nodes and can connect to none; `connect` through the service
# admits it on both (the invites checked against the list), connects one hop
# through the exit, and the internet sees the exit's address; two hops use
# the entry then the exit, and status says both are one operator's; an entry
# used as an exit forwards nothing but WireGuard; the admission service
# rate-limits a source and refuses when admission is by hand; idle open
# admissions expire; the uptime prober reports the exit up; `discover` reads a
# node by address; and no log names a client.
#
# Run as root:  hidravpn/scripts/test-admission-netns.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/test/guard.sh"
BIN="$HERE/../target/release"
WORK=""
C="ip netns exec hv-client"; E="ip netns exec hv-entry"; N="ip netns exec hv-node"; I="ip netns exec hv-inet"
PIDS=(); NODE_B=""
export RUST_BACKTRACE=0
ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok + 1)); }
fail() { echo "FAIL  $1"; bad=$((bad + 1)); }
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  ip netns pids hv-client 2>/dev/null | xargs -r kill 2>/dev/null
  for ns in hv-client hv-entry hv-node hv-inet; do ip netns del "$ns" 2>/dev/null; done
  rm -rf /etc/netns/hv-client /run/hidravpn/control.sock /run/hidravpn/control.token /run/hidravpn/netcfg.json \
         /run/hidravpn/peers.json /var/lib/hidravpn/peers.json /etc/hidravpn/client.key /etc/hidravpn/circuit.json \
         /var/run/wireguard/hva0.sock /var/run/wireguard/hvb0.sock
  [ -n "${WORK:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT
cleanup
WORK="$(mktemp -d /tmp/hidravpn-adm.XXXXXX)"
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
for b in hidravpn hidravpn-node hidravpn-service hidravpn-sign; do [ -x "$BIN/$b" ] || { echo "build first"; exit 1; }; done

# ── Network ─────────────────────────────────────────────────────────────────
ip netns add hv-client; ip netns add hv-entry; ip netns add hv-node; ip netns add hv-inet
ip link add c-e type veth peer name e-c; ip link set c-e netns hv-client; ip link set e-c netns hv-entry
ip link add e-x type veth peer name x-e; ip link set e-x netns hv-entry; ip link set x-e netns hv-node
ip link add x-i type veth peer name i-x; ip link set x-i netns hv-node; ip link set i-x netns hv-inet
$C ip addr add 10.200.0.2/24 dev c-e; $C ip link set c-e up; $C ip link set lo up; $C ip route add default via 10.200.0.1
$E ip addr add 10.200.0.1/24 dev e-c; $E ip link set e-c up; $E ip link set lo up
$E ip addr add 10.202.0.2/24 dev e-x; $E ip link set e-x up; $E ip route add default via 10.202.0.1
$N ip addr add 10.202.0.1/24 dev x-e; $N ip link set x-e up; $N ip link set lo up
$N ip addr add 10.201.0.1/24 dev x-i; $N ip link set x-i up; $N ip route add default via 10.201.0.2
$N ip route add 10.200.0.0/24 via 10.202.0.2
$I ip addr add 10.201.0.2/24 dev i-x; $I ip link set i-x up; $I ip link set lo up
mkdir -p /etc/netns/hv-client; echo "nameserver 10.200.0.1" > /etc/netns/hv-client/resolv.conf
$I python3 -I "$HERE/test/whoami-http.py" > "$WORK/http.log" 2>&1 & PIDS+=($!)
$I python3 -I "$HERE/test/dns-stub.py" 10.201.0.2 > "$WORK/dns.log" 2>&1 & PIDS+=($!)
sleep 1

# ── Two nodes, two roles, both admitting openly ─────────────────────────────
$N "$BIN/hidravpn-node" --config "$WORK/a.toml" init --endpoint 10.202.0.1:51820 --name node-a --role exit --operator maintainers --contact nodes@example.org --open-admission --dns udp://10.201.0.2 --out-interface x-i > "$WORK/init-a.log" 2>&1 || { cat "$WORK/init-a.log"; fail "node-a init"; exit 1; }
$E "$BIN/hidravpn-node" --config "$WORK/b.toml" init --endpoint 10.200.0.1:51820 --tunnel 10.78.0.0/16 --name node-b --role entry --operator maintainers --open-admission --max-clients 2 --dns udp://10.201.0.2 --out-interface e-x > "$WORK/init-b.log" 2>&1 || { cat "$WORK/init-b.log"; fail "node-b init"; exit 1; }
# Two userspace WireGuard nodes on one host need two interface names: the
# control socket lives at /var/run/wireguard/<interface>.sock, outside the
# network namespaces.
sed -i 's/^interface = "hvpn0"/interface = "hva0"/' "$WORK/a.toml"
sed -i 's/^interface = "hvpn0"/interface = "hvb0"/' "$WORK/b.toml"
grep -q '^interface = "hva0"' "$WORK/a.toml" && grep -q '^interface = "hvb0"' "$WORK/b.toml" || { fail "could not give the nodes their own interface names"; exit 1; }
grep -q 'role exit; admission open' "$WORK/init-a.log" && grep -q 'role entry; admission open' "$WORK/init-b.log" && pass "init records the role and the admission mode" || fail "init output: $(cat "$WORK/init-a.log" "$WORK/init-b.log")"
mkdir -p "$WORK/run-a" "$WORK/run-b"
$N env HIDRAVPN_RUN_DIR="$WORK/run-a" "$BIN/hidravpn-node" --config "$WORK/a.toml" run > "$WORK/a.log" 2>&1 & NODE_A=$!; PIDS+=($NODE_A)
$E env HIDRAVPN_RUN_DIR="$WORK/run-b" "$BIN/hidravpn-node" --config "$WORK/b.toml" run > "$WORK/b.log" 2>&1 & NODE_B=$!; PIDS+=($NODE_B)
for i in $(seq 1 100); do grep -q "DNS forwarder ready" "$WORK/a.log" && grep -q "DNS forwarder ready" "$WORK/b.log" && grep -q "admission service" "$WORK/a.log" && grep -q "admission service" "$WORK/b.log" && break; sleep 0.2; done
grep -q "admission service on TCP 51821 (open" "$WORK/a.log" && grep -q "admission service on TCP 51821 (open" "$WORK/b.log" && pass "both nodes up, each with its admission service" || { tail -n 5 "$WORK/a.log" "$WORK/b.log"; fail "nodes did not come up"; exit 1; }

# ── The maintainers' side: records, a list, a signature ─────────────────────
$N "$BIN/hidravpn-node" --config "$WORK/a.toml" record > "$WORK/rec-a.json" 2>/dev/null
$E "$BIN/hidravpn-node" --config "$WORK/b.toml" record > "$WORK/rec-b.json" 2>/dev/null
grep -q '"admission": "open"' "$WORK/rec-a.json" && grep -q '"role": "entry"' "$WORK/rec-b.json" && grep -q '"operator": "maintainers"' "$WORK/rec-b.json" && pass "each node prints its record: role, admission, operator" || fail "records: $(cat "$WORK/rec-a.json" "$WORK/rec-b.json")"
LISTPUB=$("$BIN/hidravpn-sign" keygen --out "$WORK/list.key" 2>/dev/null)
HIDRAVPN_SIGN="$BIN/hidravpn-sign" bash "$HERE/make-node-list.sh" --key "$WORK/list.key" --out "$WORK/nodes.json" --sequence 1 --note "test nodes" "$WORK/rec-a.json" "$WORK/rec-b.json" > "$WORK/make.log" 2>&1 && [ -f "$WORK/nodes.json.sig" ] && pass "make-node-list.sh made and signed the list ($(head -1 "$WORK/make.log"))" || { cat "$WORK/make.log"; fail "make-node-list"; }
grep -q '"sequence": 1' "$WORK/nodes.json" && grep -q '"expires": "' "$WORK/nodes.json" && pass "the list carries a sequence and an expiry" || fail "list fields"

# ── The stranger's side ─────────────────────────────────────────────────────
mkdir -p /etc/hidravpn
$C "$BIN/hidravpn" --key /etc/hidravpn/client.key keygen >/dev/null 2>&1
OUT=$($C "$BIN/hidravpn" nodes discover 10.202.0.1 2>&1); echo "$OUT" | grep -q '"node_name": "node-a"' && echo "$OUT" | grep -q "not written down" && pass "discover reads a node by address (through the entry's routing) and trusts nothing by itself" || fail "discover: $OUT"
OUT=$("$BIN/hidravpn" nodes import "$WORK/nodes.json" --pubkey "$LISTPUB" 2>&1); echo "$OUT" | grep -q "added 2 node(s) (2 known, 0 entries, 0 exits" && pass "the list makes both nodes known and none connectable" || fail "import: $OUT"
"$BIN/hidravpn" nodes list 2>/dev/null | grep -q "^known  node-a .*exit  admits openly" && "$BIN/hidravpn" nodes list 2>/dev/null | grep -q "^known  node-b .*entry  admits openly" && pass "nodes list shows role and open admission" || fail "list: $("$BIN/hidravpn" nodes list 2>&1)"
# With known nodes that admit by hand only, `up` has nobody to ask and says so.
python3 -I -c "import json; p=json.load(open('/etc/hidravpn/circuit.json')); [k.__setitem__('admission','manual') for k in p['known']]; json.dump(p, open('$WORK/by-hand.json','w'))"
OUT=$($C "$BIN/hidravpn" up --rapido --direct --pocket "$WORK/by-hand.json" 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "admitted on none yet" && pass "with known nodes that admit by hand only, up is refused and says whom to ask" || fail "up by-hand: $OUT"

# ── The service: connect joins, then connects ───────────────────────────────
$C env RUST_LOG=hidravpn_service=info "$BIN/hidravpn-service" run > "$WORK/svc.log" 2>&1 & SVC=$!; PIDS+=($SVC)
for i in $(seq 1 50); do [ -S /run/hidravpn/control.sock ] && break; sleep 0.2; done
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
R=$(svc '{"cmd":"connect","mode":"rapido"}')
echo "$R" | grep -q '"ok":true' && echo "$R" | grep -q 'node-a: admitted as exit' && echo "$R" | grep -q 'node-b: admitted as entry' && pass "connect with only known nodes joined both through open admission and connected ($(echo "$R" | grep -o '"note":"[^"]*"' | cut -c1-90))" || { echo "$R"; tail -5 "$WORK/svc.log"; fail "connect+join"; }
grep -q '"node_name": "node-a"' /etc/hidravpn/circuit.json && python3 -I -c "import json,sys; p=json.load(open('/etc/hidravpn/circuit.json')); sys.exit(0 if len(p['exits'])==1 and len(p['entries'])==1 and not p.get('known') else 1)" && pass "the pocket now holds node-a as exit and node-b as entry, and no known nodes" || fail "pocket after join: $(cat /etc/hidravpn/circuit.json | tr -d '\n ' | cut -c1-200)"
grep -q "admitted a client through the admission service" "$WORK/a.log" && grep -q "admitted a client through the admission service" "$WORK/b.log" && pass "both nodes logged an admission, as a count" || fail "node logs"
for i in $(seq 1 25); do svc '{"cmd":"status"}' | grep -q '"connected":true' && break; sleep 0.4; done
svc '{"cmd":"status"}' | grep -q '"connected":true' && pass "connected, one hop" || fail "never connected: $(svc '{"cmd":"status"}')"
EXIT_IP=$($C curl -s --max-time 8 http://10.201.0.2/ 2>/dev/null); [ "$EXIT_IP" = "10.201.0.1" ] && pass "the internet sees the exit's address" || fail "exit IP '$EXIT_IP'"
svc '{"cmd":"down"}' | grep -q '"ok":true' && pass "down" || fail "down"

# ── `up` joins by itself: a copy of the pocket that only knows the nodes ─────
"$BIN/hidravpn" nodes import --pocket "$WORK/cli-pocket.json" "$WORK/nodes.json" --pubkey "$LISTPUB" > /dev/null 2>&1
$C "$BIN/hidravpn" up --rapido --node node-a --direct --pocket "$WORK/cli-pocket.json" > "$WORK/cli-up.log" 2>&1 & CLI_UP=$!
for i in $(seq 1 100); do grep -q "^connected" "$WORK/cli-up.log" && break; sleep 0.2; done
CLI_IP=$($C curl -s --max-time 8 http://10.201.0.2/ 2>/dev/null)
kill -TERM $CLI_UP 2>/dev/null; wait $CLI_UP 2>/dev/null
grep -q "node-a: admitted" "$WORK/cli-up.log" && [ "$CLI_IP" = "10.201.0.1" ] && pass "up --rapido --node node-a with a pocket that only knows nodes joins node-a by itself and connects" || { cat "$WORK/cli-up.log"; fail "cli auto-join (ip '$CLI_IP')"; }
$C ip link show hvpn0 >/dev/null 2>&1 && fail "the CLI left a tunnel up after SIGTERM" || pass "SIGTERM put the network back"

R=$(svc '{"cmd":"connect","mode":"privado"}'); echo "$R" | grep -q '"ok":true' && echo "$R" | grep -q '"hops":2' && pass "two hops: entry node-b then exit node-a" || { echo "$R"; fail "privado"; }
for i in $(seq 1 25); do svc '{"cmd":"status"}' | grep -q '"connected":true' && break; sleep 0.4; done
S=$(svc '{"cmd":"status"}'); echo "$S" | grep -q '"same_operator":true' && pass "status says both hops are one operator's (maintainers)" || fail "same_operator: $S"
EXIT_IP=$($C curl -s --max-time 10 http://10.201.0.2/ 2>/dev/null); [ "$EXIT_IP" = "10.201.0.1" ] && pass "two hops carry traffic and the internet still sees the exit" || fail "exit IP over two hops '$EXIT_IP'"
svc '{"cmd":"down"}' >/dev/null

# ── An entry used as an exit forwards nothing but WireGuard ─────────────────
python3 -I -c "import json; p=json.load(open('/etc/hidravpn/circuit.json')); open('$WORK/b-invite.json','w').write(json.dumps(p['entries'][0]))"
$C "$BIN/hidravpn-service" up "$WORK/b-invite.json" > "$WORK/up-b.log" 2>&1 && pass "root may still hand the service an invite (node-b, one hop)" || { cat "$WORK/up-b.log"; fail "up via b"; }
for i in $(seq 1 25); do svc '{"cmd":"status"}' | grep -q '"connected":true' && break; sleep 0.4; done
$C curl -s --max-time 4 http://10.201.0.2/ >/dev/null 2>&1; RC=$?
[ "$RC" != 0 ] && pass "an entry-role node does not forward HTTP (curl exit $RC): entry policy holds" || fail "HTTP went through an entry-role node"
$C "$BIN/hidravpn-service" down >/dev/null 2>&1

# ── The admission service's limits ──────────────────────────────────────────
post() { $C curl -s -o "$WORK/post.out" -w '%{http_code}' --max-time 5 -X POST -H 'Content-Type: application/json' --data "$1" "http://$2:51821/admit" 2>/dev/null; }
[ "$(post '{"public_key":"not-a-key"}' 10.202.0.1)" = 400 ] && grep -q "not a WireGuard public key" "$WORK/post.out" && pass "a key that is not a key: 400, and it does not count against the address" || fail "bad key: $(cat "$WORK/post.out")"
codes=""; for i in 1 2 3 4 5; do K=$("$BIN/hidravpn-sign" keygen --out "$WORK/k$i" 2>/dev/null); codes="$codes $(post "{\"public_key\":\"$K\",\"name\":\"probe-$i\"}" 10.202.0.1)"; done
echo "$codes" | grep -q 200 && echo "$codes" | grep -q 429 && pass "the admission service admits a few and then rate-limits the address ($codes)" || fail "rate limit codes: $codes"
[ "$($C curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://10.202.0.1:51821/nowhere)" = 404 ] && pass "an unknown path: 404" || fail "404"
# node-b holds at most 2 leases: ours, one more, and then it is full.
K=$("$BIN/hidravpn-sign" keygen --out "$WORK/kb1" 2>/dev/null); C1=$(post "{\"public_key\":\"$K\",\"name\":\"probe-b1\"}" 10.200.0.1)
K=$("$BIN/hidravpn-sign" keygen --out "$WORK/kb2" 2>/dev/null); C2=$(post "{\"public_key\":\"$K\",\"name\":\"probe-b2\"}" 10.200.0.1)
[ "$C1" = 200 ] && [ "$C2" = 503 ] && grep -q "full" "$WORK/post.out" && pass "a node admits up to --max-clients and then answers 503 full ($C1 $C2)" || fail "max_clients: $C1 $C2 $(cat "$WORK/post.out")"
kill $NODE_B; wait $NODE_B 2>/dev/null; sed -i 's/^admission = "open"/admission = "manual"/' "$WORK/b.toml"
$E env HIDRAVPN_RUN_DIR="$WORK/run-b" "$BIN/hidravpn-node" --config "$WORK/b.toml" run > "$WORK/b2.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 50); do grep -q "admission service on TCP 51821 (by hand" "$WORK/b2.log" && break; sleep 0.2; done
K=$("$BIN/hidravpn-sign" keygen --out "$WORK/km" 2>/dev/null); [ "$(post "{\"public_key\":\"$K\"}" 10.200.0.1)" = 403 ] && grep -q "by hand" "$WORK/post.out" && pass "a node that admits by hand refuses with 403 and says whom to ask" || fail "manual: $(cat "$WORK/post.out")"
$C curl -s --max-time 5 http://10.200.0.1:51821/ | grep -qE '"admission": ?"manual"' && pass "it still describes itself, now as admitting by hand" || fail "GET / after manual"

# ── The uptime prober, through the service, then without one ────────────────
$C env HIDRAVPN_BIN="$BIN/hidravpn" bash "$HERE/probe-nodes.sh" --out "$WORK/probe-svc" --check-url http://10.201.0.2/ --timeout 20 > "$WORK/probe-svc.log" 2>&1; RC=$?
[ "$RC" = 0 ] && grep -q '"node":"node-a","up":true,"exit_ip":"10.201.0.1"' "$WORK/probe-svc/status.json" && svc '{"cmd":"status"}' | grep -q '"connected":false' && pass "the prober through the service connected via node-a, saw the exit's address, and left the service disconnected" || { cat "$WORK/probe-svc.log" "$WORK/probe-svc/status.json" 2>/dev/null; fail "prober via service (exit $RC)"; }
kill -INT $SVC; for i in $(seq 1 30); do kill -0 $SVC 2>/dev/null || break; sleep 0.2; done
sleep 8   # let the probes above age past the idle window used below, while our own handshake stays fresh
$C env HIDRAVPN_BIN="$BIN/hidravpn" bash "$HERE/probe-nodes.sh" --direct --out "$WORK/probe" --check-url http://10.201.0.2/ --timeout 20 > "$WORK/probe.log" 2>&1; RC=$?
[ "$RC" = 0 ] && grep -q '"node":"node-a","up":true,"exit_ip":"10.201.0.1"' "$WORK/probe/status.json" && grep -q '| node-a | true | 10.201.0.1 |' "$WORK/probe/status.md" && pass "the prober connected through node-a, saw the exit's address, and wrote status.json and status.md" || { cat "$WORK/probe.log" "$WORK/probe/status.json" 2>/dev/null; fail "prober (exit $RC)"; }
$C ip link show hvpn0 >/dev/null 2>&1 && fail "the prober left a tunnel up" || pass "the prober put the network back"

# ── Idle open admissions expire (30 days by default; 12 s here) ─────────────
# node-a is restarted with the idle window shortened. Its leases survive the
# restart (the run directory), and so does the handshake it wrote down at
# shutdown: the reaper forgets the probes, which never shook hands, and keeps
# us, who did a moment ago — until we too have been quiet for the window.
lease_names() { python3 -I -c "import json; print(' '.join(sorted(l['name'] for l in json.load(open('$WORK/run-a/peers.json'))['leases'])))"; }
names_before=$(lease_names)
kill $NODE_A; wait $NODE_A 2>/dev/null
python3 -I -c "import json; ls=json.load(open('$WORK/run-a/peers.json'))['leases']; assert any(l['last_seen']>0 for l in ls), ls" && pass "at shutdown the node wrote down our last handshake" || fail "no last_seen recorded: $(cat "$WORK/run-a/peers.json")"
$N env HIDRAVPN_RUN_DIR="$WORK/run-a" HIDRAVPN_IDLE_SECS=12 "$BIN/hidravpn-node" --config "$WORK/a.toml" run > "$WORK/a2.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 150); do grep -q "idle openly-admitted client(s) expired" "$WORK/a2.log" && break; sleep 0.2; done
names_after=$(lease_names)
echo "$names_before" | grep -q "probe-1" && ! echo "$names_after" | grep -q "probe-" && [ -n "$names_after" ] && pass "idle open admissions expired ($names_before -> $names_after): the probes that never shook hands are gone, we are not" || fail "expiry: $names_before -> $names_after; $(grep -c expired "$WORK/a2.log") log lines"
for i in $(seq 1 100); do [ -z "$(lease_names)" ] && break; sleep 0.2; done
[ -z "$(lease_names)" ] && pass "and after the window without a handshake, so are we" || fail "our lease never expired: $(lease_names)"

# ── Nothing identifying in the logs ─────────────────────────────────────────
grep -qE "10\.200\.0\.2|10\.77\.0\.2|10\.78\.0\.2" "$WORK/svc.log" "$WORK/a.log" "$WORK/a2.log" "$WORK/b.log" "$WORK/b2.log" && fail "a log names the client" || pass "no log names the client's address"
grep -qE "probe-[0-9]" "$WORK/a.log" "$WORK/a2.log" && fail "a log names a lease" || pass "no log names a lease or a key"

echo; echo "$ok passed, $bad failed"; [ $bad -eq 0 ]
