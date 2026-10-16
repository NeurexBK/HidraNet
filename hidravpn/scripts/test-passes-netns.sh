#!/usr/bin/env bash
# Passes, end to end (phase 5): an issuer, a node that admits with a pass,
# and a client that gets passes and connects. Three namespaces:
#
#   hv-client ──veth── hv-node ──veth── hv-inet
#   10.200.0.2        10.200.0.1        10.201.0.2  (the "internet")
#                     10.201.0.1
#                     node-p: exit, admission "pass", UDP 51820, TCP 51821
#                     the issuer on TCP 8730 (in the node's namespace, for
#                     the test only: in the network they are apart)
#   hv-q ──veth── hv-inet: a second pass node, node-q, 10.205.0.2, out on
#   the "internet" side, so a client reaches it directly and through node-p
#   hv-e ──veth── hv-inet: node-e, an entry that admits openly, 10.206.0.2,
#   for two hops with node-q as the exit
#
# It proves: the issuer makes a key and an account, and keeps the token's
# hash only; the node trusts the key and admits with passes only; the signed
# list names the issuer; the client keeps the token, gets passes, and
# `connect` joins the node by redeeming one; the internet sees the node;
# every connection shows the node a fresh key; with two hops the exit's pass
# is redeemed through the entry, the exit never hears from the client, and
# with no pass left for it the connection is refused; a pass spent once is refused
# the second time; the quota and a switched-off account stop issuance; the
# open-admission door is shut on a pass node; the wallet and the token are
# root's only; and no log names the client, the account or the token.
#
# Run as root:  hidravpn/scripts/test-passes-netns.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/test/guard.sh"
BIN="$HERE/../target/release"
WORK=""
C="ip netns exec hv-client"; N="ip netns exec hv-node"; I="ip netns exec hv-inet"; Q="ip netns exec hv-q"; E="ip netns exec hv-e"; F="ip netns exec hv-f"
PIDS=()
export RUST_BACKTRACE=0
# The issuer speaks plain HTTP on this private test network; a client sends
# a token over plain HTTP only to loopback unless told so (checked below).
export HIDRAVPN_PLAIN_HTTP_ISSUER=1
ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok + 1)); }
fail() { echo "FAIL  $1"; bad=$((bad + 1)); }
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  ip netns pids hv-client 2>/dev/null | xargs -r kill 2>/dev/null
  sleep 0.5
  [ -n "${NODE_Q:-}" ] && kill -CONT "$NODE_Q" 2>/dev/null
  for ns in hv-client hv-node hv-inet hv-q hv-e hv-f; do ip netns del "$ns" 2>/dev/null; done
  rm -rf /etc/netns/hv-client /run/hidravpn/control.sock /run/hidravpn/control.token /run/hidravpn/netcfg.json \
         /etc/hidravpn/client.key /etc/hidravpn/circuit.json /etc/hidravpn/passes.json /etc/hidravpn/pass.token \
         /var/run/wireguard/hvp0.sock /var/run/wireguard/hvq0.sock /var/run/wireguard/hve0.sock /var/run/wireguard/hvf0.sock
  [ -n "${WORK:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT
cleanup
WORK="$(mktemp -d /tmp/hidravpn-pass.XXXXXX)"
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
command -v tcpdump >/dev/null || { echo "needs tcpdump"; exit 1; }
for b in hidravpn hidravpn-node hidravpn-service hidravpn-sign hidravpn-issuer; do [ -x "$BIN/$b" ] || { echo "build first: cargo build --release --manifest-path hidravpn/Cargo.toml"; exit 1; }; done

# ── Network ─────────────────────────────────────────────────────────────────
ip netns add hv-client; ip netns add hv-node; ip netns add hv-inet
ip link add c-n type veth peer name n-c; ip link set c-n netns hv-client; ip link set n-c netns hv-node
ip link add n-i type veth peer name i-n; ip link set n-i netns hv-node; ip link set i-n netns hv-inet
$C ip addr add 10.200.0.2/24 dev c-n; $C ip link set c-n up; $C ip link set lo up; $C ip route add default via 10.200.0.1
$N ip addr add 10.200.0.1/24 dev n-c; $N ip link set n-c up; $N ip link set lo up
$N ip addr add 10.201.0.1/24 dev n-i; $N ip link set n-i up; $N ip route add default via 10.201.0.2
$I ip addr add 10.201.0.2/24 dev i-n; $I ip link set i-n up; $I ip link set lo up
# node-q hangs off the "internet". The internet gets a route back to the
# client's link only so that node-q can be joined directly in this test; the
# kill switch keeps everything else of the client off it while connected.
ip netns add hv-q
ip link add q-i type veth peer name i-q; ip link set q-i netns hv-q; ip link set i-q netns hv-inet
$Q ip addr add 10.205.0.2/24 dev q-i; $Q ip link set q-i up; $Q ip link set lo up; $Q ip route add default via 10.205.0.1
$I ip addr add 10.205.0.1/24 dev i-q; $I ip link set i-q up; $I ip route add 10.200.0.0/24 via 10.201.0.1
$I sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
mkdir -p /etc/netns/hv-client; echo "nameserver 10.200.0.1" > /etc/netns/hv-client/resolv.conf
$I python3 -I "$HERE/test/whoami-http.py" > "$WORK/http.log" 2>&1 & PIDS+=($!)
$I python3 -I "$HERE/test/dns-stub.py" 10.201.0.2 > "$WORK/dns.log" 2>&1 & PIDS+=($!)
sleep 1

# ── The issuer ──────────────────────────────────────────────────────────────
ISS="$BIN/hidravpn-issuer --accounts $WORK/accounts.json"
$ISS keygen --out "$WORK/issuer-key.json" --days 30 > "$WORK/pass-key.json" 2>"$WORK/keygen.log" && grep -q '"not_after"' "$WORK/pass-key.json" && [ "$(stat -c %a "$WORK/issuer-key.json")" = 600 ] && pass "the issuer makes a key (root-only file) and prints its record" || { cat "$WORK/keygen.log"; fail "issuer keygen"; exit 1; }
TOKEN=$($ISS account add --name alice --quota 8 2>/dev/null)
[ -n "$TOKEN" ] && ! grep -q "$TOKEN" "$WORK/accounts.json" && grep -q '"token_sha256"' "$WORK/accounts.json" && pass "an account is made; the file keeps the token's hash, never the token" || fail "account add"
$ISS run --key "$WORK/issuer-key.json" --listen 10.200.0.1:8730 >/dev/null 2>"$WORK/refuse-public.log"; [ $? -ne 0 ] && grep -q "not a loopback address" "$WORK/refuse-public.log" && pass "the issuer refuses plain HTTP off loopback unless told it is a private network" || fail "issuer listened in the clear: $(cat "$WORK/refuse-public.log")"
$N $ISS run --key "$WORK/issuer-key.json" --listen 10.200.0.1:8730 --plain-http-public > "$WORK/issuer.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 50); do grep -q "pass issuer on TCP 8730" "$WORK/issuer.log" && break; sleep 0.2; done
grep -q "pass issuer on TCP 8730 with 1 key" "$WORK/issuer.log" && pass "the issuer is up with its key" || { cat "$WORK/issuer.log"; fail "issuer did not start"; exit 1; }

# ── The node: admits with a pass, trusts the issuer's key ───────────────────
$N "$BIN/hidravpn-node" --config "$WORK/p.toml" init --endpoint 10.200.0.1:51820 --name node-p --role exit --operator maintainers --pass-admission --dns udp://10.201.0.2 --out-interface n-i > "$WORK/init.log" 2>&1 || { cat "$WORK/init.log"; fail "node init"; exit 1; }
sed -i 's/^interface = "hvpn0"/interface = "hvp0"/' "$WORK/p.toml"
grep -q "admission pass" "$WORK/init.log" && pass "init records admission with a pass" || fail "init: $(cat "$WORK/init.log")"
$N "$BIN/hidravpn-node" --config "$WORK/p.toml" pass-key add "$WORK/pass-key.json" > "$WORK/passkey.log" 2>&1 && grep -q "trusting passes under" "$WORK/passkey.log" && $N "$BIN/hidravpn-node" --config "$WORK/p.toml" pass-key list | grep -q "until" && pass "the node trusts the issuer's key (pass-key add, list)" || fail "pass-key: $(cat "$WORK/passkey.log")"
mkdir -p "$WORK/run"
$N env HIDRAVPN_RUN_DIR="$WORK/run" "$BIN/hidravpn-node" --config "$WORK/p.toml" run > "$WORK/node.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 100); do grep -q "DNS forwarder ready" "$WORK/node.log" && grep -q "admission service on" "$WORK/node.log" && break; sleep 0.2; done
grep -q "admission service on TCP 51821 (with a pass" "$WORK/node.log" && grep -q "1 issuer key(s) trusted" "$WORK/node.log" && pass "the node is up, admitting with passes under one trusted key" || { tail -5 "$WORK/node.log"; fail "node did not come up"; exit 1; }
CODE=$($C curl -s -o "$WORK/admit.json" -w '%{http_code}' --max-time 5 -X POST -d "{\"public_key\":\"$($BIN/hidravpn-sign keygen --out "$WORK/junk.key" 2>/dev/null)\"}" http://10.200.0.1:51821/admit)
[ "$CODE" = 403 ] && grep -q "admits with a pass" "$WORK/admit.json" && pass "open admission is shut on a pass node (403, says to get a pass)" || fail "admit on a pass node: $CODE $(cat "$WORK/admit.json")"

# ── The signed list names the issuer ────────────────────────────────────────
$N "$BIN/hidravpn-node" --config "$WORK/p.toml" record > "$WORK/rec.json" 2>/dev/null
grep -q '"admission": "pass"' "$WORK/rec.json" && pass "the node's record says it admits with a pass" || fail "record: $(cat "$WORK/rec.json")"
LISTPUB=$("$BIN/hidravpn-sign" keygen --out "$WORK/list.key" 2>/dev/null)
HIDRAVPN_SIGN="$BIN/hidravpn-sign" bash "$HERE/make-node-list.sh" --key "$WORK/list.key" --out "$WORK/nodes.json" --sequence 1 \
  --issuer-url http://10.200.0.1:8730 --pass-key "$WORK/pass-key.json" "$WORK/rec.json" > "$WORK/make.log" 2>&1 \
  && grep -q '"pass_issuer"' "$WORK/nodes.json" && pass "make-node-list.sh puts the issuer and its key in the signed list" || { cat "$WORK/make.log"; fail "make-node-list"; }

# ── The client ──────────────────────────────────────────────────────────────
mkdir -p /etc/hidravpn
$C "$BIN/hidravpn" keygen >/dev/null 2>&1
OUT=$("$BIN/hidravpn" nodes import "$WORK/nodes.json" --pubkey "$LISTPUB" 2>&1); echo "$OUT" | grep -q "added 1 node(s)" && pass "the list makes the node known" || fail "import: $OUT"
"$BIN/hidravpn" nodes list 2>/dev/null | grep -q "^known  node-p .*admits with a pass" && pass "nodes list says the node admits with a pass" || fail "list: $("$BIN/hidravpn" nodes list 2>&1)"
echo "$TOKEN" | "$BIN/hidravpn" passes token - > /dev/null 2>&1 && [ "$(stat -c %a /etc/hidravpn/pass.token)" = 600 ] && pass "the client keeps the account token, root only" || fail "passes token"
OUT=$($C env -u HIDRAVPN_PLAIN_HTTP_ISSUER "$BIN/hidravpn" passes get --count 3 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "only travels over https" && ! grep -q "issued" "$WORK/issuer.log" && pass "the client will not send the token over plain HTTP off this machine unless told to" || fail "plain HTTP: $OUT"
OUT=$($C "$BIN/hidravpn" passes get --count 3 2>&1); echo "$OUT" | grep -q "3 pass(es) for 1 node(s); the account has 5 left today" && pass "passes get: three passes, the account has five left ($OUT)" || fail "passes get: $OUT"
[ "$(stat -c %a /etc/hidravpn/passes.json)" = 600 ] && ! grep -q "$TOKEN" /etc/hidravpn/passes.json && pass "the wallet is root's only and holds no token" || fail "wallet mode $(stat -c %a /etc/hidravpn/passes.json)"
grep -q "issued 3 pass(es)" "$WORK/issuer.log" && pass "the issuer logged a count" || fail "issuer log: $(cat "$WORK/issuer.log")"
# Kept aside, to try spending a pass twice later.
mkdir -p "$WORK/again"; cp /etc/hidravpn/passes.json /etc/hidravpn/circuit.json "$WORK/again/"
OUT=$($C "$BIN/hidravpn" passes get --count 6 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "quota" && echo "$OUT" | grep -q "5 left" && pass "past the quota the issuer refuses (all or nothing): $(echo "$OUT" | tail -1 | cut -c1-90)" || fail "quota: $OUT"

# ── Connecting redeems a pass; every connection a fresh one ─────────────────
$C env RUST_LOG=hidravpn_service=info HIDRAVPN_PLAIN_HTTP_ISSUER=1 "$BIN/hidravpn-service" run > "$WORK/svc.log" 2>&1 & PIDS+=($!)
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
R=$(svc '{"cmd":"nodes"}'); echo "$R" | grep -q '"admission":"pass","passes":3' && pass "the service reports the node takes passes and the wallet holds 3 for it" || fail "nodes: $R"
R=$(svc '{"cmd":"connect","mode":"rapido"}')
echo "$R" | grep -q '"ok":true' && pass "connect redeemed a pass for this connection, with no join first" || { echo "$R"; tail -5 "$WORK/svc.log"; fail "connect with a pass"; }
for i in $(seq 1 25); do svc '{"cmd":"status"}' | grep -q '"connected":true' && break; sleep 0.4; done
svc '{"cmd":"status"}' | grep -q '"connected":true' && pass "connected through the pass node" || fail "never connected: $(svc '{"cmd":"status"}')"
EXIT_IP=$($C curl -s --max-time 8 http://10.201.0.2/ 2>/dev/null); [ "$EXIT_IP" = "10.201.0.1" ] && pass "the internet sees the node's address" || fail "exit IP '$EXIT_IP'"
grep -q "admitted a client with a pass" "$WORK/node.log" && pass "the node logged an admission with a pass, as a count" || fail "node log"
KEY1=$(python3 -I -c "import json; print(json.load(open('/etc/hidravpn/circuit.json'))['exits'][0]['pass']['client_secret'])")
svc '{"cmd":"down"}' >/dev/null
R=$(svc '{"cmd":"connect","mode":"rapido"}'); echo "$R" | grep -q '"ok":true' || { echo "$R"; fail "second connect"; }
for i in $(seq 1 25); do svc '{"cmd":"status"}' | grep -q '"connected":true' && break; sleep 0.4; done
KEY2=$(python3 -I -c "import json; print(json.load(open('/etc/hidravpn/circuit.json'))['exits'][0]['pass']['client_secret'])")
EXIT_IP=$($C curl -s --max-time 8 http://10.201.0.2/ 2>/dev/null)
[ -n "$KEY1" ] && [ "$KEY1" != "$KEY2" ] && [ "$EXIT_IP" = "10.201.0.1" ] && pass "the second connection redeemed the next pass: a fresh key, and traffic flows" || fail "fresh key per connection ('$EXIT_IP')"
N_PASS=$(python3 -I -c "import json; print(sum(1 for l in json.load(open('$WORK/run/peers.json'))['leases'] if l['source']=='pass'))")
N_KEYS=$(python3 -I -c "import json; print(len({l['public_key'] for l in json.load(open('$WORK/run/peers.json'))['leases']}))")
[ "$N_PASS" = 2 ] && [ "$N_KEYS" = 2 ] && pass "the node holds two pass leases under two unrelated keys" || fail "leases: $N_PASS pass, $N_KEYS keys"
R=$(svc '{"cmd":"nodes"}'); echo "$R" | grep -q '"passes":1' && pass "one pass left in the wallet" || fail "count after two connects: $R"
# A new identity with this one node: the old circuit comes down, the kill
# switch holds the machine to the node's own ports, and the node is shown the
# next pass's key; the circuit comes back up.
R=$(svc '{"cmd":"new_identity"}')
KEY3=$(python3 -I -c "import json; print(json.load(open('/etc/hidravpn/circuit.json'))['exits'][0]['pass']['client_secret'])")
echo "$R" | grep -q '"ok":true' && echo "$R" | grep -q "reconnected to the same one" && [ -n "$KEY3" ] && [ "$KEY3" != "$KEY2" ] && [ "$KEY3" != "$KEY1" ] && pass "a new identity through the same node shows it a fresh key: the next pass, redeemed while the kill switch holds" || fail "new identity: $R"
for i in $(seq 1 25); do svc '{"cmd":"status"}' | grep -q '"connected":true' && break; sleep 0.4; done
EXIT_IP=$($C curl -s --max-time 8 http://10.201.0.2/ 2>/dev/null); [ "$EXIT_IP" = "10.201.0.1" ] && pass "and the rotated circuit carries traffic" || fail "after new identity '$EXIT_IP'"
R=$(svc '{"cmd":"nodes"}'); echo "$R" | grep -q '"passes":0' && pass "one pass was spent on it: none left" || fail "count after new identity: $R"
# The node's spent list: a snapshot and a journal of the passes since.
SPENT=$(python3 -I -c "import json, os; d='$WORK/run'; t=set(json.load(open(d+'/spent.json'))['tags']) if os.path.exists(d+'/spent.json') else set(); t|={l.split()[0] for l in open(d+'/spent.log') if len(l.split())==2} if os.path.exists(d+'/spent.log') else set(); print(len(t))")
[ "$SPENT" = 3 ] && pass "the node wrote three passes down as spent" || fail "spent: $SPENT"
svc '{"cmd":"down"}' >/dev/null

# ── The browser's module: hands the token over, asks for passes ────────────
cat > "$WORK/browser.js" <<JS
const { VpnManager } = require('$HERE/../../hidra-browser/src/main/vpn-manager.js');
(async () => {
  const vpn = new VpnManager({ timeoutMs: 30000 });
  const t = await vpn.setPassToken(process.argv[2]);
  const g = await vpn.getPasses(2);
  console.log(JSON.stringify({ t, g }));
})();
JS
OUT=$(node "$WORK/browser.js" "$TOKEN" 2>&1)
echo "$OUT" | grep -q '"t":{"ok":true' && ! echo "$OUT" | grep -qF "$TOKEN" && pass "the browser's module hands the service the token, which never comes back" || fail "browser token: $OUT"
echo "$OUT" | grep -q '2 pass(es) for 1 node(s); the account has 3 left today' && echo "$OUT" | grep -q '"passes":2' && pass "the browser's module gets two passes through the service: two in the wallet" || fail "browser passes: $OUT"

# ── A new identity to another pass node redeems its next pass, through the tunnel
$Q "$BIN/hidravpn-node" --config "$WORK/q.toml" init --endpoint 10.205.0.2:51820 --tunnel 10.78.0.0/16 --name node-q --role exit --operator others --pass-admission --dns udp://10.201.0.2 --out-interface q-i > "$WORK/init-q.log" 2>&1 || { cat "$WORK/init-q.log"; fail "node-q init"; }
sed -i 's/^interface = "hvpn0"/interface = "hvq0"/' "$WORK/q.toml"
$Q "$BIN/hidravpn-node" --config "$WORK/q.toml" pass-key add "$WORK/pass-key.json" > /dev/null 2>&1
mkdir -p "$WORK/run-q"
$Q env HIDRAVPN_RUN_DIR="$WORK/run-q" "$BIN/hidravpn-node" --config "$WORK/q.toml" run > "$WORK/node-q.log" 2>&1 & NODE_Q=$!; PIDS+=($NODE_Q)
for i in $(seq 1 100); do grep -q "DNS forwarder ready" "$WORK/node-q.log" && grep -q "admission service on" "$WORK/node-q.log" && break; sleep 0.2; done
$Q "$BIN/hidravpn-node" --config "$WORK/q.toml" record > "$WORK/rec-q.json" 2>/dev/null
HIDRAVPN_SIGN="$BIN/hidravpn-sign" bash "$HERE/make-node-list.sh" --key "$WORK/list.key" --out "$WORK/nodes2.json" --sequence 2 \
  --issuer-url http://10.200.0.1:8730 --pass-key "$WORK/pass-key.json" "$WORK/rec.json" "$WORK/rec-q.json" > /dev/null 2>&1
OUT=$("$BIN/hidravpn" nodes import "$WORK/nodes2.json" --pubkey "$LISTPUB" 2>&1); echo "$OUT" | grep -q "added 1 node(s)" || fail "import v2: $OUT"
OUT=$($C "$BIN/hidravpn" passes get --node node-q --count 3 2>&1); echo "$OUT" | grep -q "3 pass(es) for 1 node(s)" || fail "passes for node-q: $OUT"
R=$(svc '{"cmd":"join","name":"node-q"}'); echo "$R" | grep -q "node-q: admitted with a pass" && pass "a second pass node, node-q, joined with a pass" || fail "join node-q: $R"
secret_of() { python3 -I -c "import json,sys; print([x for x in json.load(open('/etc/hidravpn/circuit.json'))['exits'] if x['node_name']==sys.argv[1]][0]['pass']['client_secret'])" "$1"; }
R=$(svc '{"cmd":"connect","mode":"rapido"}'); echo "$R" | grep -q '"ok":true' || fail "connect with two pass nodes: $R"
for i in $(seq 1 25); do svc '{"cmd":"status"}' | grep -q '"connected":true' && break; sleep 0.4; done
now_exit() { svc '{"cmd":"status"}' | python3 -I -c "import json,sys; print(json.load(sys.stdin)['status']['node_name'])"; }
# Each rotation takes the old circuit down and holds the kill switch to the
# next node's own ports while its next pass is redeemed: the node sees this
# machine's address, as it does in any case as the only hop.
rotate() { svc '{"cmd":"new_identity"}'; for _ in $(seq 1 25); do svc '{"cmd":"status"}' | grep -q '"connected":true' && break; sleep 0.4; done; }
[ "$(now_exit)" = node-q ] && rotate > /dev/null
OTHER=node-q
# node-q's key from its join was never used: a rotation to it uses that key
# and spends no pass. Back to node-p and to node-q again: now node-q's key
# has carried a circuit, so the next pass is redeemed.
q_passes() { svc '{"cmd":"nodes"}' | python3 -I -c "import json,sys; print([n.get('passes') for n in json.load(sys.stdin)['nodes'] if n['node_name']=='node-q'][0])"; }
q_used() { python3 -I -c "import json; print(1 if [x for x in json.load(open('/etc/hidravpn/circuit.json'))['exits'] if x['node_name']=='node-q'][0]['pass']['used_at'] else 0)"; }
QP=$(q_passes); BEFORE=$(secret_of node-q); WAS_USED=$(q_used)
R1=$(rotate); MID=$(secret_of node-q); QP1=$(q_passes)
if [ "$WAS_USED" = 0 ]; then
  echo "$R1" | grep -q "the exit is now node-q" && [ "$MID" = "$BEFORE" ] && [ "$QP1" = "$QP" ] && pass "a rotation to node-q, whose join key was never used, uses that key and spends no pass" || fail "rotation to an unused join key: $R1 ($QP -> $QP1)"
else
  echo "$R1" | grep -q "the exit is now node-q" && [ "$MID" != "$BEFORE" ] && pass "a rotation to node-q, whose key was used, redeems a fresh pass" || fail "rotation to a used key: $R1"
fi
rotate > /dev/null; [ "$(now_exit)" = node-p ] || fail "back to node-p: $(now_exit)"
R=$(rotate); AFTER=$(secret_of node-q)
echo "$R" | grep -q "the exit is now node-q" && ! echo "$R" | grep -q "keeps its key" && [ "$AFTER" != "$MID" ] && [ "$(q_passes)" -lt "$QP1" ] && pass "node-q's key has carried a circuit now: the next rotation to it redeems its next pass, a fresh key there too" || fail "rotation to node-q after use: $R"
WANT=$([ "$OTHER" = node-q ] && echo 10.205.0.2 || echo 10.201.0.1)
EXIT_IP=$($C curl -s --max-time 8 http://10.201.0.2/ 2>/dev/null); [ "$EXIT_IP" = "$WANT" ] && pass "and the internet now sees $OTHER ($EXIT_IP)" || fail "after rotation the internet sees '$EXIT_IP', not $WANT"
svc '{"cmd":"down"}' >/dev/null

# ── Two hops: the exit's pass is redeemed through the entry ────────────────
# node-e, an entry that admits openly, hangs off the "internet" too. node-q,
# as the exit of two hops, is only ever shown a key redeemed through node-e:
# the redemption and the tunnel reach it from node-e's address, never this
# machine's; and with no pass left for it the connection is refused rather
# than showing it a key it saw before.
ip netns add hv-e
ip link add e-i type veth peer name i-e; ip link set e-i netns hv-e; ip link set i-e netns hv-inet
$E ip addr add 10.206.0.2/24 dev e-i; $E ip link set e-i up; $E ip link set lo up; $E ip route add default via 10.206.0.1
$I ip addr add 10.206.0.1/24 dev i-e; $I ip link set i-e up
$E "$BIN/hidravpn-node" --config "$WORK/e.toml" init --endpoint 10.206.0.2:51820 --tunnel 10.79.0.0/16 --name node-e --role entry --operator third --open-admission --dns udp://10.201.0.2 --out-interface e-i > "$WORK/init-e.log" 2>&1 || { cat "$WORK/init-e.log"; fail "node-e init"; }
sed -i 's/^interface = "hvpn0"/interface = "hve0"/' "$WORK/e.toml"
mkdir -p "$WORK/run-e"
$E env HIDRAVPN_RUN_DIR="$WORK/run-e" "$BIN/hidravpn-node" --config "$WORK/e.toml" run > "$WORK/node-e.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 100); do grep -q "DNS forwarder ready" "$WORK/node-e.log" && grep -q "admission service on" "$WORK/node-e.log" && break; sleep 0.2; done
$E "$BIN/hidravpn-node" --config "$WORK/e.toml" record > "$WORK/rec-e.json" 2>/dev/null
HIDRAVPN_SIGN="$BIN/hidravpn-sign" bash "$HERE/make-node-list.sh" --key "$WORK/list.key" --out "$WORK/nodes3.json" --sequence 3 \
  --issuer-url http://10.200.0.1:8730 --pass-key "$WORK/pass-key.json" "$WORK/rec.json" "$WORK/rec-q.json" "$WORK/rec-e.json" > /dev/null 2>&1
OUT=$("$BIN/hidravpn" nodes import "$WORK/nodes3.json" --pubkey "$LISTPUB" 2>&1); echo "$OUT" | grep -q "added 1 node(s)" || fail "import v3: $OUT"
# node-p's passes leave the wallet, so node-q is the one exit with a pass;
# node-q gets two from a second account.
drop_passes() { python3 -I - "$1" <<'PY'
import json, sys
key = json.load(open(sys.argv[1]))['node_public_key'].strip()
w = json.load(open('/etc/hidravpn/passes.json'))
w['passes'] = [p for p in w.get('passes', []) if p['node_public_key'].strip() != key]
open('/etc/hidravpn/passes.json', 'w').write(json.dumps(w))
PY
}
drop_passes "$WORK/rec.json"; drop_passes "$WORK/rec-q.json"
TOKEN3=$($ISS account add --name carol --quota 5 2>/dev/null)
OUT=$($C "$BIN/hidravpn" passes get --node node-q --count 2 --token-file <(echo "$TOKEN3") 2>&1); echo "$OUT" | grep -q "2 pass(es) for 1 node(s)" || fail "passes for node-q: $OUT"
QP=$(q_passes)
$Q tcpdump -i q-i -U -n -w "$WORK/q.pcap" >/dev/null 2>&1 & TCPD=$!
sleep 1
R=$(svc '{"cmd":"connect","mode":"privado"}')
for i in $(seq 1 25); do svc '{"cmd":"status"}' | grep -q '"connected":true' && break; sleep 0.4; done
ST=$(svc '{"cmd":"status"}')
echo "$R" | grep -q '"ok":true' && echo "$ST" | grep -q '"entry_name":"node-e"' && echo "$ST" | grep -q '"node_name":"node-q"' && pass "two hops: node-e as the entry, node-q (which takes passes) as the exit" || fail "privado with a pass exit: $R $ST"
EXIT_IP=$($C curl -s --max-time 8 http://10.201.0.2/ 2>/dev/null); [ "$EXIT_IP" = "10.205.0.2" ] && pass "the internet sees node-q ($EXIT_IP)" || fail "privado exit IP '$EXIT_IP'"
[ "$(q_passes)" = $((QP - 1)) ] && grep -q "admitted a client with a pass" "$WORK/node-q.log" && pass "one of node-q's passes was redeemed for this connection" || fail "node-q passes: $QP -> $(q_passes)"
sleep 1; kill -INT $TCPD 2>/dev/null; wait $TCPD 2>/dev/null
FROM_CLIENT=$(tcpdump -n -r "$WORK/q.pcap" "src host 10.200.0.2 or dst host 10.200.0.2" 2>/dev/null | wc -l)
VIA_ENTRY=$(tcpdump -n -r "$WORK/q.pcap" "src host 10.206.0.2 and tcp dst port 51821" 2>/dev/null | wc -l)
[ "$FROM_CLIENT" = 0 ] && [ "$VIA_ENTRY" -gt 0 ] && pass "node-q never exchanged a packet with the client's address; the redemption came from the entry's ($VIA_ENTRY packets)" || fail "node-q saw the client: $FROM_CLIENT packets; via the entry: $VIA_ENTRY"
svc '{"cmd":"down"}' >/dev/null
# No pass left for the exit: refused, nothing sent to it, the machine open again.
drop_passes "$WORK/rec-q.json"
$Q tcpdump -i q-i -U -n -w "$WORK/q2.pcap" >/dev/null 2>&1 & TCPD=$!
sleep 1
R=$(svc '{"cmd":"connect","mode":"privado"}')
sleep 1; kill -INT $TCPD 2>/dev/null; wait $TCPD 2>/dev/null
ST=$(svc '{"cmd":"status"}')
echo "$R" | grep -q '"ok":false' && echo "$R" | grep -q "no pass left for node-" && echo "$R" | grep -q "only ever shown a key admitted through the entry" && echo "$ST" | grep -q '"connected":false' && echo "$ST" | grep -q '"killswitch":false' && pass "with no pass left for the exit of two hops, connect is refused and says why; it never falls back to a key the exit saw" || fail "no pass for the exit: $R $ST"
[ "$(tcpdump -n -r "$WORK/q2.pcap" "src host 10.200.0.2 or dst host 10.200.0.2" 2>/dev/null | wc -l)" = 0 ] && pass "and node-q heard nothing from the client" || fail "node-q heard from the client on a refused connect"

# ── Two hops through an entry that takes passes: none wasted on failures ───
# node-f, an entry that admits with a pass. When the exit cannot be used,
# nothing is spent on node-f; when the exit fails after node-f admitted this
# machine, node-f's lease is kept and the next try uses it instead of
# another pass, and the exit's pass, which never reached it, stays.
ip netns add hv-f
ip link add f-i type veth peer name i-f; ip link set f-i netns hv-f; ip link set i-f netns hv-inet
$F ip addr add 10.207.0.2/24 dev f-i; $F ip link set f-i up; $F ip link set lo up; $F ip route add default via 10.207.0.1
$I ip addr add 10.207.0.1/24 dev i-f; $I ip link set i-f up
$F "$BIN/hidravpn-node" --config "$WORK/f.toml" init --endpoint 10.207.0.2:51820 --tunnel 10.80.0.0/16 --name node-f --role entry --operator fourth --pass-admission --dns udp://10.201.0.2 --out-interface f-i > "$WORK/init-f.log" 2>&1 || { cat "$WORK/init-f.log"; fail "node-f init"; }
sed -i 's/^interface = "hvpn0"/interface = "hvf0"/' "$WORK/f.toml"
$F "$BIN/hidravpn-node" --config "$WORK/f.toml" pass-key add "$WORK/pass-key.json" > /dev/null 2>&1
mkdir -p "$WORK/run-f" "$WORK/f"
$F env HIDRAVPN_RUN_DIR="$WORK/run-f" "$BIN/hidravpn-node" --config "$WORK/f.toml" run > "$WORK/node-f.log" 2>&1 & PIDS+=($!)
for _ in $(seq 1 100); do grep -q "DNS forwarder ready" "$WORK/node-f.log" && grep -q "admission service on" "$WORK/node-f.log" && break; sleep 0.2; done
$F "$BIN/hidravpn-node" --config "$WORK/f.toml" record > "$WORK/rec-f.json" 2>/dev/null
HIDRAVPN_SIGN="$BIN/hidravpn-sign" bash "$HERE/make-node-list.sh" --key "$WORK/list.key" --out "$WORK/nodes4.json" --sequence 4 \
  --issuer-url http://10.200.0.1:8730 --pass-key "$WORK/pass-key.json" "$WORK/rec-f.json" "$WORK/rec-q.json" > /dev/null 2>&1
FP="$WORK/f/circuit.json"
OUT=$("$BIN/hidravpn" --pocket "$FP" nodes import "$WORK/nodes4.json" --pubkey "$LISTPUB" 2>&1); echo "$OUT" | grep -q "added 2 node(s)" || fail "import v4: $OUT"
TOKEN4=$($ISS account add --name dave --quota 10 2>/dev/null)
OUT=$($C "$BIN/hidravpn" --pocket "$FP" passes get --node node-f --count 2 --token-file <(echo "$TOKEN4") 2>&1); echo "$OUT" | grep -q "2 pass(es) for 1 node(s)" || fail "passes for node-f: $OUT"
left() { python3 -I - "$1" "$WORK/f/passes.json" <<'PY'
import json, sys
key = json.load(open(sys.argv[1]))['node_public_key'].strip()
print(sum(1 for p in json.load(open(sys.argv[2])).get('passes', []) if p['node_public_key'].strip() == key))
PY
}
f_lease() { python3 -I -c "import json,sys; e=[x for x in json.load(open(sys.argv[1]))['entries'] if x['node_name']=='node-f']; print(e[0]['pass']['client_secret'] if e and e[0].get('pass') else '-')" "$FP"; }
up2() { $C "$BIN/hidravpn" --direct --key /etc/hidravpn/client.key --pocket "$FP" up --privado 2>&1; }
OUT=$(up2)
echo "$OUT" | grep -q "no pass left for node-q" && [ "$(left "$WORK/rec-f.json")" = 2 ] && [ "$(f_lease)" = - ] && pass "no pass left for the exit: refused before anything is asked of the entry, whose 2 passes stay" || fail "no exit pass: $(echo "$OUT" | tail -1); node-f passes $(left "$WORK/rec-f.json"), lease $(f_lease)"
OUT=$($C "$BIN/hidravpn" --pocket "$FP" passes get --node node-q --count 2 --token-file <(echo "$TOKEN4") 2>&1); echo "$OUT" | grep -q "2 pass(es) for 1 node(s)" || fail "passes for node-q: $OUT"
# node-q stops answering: its kernel still takes the connection, and the
# redemption through node-f waits for a reply that never comes.
kill -STOP "$NODE_Q"
OUT=$(up2)
L1=$(f_lease)
[ "$(left "$WORK/rec-f.json")" = 1 ] && [ "$L1" != - ] && [ "$(left "$WORK/rec-q.json")" = 2 ] && pass "the exit did not answer: one of node-f's passes was spent and its lease kept; node-q's pass, never redeemed, is back in the wallet" || fail "exit hung: $(echo "$OUT" | tail -1); node-f $(left "$WORK/rec-f.json") lease $L1, node-q $(left "$WORK/rec-q.json")"
OUT=$(up2)
[ "$(left "$WORK/rec-f.json")" = 1 ] && [ "$(f_lease)" = "$L1" ] && [ "$(left "$WORK/rec-q.json")" = 2 ] && pass "the next try uses node-f's kept lease: no pass spent on either node" || fail "second try: $(echo "$OUT" | tail -1); node-f $(left "$WORK/rec-f.json") lease $(f_lease), node-q $(left "$WORK/rec-q.json")"
kill -CONT "$NODE_Q"
{ $C ip link show hvpn0 || $C nft list table inet hidravpn_ks; } >/dev/null 2>&1 && fail "a failed two-hop try left a tunnel or the kill switch behind" || pass "the failed tries left nothing behind"

# ── A pass spent once is refused the second time ────────────────────────────
OUT=$($C "$BIN/hidravpn" --pocket "$WORK/again/circuit.json" nodes join --all 2>&1)
echo "$OUT" | grep -q "already spent" && pass "the same pass, redeemed again from a copy of the wallet, is refused: already spent" || fail "double spend: $OUT"

# ── A switched-off account gets nothing ─────────────────────────────────────
$ISS account disable alice > /dev/null 2>&1
TOKEN2=$($ISS account add --name bob --quota 10 2>/dev/null); $ISS account disable bob > /dev/null 2>&1
OUT=$($C "$BIN/hidravpn" passes get --count 1 --token-file <(echo "$TOKEN2") 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "switched off" && pass "a switched-off account is refused" || fail "disabled: $OUT"
OUT=$($C "$BIN/hidravpn" passes get --count 1 --token-file <(echo "not-a-token") 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "not an account token" && pass "a token nobody issued is refused" || fail "unknown token: $OUT"

# ── Nothing identifying in the logs ─────────────────────────────────────────
grep -qE "10\.200\.0\.2|10\.7[789]\.0\.[2-9]" "$WORK/svc.log" "$WORK/node.log" "$WORK/node-q.log" "$WORK/node-e.log" "$WORK/issuer.log" && fail "a log names the client" || pass "no log names the client's address"
grep -qF -e "$TOKEN" -e "$TOKEN3" -e "alice" -e "bob" -e "carol" "$WORK/issuer.log" "$WORK/svc.log" "$WORK/node.log" "$WORK/node-q.log" && fail "a log names an account or a token" || pass "no log names an account or a token"
grep -qF "$KEY1" "$WORK/svc.log" "$WORK/node.log" && fail "a log holds a pass key" || pass "no log holds a pass's key"

echo; echo "$ok passed, $bad failed"; [ $bad -eq 0 ]
