#!/usr/bin/env bash
# A node under load (scripts/test/load-http.py). Four namespaces:
#
#   hv-lc (the crowd: 150 addresses) ──┬── hv-lo (node-o, open, 41 clients at most)
#                                      │       └── hv-lr (a real client, connected the whole time)
#                                      └── hv-lp (node-p, admits with passes, 40 at most; the issuer)
#
# It proves: 300 admissions at once from 150 addresses fill node-o exactly
# to its limit (the real client holds two leases: the key its operator
# admitted, and the session key made for its connection, which is the one
# an open node is shown), every client with its own address, the rest told "full" or
# "too many" and nobody left hanging; meanwhile the real client's tunnel
# keeps carrying traffic; idle connections hold the door for no longer than
# the per-connection timeout; 100 passes, each sent twice at once, fill
# node-p exactly to its limit, no pass taken twice, a pass refused for "full"
# not spent (so the client keeps it); a node with 100 000 spent passes on
# record still takes a redemption quickly; and afterwards both nodes and the
# issuer are running, nothing panicked and no log names an address.
#
# Run as root:  hidravpn/scripts/test-load-netns.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/test/guard.sh"
BIN="$HERE/../target/release"
WORK=""
LC="ip netns exec hv-lc"; LO="ip netns exec hv-lo"; LP="ip netns exec hv-lp"; LR="ip netns exec hv-lr"
PIDS=()
export RUST_BACKTRACE=0
export HIDRAVPN_PLAIN_HTTP_ISSUER=1
LOAD="python3 -I $HERE/test/load-http.py"
ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok + 1)); }
fail() { echo "FAIL  $1"; bad=$((bad + 1)); }
# Spent passes on record: the snapshot and the journal beside it.
spent_count() { python3 -I - "$1" <<'PY'
import json, os, sys
d = sys.argv[1]
tags = set()
if os.path.exists(d + "/spent.json"):
    tags |= set(json.load(open(d + "/spent.json")).get("tags", {}))
if os.path.exists(d + "/spent.log"):
    tags |= {l.split()[0] for l in open(d + "/spent.log") if len(l.split()) == 2}
print(len(tags))
PY
}
jget() { python3 -I -c 'import json,sys; d=json.loads(sys.argv[1]); print(eval(sys.argv[2], {}, {"d": d}))' "$1" "$2"; }
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  ip netns pids hv-lr 2>/dev/null | xargs -r kill 2>/dev/null
  sleep 0.5
  for ns in hv-lc hv-lo hv-lp hv-lr; do ip netns del "$ns" 2>/dev/null; done
  rm -rf /etc/netns/hv-lr /run/hidravpn/netcfg.json /etc/hidravpn/client.key /etc/hidravpn/circuit.json \
         /etc/hidravpn/passes.json /etc/hidravpn/pass.token /var/run/wireguard/hvo0.sock /var/run/wireguard/hvp0.sock
  [ -n "${WORK:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
cleanup
WORK="$(mktemp -d /tmp/hidravpn-load.XXXXXX)"
for b in hidravpn hidravpn-node hidravpn-sign hidravpn-issuer; do [ -x "$BIN/$b" ] || { echo "build first: cargo build --release --manifest-path hidravpn/Cargo.toml"; exit 1; }; done

# ── Network ─────────────────────────────────────────────────────────────────
for ns in hv-lc hv-lo hv-lp hv-lr; do ip netns add $ns; ip netns exec $ns ip link set lo up; done
ip link add c-o type veth peer name o-c; ip link set c-o netns hv-lc; ip link set o-c netns hv-lo
ip link add c-p type veth peer name p-c; ip link set c-p netns hv-lc; ip link set p-c netns hv-lp
ip link add r-o type veth peer name o-r; ip link set r-o netns hv-lr; ip link set o-r netns hv-lo
$LO ip addr add 10.220.0.1/24 dev o-c; $LO ip link set o-c up
$LO ip addr add 10.222.0.1/24 dev o-r; $LO ip link set o-r up
$LP ip addr add 10.221.0.1/24 dev p-c; $LP ip link set p-c up
$LR ip addr add 10.222.0.2/24 dev r-o; $LR ip link set r-o up; $LR ip route add default via 10.222.0.1
$LC ip link set c-o up; $LC ip link set c-p up; $LC ip addr add 10.221.0.2/24 dev c-p
SOURCES=""
# 10.220.0.10 first: the crowd's DNS server answers from it.
$LC ip addr add 10.220.0.10/24 dev c-o
for i in $(seq 11 160); do $LC ip addr add 10.220.0.$i/24 dev c-o; SOURCES="$SOURCES,10.220.0.$i"; done
SOURCES="${SOURCES#,}"
PSOURCES=""
for i in $(seq 10 109); do $LC ip addr add 10.221.0.$i/24 dev c-p; PSOURCES="$PSOURCES,10.221.0.$i"; done
PSOURCES="${PSOURCES#,}"
mkdir -p /etc/netns/hv-lr; echo "nameserver 10.222.0.1" > /etc/netns/hv-lr/resolv.conf
# The "internet" DNS server node-o forwards to, on the crowd's side.
$LC python3 -I "$HERE/test/dns-stub.py" 10.220.0.10 > "$WORK/dns.log" 2>&1 & PIDS+=($!)

# ── node-o, open, and a real client on it ───────────────────────────────────
$LO "$BIN/hidravpn-node" --config "$WORK/o.toml" init --endpoint 10.222.0.1:51820 --name node-o --role exit --open-admission --max-clients 41 --dns udp://10.220.0.10 --out-interface o-c > "$WORK/init-o.log" 2>&1 || { cat "$WORK/init-o.log"; fail "node-o init"; exit 1; }
sed -i 's/^interface = "hvpn0"/interface = "hvo0"/' "$WORK/o.toml"
mkdir -p "$WORK/run-o" "$WORK/run-p"
NODE_PUB=$(grep -o 'node public key: .*' "$WORK/init-o.log" | cut -d' ' -f4)
$LR "$BIN/hidravpn" --key "$WORK/real.key" keygen >/dev/null 2>&1
RPUB=$($LR "$BIN/hidravpn" --key "$WORK/real.key" pubkey --node "$NODE_PUB" 2>/dev/null)
$LO env HIDRAVPN_RUN_DIR="$WORK/run-o" "$BIN/hidravpn-node" --config "$WORK/o.toml" admit --name real --pubkey "$RPUB" > "$WORK/real-invite.json" 2>/dev/null
$LO env HIDRAVPN_RUN_DIR="$WORK/run-o" "$BIN/hidravpn-node" --config "$WORK/o.toml" run > "$WORK/node-o.log" 2>&1 & PIDS+=($!); O_PID=$!
for i in $(seq 1 100); do grep -q "admission service on" "$WORK/node-o.log" && break; sleep 0.2; done
grep -q "admission service on TCP 51821 (open" "$WORK/node-o.log" && pass "node-o is up, open, 41 clients at most" || { tail -5 "$WORK/node-o.log"; fail "node-o"; exit 1; }
$LR "$BIN/hidravpn" --key "$WORK/real.key" up "$WORK/real-invite.json" > "$WORK/real.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 100); do grep -q "^connected" "$WORK/real.log" && break; sleep 0.2; done
grep -q "^connected" "$WORK/real.log" && pass "a real client is connected to node-o" || { cat "$WORK/real.log"; fail "real client"; exit 1; }

# ── The operator admits and revokes by hand while the node runs ─────────────
NODE_O="$LO env HIDRAVPN_RUN_DIR=$WORK/run-o $BIN/hidravpn-node --config $WORK/o.toml"
key() { python3 -I -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())'; }
HAND=$(key); K1=$(key); K2=$(key)
HAND_IP=$($NODE_O admit --name by-hand --pubkey "$HAND" 2>/dev/null | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["client_address"])')
admit_from() { $LC curl -s --max-time 5 --interface "$1" -X POST -d "{\"public_key\":\"$2\",\"name\":\"x\"}" http://10.220.0.1:51821/admit | python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("client_address","?"))'; }
IP1=$(admit_from 10.220.0.11 "$K1")
[ -n "$HAND_IP" ] && [ "$IP1" != "?" ] && [ "$IP1" != "$HAND_IP" ] && pass "a client the operator admitted by hand while the node ran keeps its address; the next one gets another ($HAND_IP, $IP1)" || fail "addresses: by hand '$HAND_IP', then '$IP1'"
$NODE_O revoke --pubkey "$HAND" >/dev/null 2>&1
IP2=$(admit_from 10.220.0.12 "$K2")
grep -q "$HAND" "$WORK/run-o/peers.json" && fail "the node wrote a revoked lease back" || pass "a lease revoked while the node ran stays revoked after the node next writes its leases ($IP2)"
$NODE_O revoke --pubkey "$K1" >/dev/null 2>&1; $NODE_O revoke --pubkey "$K2" >/dev/null 2>&1
# The real client's two: the key admitted by hand, and the session key made
# for its connection (an open node is shown a key for one connection only).
[ "$(python3 -I -c 'import json,sys; ls=json.load(open(sys.argv[1]))["leases"]; print(len(ls), sorted(l["source"] for l in ls))' "$WORK/run-o/peers.json")" = "2 ['manual', 'session']" ] && pass "revoked by hand, only the real client's leases are left (by hand, and its session)" || fail "leases: $(cat "$WORK/run-o/peers.json")"

# ── 300 admissions at once, while the real client uses its tunnel ──────────
# 40 names looked up through the tunnel (the node's resolver), one every
# tenth of a second, while the crowd comes.
$LR python3 -I -c '
import socket, time
ok = 0
for i in range(40):
    try:
        socket.gethostbyname("n%d.whoami.test" % i); ok += 1
    except OSError:
        pass
    time.sleep(0.1)
print(ok)' > "$WORK/lookups.log" 2>&1 & PING=$!
R=$($LC $LOAD admit 10.220.0.1:51821 "$SOURCES" 2)
echo "      $R"
wait $PING
[ "$(jget "$R" 'd["admitted"]')" = 39 ] && pass "node-o took exactly 39 of 300 (its limit, with the real client's two leases)" || fail "admitted: $R"
[ "$(jget "$R" 'd["distinct_addresses"]')" = 39 ] && pass "every admitted client got its own address" || fail "addresses: $R"
[ "$(jget "$R" 'd["statuses"].get("503", 0) + d["statuses"].get("429", 0)')" = 261 ] && pass "the other 261 were told the node is full or the requests too many" || fail "statuses: $R"
[ "$(jget "$R" 'int(d["slowest_secs"] < 6)')" = 1 ] && pass "nobody waited past the timeout (slowest $(jget "$R" 'd["slowest_secs"]') s)" || fail "slow answers: $R"
LOOKUPS=$(cat "$WORK/lookups.log")
[ "$LOOKUPS" -ge 38 ] 2>/dev/null && pass "the real client's tunnel kept working through it ($LOOKUPS of 40 lookups answered)" || fail "the real client's lookups: $LOOKUPS"
LEASES=$(python3 -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["leases"]))' "$WORK/run-o/peers.json")
[ "$LEASES" = 41 ] && pass "the leases file holds 41 leases" || fail "leases: $LEASES"

# ── Idle connections ────────────────────────────────────────────────────────
R=$($LC $LOAD idle 10.220.0.1:51821 10.220.0.11 300 10.220.0.12)
echo "      $R"
[ "$(jget "$R" 'd["get_status"]')" = 200 ] && [ "$(jget "$R" 'int(d["get_secs"] < 1)')" = 1 ] && pass "300 idle connections from one address do not hold the door ($(jget "$R" 'd["get_secs"]') s for the next request)" || fail "behind one address's idle connections: $R"
R=$($LC $LOAD idle 10.220.0.1:51821 "${SOURCES%,10.220.0.160}" 1 10.220.0.160)
echo "      $R"
[ "$(jget "$R" 'd["get_status"]')" = 200 ] && [ "$(jget "$R" 'int(d["get_secs"] < 1)')" = 1 ] && pass "nor do 149 idle connections from 149 addresses ($(jget "$R" 'd["get_secs"]') s)" || fail "behind 150 addresses' idle connections: $R"

# ── node-p, with passes, and the issuer ─────────────────────────────────────
ISS="$BIN/hidravpn-issuer --accounts $WORK/accounts.json"
$ISS keygen --out "$WORK/issuer-key.json" --days 30 > "$WORK/pass-key.json" 2>/dev/null
$ISS account add --name load --quota 500 > "$WORK/token" 2>/dev/null
$LP $ISS run --key "$WORK/issuer-key.json" --listen 10.221.0.1:8730 --plain-http-public > "$WORK/issuer.log" 2>&1 & PIDS+=($!); ISS_PID=$!
$LP "$BIN/hidravpn-node" --config "$WORK/p.toml" init --endpoint 10.221.0.1:51820 --name node-p --role exit --pass-admission --max-clients 40 --out-interface p-c > "$WORK/init-p.log" 2>&1 || { cat "$WORK/init-p.log"; fail "node-p init"; exit 1; }
sed -i 's/^interface = "hvpn0"/interface = "hvp0"/' "$WORK/p.toml"
$LP "$BIN/hidravpn-node" --config "$WORK/p.toml" pass-key add "$WORK/pass-key.json" > /dev/null 2>&1
$LP env HIDRAVPN_RUN_DIR="$WORK/run-p" "$BIN/hidravpn-node" --config "$WORK/p.toml" run > "$WORK/node-p.log" 2>&1 & PIDS+=($!); P_PID=$!
for i in $(seq 1 100); do grep -q "admission service on" "$WORK/node-p.log" && grep -q "pass issuer on" "$WORK/issuer.log" && break; sleep 0.2; done
grep -q "admission service on TCP 51821 (with a pass" "$WORK/node-p.log" && pass "node-p is up, with passes, 40 clients at most" || { tail -5 "$WORK/node-p.log"; fail "node-p"; exit 1; }
PPUB=$(grep -o 'node public key: .*' "$WORK/init-p.log" | cut -d' ' -f4)
$LP "$BIN/hidravpn-node" --config "$WORK/p.toml" record > "$WORK/rec-p.json" 2>/dev/null
LISTPUB=$("$BIN/hidravpn-sign" keygen --out "$WORK/list.key" 2>/dev/null)
HIDRAVPN_SIGN="$BIN/hidravpn-sign" bash "$HERE/make-node-list.sh" --key "$WORK/list.key" --out "$WORK/nodes.json" --sequence 1 \
  --issuer-url http://10.221.0.1:8730 --pass-key "$WORK/pass-key.json" "$WORK/rec-p.json" > /dev/null 2>&1
mkdir -p /etc/hidravpn
"$BIN/hidravpn" keygen >/dev/null 2>&1
"$BIN/hidravpn" nodes import "$WORK/nodes.json" --pubkey "$LISTPUB" > /dev/null 2>&1
"$BIN/hidravpn" passes token "$WORK/token" > /dev/null 2>&1
T0=$(date +%s.%N)
OUT=$($LC "$BIN/hidravpn" passes get --count 100 2>&1)
T1=$(date +%s.%N)
echo "$OUT" | grep -q "100 pass(es)" && pass "100 passes in one go ($(python3 -c "print(round($T1-$T0,1))") s, sixteen at a time)" || { fail "passes get: $OUT"; exit 1; }
$LOAD wallet-to-redemptions /etc/hidravpn/passes.json "$WORK/all.json" "$PPUB" > /dev/null
cp "$WORK/all.json" "$WORK/reds.json"

# ── 100 passes, each sent twice at once ─────────────────────────────────────
R=$($LC $LOAD redeem 10.221.0.1:51821 "$WORK/reds.json" 2 "$PSOURCES" "$WORK/untaken.json")
echo "      $R"
[ "$(jget "$R" 'd["passes_taken"]')" = 40 ] && pass "node-p took exactly 40 passes (its limit)" || fail "taken: $R"
[ "$(jget "$R" 'd["passes_taken_twice"]')" = 0 ] && pass "no pass was taken twice, though each came twice at the same moment" || fail "taken twice: $R"
[ "$(jget "$R" 'd["distinct_addresses"]')" = 40 ] && pass "every pass client got its own address" || fail "addresses: $R"
[ "$(jget "$R" 'd["statuses"].get("409", 0)')" = 40 ] && [ "$(jget "$R" 'd["statuses"].get("503", 0)')" = 120 ] && pass "the second copy of each taken pass was refused as spent (40), the rest as full (120)" || fail "statuses: $R"
[ "$(jget "$R" 'int(d["slowest_secs"] < 6)')" = 1 ] && pass "nobody waited past the timeout (slowest $(jget "$R" 'd["slowest_secs"]') s)" || fail "slow: $R"
SPENT=$(spent_count "$WORK/run-p")
[ "$SPENT" = 40 ] && pass "40 passes written down as spent: one refused for \"full\" is not spent, the client keeps it" || fail "spent: $SPENT"

# ── A node with 100 000 spent passes on record ──────────────────────────────
# (HV_ON_RECORD=N for another number, to measure.)
ON_RECORD="${HV_ON_RECORD:-100000}"
kill -INT $P_PID; for i in $(seq 1 25); do kill -0 $P_PID 2>/dev/null || break; sleep 0.2; done
python3 -I - "$WORK/run-p/spent.json" "$ON_RECORD" <<'PY'
import json, sys, os, time
d = json.load(open(sys.argv[1])) if os.path.exists(sys.argv[1]) else {"tags": {}}
until = int(time.time()) + 30 * 86400
for i in range(int(sys.argv[2])):
    d["tags"][os.urandom(32).hex()] = until
json.dump(d, open(sys.argv[1], "w"))
PY
python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); d["leases"]=[]; json.dump(d, open(sys.argv[1],"w"))' "$WORK/run-p/peers.json" 2>/dev/null
$LP env HIDRAVPN_RUN_DIR="$WORK/run-p" "$BIN/hidravpn-node" --config "$WORK/p.toml" run > "$WORK/node-p2.log" 2>&1 & PIDS+=($!); P_PID=$!
for i in $(seq 1 100); do grep -q "admission service on" "$WORK/node-p2.log" && break; sleep 0.2; done
python3 -I -c 'import json,sys; r=json.load(open(sys.argv[1])); json.dump(r[:20], open(sys.argv[2],"w"))' "$WORK/untaken.json" "$WORK/twenty.json"
R=$($LC $LOAD redeem 10.221.0.1:51821 "$WORK/twenty.json" 1 "$PSOURCES")
echo "      $R"
[ "$(jget "$R" 'd["passes_taken"]')" = 20 ] && [ "$(jget "$R" 'int(d["slowest_secs"] < 1)')" = 1 ] && pass "with $ON_RECORD spent passes on record, 20 redemptions at once are all taken, the slowest in $(jget "$R" 'd["slowest_secs"]') s" || fail "redemptions on a long spent list: $R"
SPENT=$(spent_count "$WORK/run-p")
[ "$SPENT" = $((ON_RECORD + 60)) ] && pass "and all $((ON_RECORD + 60)) stay written down" || fail "spent after: $SPENT"

# ── Afterwards ──────────────────────────────────────────────────────────────
kill -0 $O_PID 2>/dev/null && kill -0 $P_PID 2>/dev/null && kill -0 $ISS_PID 2>/dev/null && pass "both nodes and the issuer are still running" || fail "a process died"
grep -qi panicked "$WORK"/node-*.log "$WORK"/issuer.log && fail "a panic: $(grep -i -m3 panicked "$WORK"/*.log)" || pass "nothing panicked"
grep -E '10\.22[0-2]\.0\.([2-9]|1[1-9]|[2-9][0-9]|1[0-9][0-9])\b|10\.77\.0\.[2-9]' "$WORK"/node-*.log "$WORK"/issuer.log >/dev/null && fail "a log names an address: $(grep -E -m3 '10\.22[0-2]\.0\.[0-9]+' "$WORK"/node-*.log)" || pass "no log names a client's address"

echo; echo "$ok passed, $bad failed"; [ $bad -eq 0 ]
