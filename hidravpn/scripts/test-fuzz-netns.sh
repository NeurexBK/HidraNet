#!/usr/bin/env bash
# The three doors that take requests from anyone — a node's /admit, a node's
# /redeem and the issuer's /issue — under thousands of broken and mutated
# requests (scripts/test/fuzz-http.py). Three namespaces:
#
#   hv-fo (node-o, open)  ──veth──  hv-fc (the fuzzer)  ──veth──  hv-fp (node-p, pass; the issuer)
#   10.210.0.1                      10.210.0.2 / 10.211.0.2        10.211.0.1
#
# It proves: every answer is a well-formed HTTP answer with an expected
# status, never a 500 and never a hang; broken JSON, broken HTTP, oversized
# and half-sent requests are refused; nothing is signed or charged for a
# broken request; a pass written differently is still one pass, taken once;
# a half-open connection is dropped on time; afterwards every door still
# works, both nodes and the issuer are still running, nothing panicked, and
# no log names an address, a token or a key.
#
# Run as root:  hidravpn/scripts/test-fuzz-netns.sh [ROUNDS] [SEED]
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/test/guard.sh"
BIN="$HERE/../target/release"
ROUNDS="${1:-3000}"
SEED="${2:-$RANDOM}"
WORK=""
F="ip netns exec hv-fc"; O="ip netns exec hv-fo"; P="ip netns exec hv-fp"
PIDS=()
export RUST_BACKTRACE=0
export HIDRAVPN_PLAIN_HTTP_ISSUER=1
ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok + 1)); }
fail() { echo "FAIL  $1"; bad=$((bad + 1)); }
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  sleep 0.5
  for ns in hv-fc hv-fo hv-fp; do ip netns del "$ns" 2>/dev/null; done
  rm -rf /etc/hidravpn/client.key /etc/hidravpn/circuit.json /etc/hidravpn/passes.json /etc/hidravpn/pass.token \
         /var/run/wireguard/hvo0.sock /var/run/wireguard/hvp0.sock
  [ -n "${WORK:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
cleanup
WORK="$(mktemp -d /tmp/hidravpn-fuzz.XXXXXX)"
for b in hidravpn hidravpn-node hidravpn-sign hidravpn-issuer; do [ -x "$BIN/$b" ] || { echo "build first: cargo build --release --manifest-path hidravpn/Cargo.toml"; exit 1; }; done
echo "rounds $ROUNDS, seed $SEED"

# ── Network ─────────────────────────────────────────────────────────────────
ip netns add hv-fc; ip netns add hv-fo; ip netns add hv-fp
ip link add f-o type veth peer name o-f; ip link set f-o netns hv-fc; ip link set o-f netns hv-fo
ip link add f-p type veth peer name p-f; ip link set f-p netns hv-fc; ip link set p-f netns hv-fp
$F ip addr add 10.210.0.2/24 dev f-o; $F ip addr add 10.211.0.2/24 dev f-p
$F ip link set f-o up; $F ip link set f-p up; $F ip link set lo up
$O ip addr add 10.210.0.1/24 dev o-f; $O ip link set o-f up; $O ip link set lo up
$P ip addr add 10.211.0.1/24 dev p-f; $P ip link set p-f up; $P ip link set lo up

# ── The issuer, and an account ──────────────────────────────────────────────
ISS="$BIN/hidravpn-issuer --accounts $WORK/accounts.json"
$ISS keygen --out "$WORK/issuer-key.json" --days 30 > "$WORK/pass-key.json" 2>/dev/null || { fail "issuer keygen"; exit 1; }
KEY_ID=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$WORK/pass-key.json")
$ISS account add --name fuzz --quota 20 > "$WORK/token" 2>/dev/null
$P $ISS run --key "$WORK/issuer-key.json" --listen 10.211.0.1:8730 --plain-http-public > "$WORK/issuer.log" 2>&1 & PIDS+=($!); ISS_PID=$!
for i in $(seq 1 50); do grep -q "pass issuer on TCP 8730" "$WORK/issuer.log" && break; sleep 0.2; done
grep -q "pass issuer on TCP 8730" "$WORK/issuer.log" && pass "the issuer is up" || { cat "$WORK/issuer.log"; fail "issuer"; exit 1; }

# ── The nodes ───────────────────────────────────────────────────────────────
$O "$BIN/hidravpn-node" --config "$WORK/o.toml" init --endpoint 10.210.0.1:51820 --name node-o --role exit --open-admission --max-clients 50 --out-interface o-f > "$WORK/init-o.log" 2>&1 || { cat "$WORK/init-o.log"; fail "node-o init"; exit 1; }
sed -i 's/^interface = "hvpn0"/interface = "hvo0"/' "$WORK/o.toml"
$P "$BIN/hidravpn-node" --config "$WORK/p.toml" init --endpoint 10.211.0.1:51820 --name node-p --role exit --pass-admission --out-interface p-f > "$WORK/init-p.log" 2>&1 || { cat "$WORK/init-p.log"; fail "node-p init"; exit 1; }
sed -i 's/^interface = "hvpn0"/interface = "hvp0"/' "$WORK/p.toml"
$P "$BIN/hidravpn-node" --config "$WORK/p.toml" pass-key add "$WORK/pass-key.json" > /dev/null 2>&1
mkdir -p "$WORK/run-o" "$WORK/run-p"
$O env HIDRAVPN_RUN_DIR="$WORK/run-o" "$BIN/hidravpn-node" --config "$WORK/o.toml" run > "$WORK/node-o.log" 2>&1 & PIDS+=($!); O_PID=$!
$P env HIDRAVPN_RUN_DIR="$WORK/run-p" "$BIN/hidravpn-node" --config "$WORK/p.toml" run > "$WORK/node-p.log" 2>&1 & PIDS+=($!); P_PID=$!
for _ in $(seq 1 100); do grep -q "admission service on" "$WORK/node-o.log" && grep -q "admission service on" "$WORK/node-p.log" && break; sleep 0.2; done
grep -q "admission service on TCP 51821 (open" "$WORK/node-o.log" && pass "node-o is up, open" || { tail -5 "$WORK/node-o.log"; fail "node-o"; exit 1; }
grep -q "admission service on TCP 51821 (with a pass" "$WORK/node-p.log" && pass "node-p is up, with passes" || { tail -5 "$WORK/node-p.log"; fail "node-p"; exit 1; }

# ── One real pass for node-p, to mutate ─────────────────────────────────────
$P "$BIN/hidravpn-node" --config "$WORK/p.toml" record > "$WORK/rec-p.json" 2>/dev/null
LISTPUB=$("$BIN/hidravpn-sign" keygen --out "$WORK/list.key" 2>/dev/null)
HIDRAVPN_SIGN="$BIN/hidravpn-sign" bash "$HERE/make-node-list.sh" --key "$WORK/list.key" --out "$WORK/nodes.json" --sequence 1 \
  --issuer-url http://10.211.0.1:8730 --pass-key "$WORK/pass-key.json" "$WORK/rec-p.json" > /dev/null 2>&1
mkdir -p /etc/hidravpn
"$BIN/hidravpn" keygen >/dev/null 2>&1
"$BIN/hidravpn" nodes import "$WORK/nodes.json" --pubkey "$LISTPUB" > /dev/null 2>&1
"$BIN/hidravpn" passes token "$WORK/token" > /dev/null 2>&1
OUT=$($F "$BIN/hidravpn" passes get --count 1 2>&1); echo "$OUT" | grep -q "1 pass(es)" && pass "a real pass for node-p" || { fail "passes get: $OUT"; exit 1; }
python3 -I - /etc/hidravpn/passes.json "$WORK/redemption.json" <<'PY'
import base64, json, sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
p = json.load(open(sys.argv[1]))["passes"][0]
sk = X25519PrivateKey.from_private_bytes(base64.b64decode(p["client_secret"]))
pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
red = {k: p[k] for k in ("key_id", "node_public_key", "nonce", "randomizer", "signature")}
red["client_public_key"] = base64.b64encode(pub).decode()
json.dump(red, open(sys.argv[2], "w"))
PY
[ -s "$WORK/redemption.json" ] && pass "its redemption, as the node will be shown it" || { fail "redemption"; exit 1; }

# ── Fuzz ────────────────────────────────────────────────────────────────────
cp "$WORK/accounts.json" "$WORK/accounts-before.json"
$F python3 -I "$HERE/test/fuzz-http.py" --open 10.210.0.1:51821 --pass 10.211.0.1:51821 --issuer 10.211.0.1:8730 \
   --redemption "$WORK/redemption.json" --token-file "$WORK/token" --key-id "$KEY_ID" --rounds "$ROUNDS" --seed "$SEED" > "$WORK/fuzz.log" 2>&1
FZ=$?
grep -E '^(FINDING|closed without)' "$WORK/fuzz.log" | head -20
tail -3 "$WORK/fuzz.log"
[ $FZ -eq 0 ] && pass "the fuzzer found nothing: $(tail -2 "$WORK/fuzz.log" | head -1)" || fail "the fuzzer: $(grep -c '^FINDING' "$WORK/fuzz.log") finding(s) (seed $SEED)"

# ── Afterwards ──────────────────────────────────────────────────────────────
kill -0 $O_PID 2>/dev/null && kill -0 $P_PID 2>/dev/null && kill -0 $ISS_PID 2>/dev/null && pass "both nodes and the issuer are still running" || fail "a process died: o $(kill -0 $O_PID 2>/dev/null && echo up || echo DOWN), p $(kill -0 $P_PID 2>/dev/null && echo up || echo DOWN), issuer $(kill -0 $ISS_PID 2>/dev/null && echo up || echo DOWN)"
grep -qi "panicked" "$WORK"/node-o.log "$WORK"/node-p.log "$WORK"/issuer.log && fail "a panic: $(grep -i -m3 panicked "$WORK"/*.log)" || pass "nothing panicked"
RSS_O=$(awk '/VmRSS/{print $2}' /proc/$O_PID/status 2>/dev/null); RSS_P=$(awk '/VmRSS/{print $2}' /proc/$P_PID/status 2>/dev/null); RSS_I=$(awk '/VmRSS/{print $2}' /proc/$ISS_PID/status 2>/dev/null)
[ "${RSS_O:-999999}" -lt 100000 ] && [ "${RSS_P:-999999}" -lt 100000 ] && [ "${RSS_I:-999999}" -lt 100000 ] && pass "memory stays small: node-o ${RSS_O} kB, node-p ${RSS_P} kB, issuer ${RSS_I} kB" || fail "memory: node-o ${RSS_O:-?} kB, node-p ${RSS_P:-?} kB, issuer ${RSS_I:-?} kB"
python3 -I - "$WORK/accounts-before.json" "$WORK/accounts.json" <<'PY' && pass "the fuzzing charged the account nothing" || fail "the account was charged by the fuzzing"
import json, sys
def used(path):
    a = json.load(open(path))
    accs = a.get("accounts", a) if isinstance(a, dict) else a
    if isinstance(accs, dict):
        accs = list(accs.values())
    return [(x.get("used_today", x.get("used")), x.get("day")) for x in accs]
sys.exit(0 if used(sys.argv[1]) == used(sys.argv[2]) else 1)
PY
TOKEN=$(cat "$WORK/token"); CPUB=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["client_public_key"])' "$WORK/redemption.json")
# Fixed strings: a token or a key in base64 is no pattern ("+" would be one).
LOGS="$WORK/node-o.log $WORK/node-p.log $WORK/issuer.log"
if [ -z "$TOKEN" ] || [ -z "$CPUB" ]; then fail "no token or key to look for"
elif grep -E "10\.21[01]\.0\.2" $LOGS >/dev/null || grep -F -e "$TOKEN" -e "$CPUB" $LOGS >/dev/null; then fail "a log names an address, the token or a key"
else pass "no log names the fuzzer's address, the token or the pass's key"; fi
LINES=$(cat "$WORK"/node-o.log "$WORK"/node-p.log "$WORK"/issuer.log | wc -l)
[ "$LINES" -lt 2000 ] && pass "the logs stay short ($LINES lines for all of it)" || fail "the logs grew to $LINES lines"

echo; echo "$ok passed, $bad failed"; [ $bad -eq 0 ]
