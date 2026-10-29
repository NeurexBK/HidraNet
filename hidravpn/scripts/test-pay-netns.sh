#!/usr/bin/env bash
# Passes bought with HNET, end to end (phase 7): an issuer that sells packs,
# a stand-in for Solana's RPC, a node that admits with a pass, and a client
# that opens an order, "pays" it, claims it and connects. Three namespaces:
#
#   hv-client ──veth── hv-node ──veth── hv-inet
#   10.200.0.2        10.200.0.1        10.201.0.2  (the "internet": the
#                     10.201.0.1                     chain's RPC, TCP 8899,
#                                                    the price feed, TCP 8898)
#                     node-p: exit, admission "pass", UDP 51820, TCP 51821
#                     the issuer on TCP 8730, selling passes
#
# It proves: the issuer sells only with a wallet and packs, and tells the
# packs; a pack priced in dollars is sold at the going rate from a price
# feed, a wild move of the rate is held until the feed insists, and a feed
# that is down makes such a pack not for sale once the rate is stale;
# an order is the pack's price plus a tag of its own, to the wallet,
# kept root-only beside the pocket with a token made for it; a claim with no
# transaction, a failed one, one of another amount, one from before the
# order, or one that already paid is refused, each with its reason; the
# right one credits the pack, once, and the token then gets passes, prepaid;
# a second purchase tops the account up; someone who saw the payment on
# chain cannot claim it without the token, nor with an order of their own;
# a flood of quotes is slowed, while a flood of claims for tokens with no
# order, of quotes past a token's orders open and of claims on that token's
# own orders crowds no buyer out, one token's claims at once are bounded; a
# request not sent as JSON is refused; an order no claim reached lapses in
# two hours, and a lapsed order paid in time is credited by hand; the node
# admits with a pass bought this way; the issuer's files keep hashes only;
# and no log names the wallet, a transaction, an amount, a token or the
# client.
#
# Run as root:  hidravpn/scripts/test-pay-netns.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/test/guard.sh"
BIN="$HERE/../target/release"
WORK=""
C="ip netns exec hv-client"; N="ip netns exec hv-node"; I="ip netns exec hv-inet"
PIDS=()
export RUST_BACKTRACE=0
# The issuer speaks plain HTTP on this private test network; a client sends
# a token over plain HTTP only to loopback unless told so.
export HIDRAVPN_PLAIN_HTTP_ISSUER=1
WALLET=So11111111111111111111111111111111111111112
MINT=Aov3BtQvrGXM5V9oiHu8PKJWeV8a2rFnr24fwWcNpump
ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok + 1)); }
fail() { echo "FAIL  $1"; bad=$((bad + 1)); }
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  ip netns pids hv-client 2>/dev/null | xargs -r kill 2>/dev/null
  sleep 0.5
  for ns in hv-client hv-node hv-inet; do ip netns del "$ns" 2>/dev/null; done
  rm -rf /etc/netns/hv-client /run/hidravpn/control.sock /run/hidravpn/control.token /run/hidravpn/netcfg.json \
         /etc/hidravpn/client.key /etc/hidravpn/circuit.json /etc/hidravpn/passes.json /etc/hidravpn/pass.token \
         /etc/hidravpn/order.json /var/run/wireguard/hvp0.sock
  [ -n "${WORK:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT
cleanup
WORK="$(mktemp -d /tmp/hidravpn-pay.XXXXXX)"
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
for b in hidravpn hidravpn-node hidravpn-sign hidravpn-issuer; do [ -x "$BIN/$b" ] || { echo "build first: cargo build --release --manifest-path hidravpn/Cargo.toml"; exit 1; }; done

# ── Network ─────────────────────────────────────────────────────────────────
ip netns add hv-client; ip netns add hv-node; ip netns add hv-inet
ip link add c-n type veth peer name n-c; ip link set c-n netns hv-client; ip link set n-c netns hv-node
ip link add n-i type veth peer name i-n; ip link set n-i netns hv-node; ip link set i-n netns hv-inet
$C ip addr add 10.200.0.2/24 dev c-n; $C ip link set c-n up; $C ip link set lo up; $C ip route add default via 10.200.0.1
$N ip addr add 10.200.0.1/24 dev n-c; $N ip link set n-c up; $N ip link set lo up
$N ip addr add 10.201.0.1/24 dev n-i; $N ip link set n-i up; $N ip route add default via 10.201.0.2
$I ip addr add 10.201.0.2/24 dev i-n; $I ip link set i-n up; $I ip link set lo up
mkdir -p /etc/netns/hv-client; echo "nameserver 10.200.0.1" > /etc/netns/hv-client/resolv.conf
$I python3 -I "$HERE/test/dns-stub.py" 10.201.0.2 > "$WORK/dns.log" 2>&1 & PIDS+=($!)
LEDGER="$WORK/ledger.json"; echo '{}' > "$LEDGER"
$I python3 -I "$HERE/test/solana-rpc-stub.py" "$LEDGER" "$WALLET" "$MINT" > "$WORK/rpc.log" 2>&1 & PIDS+=($!)
PRICE="$WORK/price.txt"; echo 0.00012686 > "$PRICE"
$I python3 -I "$HERE/test/price-stub.py" "$PRICE" "$MINT" > "$WORK/price.log" 2>&1 & PIDS+=($!)
sleep 1

# ── The issuer sells passes ─────────────────────────────────────────────────
ISS="$BIN/hidravpn-issuer --accounts $WORK/accounts.json --orders $WORK/orders.json"
$ISS keygen --out "$WORK/issuer-key.json" --days 30 > "$WORK/pass-key.json" 2>/dev/null || { fail "issuer keygen"; exit 1; }
OUT=$($ISS run --key "$WORK/issuer-key.json" --pay-pack 10=50 2>&1); echo "$OUT" | grep -q "needs --pay-wallet" && pass "packs without a wallet: refused" || fail "no wallet: $OUT"
OUT=$($ISS run --key "$WORK/issuer-key.json" --pay-wallet "$WALLET" 2>&1); echo "$OUT" | grep -q "needs at least one --pay-pack" && pass "a wallet without packs: refused" || fail "no packs: $OUT"
OUT=$($ISS run --key "$WORK/issuer-key.json" --pay-wallet not-a-wallet --pay-pack 10=50 2>&1); echo "$OUT" | grep -q "not a Solana address" && pass "a wallet that is not an address: refused" || fail "bad wallet: $OUT"
OUT=$($ISS run --key "$WORK/issuer-key.json" --pay-wallet "$WALLET" --pay-pack 10=50.5 2>&1); echo "$OUT" | grep -q "whole number" && pass "a price with decimals: refused (the tag takes the decimals)" || fail "bad price: $OUT"
OUT=$($ISS run --key "$WORK/issuer-key.json" --pay-wallet "$WALLET" --pay-pack 10=50 --pay-rpc http://example.org/ 2>&1); echo "$OUT" | grep -q "plain HTTP" && pass "an RPC over plain HTTP on the open internet: refused" || fail "bad rpc: $OUT"
OUT=$($ISS run --key "$WORK/issuer-key.json" --pay-wallet "$WALLET" --pay-pack 150=5.99usd --pay-price-url http://example.org/ 2>&1); echo "$OUT" | grep -q "plain HTTP" && pass "a price feed over plain HTTP on the open internet: refused" || fail "bad feed: $OUT"
$N $ISS run --key "$WORK/issuer-key.json" --listen 10.200.0.1:8730 --plain-http-public \
  --pay-wallet "$WALLET" --pay-pack 10=50 --pay-pack 30=140 --pay-pack 150=5.99usd --pay-rpc http://10.201.0.2:8899/ \
  --pay-price-url http://10.201.0.2:8898/ --pay-price-every 1 --pay-price-max-age 4 > "$WORK/issuer.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 50); do grep -q "pass issuer on TCP 8730" "$WORK/issuer.log" && break; sleep 0.2; done
grep -q "pass issuer on TCP 8730 with 1 key" "$WORK/issuer.log" && pass "the issuer is up, selling" || { cat "$WORK/issuer.log"; fail "issuer did not start"; exit 1; }
for i in $(seq 1 30); do grep -q "going rate refreshed" "$WORK/issuer.log" && break; sleep 0.2; done
grep -q "going rate refreshed: 0.00012686 USD for one token" "$WORK/issuer.log" && pass "the issuer fetched the going rate from the feed" || fail "rate: $(cat "$WORK/issuer.log")"
OUT=$($C curl -s --max-time 5 http://10.200.0.1:8730/packs); echo "$OUT" | grep -q "\"passes\":10,\"price_raw\":50000000" && echo "$OUT" | grep -q "\"wallet\":\"$WALLET\"" && pass "GET /packs tells the packs, the wallet and the mint" || fail "packs: $OUT"
echo "$OUT" | grep -q "\"passes\":150,\"price_raw\":47217000000,\"usd_cents\":599" && echo "$OUT" | grep -q "\"rate\":\"0.00012686\"" && pass "a pack priced in dollars is told in today's HNET: 5.99 USD is 47217 HNET" || fail "usd pack: $OUT"

# ── The going rate moves ────────────────────────────────────────────────────
# Ten percent up: taken at the next fetch, fewer HNET for the same dollars.
echo 0.00013955 > "$PRICE"; sleep 2.5
OUT=$($C curl -s --max-time 5 http://10.200.0.1:8730/packs); echo "$OUT" | grep -q "\"passes\":150,\"price_raw\":42924000000" && pass "the rate up 10 %: the pack costs 42924 HNET now" || fail "after +10%: $OUT"
# Doubled in a second: held, the pack stays; after three fetches that agree, taken.
echo 0.0002791 > "$PRICE"; sleep 1.5
OUT=$($C curl -s --max-time 5 http://10.200.0.1:8730/packs); echo "$OUT" | grep -q "\"passes\":150,\"price_raw\":42924000000" && grep -q "held until the feed agrees" "$WORK/issuer.log" && pass "the rate doubled at once: held, the pack keeps its price" || fail "after a jump: $OUT $(grep held "$WORK/issuer.log")"
sleep 3
OUT=$($C curl -s --max-time 5 http://10.200.0.1:8730/packs); echo "$OUT" | grep -q "\"passes\":150,\"price_raw\":21462000000" && pass "the feed insisted three times: the doubled rate is taken, 21462 HNET" || fail "after insisting: $OUT"
# The feed breaks: the last rate serves until it is too old, then the pack
# is not for sale, while the packs in HNET still are.
echo down > "$PRICE"; sleep 1.5
OUT=$($C curl -s --max-time 5 http://10.200.0.1:8730/packs); echo "$OUT" | grep -q "\"passes\":150" && grep -q "the price feed did not answer" "$WORK/issuer.log" && pass "the feed is down: the last rate still serves" || fail "feed down: $OUT"
sleep 4
OUT=$($C curl -s --max-time 5 http://10.200.0.1:8730/packs); ! echo "$OUT" | grep -q "\"passes\":150" && echo "$OUT" | grep -q "\"passes\":10" && pass "the rate went stale: the dollar pack is off the list, the HNET packs stay" || fail "stale: $OUT"
CODE=$($C curl -s -o "$WORK/q.json" -w '%{http_code}' --max-time 5 -X POST -H 'Content-Type: application/json' -d "{\"token_sha256\":\"$(printf stale | sha256sum | cut -d' ' -f1)\",\"passes\":150}" http://10.200.0.1:8730/quote)
[ "$CODE" = 503 ] && grep -q "not known right now" "$WORK/q.json" && pass "and an order for it is refused: the rate is not known" || fail "stale quote: $CODE $(cat "$WORK/q.json")"
echo 0.00012686 > "$PRICE"; sleep 2.5
OUT=$($C curl -s --max-time 5 http://10.200.0.1:8730/packs); echo "$OUT" | grep -q "\"passes\":150,\"price_raw\":47217000000" && pass "the feed is back: the pack is for sale again at the rate it says" || fail "feed back: $OUT"

# ── The node admits with a pass; the list names the issuer ──────────────────
$N "$BIN/hidravpn-node" --config "$WORK/p.toml" init --endpoint 10.200.0.1:51820 --name node-p --role exit --operator maintainers --pass-admission --dns udp://10.201.0.2 --out-interface n-i > "$WORK/init.log" 2>&1 || { cat "$WORK/init.log"; fail "node init"; exit 1; }
sed -i 's/^interface = "hvpn0"/interface = "hvp0"/' "$WORK/p.toml"
$N "$BIN/hidravpn-node" --config "$WORK/p.toml" pass-key add "$WORK/pass-key.json" > /dev/null 2>&1
mkdir -p "$WORK/run"
$N env HIDRAVPN_RUN_DIR="$WORK/run" "$BIN/hidravpn-node" --config "$WORK/p.toml" run > "$WORK/node.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 100); do grep -q "DNS forwarder ready" "$WORK/node.log" && grep -q "admission service on" "$WORK/node.log" && break; sleep 0.2; done
grep -q "admission service on TCP 51821 (with a pass" "$WORK/node.log" || { tail -5 "$WORK/node.log"; fail "node did not come up"; exit 1; }
$N "$BIN/hidravpn-node" --config "$WORK/p.toml" record > "$WORK/rec.json" 2>/dev/null
LISTPUB=$("$BIN/hidravpn-sign" keygen --out "$WORK/list.key" 2>/dev/null)
HIDRAVPN_SIGN="$BIN/hidravpn-sign" bash "$HERE/make-node-list.sh" --key "$WORK/list.key" --out "$WORK/nodes.json" --sequence 1 \
  --issuer-url http://10.200.0.1:8730 --pass-key "$WORK/pass-key.json" "$WORK/rec.json" > /dev/null 2>&1 || fail "make-node-list"
mkdir -p /etc/hidravpn
$C "$BIN/hidravpn" keygen >/dev/null 2>&1
"$BIN/hidravpn" nodes import "$WORK/nodes.json" --pubkey "$LISTPUB" 2>&1 | grep -q "added 1 node(s)" || fail "import"

# ── An order ────────────────────────────────────────────────────────────────
OUT=$($C "$BIN/hidravpn" passes buy 2>&1); echo "$OUT" | grep -q "10 passes for 50 HNET" && echo "$OUT" | grep -q "150 passes for 5.99 USD, 47217 HNET today" && echo "$OUT" | grep -q "today's rate: 0.00012686 USD for one HNET" && pass "passes buy, alone, lists the packs, the dollar one in today's HNET" || fail "list packs: $OUT"
OUT=$($C "$BIN/hidravpn" passes claim x 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "no order is open" && pass "a claim with no order open is refused at home" || fail "claim without order: $OUT"
OUT=$($C "$BIN/hidravpn" passes buy 7 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "no pack of 7 passes" && echo "$OUT" | grep -q "a new pass account token was made" && [ ! -e /etc/hidravpn/order.json ] && pass "a pack the issuer does not sell: refused, no order (the token for purchases was made, and kept)" || fail "buy 7: $OUT"
OUT=$($C "$BIN/hidravpn" passes buy 10 2>&1); RC=$?
AMOUNT=$(python3 -I -c "import json; print(json.load(open('/etc/hidravpn/order.json'))['amount'])" 2>/dev/null)
RAW=$(python3 -I -c "import json; print(json.load(open('/etc/hidravpn/order.json'))['amount_raw'])" 2>/dev/null)
[ $RC = 0 ] && ! echo "$OUT" | grep -q "token was made" && echo "$OUT" | grep -q "Send exactly $AMOUNT HNET to" && echo "$OUT" | grep -q "$WALLET" \
  && pass "passes buy 10: an order open on the kept token, the amount and the wallet told ($AMOUNT HNET)" || fail "buy: $OUT"
EXPIRES=$(python3 -I -c "import json; print(json.load(open('/etc/hidravpn/order.json'))['expires'])" 2>/dev/null)
LEFT=$(( $(date -u -d "$EXPIRES" +%s) - $(date +%s) ))
[ "$LEFT" -gt 7000 ] && [ "$LEFT" -le 7200 ] && pass "the order is open two hours, until a claim reaches it ($EXPIRES)" || fail "expires: $EXPIRES ($LEFT s)"
[ "$RAW" -gt 50000000 ] && [ "$RAW" -lt 50100000 ] && [ "$(stat -c %a /etc/hidravpn/order.json)" = 600 ] && [ "$(stat -c %a /etc/hidravpn/pass.token)" = 600 ] \
  && pass "the amount is the price plus a tag under 0.1 HNET; the order and the token are root's only" || fail "order file: raw=$RAW $(ls -l /etc/hidravpn)"
TOKEN=$(cat /etc/hidravpn/pass.token)
OUT=$($C "$BIN/hidravpn" passes buy 10 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "already open" && pass "a second buy with an order open says so (--replace makes a new one)" || fail "second buy: $OUT"
OUT=$($C "$BIN/hidravpn" passes list 2>&1); echo "$OUT" | grep -q "an order for 10 pass(es) is open, unclaimed: $AMOUNT HNET" && pass "passes list shows the open order" || fail "list: $OUT"
grep -q "order opened for 10 pass(es)" "$WORK/issuer.log" && pass "the issuer logged the order as a count" || fail "issuer log: $(cat "$WORK/issuer.log")"

# ── Claims that must fail ───────────────────────────────────────────────────
sig() { python3 -I -c "
import sys
A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
b=bytes([int(sys.argv[1])]*64); n=int.from_bytes(b,'big'); s=''
while n: n,r=divmod(n,58); s=A[r]+s
print('1'*(len(b)-len(b.lstrip(b'\x00')))+s)" "$1"; }
NOW=$(date +%s)
OUT=$($C "$BIN/hidravpn" passes claim not-a-signature 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "not a transaction signature" && pass "a signature that is not one is refused at home" || fail "bad sig: $OUT"
OUT=$($C "$BIN/hidravpn" passes claim "$(sig 1)" 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "not on chain as finalized yet" && pass "a transaction the chain never saw: not yet (404)" || fail "unknown tx: $OUT"
python3 -I - "$LEDGER" "$RAW" "$NOW" "$(sig 2)" "$(sig 3)" "$(sig 4)" "$(sig 5)" "$(sig 6)" "$(sig 7)" <<'PY'
import json, sys
p, raw, now = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
s2, s3, s4, s5, s6, s7 = sys.argv[4:10]
json.dump({
  s2: {"amount": raw - 1, "time": now, "ok": True},
  s3: {"amount": raw, "time": now, "ok": False},
  s4: {"amount": raw, "time": now - 90000, "ok": True},
  s5: {"amount": raw, "time": now, "ok": True, "owner": "ExYv4idyqxmuodpoZtxyGxeTGi6oYrqFAshAgCsRissc"},
  s6: {"amount": raw, "time": now, "ok": True, "mint": "ExYv4idyqxmuodpoZtxyGxeTGi6oYrqFAshAgCsRissc"},
  s7: {"amount": raw, "time": now, "ok": True},
}, open(p, "w"))
PY
OUT=$($C "$BIN/hidravpn" passes claim "$(sig 2)" 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "another amount" && pass "one unit short: refused, the amount must match exactly" || fail "short: $OUT"
OUT=$($C "$BIN/hidravpn" passes claim "$(sig 3)" 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "failed on chain" && pass "a failed transaction: refused" || fail "failed tx: $OUT"
OUT=$($C "$BIN/hidravpn" passes claim "$(sig 4)" 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "older than this order" && pass "a payment from before the order: refused" || fail "old tx: $OUT"
OUT=$($C "$BIN/hidravpn" passes claim "$(sig 5)" 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "none of the token to the receiving wallet" && pass "the amount to another wallet: refused" || fail "other wallet: $OUT"
OUT=$($C "$BIN/hidravpn" passes claim "$(sig 6)" 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "none of the token to the receiving wallet" && pass "another token to the wallet: refused" || fail "other mint: $OUT"
[ -e /etc/hidravpn/order.json ] && pass "the order stays open through refused claims" || fail "order gone"

# ── The right payment ───────────────────────────────────────────────────────
OUT=$($C "$BIN/hidravpn" passes claim "$(sig 7)" 2>&1); echo "$OUT" | grep -q "paid: 10 pass(es) credited; the account has 10 in all" && [ ! -e /etc/hidravpn/order.json ] && pass "the exact amount, after the order: 10 passes credited, the order closed" || fail "claim: $OUT"
grep -q "order claimed: 10 pass(es) credited" "$WORK/issuer.log" && pass "the issuer logged the credit as a count" || fail "issuer log"
$ISS account list 2>/dev/null | grep -q "^paid-[0-9a-f]\{8\} .* 10 left (prepaid)" && pass "the account is there, prepaid, under a name that says nothing" || fail "account list: $($ISS account list 2>&1)"
OUT=$($C "$BIN/hidravpn" passes get --count 3 2>&1); echo "$OUT" | grep -q "3 pass(es) for 1 node(s); the account has 7 left$" && pass "passes get: three passes, seven left in all (no day)" || fail "get: $OUT"
OUT=$($C "$BIN/hidravpn" passes get --count 8 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "has 7 pass(es) left, not 8" && echo "$OUT" | grep -q "passes buy" && pass "past the balance: refused, all or nothing, told to buy" || fail "over balance: $OUT"
OUT=$($C "$BIN/hidravpn" nodes join --all 2>&1); echo "$OUT" | grep -q "node-p: admitted with a pass" && pass "the node admits with a pass bought this way" || fail "join: $OUT"
grep -q "admitted a client with a pass" "$WORK/node.log" || fail "node log"

# ── A second purchase tops the same account up; a payment pays once ────────
OUT=$($C "$BIN/hidravpn" passes buy 30 2>&1); echo "$OUT" | grep -q "order open for 30 pass(es)" && ! echo "$OUT" | grep -q "token was made" && pass "a second order, on the same token" || fail "buy 30: $OUT"
RAW2=$(python3 -I -c "import json; print(json.load(open('/etc/hidravpn/order.json'))['amount_raw'])")
[ "$RAW2" -gt 140000000 ] && [ "$RAW2" -lt 140100000 ] && [ "$RAW2" != "$RAW" ] || fail "second amount $RAW2"
OUT=$($C "$BIN/hidravpn" passes claim "$(sig 7)" 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "had already paid an earlier order of 10 pass(es), not the open one" && [ -e /etc/hidravpn/order.json ] && pass "the first payment again: it paid the earlier order, the open one stays open" || fail "reuse: $OUT"
# Someone else, with an order of their own (a fresh token, an order of
# the same pack as the owner's open one).
OTHER_HASH=$(printf other-token | sha256sum | cut -d' ' -f1)
CODE=$($C curl -s -o "$WORK/q.json" -w '%{http_code}' --max-time 5 -X POST -H 'Content-Type: application/json' -d "{\"token_sha256\":\"$OTHER_HASH\",\"passes\":30}" http://10.200.0.1:8730/quote)
[ "$CODE" = 200 ] || fail "other quote: $CODE $(cat "$WORK/q.json")"
CODE=$($C curl -s -o "$WORK/c.json" -w '%{http_code}' --max-time 10 -X POST -H 'Content-Type: application/json' -d "{\"token\":\"other-token\",\"signature\":\"$(sig 7)\"}" http://10.200.0.1:8730/claim)
[ "$CODE" = 409 ] && grep -q "already paid an order" "$WORK/c.json" && pass "the first payment with another token's open order: it already paid, used up" || fail "reuse by another: $CODE $(cat "$WORK/c.json")"
python3 -I - "$LEDGER" "$RAW2" "$NOW" "$(sig 8)" "$(sig 9)" <<'PY'
import json, sys
p, raw, now, s8, s9 = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5]
d = json.load(open(p)); d[s8] = {"amount": raw, "time": now + 1, "ok": True}; d[s9] = {"amount": raw, "time": now + 1, "ok": True}
json.dump(d, open(p, "w"))
PY
# Someone who saw the payment on chain: without the token there is no
# order of theirs (404); with the order of their own, the amount is not
# theirs (402).
CODE=$($C curl -s -o "$WORK/c.json" -w '%{http_code}' --max-time 10 -X POST -H 'Content-Type: application/json' -d "{\"token\":\"other-token\",\"signature\":\"$(sig 8)\"}" http://10.200.0.1:8730/claim)
[ "$CODE" = 402 ] && grep -q "another amount" "$WORK/c.json" && pass "a watcher of the chain with an order of their own cannot claim the payment: not their amount" || fail "watcher with order: $CODE $(cat "$WORK/c.json")"
CODE=$($C curl -s -o "$WORK/c.json" -w '%{http_code}' --max-time 10 -X POST -H 'Content-Type: application/json' -d "{\"token\":\"nobody\",\"signature\":\"$(sig 8)\"}" http://10.200.0.1:8730/claim)
[ "$CODE" = 404 ] && pass "a watcher without an order: no order for that token" || fail "watcher: $CODE $(cat "$WORK/c.json")"
# ── Floods that crowd no buyer out ─────────────────────────────────────────
# Claims for tokens that have no order, and quotes for a token that has as
# many orders open as it may, are answered without a share of the buckets:
# right after sixty of each, the owner's claim and a new quote go through.
S8=$(sig 8)
CODES=$(for i in $(seq 1 60); do $C curl -s -o /dev/null -w '%{http_code}\n' --max-time 5 -X POST -H 'Content-Type: application/json' -d "{\"token\":\"nobody-$i\",\"signature\":\"$S8\"}" http://10.200.0.1:8730/claim; done | sort | uniq -c | tr -s ' ' | tr '\n' ';')
[ "$CODES" = " 60 404;" ] && pass "sixty claims for tokens with no order: each told so, none slowed ($CODES)" || fail "orderless claims: $CODES"
FLOOD_HASH=$(printf one-hash-for-nobody | sha256sum | cut -d' ' -f1)
CODES=$(for i in $(seq 1 60); do $C curl -s -o /dev/null -w '%{http_code}\n' --max-time 5 -X POST -H 'Content-Type: application/json' -d "{\"token_sha256\":\"$FLOOD_HASH\",\"passes\":10}" http://10.200.0.1:8730/quote; done | sort | uniq -c | tr -s ' ' | tr '\n' ';')
[ "$CODES" = " 5 200; 55 429;" ] && pass "sixty quotes for one token: five orders, then told it has five open ($CODES)" || fail "one-token quotes: $CODES"
CODE=$($C curl -s -o "$WORK/q.json" -w '%{http_code}' --max-time 5 -X POST -H 'Content-Type: application/json' -d "{\"token_sha256\":\"$FLOOD_HASH\",\"passes\":10}" http://10.200.0.1:8730/quote)
[ "$CODE" = 429 ] && grep -q "already has 5 orders open" "$WORK/q.json" && pass "the token's limit, not the issuer's bucket, said no" || fail "one-token quote: $CODE $(cat "$WORK/q.json")"
# Claims on those orders of its own, with a signature that pays none of
# them: each counts a try on all five, so six reach the chain and the rest
# are answered, without the bucket, that the tries are spent.
CODES=$(for i in $(seq 1 60); do $C curl -s -o /dev/null -w '%{http_code}\n' --max-time 10 -X POST -H 'Content-Type: application/json' -d "{\"token\":\"one-hash-for-nobody\",\"signature\":\"$S8\"}" http://10.200.0.1:8730/claim; done | sort | uniq -c | tr -s ' ' | tr '\n' ';')
[ "$CODES" = " 6 402; 54 429;" ] && pass "sixty claims on that token's own orders: six reach the chain, then its tries are spent ($CODES)" || fail "own-order claims: $CODES"
CODE=$($C curl -s -o "$WORK/q.json" -w '%{http_code}' --max-time 5 -X POST -H 'Content-Type: application/json' -d "{\"token_sha256\":\"$(printf after-the-flood | sha256sum | cut -d' ' -f1)\",\"passes\":10}" http://10.200.0.1:8730/quote)
[ "$CODE" = 200 ] && pass "a buyer right after both floods: the order opens" || fail "quote after the flood: $CODE $(cat "$WORK/q.json")"
OUT=$($C "$BIN/hidravpn" passes claim "$(sig 8)" 2>&1); echo "$OUT" | grep -q "paid: 30 pass(es) credited; the account has 37 in all" && pass "the owner claims it: 30 more, 37 in all" || fail "claim 30: $OUT"
# A second transaction of the same amount, after the order was paid: no
# order of this token is open for it.
OUT=$($C "$BIN/hidravpn" passes claim "$(sig 9)" 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "no order is open" && pass "paid twice by mistake: there is no order to claim at home" || fail "second payment: $OUT"
CODE=$($C curl -s -o "$WORK/c.json" -w '%{http_code}' --max-time 10 -X POST -H 'Content-Type: application/json' -d "{\"token\":\"$TOKEN\",\"signature\":\"$(sig 9)\"}" http://10.200.0.1:8730/claim)
[ "$CODE" = 404 ] && pass "nor at the issuer: no open order (an operator can credit it by hand)" || fail "second payment at the issuer: $CODE $(cat "$WORK/c.json")"
# A watcher who opened an order of their own for the same pack and sends
# the second payment's signature: the amount is the victim's, not theirs.
CODE=$($C curl -s -o "$WORK/c.json" -w '%{http_code}' --max-time 10 -X POST -H 'Content-Type: application/json' -d "{\"token\":\"other-token\",\"signature\":\"$(sig 9)\"}" http://10.200.0.1:8730/claim)
[ "$CODE" = 402 ] && pass "a watcher with an order of the same pack cannot take a stray payment either" || fail "watcher stray: $CODE $(cat "$WORK/c.json")"
# The same claim once more: idempotent, nothing credited twice. (A few
# seconds on: the token has made many claims, and one token's are paced.)
sleep 6.5
CODE=$($C curl -s -o "$WORK/c.json" -w '%{http_code}' --max-time 10 -X POST -H 'Content-Type: application/json' -d "{\"token\":\"$TOKEN\",\"signature\":\"$(sig 8)\"}" http://10.200.0.1:8730/claim)
[ "$CODE" = 200 ] && grep -q '"balance":37,"amount_raw":'"$RAW2"',"already_claimed":true' "$WORK/c.json" && pass "the same claim again: already claimed, the balance as it was" || fail "idempotent: $CODE $(cat "$WORK/c.json")"

# ── An order in dollars ─────────────────────────────────────────────────────
OUT=$($C "$BIN/hidravpn" passes buy 150 2>&1); echo "$OUT" | grep -q "Send exactly 47217.0[0-9]* HNET (5.99 USD at 0.00012686 USD for one HNET, fixed for this order)" && pass "an order in dollars says the HNET amount, the dollars and the rate" || fail "buy 150: $OUT"
grep -q '"usd": "5.99"' /etc/hidravpn/order.json && grep -q '"rate": "0.00012686"' /etc/hidravpn/order.json && pass "the order file keeps the dollars and the rate" || fail "order file: $(cat /etc/hidravpn/order.json)"

# ── A flood of quotes is slowed ─────────────────────────────────────────────
CODES=$(for i in $(seq 1 40); do $C curl -s -o /dev/null -w '%{http_code}\n' --max-time 5 -X POST -H 'Content-Type: application/json' -d "{\"token_sha256\":\"$(printf "flood-%s" "$i" | sha256sum | cut -d' ' -f1)\",\"passes\":10}" http://10.200.0.1:8730/quote; done | sort | uniq -c | tr -s ' ' | tr '\n' ';')
echo "$CODES" | grep -q " 429;" && echo "$CODES" | grep -q " 200;" && pass "forty quotes at once: some answered, the rest told to wait ($CODES)" || fail "flood: $CODES"
CODE=$($C curl -s -o "$WORK/q.json" -w '%{http_code}' --max-time 5 -X POST -H 'Content-Type: application/json' -d '{"token_sha256":"zz","passes":10}' http://10.200.0.1:8730/quote)
[ "$CODE" = 400 ] && pass "a quote without a proper hash: refused" || fail "bad hash: $CODE"
CODE=$($C curl -s -o "$WORK/q.json" -w '%{http_code}' --max-time 5 -X POST -H 'Content-Type: application/json' -d 'not json' http://10.200.0.1:8730/claim)
[ "$CODE" = 400 ] && pass "a claim that is not one: refused" || fail "bad claim: $CODE"
# One token's claims at once are paced: on an order of its own, twenty
# claims in a moment, ten reach the chain and ten are told to wait. (A
# second first, for the quote bucket the flood above emptied.) The
# signature is of no transaction: each claim that gets through is a lookup.
sleep 1
S11=$(sig 11)
CODE=$($C curl -s -o "$WORK/q.json" -w '%{http_code}' --max-time 5 -X POST -H 'Content-Type: application/json' -d "{\"token_sha256\":\"$(printf one-order | sha256sum | cut -d' ' -f1)\",\"passes\":10}" http://10.200.0.1:8730/quote)
[ "$CODE" = 200 ] || fail "one-order quote: $CODE $(cat "$WORK/q.json")"
CODES=$(for i in $(seq 1 20); do $C curl -s -o "$WORK/c-$i.json" -w '%{http_code}\n' --max-time 10 -X POST -H 'Content-Type: application/json' -d "{\"token\":\"one-order\",\"signature\":\"$S11\"}" http://10.200.0.1:8730/claim; done | sort | uniq -c | tr -s ' ' | tr '\n' ';')
[ "$CODES" = " 10 404; 10 429;" ] && [ "$(grep -l "many claims just now" "$WORK"/c-*.json | wc -l)" = 10 ] && pass "twenty claims of one token at once: ten reach the chain, ten told to wait ($CODES)" || fail "token pace: $CODES"

# ── Only JSON is read ───────────────────────────────────────────────────────
# A web page can make its visitors' browsers send text or a form here
# without asking; neither is read, so no page can spend the buckets.
TEXT_HASH=$(printf sent-as-text | sha256sum | cut -d' ' -f1)
CODE=$($C curl -s -o "$WORK/q.json" -w '%{http_code}' --max-time 5 -X POST -H 'Content-Type: text/plain' -d "{\"token_sha256\":\"$TEXT_HASH\",\"passes\":10}" http://10.200.0.1:8730/quote)
[ "$CODE" = 415 ] && grep -q "application/json" "$WORK/q.json" && ! grep -q "$TEXT_HASH" "$WORK/orders.json" && pass "a quote sent as text/plain: refused (415), no order opened" || fail "text/plain quote: $CODE $(cat "$WORK/q.json")"
CODE=$($C curl -s -o "$WORK/q.json" -w '%{http_code}' --max-time 5 -X POST -d "{\"token_sha256\":\"$TEXT_HASH\",\"passes\":10}" http://10.200.0.1:8730/quote)
[ "$CODE" = 415 ] && pass "a quote sent as a form: refused (415)" || fail "form quote: $CODE"
CODE=$($C curl -s -o "$WORK/c.json" -w '%{http_code}' --max-time 5 -X POST -H 'Content-Type: text/plain;charset=UTF-8' -d "{\"token\":\"$TOKEN\",\"signature\":\"$(sig 8)\"}" http://10.200.0.1:8730/claim)
[ "$CODE" = 415 ] && pass "a claim sent as text/plain: refused (415)" || fail "text/plain claim: $CODE $(cat "$WORK/c.json")"
CODE=$($C curl -s -o /dev/null -w '%{http_code}' --max-time 5 -X POST -H 'Content-Type: text/plain' -d '{}' http://10.200.0.1:8730/issue)
[ "$CODE" = 415 ] && pass "an issuance sent as text/plain: refused (415)" || fail "text/plain issue: $CODE"

# ── A lapsed order, credited by hand ────────────────────────────────────────
# An order no claim reached, lapsed two hours after it was made; its record
# is kept. The operator, having checked the payment on chain, credits it to
# the account that made the order, and the transaction pays nothing else.
LATE="$BIN/hidravpn-issuer --accounts $WORK/late-accounts.json --orders $WORK/late-orders.json"
LATE_HASH=$(printf late-token | sha256sum | cut -d' ' -f1)
python3 -I - "$WORK/late-orders.json" "$LATE_HASH" "$NOW" <<'PY'
import json, sys
p, h, now = sys.argv[1], sys.argv[2], int(sys.argv[3])
json.dump({"orders": [{"token_sha256": h, "passes": 10, "amount_raw": 50012345, "created": now - 10000, "tries": 0, "unclaimed": True}], "used": []}, open(p, "w"))
PY
utc() { date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; }
OUT=$($LATE order lapsed 2>&1); echo "$OUT" | grep -q "^50.012345 for 10 pass(es)  made $(utc $((NOW - 10000)))  lapsed $(utc $((NOW - 10000 + 7200)))  never claimed  account $LATE_HASH$" && pass "order lapsed: the unpaid order, two hours after it was made, with the amount and whose it was" || fail "order lapsed: $OUT"
OUT=$($LATE order credit --amount 50.012345 --signature "$(sig 10)" --paid-at "$(utc $((NOW - 100)))" 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "no lapsed order of that amount could have been paid at that time" && pass "a payment after the order lapsed: not credited" || fail "late credit: $OUT"
OUT=$($LATE order credit --amount 50.012346 --signature "$(sig 10)" --paid-at "$(utc $((NOW - 9000)))" 2>&1); [ $? -ne 0 ] && pass "another amount: not credited" || fail "wrong amount credit: $OUT"
OUT=$($LATE order credit --amount 50.012345 --signature "$(sig 10)" --paid-at "$(utc $((NOW - 9000)))" 2>&1); echo "$OUT" | grep -q "credited 10 pass(es) to the account that made the order; it has 10 in all" && pass "paid while it was open: credited by hand" || fail "credit: $OUT"
$LATE account list 2>/dev/null | grep -q "^paid-[0-9a-f]\{8\} .* 10 left (prepaid)" && python3 -I -c "import json,sys; a=json.load(open(sys.argv[1]))['accounts']; sys.exit(0 if a[0]['token_sha256']==sys.argv[2] else 1)" "$WORK/late-accounts.json" "$LATE_HASH" && pass "on the account of the order's own token" || fail "late account: $($LATE account list 2>&1)"
OUT=$($LATE order credit --amount 50.012345 --signature "$(sig 10)" --paid-at "$(utc $((NOW - 9000)))" 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "already paid an order" && pass "the same credit again: refused, the transaction is used" || fail "credit twice: $OUT"

# ── Nothing identifying kept or logged ──────────────────────────────────────
[ "$(stat -c %a "$WORK/orders.json")" = 600 ] && pass "the orders file is the issuer's only" || fail "orders mode $(stat -c %a "$WORK/orders.json")"
grep -qF -e "$TOKEN" -e "$(sig 7)" -e "$(sig 8)" -e "$WALLET" "$WORK/orders.json" "$WORK/accounts.json" && fail "the issuer's files hold a token, a transaction or the wallet" || pass "the issuer's files keep hashes: no token, no transaction, no wallet"
grep -qF -e "$TOKEN" -e "$(sig 7)" -e "$(sig 8)" -e "$WALLET" -e "$AMOUNT" -e "$RAW" -e "10.200.0.2" "$WORK/issuer.log" "$WORK/node.log" && fail "a log names the wallet, a transaction, an amount, a token or the client" || pass "no log names the wallet, a transaction, an amount, a token or the client"
grep -q "claim refused: wrong-amount" "$WORK/issuer.log" && grep -q "claim refused: too-early" "$WORK/issuer.log" && pass "refusals are logged by kind only" || fail "refusal log: $(grep refused "$WORK/issuer.log")"

echo; echo "$ok passed, $bad failed"; [ $bad -eq 0 ]
