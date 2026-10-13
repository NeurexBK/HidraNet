#!/usr/bin/env bash
# The signed node list, through the command line: made the way the maintainers
# will make it (hidravpn-sign), imported the way a person will import it
# (hidravpn nodes import), refused the ways it must be refused. No network, no
# namespaces; a temporary pocket. Root is needed only because `hidravpn nodes`
# asks for it.
#
#   sudo hidravpn/scripts/test-directory.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/../target/release"
ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok + 1)); }
fail() { echo "FAIL  $1"; bad=$((bad + 1)); }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
for b in hidravpn hidravpn-sign; do [ -x "$BIN/$b" ] || { echo "build first: cargo build --release --manifest-path hidravpn/Cargo.toml"; exit 1; }; done
W="$(mktemp -d /tmp/hidravpn-dir.XXXXXX)"; trap 'rm -rf "$W"' EXIT
POCKET="$W/pocket.json"
HV="$BIN/hidravpn --pocket $POCKET"

# ── The maintainers' side: a key, a list, a signature ───────────────────────
PUB=$("$BIN/hidravpn-sign" keygen --out "$W/release.key" 2>/dev/null)
[ ${#PUB} -eq 44 ] && pass "a release key pair is made; the public key is 44 base64 characters" || fail "keygen: '$PUB'"
# Node keys here are only shapes (any 32 bytes); the list is about the format.
k() { "$BIN/hidravpn-sign" keygen --out "$W/k$1" 2>/dev/null; }
cat > "$W/nodes.json" <<JSON
{ "version": 1, "generated": "2026-10-13T00:00:00Z", "note": "the first nodes",
  "nodes": [ { "node_name": "node-1", "node_public_key": "$(k 1)", "endpoint": "203.0.113.10:51820", "operator": "the maintainers", "contact": "nodes@example.org" },
             { "node_name": "node-2", "node_public_key": "$(k 2)", "endpoint": "203.0.113.11:51820", "operator": "the maintainers" },
             { "node_name": "node-3", "node_public_key": "$(k 3)", "endpoint": "203.0.113.20:51820" } ] }
JSON
"$BIN/hidravpn-sign" sign --key "$W/release.key" "$W/nodes.json" >/dev/null 2>&1 && [ -f "$W/nodes.json.sig" ] && pass "the list is signed; nodes.json.sig sits beside it" || fail "sign"
"$BIN/hidravpn-sign" verify --pubkey "$PUB" "$W/nodes.json" >/dev/null 2>&1 && pass "hidravpn-sign verify accepts it" || fail "verify"

# ── The person's side ───────────────────────────────────────────────────────
OUT=$($HV nodes import "$W/nodes.json" 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "no list key\|not accepted" && pass "with no key given: refused, either because none is built in or because the built-in one did not sign it" || fail "no key: $OUT"
[ ! -e "$POCKET" ] && pass "a refused import leaves no pocket behind" || fail "pocket written by a refused import"

OUT=$($HV nodes import "$W/nodes.json" --pubkey "$PUB" 2>&1); [ $? -eq 0 ] && echo "$OUT" | grep -q "added 3 node(s) (3 known, 0 entries, 0 exits in the pocket)" && pass "with the key: three nodes become known, none connectable ($(echo "$OUT" | head -1))" || fail "import: $OUT"
echo "$OUT" | grep -q "^  + node-1" && echo "$OUT" | grep -q "not admitted" && pass "each added node is named, and the import says they are not admitted" || fail "names: $OUT"
$HV nodes list 2>/dev/null | grep -q "^known  node-1 .*run by the maintainers  ask: nodes@example.org" && $HV nodes list 2>/dev/null | grep -q "hidravpn pubkey --node" && pass "nodes list shows them as known, who runs them, whom to ask, and how" || fail "list: $($HV nodes list 2>&1)"
grep -q node_public_key "$POCKET" && ! grep -q client_address "$POCKET" && [ "$(stat -c %a "$POCKET")" = "600" ] && pass "the pocket on disk is readable by root only, and a known node carries no client address" || fail "pocket mode $(stat -c %a "$POCKET")"

OUT=$($HV nodes import "$W/nodes.json" --pubkey "$PUB" 2>&1); echo "$OUT" | grep -q "added 0 node(s), skipped 3" && pass "importing it again adds nothing and breaks nothing" || fail "again: $OUT"

sed 's/203.0.113.10/198.51.100.99/' "$W/nodes.json" > "$W/changed.json"; cp "$W/nodes.json.sig" "$W/changed.json.sig"
OUT=$($HV nodes import "$W/changed.json" --pubkey "$PUB" 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "not accepted" && pass "a list changed after signing: refused" || fail "tampered: $OUT"
OTHER=$("$BIN/hidravpn-sign" keygen --out "$W/other.key" 2>/dev/null)
OUT=$($HV nodes import "$W/nodes.json" --pubkey "$OTHER" 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "not accepted" && pass "a list signed with another key: refused" || fail "other key: $OUT"
rm -f "$W/changed.json.sig"
OUT=$($HV nodes import "$W/changed.json" --pubkey "$PUB" 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "reading the signature" && pass "a list with no .sig beside it: refused" || fail "no sig: $OUT"
OUT=$($HV nodes import "$W/nodes.json" --pubkey "not-a-key" 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -qi "base64\|32 bytes" && pass "a key that is not a key: refused" || fail "bad key: $OUT"
[ "$($HV nodes list 2>/dev/null | grep -c "^known  ")" = 3 ] && pass "after every refusal the pocket still knows exactly the three" || fail "pocket changed: $($HV nodes list 2>&1)"

# ── A known node is not a node to connect to; admission makes it one ──────
# `up --rapido` from a pocket that only knows nodes must refuse with the way
# forward, and never touch the network (so no root-only path is reached).
OUT=$($HV up --rapido --direct 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "no exit node\|knows\|admitted" && pass "connecting from known nodes alone is refused with what to do ($(echo "$OUT" | tail -1 | cut -c1-80))" || fail "up from known: $OUT"
# The operator of node-1 admits this machine (an invite, as `admit` prints it).
cat > "$W/invite.json" <<JSON
{ "node_name": "node-1", "node_public_key": "$(grep -o '"node_public_key": "[^"]*"' "$W/nodes.json" | head -1 | cut -d'"' -f4)", "endpoint": "203.0.113.10:51820", "client_address": "10.77.0.2/16", "dns": "10.77.0.1" }
JSON
$HV nodes add --exit "$W/invite.json" >/dev/null 2>&1 && pass "admission on node-1: its invite goes into the pocket" || fail "nodes add after import"
[ "$($HV nodes list 2>/dev/null | grep -c "^known  ")" = 2 ] && $HV nodes list 2>/dev/null | grep -q "^exit   node-1 " && pass "node-1 is now an exit and no longer merely known" || fail "promotion: $($HV nodes list 2>&1)"
OUT=$($HV nodes import "$W/nodes.json" --pubkey "$PUB" 2>&1); echo "$OUT" | grep -q "added 0 node(s), skipped 3" && echo "$OUT" | grep -q "node-1: already admitted" && pass "importing the list again does not demote an admitted node" || fail "re-import: $OUT"

# ── A newer list follows a node that moved: the same key, a new address ────
sed -e 's/"generated": "2026-10-13T00:00:00Z"/"generated": "2026-11-01T00:00:00Z", "sequence": 2/' -e 's/203.0.113.11/203.0.113.12/' "$W/nodes.json" > "$W/nodes2.json"
"$BIN/hidravpn-sign" sign --key "$W/release.key" "$W/nodes2.json" >/dev/null 2>&1
# node-2 moved; and node-1, admitted from an invite that named no operator,
# now gets the operator the list vouches for. node-3 is as it was.
OUT=$($HV nodes import "$W/nodes2.json" --pubkey "$PUB" 2>&1); echo "$OUT" | grep -q "added 0 node(s), updated 2, skipped 1" && echo "$OUT" | grep -q "~ node-2: endpoint" && echo "$OUT" | grep -q "~ node-1: operator" && pass "a newer list (sequence 2): node-2 at its new address and node-1's operator filled in, and it says what changed" || fail "newer list: $OUT"
$HV nodes list 2>/dev/null | grep -q "^known  node-2 .*203.0.113.12:51820" && pass "nodes list now shows node-2 at its new address" || fail "list after the update: $($HV nodes list 2>&1)"
OUT=$($HV nodes import "$W/nodes2.json" --pubkey "$PUB" 2>&1); echo "$OUT" | grep -q "added 0 node(s), skipped 3" && pass "the same list again (same sequence) changes nothing" || fail "same sequence: $OUT"
OUT=$($HV nodes import "$W/nodes.json" --pubkey "$PUB" 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "older" && pass "the first list (no sequence) is now older than the one held: refused" || fail "older list: $OUT"

echo; echo "$ok passed, $bad failed"; [ $bad -eq 0 ]
