#!/usr/bin/env bash
# Kill-switch leak test, in two network namespaces.
#
#   ks  — the client machine, where the kill switch is armed
#   gw  — the "router/internet": an HTTP server (the open internet), a UDP echo
#         (the node's WireGuard endpoint) and a DNS resolver (a public one, not
#         the node's)
#
# With the kill switch off, the client reaches all three — that is the leak
# path a dropped tunnel could fall back to. With it on, only the node endpoint
# is reachable; HTTP and the public DNS are blocked, loopback still works, and
# turning it off restores everything.
#
# Run as root:  hidravpn/scripts/test-killswitch.sh
# Needs: the release binary built, python3, curl, nft, ip netns.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
SVC="$HERE/../target/release/hidravpn-service"
PY="$HERE/test"

pass=0
fail=0
ok() { echo "ok    $1"; pass=$((pass + 1)); }
no() { echo "FAIL  $1"; fail=$((fail + 1)); }

cleanup() {
  for ns in ks gw; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns del "$ns" 2>/dev/null
  done
}
trap cleanup EXIT
cleanup

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -x "$SVC" ] || { echo "build first: cargo build --release --manifest-path hidravpn/Cargo.toml -p hidravpn-service"; exit 1; }

cq() { ip netns exec ks "$@"; }

echo "── setting up the two namespaces"
ip netns add gw
ip netns add ks
ip link add ks-eth netns ks type veth peer name gw-eth netns gw
ip -n gw addr add 10.90.0.1/24 dev gw-eth
ip -n ks addr add 10.90.0.2/24 dev ks-eth
ip -n gw link set gw-eth up
ip -n ks link set ks-eth up
ip -n gw link set lo up
ip -n ks link set lo up
ip -n ks route add default via 10.90.0.1
# A dummy tunnel interface so "allow the tunnel interface" has a real target;
# best effort, the test does not depend on sending through it.
ip -n ks link add hvpn0 type dummy 2>/dev/null && {
  ip -n ks addr add 10.77.0.2/16 dev hvpn0
  ip -n ks link set hvpn0 up
}

# A loopback service in the client, to prove loopback keeps working with the
# kill switch on (ICMP ping is restricted in some sandboxes; TCP is reliable).
ip netns exec ks python3 -m http.server 9900 --bind 127.0.0.1 >/dev/null 2>&1 &

echo "── starting the internet, the node endpoint and a public resolver in gw"
ip netns exec gw python3 -m http.server 8080 --bind 10.90.0.1 >/dev/null 2>&1 &
ip netns exec gw python3 "$PY/keepalive-http.py" 10.90.0.1 8082 >/dev/null 2>&1 &
ip netns exec gw python3 "$PY/udp-echo.py" 10.90.0.1 51820 >/dev/null 2>&1 &
ip netns exec gw python3 "$PY/dns-stub.py" 10.90.0.1 >/dev/null 2>&1 &
sleep 1

echo "── before the kill switch (the leak path must work)"
code=$(cq curl -s -m 4 -o /dev/null -w "%{http_code}" http://10.90.0.1:8080 2>/dev/null)
[ "$code" = 200 ] && ok "HTTP to the internet works (a leak path exists)" || no "HTTP should work before the kill switch (got $code)"
cq python3 "$PY/udp-ping.py" 10.90.0.1 53 && ok "DNS to a public resolver works" || no "DNS should work before the kill switch"
cq python3 "$PY/udp-ping.py" 10.90.0.1 51820 && ok "the node endpoint answers" || no "the node endpoint should answer"
# A connection to the internet that is open before the kill switch, and kept
# open across it: an established flow, the kind a blanket "established
# connections pass" rule would let carry on in the clear. A desktop firewall
# (ufw, firewalld) tracks connections before the VPN ever runs; this table
# stands in for one, so the flow is tracked the way it would be there.
cq nft -f - <<'NFT'
table inet hv_desktop_firewall {
  chain input {
    type filter hook input priority -10; policy accept;
    ct state established,related accept
  }
}
NFT
REUSE_DIR=$(mktemp -d /tmp/hidravpn-ks.XXXXXX)
cq python3 "$PY/tcp-reuse.py" 10.90.0.1 8082 "$REUSE_DIR/go" > "$REUSE_DIR/log" 2>&1 & REUSE=$!
for _ in $(seq 1 30); do grep -q "^first ok" "$REUSE_DIR/log" 2>/dev/null && break; sleep 0.2; done
grep -q "^first ok" "$REUSE_DIR/log" && ok "a connection to the internet is open before the kill switch, and stays open" || no "the keep-alive connection did not work before the kill switch: $(cat "$REUSE_DIR/log")"

echo "── arming the kill switch"
cq "$SVC" firewall on --interface hvpn0 --node 10.90.0.1:51820 --dns 10.77.0.1 >/dev/null 2>&1 && ok "kill switch armed" || no "could not arm the kill switch"
cq nft list table inet hidravpn_ks >/dev/null 2>&1 && ok "the kill-switch table is present" || no "the table should be present"

echo "── with the kill switch on"
code=$(cq curl -s -m 4 -o /dev/null -w "%{http_code}" http://10.90.0.1:8080 2>/dev/null)
[ "$code" = 000 ] && ok "HTTP to the internet is blocked" || no "HTTP leaked past the kill switch (code $code)"
cq python3 "$PY/udp-ping.py" 10.90.0.1 53 && no "DNS to a public resolver leaked" || ok "DNS to a public resolver is blocked"
cq python3 "$PY/udp-ping.py" 10.90.0.1 51820 && ok "the node endpoint is still reachable" || no "the node endpoint should stay reachable"
lo_code=$(cq curl -s -m 4 -o /dev/null -w "%{http_code}" http://127.0.0.1:9900 2>/dev/null)
[ "$lo_code" = 200 ] && ok "loopback still works" || no "loopback should work (got $lo_code)"
touch "$REUSE_DIR/go"; wait $REUSE; REUSE_RC=$?
[ "$REUSE_RC" = 0 ] && grep -q "^second blocked" "$REUSE_DIR/log" && ok "the connection opened before the kill switch is cut off too: being established opens nothing" || no "an established connection carried on through the kill switch: $(cat "$REUSE_DIR/log")"
rm -rf "$REUSE_DIR"

echo "── lifting the kill switch"
cq "$SVC" firewall off >/dev/null 2>&1 && ok "kill switch lifted" || no "could not lift the kill switch"
cq nft list table inet hidravpn_ks >/dev/null 2>&1 && no "the table should be gone" || ok "the kill-switch table is gone"
code=$(cq curl -s -m 4 -o /dev/null -w "%{http_code}" http://10.90.0.1:8080 2>/dev/null)
[ "$code" = 200 ] && ok "HTTP works again after the kill switch is off" || no "HTTP should work again (got $code)"

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
