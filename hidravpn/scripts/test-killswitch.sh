#!/usr/bin/env bash
# Kill-switch leak test, in three network namespaces.
#
#   ks  — the client machine, where the kill switch is armed
#   gw  — the "router/internet": an HTTP server (the open internet), a UDP echo
#         (the node's WireGuard endpoint) and a DNS resolver (a public one, not
#         the node's)
#   kt  — the far end of the tunnel interface hvpn0 (a veth standing in for
#         the tunnel): what the node puts into the tunnel, and the node's
#         resolver at its tunnel address
#
# With the kill switch off, the client reaches all three — that is the leak
# path a dropped tunnel could fall back to. With it on, only the node endpoint
# is reachable; HTTP and the public DNS are blocked, loopback still works, and
# turning it off restores everything. Through the tunnel the client reaches
# what it asks for, and the far end reaches nothing on the client unasked.
# That holds whatever source the far end puts on what it sends: the node's
# own endpoint, a DHCP server's port. With "Allow LAN" the local network is
# reached, but no DNS query goes to it, even when a route sends the node's
# resolver address there.
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

SINK=""
cleanup() {
  for ns in ks gw kt; do
    ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns del "$ns" 2>/dev/null
  done
  [ -n "$SINK" ] && rm -f "$SINK"
}
trap cleanup EXIT
cleanup
SINK="$(mktemp /tmp/hidravpn-ks-sink.XXXXXX)"

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -x "$SVC" ] || { echo "build first: cargo build --release --manifest-path hidravpn/Cargo.toml -p hidravpn-service"; exit 1; }

cq() { ip netns exec ks "$@"; }

echo "── setting up the two namespaces"
ip netns add gw
ip netns add ks
ip netns add kt
ip link add ks-eth netns ks type veth peer name gw-eth netns gw
ip -n gw addr add 10.90.0.1/24 dev gw-eth
ip -n ks addr add 10.90.0.2/24 dev ks-eth
ip -n gw link set gw-eth up
ip -n ks link set ks-eth up
ip -n gw link set lo up
ip -n ks link set lo up
ip -n ks route add default via 10.90.0.1
# The tunnel interface: a veth whose other end, in kt, plays the node's end
# of the tunnel, at the node's tunnel address. kt also routes the client's
# local network back through it, as a node could put any destination in.
ip link add hvpn0 netns ks type veth peer name kt-tun netns kt
ip -n ks addr add 10.77.0.2/16 dev hvpn0
ip -n kt addr add 10.77.0.1/16 dev kt-tun
ip -n ks link set hvpn0 up
ip -n kt link set kt-tun up
ip -n kt link set lo up
ip -n kt route add 10.90.0.0/24 dev kt-tun
# The node's endpoint address in kt as well: the far end of a tunnel puts
# any source it likes on what it sends in, the node's own endpoint included.
# The client's reverse-path filter is loose, as Ubuntu and Fedora ship it:
# a packet comes in on any interface if its source has a route back at all.
ip -n kt addr add 10.90.0.1/32 dev lo
ip netns exec ks sysctl -qw net.ipv4.conf.all.rp_filter=2

# A loopback service in the client, to prove loopback keeps working with the
# kill switch on (ICMP ping is restricted in some sandboxes; TCP is reliable).
ip netns exec ks python3 -m http.server 9900 --bind 127.0.0.1 >/dev/null 2>&1 &

echo "── starting the internet, the node endpoint and a public resolver in gw"
ip netns exec gw python3 -m http.server 8080 --bind 10.90.0.1 >/dev/null 2>&1 &
ip netns exec gw python3 "$PY/keepalive-http.py" 10.90.0.1 8082 >/dev/null 2>&1 &
ip netns exec gw python3 "$PY/udp-echo.py" 10.90.0.1 51820 >/dev/null 2>&1 &
ip netns exec gw python3 "$PY/dns-stub.py" 10.90.0.1 >/dev/null 2>&1 &
echo "── starting the node's resolver and a web server at the tunnel's far end"
ip netns exec kt python3 "$PY/dns-stub.py" 10.77.0.1 >/dev/null 2>&1 &
ip netns exec kt python3 -m http.server 8080 --bind 10.77.0.1 >/dev/null 2>&1 &
# Programs listening on every address of the client, TCP and UDP: what the
# far end of the tunnel must not reach.
ip netns exec ks python3 -m http.server 9901 --bind 0.0.0.0 >/dev/null 2>&1 &
ip netns exec ks python3 "$PY/udp-echo.py" 0.0.0.0 9902 >/dev/null 2>&1 &
# And two that answer nothing, only note what they get: an answer to a
# forged source would go elsewhere, so the client side tells.
ip netns exec ks python3 "$PY/udp-sink.py" "$SINK" 9904 68 >/dev/null 2>&1 &
sleep 1
# Whether a datagram from the tunnel's far end, from the source given, gets
# to the client's sink on the port given.
arrives() {
  : > "$SINK"
  ip netns exec kt python3 "$PY/probe.py" send "$1" "$2" 10.77.0.2 "$3" >/dev/null
  sleep 1
  [ -s "$SINK" ]
}

echo "── before the kill switch (the leak path must work)"
code=$(cq curl -s -m 4 -o /dev/null -w "%{http_code}" http://10.90.0.1:8080 2>/dev/null)
[ "$code" = 200 ] && ok "HTTP to the internet works (a leak path exists)" || no "HTTP should work before the kill switch (got $code)"
cq python3 "$PY/udp-ping.py" 10.90.0.1 53 && ok "DNS to a public resolver works" || no "DNS should work before the kill switch"
cq python3 "$PY/udp-ping.py" 10.90.0.1 51820 && ok "the node endpoint answers" || no "the node endpoint should answer"
# The probes from the tunnel's far end work, so their silence later means
# something: without a kill switch the far end reaches the client's programs.
[ "$(ip netns exec kt python3 "$PY/probe.py" tcp 10.77.0.2 9901)" = open ] && [ "$(ip netns exec kt python3 "$PY/probe.py" tcp 10.90.0.2 9901)" = open ] && [ "$(ip netns exec kt python3 "$PY/probe.py" udp 10.77.0.2 9902)" = answered ] && ok "the tunnel's far end reaches the client's listeners (the exposure the kill switch must close)" || no "the probes from the tunnel's far end did not work before the kill switch"
arrives 10.90.0.1 51820 9904 && arrives 10.77.0.1 67 68 && ok "so do its datagrams with the node's endpoint, or a DHCP server's port, as their source" || no "the forged-source datagrams from the tunnel's far end did not arrive before the kill switch"
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

# From the far end of the tunnel: before the kill switch, all of it answers
# (the node could reach every listening program); with it, none of it.
inbound() {
  for t in "tcp 10.77.0.2 9901:a TCP listener, at the tunnel address" \
           "tcp 10.90.0.2 9901:a TCP listener, at the client's local-network address" \
           "tcp 10.77.0.2 9903:a closed TCP port (a reset would give the address away)" \
           "udp 10.77.0.2 9902:a UDP listener" \
           "icmp 10.77.0.2:an echo request"; do
    got=$(ip netns exec kt python3 "$PY/probe.py" ${t%%:*})
    if [ "$got" = silent ]; then ok "$1: from the tunnel's far end, ${t#*:}: no answer"; else no "$1: from the tunnel's far end, ${t#*:}: $got"; fi
  done
  # The node's endpoint is let in off the tunnel, by address; the same
  # address on a packet inside the tunnel must not be.
  arrives 10.90.0.1 51820 9904 && no "$1: from the tunnel's far end, with the node's endpoint as source: it arrived" || ok "$1: from the tunnel's far end, with the node's endpoint as source: dropped"
  arrives 10.77.0.1 67 68 && no "$1: from the tunnel's far end, as a DHCP answer: it arrived" || ok "$1: from the tunnel's far end, as a DHCP answer: dropped"
}

echo "── through the tunnel, with the kill switch on"
code=$(cq curl -s -m 4 -o /dev/null -w "%{http_code}" http://10.77.0.1:8080 2>/dev/null)
[ "$code" = 200 ] && ok "a connection the client opens through the tunnel works, answers and all" || no "a connection through the tunnel should work (got $code)"
[ "$(cq python3 "$PY/probe.py" udp 10.77.0.1 53)" = answered ] && ok "DNS to the node's resolver through the tunnel is answered" || no "DNS to the node's resolver through the tunnel should work"
inbound "kill switch on"

echo "── with \"Allow LAN\""
cq "$SVC" firewall on --interface hvpn0 --node 10.90.0.1:51820 --dns 10.77.0.1 --allow-lan >/dev/null 2>&1 && ok "kill switch armed again, with the local network allowed" || no "could not arm the kill switch with --allow-lan"
code=$(cq curl -s -m 4 -o /dev/null -w "%{http_code}" http://10.90.0.1:8080 2>/dev/null)
[ "$code" = 200 ] && ok "a host on the local network is reached" || no "the local network should be reached with --allow-lan (got $code)"
[ "$(cq python3 "$PY/probe.py" udp 10.90.0.1 53)" = blocked ] && ok "DNS to the local network's resolver is refused (EPERM)" || no "DNS to the local network's resolver was not refused"
[ "$(cq python3 "$PY/probe.py" udp 10.77.0.1 53)" = answered ] && ok "DNS to the node's resolver through the tunnel is answered" || no "DNS to the node's resolver through the tunnel should work"
code=$(cq curl -s -m 4 -o /dev/null -w "%{http_code}" http://10.77.0.1:8080 2>/dev/null)
[ "$code" = 200 ] && ok "a connection through the tunnel still works" || no "a connection through the tunnel should work (got $code)"
# The node's tunnel address is a private one, inside what "Allow LAN" opens:
# what it sends in through the tunnel must not pass for the local network.
inbound "Allow LAN"
# A network that routes the resolver's address to itself: a route it pushes
# (DHCP option 121), then a subnet of its own on the tunnel's private range.
# gw answers at that address. The query must not leave on the link.
ip -n gw addr add 10.77.0.1/32 dev lo
ip -n ks route add 10.77.0.1/32 via 10.90.0.1 dev ks-eth
got=$(cq python3 "$PY/probe.py" udp 10.77.0.1 53)
[ "$got" = blocked ] && ok "a route pushed for the resolver through the local network: the query is refused (EPERM)" || no "a route pushed for the resolver through the local network: the query was $got"
# TCP: the kernel retries a SYN the firewall drops instead of failing the
# connect, so it reads as silence; a SYN that left would draw gw's reset.
got=$(cq python3 "$PY/probe.py" tcp 10.77.0.1 53)
case "$got" in blocked|silent) ok "the same over TCP: nothing leaves ($got)" ;; *) no "the same over TCP: $got" ;; esac
ip -n ks route del 10.77.0.1/32 via 10.90.0.1 dev ks-eth
ip -n gw addr del 10.77.0.1/32 dev lo
ip -n gw addr add 10.77.0.1/24 dev gw-eth
ip -n ks addr add 10.77.0.5/24 dev ks-eth
got=$(cq python3 "$PY/probe.py" udp 10.77.0.1 53)
[ "$got" = blocked ] && ok "a local network on the tunnel's own range: the query is refused (EPERM)" || no "a local network on the tunnel's own range: the query was $got"
ip -n ks addr del 10.77.0.5/24 dev ks-eth
ip -n gw addr del 10.77.0.1/24 dev gw-eth

echo "── lifting the kill switch"
cq "$SVC" firewall off >/dev/null 2>&1 && ok "kill switch lifted" || no "could not lift the kill switch"
cq nft list table inet hidravpn_ks >/dev/null 2>&1 && no "the table should be gone" || ok "the kill-switch table is gone"
code=$(cq curl -s -m 4 -o /dev/null -w "%{http_code}" http://10.90.0.1:8080 2>/dev/null)
[ "$code" = 200 ] && ok "HTTP works again after the kill switch is off" || no "HTTP should work again (got $code)"

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
