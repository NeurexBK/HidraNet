#!/usr/bin/env bash
# The service inside the systemd unit's sandbox, on a machine without
# systemd-resolved: the file system read-only but for /etc, /proc/sys/net and
# the runtime directory (ProtectSystem=strict, ReadWritePaths=), and
# /etc/resolv.conf either NetworkManager's link into /run or a plain file.
# Proves, for both: the service connects and names resolve through the tunnel;
# NetworkManager's own file is never touched; `down` puts resolv.conf back as
# it was, link and all; and after a power cut while connected (the plan in
# /run gone, resolv.conf still the tunnel's), the next start of the service
# puts the machine's DNS back by itself.
#
# This machine's /etc, as the service sees it, is a directory of the test's
# own: nothing of the real /etc/resolv.conf is changed.
#
# Run as root:  hidravpn/scripts/test-unit-sandbox-netns.sh
# Needs: the release binaries built, python3, curl, nft, ip netns, unshare, nsenter.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/test/guard.sh"
BIN="$HERE/../target/release"
WORK=""
C="ip netns exec hv-client"
N="ip netns exec hv-node"
I="ip netns exec hv-inet"
PIDS=()
SVC=""

ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok + 1)); }
fail() { echo "FAIL  $1"; bad=$((bad + 1)); }

cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  ip netns pids hv-client 2>/dev/null | xargs -r kill 2>/dev/null
  for ns in hv-client hv-node hv-inet; do ip netns del "$ns" 2>/dev/null; done
  rm -rf /run/hidravpn/control.sock /run/hidravpn/control.token /run/hidravpn/netcfg.json /etc/hidravpn/client.key
  rmdir /run/NetworkManager 2>/dev/null
  [ "${MADE_GROUP:-0}" = 1 ] && groupdel hidravpn 2>/dev/null
  [ -n "${WORK:-}" ] && rm -rf "$WORK"
}
trap cleanup EXIT
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -e /run/NetworkManager ] && { echo "this machine runs NetworkManager; run the test elsewhere"; exit 1; }
cleanup
WORK="$(mktemp -d /tmp/hidravpn-unit.XXXXXX)"
mkdir -p "$WORK/run"
for b in hidravpn hidravpn-node hidravpn-service; do
  [ -x "$BIN/$b" ] || { echo "build first: cargo build --release --manifest-path hidravpn/Cargo.toml"; exit 1; }
done

# ── Network (same topology as test-netns.sh) ────────────────────────────────
ip netns add hv-client; ip netns add hv-node; ip netns add hv-inet
ip link add c-n type veth peer name n-c; ip link set c-n netns hv-client; ip link set n-c netns hv-node
ip link add n-i type veth peer name i-n; ip link set n-i netns hv-node; ip link set i-n netns hv-inet
$C ip addr add 10.200.0.2/24 dev c-n; $C ip link set c-n up; $C ip link set lo up; $C ip route add default via 10.200.0.1
$N ip addr add 10.200.0.1/24 dev n-c; $N ip link set n-c up; $N ip link set lo up
$N ip addr add 10.201.0.1/24 dev n-i; $N ip link set n-i up; $N ip route add default via 10.201.0.2
$I ip addr add 10.201.0.2/24 dev i-n; $I ip link set i-n up; $I ip link set lo up
$I python3 -I "$HERE/test/whoami-http.py" > "$WORK/http.log" 2>&1 & PIDS+=($!)
$I python3 -I "$HERE/test/dns-stub.py" 10.201.0.2 > "$WORK/dns.log" 2>&1 & PIDS+=($!)
sleep 1

$N "$BIN/hidravpn-node" --config "$WORK/node.toml" init --endpoint 10.200.0.1:51820 --name test-node --dns udp://10.201.0.2 --out-interface n-i > "$WORK/init.log" 2>&1 || { cat "$WORK/init.log"; fail "node init"; exit 1; }
$N env HIDRAVPN_RUN_DIR="$WORK/run" "$BIN/hidravpn-node" --config "$WORK/node.toml" run > "$WORK/node.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 50); do grep -q "DNS forwarder ready" "$WORK/node.log" && break; sleep 0.2; done
grep -q "DNS forwarder ready" "$WORK/node.log" && pass "node up" || { cat "$WORK/node.log"; fail "node did not come up"; exit 1; }

mkdir -p /etc/hidravpn /run/hidravpn /run/NetworkManager "$WORK/run"
NODE_PUB=$(grep -o 'node public key: .*' "$WORK/init.log" | cut -d' ' -f4)
$C "$BIN/hidravpn" --key /etc/hidravpn/client.key keygen >/dev/null 2>&1
PUB=$($C "$BIN/hidravpn" --key /etc/hidravpn/client.key pubkey --node "$NODE_PUB" 2>/dev/null)
$N env HIDRAVPN_RUN_DIR="$WORK/run" "$BIN/hidravpn-node" --config "$WORK/node.toml" admit --name laptop --pubkey "$PUB" > "$WORK/invite.json" 2>/dev/null
grep -q '"client_address"' "$WORK/invite.json" && pass "client admitted" || { cat "$WORK/invite.json"; fail "admit"; exit 1; }

# The service in the sandbox, in the client namespace; SP its process.
start_service() {
  $C unshare -m "$HERE/test/unit-sandbox.sh" "$ETC" env RUST_LOG=hidravpn_service=info "$BIN/hidravpn-service" run >> "$WORK/svc-$MODE.log" 2>&1 &
  SVC=$!; PIDS+=($SVC)
  SP=""
  for i in $(seq 1 50); do
    [ -S /run/hidravpn/control.sock ] && SP=$(pgrep -f "^$BIN/hidravpn-service run" | head -1) && [ -n "$SP" ] && break
    sleep 0.2
  done
  IN="nsenter -t ${SP:-0} -m -n"
}
stop_service() {
  kill -INT "$SVC" 2>/dev/null; for i in $(seq 1 25); do kill -0 "$SVC" 2>/dev/null || break; sleep 0.2; done
  rm -f /run/hidravpn/control.sock
}
resolv_is_original() {
  if [ "$MODE" != file ]; then
    [ "$($IN readlink /etc/resolv.conf)" = /run/NetworkManager/resolv.conf ] && $IN grep -q "nameserver 10.200.0.1" /etc/resolv.conf
  else
    [ ! -L "$ETC/resolv.conf" ] && [ "$(cat "$ETC/resolv.conf")" = "nameserver 10.200.0.1" ]
  fi
}

# The capabilities the unit leaves the service, read from the unit itself.
UNIT_CAPS=$(grep -o '^CapabilityBoundingSet=.*' "$HERE/../crates/hidravpn-service/src/install/linux.rs" | cut -d= -f2 \
  | tr ' ' '\n' | sed 's/^CAP_/+/' | tr 'A-Z' 'a-z' | paste -sd, -)
export UNIT_CAPS
[ -n "$UNIT_CAPS" ] && pass "the unit's capabilities: $UNIT_CAPS" || { fail "could not read the unit's CapabilityBoundingSet"; exit 1; }
# The control group, as the installer makes it: the service hands it the
# socket and the token, which takes a capability of its own.
MADE_GROUP=0
if ! getent group hidravpn >/dev/null; then groupadd --system hidravpn && MADE_GROUP=1; fi

for MODE in link file readonly; do
  echo "── /etc/resolv.conf as a $MODE ──"
  ETC="$WORK/etc-$MODE"; mkdir "$ETC"
  cp -a /etc/hidravpn /etc/hosts /etc/nsswitch.conf /etc/passwd /etc/group "$ETC/" 2>/dev/null
  if [ "$MODE" != file ]; then
    ln -s /run/NetworkManager/resolv.conf "$ETC/resolv.conf"
  else
    echo "nameserver 10.200.0.1" > "$ETC/resolv.conf"
  fi

  if [ "$MODE" = readonly ]; then export ETC_RO=1; else unset ETC_RO; fi
  start_service
  [ -n "$SP" ] && pass "$MODE: the service is up in the unit's sandbox" || { cat "$WORK/svc-$MODE.log"; fail "$MODE: the service did not start"; exit 1; }
  [ "$(stat -c %G /run/hidravpn/control.token)" = hidravpn ] && [ "$(stat -c %G /run/hidravpn/control.sock)" = hidravpn ] \
    && pass "$MODE: with only the unit's capabilities, the socket and the token go to the hidravpn group" || fail "$MODE: token group $(stat -c %G /run/hidravpn/control.token)"
  $IN sh -c 'touch /usr/.hv-probe' 2>/dev/null && { rm -f /usr/.hv-probe; fail "$MODE: /usr is writable, the sandbox is not in place"; } || pass "$MODE: outside /etc the file system is read-only, as ProtectSystem=strict makes it"
  $IN sh -c 'touch /run/NetworkManager/.hv-probe' 2>/dev/null && fail "$MODE: /run is writable" || pass "$MODE: /run is read-only too"
  resolv_is_original && pass "$MODE: resolv.conf starts as the machine's" || fail "$MODE: setup: $($IN ls -l /etc/resolv.conf)"

  if [ "$MODE" = readonly ]; then
    # /etc cannot be written: the connection fails — at the pocket's lock,
    # before the network is touched, or at the DNS step, after which what was
    # done before it (the routes) is undone at once — and nothing is left.
    $C "$BIN/hidravpn-service" up "$WORK/invite.json" > "$WORK/up-ro.log" 2>&1 && fail "readonly: connected with /etc read-only" || pass "readonly: with /etc read-only the connection fails ($(grep -oE '(writing|opening) [^:]*' "$WORK/up-ro.log" | head -1))"
    $C ip -4 route | grep -qE '^(0\.0\.0\.0/1|128\.0\.0\.0/1|10\.200\.0\.1 )' && fail "readonly: routes left behind: $($C ip -4 route | tr '\n' ';')" || pass "readonly: no route is left behind"
    [ -e /run/hidravpn/netcfg.json ] && fail "readonly: a network plan was left behind" || pass "readonly: no network plan is left behind"
    $C nft list table inet hidravpn_ks >/dev/null 2>&1 && fail "readonly: the kill switch was left armed" || pass "readonly: the kill switch is not left armed"
    stop_service
    continue
  fi

  # ── Up and down ───────────────────────────────────────────────────────────
  $C "$BIN/hidravpn-service" up "$WORK/invite.json" > "$WORK/up.log" 2>&1 && pass "$MODE: the service connected" || { cat "$WORK/up.log"; fail "$MODE: service up"; }
  $IN grep -q "nameserver 10.77.0.1" /etc/resolv.conf && pass "$MODE: DNS is the node while connected" || fail "$MODE: DNS while connected: $($IN cat /etc/resolv.conf | tr '\n' ' ')"
  BYNAME=$($IN curl -s --max-time 5 http://whoami.test/ 2>/dev/null)
  [ "$BYNAME" = "10.201.0.1" ] && pass "$MODE: a request by name goes through the tunnel" || fail "$MODE: by name: '$BYNAME'"
  $IN grep -q "Generated by NetworkManager" /run/NetworkManager/resolv.conf && pass "$MODE: NetworkManager's own file is left alone" || fail "$MODE: NetworkManager's file changed"
  $C "$BIN/hidravpn-service" down > "$WORK/down.log" 2>&1 && pass "$MODE: the service disconnected" || { cat "$WORK/down.log"; fail "$MODE: service down"; }
  resolv_is_original && pass "$MODE: resolv.conf is back as it was" || fail "$MODE: after down: $($IN ls -l /etc/resolv.conf) $($IN cat /etc/resolv.conf | tr '\n' ' ')"
  [ -e "$ETC/hidravpn/resolv.conf.saved" ] && fail "$MODE: the saved copy outlived the connection" || pass "$MODE: the saved copy is gone with the connection"

  # ── A power cut while connected ───────────────────────────────────────────
  $C "$BIN/hidravpn-service" up "$WORK/invite.json" > "$WORK/up2.log" 2>&1 || { cat "$WORK/up2.log"; fail "$MODE: second up"; }
  kill -9 "$SP" 2>/dev/null; wait "$SVC" 2>/dev/null; sleep 0.5
  # What a reboot clears: /run, the firewall, the interfaces, the routes.
  rm -f /run/hidravpn/netcfg.json /run/hidravpn/control.sock /run/hidravpn/control.token /run/hidravpn/control.pub
  $C nft delete table inet hidravpn_ks 2>/dev/null; $C ip link del hvpn0 2>/dev/null
  $C ip -4 route del 10.200.0.1/32 2>/dev/null
  grep -q "nameserver 10.77.0.1" "$ETC/resolv.conf" && pass "$MODE: after the power cut resolv.conf is still the tunnel's" || fail "$MODE: the cut did not leave the tunnel's resolv.conf: $(cat "$ETC/resolv.conf")"
  start_service
  [ -n "$SP" ] && pass "$MODE: the service starts again after the cut" || { tail -5 "$WORK/svc-$MODE.log"; fail "$MODE: no restart"; }
  resolv_is_original && pass "$MODE: and puts the machine's DNS back by itself" || fail "$MODE: after the restart: $($IN ls -l /etc/resolv.conf) $($IN cat /etc/resolv.conf | tr '\n' ' ')"
  [ -e "$ETC/hidravpn/resolv.conf.saved" ] && fail "$MODE: the saved copy outlived the recovery" || pass "$MODE: the saved copy is gone"
  stop_service
done

grep -E '10\.200\.0\.2|10\.77\.0\.2' "$WORK"/svc-*.log >/dev/null && fail "a service log names the client's address" || pass "no service log names the client's address"

echo; echo "$ok passed, $bad failed"; [ $bad -eq 0 ]
