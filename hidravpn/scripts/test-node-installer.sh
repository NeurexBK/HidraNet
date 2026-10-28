#!/usr/bin/env bash
# The one-command node installer, without installing anything: its syntax,
# a shellcheck pass when available, every step it would take in --dry-run, and the
# ways it must refuse (no endpoint, a bad endpoint, not root).
#
#   bash hidravpn/scripts/test-node-installer.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
S="$HERE/install-node-linux.sh"
ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok + 1)); }
fail() { echo "FAIL  $1"; bad=$((bad + 1)); }

bash -n "$S" && pass "the installer parses" || fail "syntax error"
if command -v shellcheck >/dev/null; then
  shellcheck -S warning "$S" >/dev/null 2>&1 && pass "shellcheck finds nothing at warning level" || { shellcheck -S warning "$S" | head -30; fail "shellcheck"; }
else
  echo "note  shellcheck not installed; skipped"
fi

OUT=$(bash "$S" --dry-run --endpoint 203.0.113.10:51820 --name node-1 --out-interface eth9 --role exit --operator "the maintainers" --contact nodes@example.org --open-admission --dns https://dns.quad9.net/dns-query@9.9.9.9 2>&1); RC=$?
[ $RC -eq 0 ] && pass "a dry run exits 0" || { echo "$OUT"; fail "dry run exited $RC"; }
has() { echo "$OUT" | grep -qF -- "$2" && pass "$1" || { fail "$1 — missing: $2"; }; }
has "it installs the binary"            "would run: install -m 0755"
has "it initialises the node with the endpoint, port, name and interface" "init --endpoint 203.0.113.10:51820 --port 51820 --name node-1 --out-interface eth9"
has "it passes the resolvers through"   "--dns https://dns.quad9.net/dns-query@9.9.9.9"
has "it passes the role, the operator, the contact and open admission" "--role exit --admission-port 51821 --operator the maintainers --contact nodes@example.org --open-admission"
has "it opens the admission port too"   "UDP 51820 (the tunnel) and TCP 51821 (admission"
has "it says how to get the node's record for the list" "hidravpn-node record >"
has "it says how clients join an open node" "hidravpn nodes join --all"
has "it installs the systemd unit"      "hidravpn-node.service"
has "the unit runs the installed binary with the settings init wrote" "it runs /usr/local/bin/hidravpn-node --config /etc/hidravpn/node.toml run"
OUT2=$(HIDRAVPN_PREFIX=/opt/hv/bin HIDRAVPN_ETC=/opt/hv/etc bash "$S" --dry-run --endpoint 203.0.113.10:51820 --name node-1 --out-interface eth9 2>&1)
echo "$OUT2" | grep -q "it runs /opt/hv/bin/hidravpn-node --config /opt/hv/etc/node.toml run" && pass "with HIDRAVPN_PREFIX and HIDRAVPN_ETC the unit runs that binary with those settings" || fail "custom paths: $(echo "$OUT2" | grep 'systemd unit')"
has "it enables and starts the service" "would run: systemctl enable --now hidravpn-node"
has "it says which ports must be open and nothing else" "must reach this node; SSH stays as it is"
has "it prints how to admit a client"   "hidravpn-node admit --name <a-name>"
has "it says plainly what an exit means" "abuse complaints for"
has "it points at the bootstrap plan"   "docs/business/16-network-bootstrap.md"
has "it checks the machine before touching it" "checking the machine"
has "it tells the operator to back up the key" "BACK UP"
has "it says where admitted clients live and that they survive reboots" "survive reboots"
has "it says what the exit policy blocks" "Mail (port 25)"
echo "$OUT" | grep -q "would run: .*cargo build" && echo "note  the node binary is not built here; the dry run would build it" || true
# Nothing is written by a dry run.
[ ! -e /etc/systemd/system/hidravpn-node.service ] || [ -n "${HIDRAVPN_UNIT:-}" ] && pass "a dry run writes nothing" || fail "a dry run touched the system"

# The order of the steps is the order they appear in.
echo "$OUT" | grep -n '^>> ' | cut -d: -f2 | tr '\n' '|' | grep -q 'installing the binary.*|.*key and settings.*|.*systemd unit.*|.*firewall' && pass "the steps come in the right order" || fail "order: $(echo "$OUT" | grep '^>> ' | tr '\n' '|')"

OUT=$(bash "$S" --dry-run --name x 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q -- "--endpoint IP:PORT is required" && pass "no endpoint: refused, with the reason" || fail "no endpoint: $OUT"
OUT=$(bash "$S" --dry-run --endpoint 203.0.113.10 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "must be IP:PORT" && pass "an endpoint without a port: refused" || fail "no port: $OUT"
OUT=$(bash "$S" --dry-run --endpoint 203.0.113.10:abc 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "has no port" && pass "a port that is not a number: refused" || fail "bad port: $OUT"
OUT=$(bash "$S" --dry-run --endpoint 203.0.113.10:51820 --bogus 2>&1); [ $? -eq 2 ] && echo "$OUT" | grep -q "unknown option" && pass "an unknown option: refused with usage" || fail "bogus: $OUT"
OUT=$(bash "$S" --dry-run --endpoint 203.0.113.10:51820 --role relay 2>&1); [ $? -eq 2 ] && echo "$OUT" | grep -q "entry, exit or both" && pass "a role that is not one: refused" || fail "role: $OUT"
OUT=$(bash "$S" --dry-run --endpoint 203.0.113.10:51820 2>&1); echo "$OUT" | grep -q -- "--role both --admission-port 51821" && ! echo "$OUT" | grep -q -- "--open-admission" && pass "by default a node is both and admits by hand" || fail "defaults: $(echo "$OUT" | grep 'init --endpoint')"
OUT=$(bash "$S" --dry-run --endpoint 203.0.113.10:51820 2>&1); echo "$OUT" | grep -qE -- "--name node-[0-9a-f]{8} " && pass "the name defaults to a random one, never the hostname" || fail "default name: $(echo "$OUT" | grep 'init --endpoint')"
echo "$OUT" | grep -q -- "--name $(hostname -s) " && fail "the hostname leaked into the default name" || pass "the hostname is not the default name"
if command -v setpriv >/dev/null && [ "$(id -u)" = 0 ]; then
  # A copy nobody can read: the checkout may sit under a home directory
  # other accounts cannot enter (as on a CI runner).
  NR="$(mktemp -d)"; cp "$S" "$NR/"; chmod 755 "$NR"; chmod 644 "$NR/$(basename "$S")"
  OUT=$(setpriv --reuid=nobody --regid=nogroup --clear-groups bash "$NR/$(basename "$S")" --endpoint 203.0.113.10:51820 2>&1); [ $? -eq 1 ] && echo "$OUT" | grep -q "run it with sudo" && pass "not root and not a dry run: refused before touching anything" || fail "non-root: $OUT"
  rm -rf "$NR"
fi
bash "$S" --help 2>&1 | grep -q -- "--dry-run" && pass "--help prints the options" || fail "help"
OUT=$(bash "$S" --dry-run --endpoint 203.0.113.10:443 --name x 2>&1); echo "$OUT" | grep -q -- "--port 443 " && echo "$OUT" | grep -q "UDP 443 (the tunnel)" && pass "the port the node listens on is the port the firewall opens" || fail "port mismatch: $(echo "$OUT" | grep -E 'init --endpoint|UDP')"
OUT=$(bash "$S" --dry-run --endpoint 203.0.113.10:51820 --name x --pass-admission 2>&1); echo "$OUT" | grep -q -- "init --endpoint .* --pass-admission" && echo "$OUT" | grep -q "Admission: with a pass" && pass "--pass-admission initialises a node that admits with a pass, and says to add the issuer's key" || fail "pass admission: $(echo "$OUT" | grep -E 'init --endpoint|Admission')"
OUT=$(bash "$S" --dry-run --endpoint 203.0.113.10:51820 --open-admission --pass-admission 2>&1); [ $? -ne 0 ] && echo "$OUT" | grep -q "choose one" && pass "open and pass admission together: refused" || fail "both admissions accepted"
OUT=$(bash "$S" --dry-run --endpoint 203.0.113.10:51820 --name x --role entry --open-admission --country nl --tunnel 10.80.0.0/16 2>&1); echo "$OUT" | grep -q -- "init --endpoint .* --country NL --tunnel 10.80.0.0/16" && pass "--country (upper-cased) and --tunnel reach the node's settings" || fail "country/tunnel: $(echo "$OUT" | grep 'init --endpoint')"
OUT=$(bash "$S" --dry-run --endpoint 203.0.113.10:51820 2>&1); echo "$OUT" | grep -qE -- "--country|--tunnel" && fail "country/tunnel passed without being asked" || pass "without --country and --tunnel the node keeps its defaults"
OUT=$(bash "$S" --dry-run --endpoint 203.0.113.10:51820 --country NLD 2>&1); [ $? -eq 2 ] && echo "$OUT" | grep -q "two letters" && pass "a country that is not two letters: refused" || fail "country NLD: $OUT"
OUT=$(bash "$S" --dry-run --endpoint 203.0.113.10:51820 --tunnel 10.80.0.0 2>&1); [ $? -eq 2 ] && echo "$OUT" | grep -q "IPv4 subnet" && pass "a tunnel that is not a subnet: refused" || fail "tunnel without prefix: $OUT"
for tun in 10.80.0.1/16 8.8.8.0/24 10.0.0.0/31 10.0.0.0/4 300.0.0.0/16 010.80.0.0/16; do
  OUT=$(bash "$S" --dry-run --endpoint 203.0.113.10:51820 --tunnel "$tun" 2>&1); [ $? -eq 2 ] && echo "$OUT" | grep -q -- "--tunnel" && pass "a tunnel init would refuse is refused before anything runs: $tun" || fail "tunnel $tun accepted: $(echo "$OUT" | grep 'init --endpoint')"
done
OUT=$(bash "$S" --dry-run --endpoint 203.0.113.10:51820 --tunnel 100.64.0.0/10 2>&1); echo "$OUT" | grep -q -- "--tunnel 100.64.0.0/10" && pass "a shared-address-space tunnel is accepted" || fail "100.64.0.0/10: $OUT"

echo; echo "$ok passed, $bad failed"; [ $bad -eq 0 ]
