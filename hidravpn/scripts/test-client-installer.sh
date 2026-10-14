#!/usr/bin/env bash
# The client installer the browser runs, run for real: `hidravpn-service
# install` from a download folder, an update over it, `uninstall`, and
# `uninstall --purge`. systemd is replaced by a stand-in that only records
# what it was asked (containers have no systemd), so this checks everything
# the installer itself does: where the programs go, the unit it writes, the
# group and the account put in it, the machine's key made once and kept, and
# what a purge removes.
#
#   sudo hidravpn/scripts/test-client-installer.sh
#
# It installs into the real places (/usr/local/bin, /etc/hidravpn,
# /etc/systemd/system), so it refuses to run where HidraVPN is installed.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/../target/release"
ok=0; bad=0
pass() { echo "ok    $1"; ok=$((ok + 1)); }
fail() { echo "FAIL  $1"; bad=$((bad + 1)); }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
for b in hidravpn hidravpn-service; do [ -x "$BIN/$b" ] || { echo "build first: cargo build --release --manifest-path hidravpn/Cargo.toml -p hidravpn -p hidravpn-service"; exit 1; }; done
if [ -e /usr/local/bin/hidravpn-service ] || [ -e /etc/hidravpn/client.key ] || [ -e /etc/systemd/system/hidravpn.service ]; then
  echo "HidraVPN is installed on this machine; this test would replace it. Run it in a container."; exit 1
fi

W="$(mktemp -d /tmp/hv-inst.XXXXXX)"
TESTUSER=hvinstalltest
cleanup() {
  rm -f /usr/local/bin/hidravpn-service /usr/local/bin/hidravpn /etc/systemd/system/hidravpn.service
  rm -rf /etc/hidravpn
  userdel "$TESTUSER" 2>/dev/null; groupdel hidravpn 2>/dev/null
  rm -rf "$W"
}
trap cleanup EXIT

# A systemctl that records and succeeds.
mkdir -p "$W/fake"
cat > "$W/fake/systemctl" <<'SH'
#!/bin/sh
echo "$*" >> "$HV_SYSTEMCTL_LOG"
exit 0
SH
chmod +x "$W/fake/systemctl"
export HV_SYSTEMCTL_LOG="$W/systemctl.log"
export PATH="$W/fake:$PATH"

# The folder the browser downloads into and checks.
mkdir -p "$W/dl"
cp "$BIN/hidravpn-service" "$BIN/hidravpn" "$W/dl/"
useradd --no-create-home "$TESTUSER" 2>/dev/null

OUT=$("$W/dl/hidravpn-service" install --client "$W/dl/hidravpn" --user "$TESTUSER" 2>&1); RC=$?
[ $RC = 0 ] && pass "install from the download folder succeeds ($(echo "$OUT" | tail -1))" || fail "install: rc=$RC $OUT"
cmp -s "$BIN/hidravpn-service" /usr/local/bin/hidravpn-service && cmp -s "$BIN/hidravpn" /usr/local/bin/hidravpn \
  && pass "the service and the client are in /usr/local/bin, byte for byte" || fail "binaries not placed"
grep -q "^ExecStart=/usr/local/bin/hidravpn-service run$" /etc/systemd/system/hidravpn.service \
  && pass "the unit runs the installed copy, not the download" || fail "unit: $(grep ExecStart /etc/systemd/system/hidravpn.service 2>&1)"
grep -q "^daemon-reload" "$HV_SYSTEMCTL_LOG" && grep -q "^enable --now hidravpn" "$HV_SYSTEMCTL_LOG" \
  && pass "systemd is asked to reload, enable and start it" || fail "systemctl: $(cat "$HV_SYSTEMCTL_LOG")"
id -nG "$TESTUSER" | tr ' ' '\n' | grep -qx hidravpn && pass "the account that asked is in the hidravpn group" || fail "group: $(id -nG "$TESTUSER")"
KEY=/etc/hidravpn/client.key
[ -f $KEY ] && [ "$(stat -c %a $KEY)" = 600 ] && [ "$(tr -d '\n' < $KEY | wc -c)" = 44 ] \
  && pass "this machine's key is made, 44 characters, readable by root only" || fail "key: $(ls -l $KEY 2>&1)"
SUM1=$(sha256sum $KEY)

: > "$HV_SYSTEMCTL_LOG"
OUT=$("$W/dl/hidravpn-service" install --client "$W/dl/hidravpn" 2>&1); RC=$?
[ $RC = 0 ] && pass "installing again (an update) succeeds" || fail "update: $OUT"
grep -q "^stop hidravpn" "$HV_SYSTEMCTL_LOG" && [ "$(grep -n '^stop hidravpn' "$HV_SYSTEMCTL_LOG" | head -1 | cut -d: -f1)" -lt "$(grep -n '^enable' "$HV_SYSTEMCTL_LOG" | head -1 | cut -d: -f1)" ] \
  && pass "an update stops the running service before replacing it, then starts it" || fail "update order: $(cat "$HV_SYSTEMCTL_LOG")"
[ "$(sha256sum $KEY)" = "$SUM1" ] && pass "an update keeps the key every node knows this machine by" || fail "the key changed"

: > "$HV_SYSTEMCTL_LOG"
OUT=$("$W/dl/hidravpn-service" install --user 'x;id' 2>&1); RC=$?
[ $RC != 0 ] && echo "$OUT" | grep -q "not a login name" && [ ! -s "$HV_SYSTEMCTL_LOG" ] \
  && pass "a --user that is not a login name is refused before the service is touched" || fail "bad user: $OUT / $(cat "$HV_SYSTEMCTL_LOG")"

echo '{"entries":[],"exits":[]}' > /etc/hidravpn/circuit.json
OUT=$(/usr/local/bin/hidravpn-service uninstall 2>&1); RC=$?
[ $RC = 0 ] && [ ! -e /etc/systemd/system/hidravpn.service ] && pass "uninstall removes the service ($(echo "$OUT" | tail -1))" || fail "uninstall: $OUT"
[ "$(sha256sum $KEY)" = "$SUM1" ] && [ -f /etc/hidravpn/circuit.json ] && [ -x /usr/local/bin/hidravpn ] \
  && pass "without --purge the key, the nodes and the programs stay" || fail "plain uninstall removed too much"

"$W/dl/hidravpn-service" install --client "$W/dl/hidravpn" >/dev/null 2>&1
OUT=$(/usr/local/bin/hidravpn-service uninstall --purge 2>&1); RC=$?
[ $RC = 0 ] && pass "uninstall --purge succeeds ($(echo "$OUT" | tail -1))" || fail "purge: $OUT"
[ ! -e $KEY ] && [ ! -e /etc/hidravpn/circuit.json ] && [ ! -e /usr/local/bin/hidravpn ] && [ ! -e /usr/local/bin/hidravpn-service ] && [ ! -e /etc/systemd/system/hidravpn.service ] \
  && pass "--purge removes the programs, the nodes and the key" || fail "left behind: $(ls /usr/local/bin/hidravpn* /etc/hidravpn 2>&1)"

# ── The whole chain the browser runs: a manifest made by the script, signed
# by hidravpn-sign, read and checked by the browser's installer, which then
# installs the downloaded service. Only the network (files read from disk)
# and pkexec (already root) are stood in for.
if command -v node >/dev/null && [ -x "$BIN/hidravpn-sign" ]; then
  mkdir -p "$W/rel/linux-x64"
  cp "$BIN/hidravpn-service" "$BIN/hidravpn" "$W/rel/linux-x64/"
  PUB=$("$BIN/hidravpn-sign" keygen --out "$W/release.key" 2>/dev/null)
  "$HERE/make-release-manifest.sh" --version 9.9.9 --base https://hidranet.org/vpn/release/9.9.9 --linux-x64 "$W/rel/linux-x64" > "$W/rel/manifest.json"
  "$BIN/hidravpn-sign" sign --key "$W/release.key" "$W/rel/manifest.json" >/dev/null 2>&1
  OUT=$(cd "$HERE/../../hidra-browser" && HV_REL="$W/rel" HV_PUB="$PUB" HV_USER="$TESTUSER" node -e '
    const fs = require("fs"); const path = require("path"); const { execFile } = require("child_process");
    const { VpnInstaller } = require("./src/main/vpn-installer");
    const rel = process.env.HV_REL;
    const local = (url) => url.endsWith("manifest.json") || url.endsWith("manifest.json.sig")
      ? path.join(rel, path.basename(url)) : path.join(rel, "linux-x64", path.basename(url));
    const inst = new VpnInstaller({
      manifestUrl: "https://hidranet.org/vpn/release/manifest.json", publicKey: process.env.HV_PUB,
      platform: "linux", arch: "x64", user: process.env.HV_USER,
      fetchText: async (u) => fs.readFileSync(local(u), "utf8"),
      fetchBuffer: async (u) => fs.readFileSync(local(u)),
      // Already root: pkexec would only ask for the password.
      run: (file, args) => new Promise((res) => execFile(args[0], args.slice(1), (e, so, se) => res({ code: e ? (e.code || 1) : 0, stdout: so, stderr: se }))),
    });
    (async () => {
      const c = await inst.checkRelease();
      const r = await inst.install();
      const bad = await new VpnInstaller({ ...inst, publicKey: "denZsjS2YtKOo4LRIGGTaKuHIWDFigChoLa71o0jBq8=",
        manifestUrl: inst.manifestUrl, fetchText: inst.fetchText, fetchBuffer: inst.fetchBuffer, run: inst.run, platform: "linux", arch: "x64" }).checkRelease();
      console.log(JSON.stringify({ c, r, bad }));
    })();' 2>&1)
  echo "$OUT" | grep -q '"c":{"ok":true,"version":"9.9.9"' && pass "the script's manifest, signed by hidravpn-sign, is accepted by the browser" || fail "manifest: $OUT"
  echo "$OUT" | grep -q '"bad":{"ok":false' && pass "the same manifest is refused under any other release key" || fail "other key: $OUT"
  echo "$OUT" | grep -q '"r":{"ok":true' && cmp -s "$BIN/hidravpn-service" /usr/local/bin/hidravpn-service \
    && pass "the browser's installer installs the checked download for real" || fail "install via browser: $OUT"
  /usr/local/bin/hidravpn-service uninstall --purge >/dev/null 2>&1
else
  echo "skip  the browser chain (needs node and hidravpn-sign built)"
fi

echo; echo "$ok passed, $bad failed"; [ $bad -eq 0 ]
