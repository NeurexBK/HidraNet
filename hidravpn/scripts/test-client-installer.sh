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
if [ -e /usr/local/bin/hidravpn-service ] || [ -e /etc/hidravpn/client.key ] || [ -e /etc/systemd/system/hidravpn.service ] \
   || [ -e /etc/hidravpn/node.toml ] || [ -e /etc/systemd/system/hidravpn-node.service ]; then
  echo "HidraVPN (a client or a node) is installed on this machine; this test would replace it. Run it in a container."; exit 1
fi
MADE_GROUP=0; getent group hidravpn >/dev/null || MADE_GROUP=1

W="$(mktemp -d /tmp/hv-inst.XXXXXX)"
TESTUSER=hvinstalltest
cleanup() {
  rm -f /usr/local/bin/hidravpn-service /usr/local/bin/hidravpn /etc/systemd/system/hidravpn.service
  rm -rf /etc/hidravpn
  userdel "$TESTUSER" 2>/dev/null; [ "$MADE_GROUP" = 1 ] && groupdel hidravpn 2>/dev/null
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
# The stand-in systemd starts nothing, so the service never answers: the
# install puts everything in place and says so, with exit 69, not success.
[ $RC = 69 ] && echo "$OUT" | grep -q "installed, but it has not answered in 15 seconds" \
  && pass "install from the download folder puts it in place; with nothing running it, it says the service has not answered (exit 69)" || fail "install: rc=$RC $OUT"
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
[ $RC = 69 ] && echo "$OUT" | grep -q "has not answered" && pass "installing again (an update) goes through, and says the same" || fail "update: rc=$RC $OUT"
grep -q "^stop hidravpn" "$HV_SYSTEMCTL_LOG" && [ "$(grep -n '^stop hidravpn' "$HV_SYSTEMCTL_LOG" | head -1 | cut -d: -f1)" -lt "$(grep -n '^enable' "$HV_SYSTEMCTL_LOG" | head -1 | cut -d: -f1)" ] \
  && pass "an update stops the running service before replacing it, then starts it" || fail "update order: $(cat "$HV_SYSTEMCTL_LOG")"
[ "$(sha256sum $KEY)" = "$SUM1" ] && pass "an update keeps the key every node knows this machine by" || fail "the key changed"

# An older build over a newer one: refused before the service is touched,
# unless asked for. The installed copy says its version in its own bytes.
VER=$("$BIN/hidravpn-service" --version | awk '{print $2}')
grep -qaF "hidravpn-service-version=$VER" /usr/local/bin/hidravpn-service \
  && pass "the installed service carries its version ($VER) where an install can read it" || fail "no version mark for $VER in the installed service"
cp /usr/local/bin/hidravpn-service "$W/installed.bak"
printf 'a newer build\0hidravpn-service-version=99.0.0\0' > /usr/local/bin/hidravpn-service
SUM_NEWER=$(sha256sum /usr/local/bin/hidravpn-service)
: > "$HV_SYSTEMCTL_LOG"
OUT=$("$W/dl/hidravpn-service" install --client "$W/dl/hidravpn" 2>&1); RC=$?
[ $RC != 0 ] && [ $RC != 69 ] && echo "$OUT" | grep -q "HidraVPN 99.0.0 is installed, which is newer than this $VER; nothing was changed" \
  && [ ! -s "$HV_SYSTEMCTL_LOG" ] && [ "$(sha256sum /usr/local/bin/hidravpn-service)" = "$SUM_NEWER" ] \
  && pass "an older build does not replace a newer installed one: refused before the service is stopped" || fail "downgrade guard: rc=$RC $OUT / $(cat "$HV_SYSTEMCTL_LOG")"
OUT=$("$W/dl/hidravpn-service" install --client "$W/dl/hidravpn" --allow-downgrade 2>&1); RC=$?
[ $RC = 69 ] && cmp -s "$BIN/hidravpn-service" /usr/local/bin/hidravpn-service && grep -q "^stop hidravpn" "$HV_SYSTEMCTL_LOG" \
  && pass "with --allow-downgrade it goes back on purpose" || fail "--allow-downgrade: rc=$RC $OUT"
# Whatever happened, the checks below run against the real installed copy.
cmp -s "$BIN/hidravpn-service" /usr/local/bin/hidravpn-service || cp "$W/installed.bak" /usr/local/bin/hidravpn-service

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
# Passes, the account token, the ones it replaced and the lock: a purge
# takes them too.
echo '{"passes":[]}' > /etc/hidravpn/passes.json; echo token > /etc/hidravpn/pass.token; : > /etc/hidravpn/hidravpn.lock
echo old-token > /etc/hidravpn/pass.token.previous; echo older-token > /etc/hidravpn/pass.token.previous.1
OUT=$(/usr/local/bin/hidravpn-service uninstall --purge 2>&1); RC=$?
[ $RC = 0 ] && pass "uninstall --purge succeeds ($(echo "$OUT" | tail -1))" || fail "purge: $OUT"
[ ! -e $KEY ] && [ ! -e /etc/hidravpn/circuit.json ] && [ ! -e /usr/local/bin/hidravpn ] && [ ! -e /usr/local/bin/hidravpn-service ] && [ ! -e /etc/systemd/system/hidravpn.service ] \
  && pass "--purge removes the programs, the nodes and the key" || fail "left behind: $(ls /usr/local/bin/hidravpn* /etc/hidravpn 2>&1)"
[ ! -e /etc/hidravpn ] && pass "--purge leaves no passes, no account token and no folder behind" || fail "left in /etc/hidravpn: $(ls -A /etc/hidravpn 2>&1)"

# ── The whole chain the browser runs: a manifest made by the script, signed
# by hidravpn-sign, read and checked by the browser's installer, which then
# installs the downloaded service. Only the network (files read from disk)
# and pkexec (already root) are stood in for.
if command -v node >/dev/null && [ -x "$BIN/hidravpn-sign" ]; then
  mkdir -p "$W/rel/linux-x64"
  cp "$BIN/hidravpn-service" "$BIN/hidravpn" "$W/rel/linux-x64/"
  PUB=$("$BIN/hidravpn-sign" keygen --out "$W/release.key" 2>/dev/null)
  "$HERE/make-release-manifest.sh" --version 9.9.9 --sequence 7 --base https://hidranet.org/vpn/release/9.9.9 --linux-x64 "$W/rel/linux-x64" > "$W/rel/manifest.json"
  "$BIN/hidravpn-sign" sign --key "$W/release.key" "$W/rel/manifest.json" >/dev/null 2>&1
  # An older manifest, as genuinely signed, for after the install.
  mkdir -p "$W/old"
  "$HERE/make-release-manifest.sh" --version 9.9.9 --sequence 6 --base https://hidranet.org/vpn/release/9.9.9 --linux-x64 "$W/rel/linux-x64" > "$W/old/manifest.json"
  "$BIN/hidravpn-sign" sign --key "$W/release.key" "$W/old/manifest.json" >/dev/null 2>&1
  # Sequence 0 is what the 0.1.0 manifest counts as: one signed at 0 would
  # set no floor above it, so the script refuses it, and writes nothing.
  OUT=$("$HERE/make-release-manifest.sh" --version 9.9.9 --sequence 0 --base https://hidranet.org/vpn/release/9.9.9 --linux-x64 "$W/rel/linux-x64" 2>&1 >"$W/zero.json"); RC=$?
  [ $RC != 0 ] && [ ! -s "$W/zero.json" ] && echo "$OUT" | grep -q 'sequence must be 1 or more: the 0.1.0 manifest counts as sequence 0' \
    && pass "the script refuses --sequence 0, and says why" || fail "--sequence 0: rc $RC, $OUT"
  OUT=$("$HERE/make-release-manifest.sh" --version 9.9.9 --sequence 000 --base https://hidranet.org/vpn/release/9.9.9 --linux-x64 "$W/rel/linux-x64" 2>&1 >/dev/null); RC=$?
  [ $RC != 0 ] && pass "the script refuses --sequence 000 too" || fail "--sequence 000 was taken: $OUT"
  grep -q '"sequence": 7,' "$W/rel/manifest.json" && grep -q '"expires": "20[0-9-]*T[0-9:]*Z",' "$W/rel/manifest.json" \
    && pass "the script's manifest carries a sequence and an expiry, under the signature" || fail "manifest fields: $(head -8 "$W/rel/manifest.json")"
  OUT=$(cd "$HERE/../../hidra-browser" && HV_REL="$W/rel" HV_OLD="$W/old" HV_STATE="$W/vpn-release.json" HV_PUB="$PUB" HV_USER="$TESTUSER" node -e '
    const fs = require("fs"); const path = require("path"); const { execFile } = require("child_process");
    const { VpnInstaller } = require("./src/main/vpn-installer");
    let rel = process.env.HV_REL;
    const local = (url) => url.endsWith("manifest.json") || url.endsWith("manifest.json.sig")
      ? path.join(rel, path.basename(url)) : path.join(rel, "linux-x64", path.basename(url));
    const inst = new VpnInstaller({
      manifestUrl: "https://hidranet.org/vpn/release/manifest.json", publicKey: process.env.HV_PUB,
      platform: "linux", arch: "x64", user: process.env.HV_USER, stateFile: process.env.HV_STATE,
      fetchText: async (u) => fs.readFileSync(local(u), "utf8"),
      fetchBuffer: async (u) => fs.readFileSync(local(u)),
      // Already root: pkexec would only ask for the password.
      run: (file, args) => new Promise((res) => execFile(args[0], args.slice(1), (e, so, se) => res({ code: e ? (e.code || 1) : 0, stdout: so, stderr: se }))),
    });
    (async () => {
      const c = await inst.checkRelease();
      const r = await inst.install(c);
      const bad = await new VpnInstaller({ ...inst, publicKey: "denZsjS2YtKOo4LRIGGTaKuHIWDFigChoLa71o0jBq8=",
        manifestUrl: inst.manifestUrl, fetchText: inst.fetchText, fetchBuffer: inst.fetchBuffer, run: inst.run, platform: "linux", arch: "x64" }).checkRelease();
      // The site now serves the older manifest; a later run of the browser
      // (the same data folder) refuses it.
      const binaries = rel;
      rel = process.env.HV_OLD;
      const later = new VpnInstaller({ manifestUrl: inst.manifestUrl, publicKey: process.env.HV_PUB, platform: "linux", arch: "x64",
        stateFile: process.env.HV_STATE, fetchText: inst.fetchText, fetchBuffer: (u) => fs.promises.readFile(path.join(binaries, "linux-x64", path.basename(u))), run: inst.run });
      const old = await later.checkRelease();
      console.log(JSON.stringify({ c, r, bad, old }));
    })();' 2>&1)
  echo "$OUT" | grep -q '"c":{"ok":true,"version":"9.9.9"' && pass "the script's manifest, signed by hidravpn-sign, is accepted by the browser" || fail "manifest: $OUT"
  echo "$OUT" | grep -q '"bad":{"ok":false' && pass "the same manifest is refused under any other release key" || fail "other key: $OUT"
  echo "$OUT" | grep -q '"r":{"ok":false,"installed":true,"version":"9.9.9"' && echo "$OUT" | grep -q "its service did not answer" \
    && cmp -s "$BIN/hidravpn-service" /usr/local/bin/hidravpn-service \
    && pass "the browser's installer installs the checked download for real, and does not call a service nothing runs 'running'" || fail "install via browser: $OUT"
  echo "$OUT" | grep -q '"old":{"ok":false,"error":"the release manifest is older (sequence 6) than one this browser already accepted (sequence 7)' \
    && pass "after that, an older signed manifest is refused by the browser, across runs" || fail "older manifest: $OUT"
  /usr/local/bin/hidravpn-service uninstall --purge >/dev/null 2>&1
else
  echo "skip  the browser chain (needs node and hidravpn-sign built)"
fi

echo; echo "$ok passed, $bad failed"; [ $bad -eq 0 ]
