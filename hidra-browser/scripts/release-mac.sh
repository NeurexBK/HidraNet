#!/bin/bash
#
# HidraNet — build and verify the macOS packages.
#
# Run this on a Mac. It fetches Tor, builds both architectures, and then
# checks the result. It refuses to call a package good if anything that
# matters is missing, so a green verdict here means the zip is safe to
# upload; a red one means do not ship it.
#
#   cd hidra-browser
#   bash scripts/release-mac.sh
#
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="1.0.0"
DESKTOP="$HOME/Desktop"
FAIL=0

bold()  { printf '\033[1m%s\033[0m\n' "$1"; }
ok()    { printf '  \033[32mok\033[0m    %s\n' "$1"; }
bad()   { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=1; }
warn()  { printf '  \033[33mwarn\033[0m  %s\n' "$1"; }
step()  { printf '\n'; bold "── $1"; }

step "Prerequisites"

command -v node >/dev/null 2>&1 && ok "node $(node --version)" || { bad "node not found — install Node 20 or newer"; exit 1; }
command -v codesign >/dev/null 2>&1 && ok "codesign present" \
  || warn "codesign not found. Users will need it. Install: xcode-select --install"
[ "$(uname)" = "Darwin" ] && ok "running on macOS" \
  || warn "not macOS — the build still works, but you cannot test-launch the result here"

step "Fetching Tor"

# Without Tor the browser has no anonymity layer at all. This is not an
# optional extra, so a failure here stops the run.
for arch in arm64 x64; do
  if node scripts/fetch-tor.js --platform darwin --arch "$arch"; then
    ok "Tor fetched for darwin-$arch"
  else
    bad "could not fetch Tor for darwin-$arch"
    printf '\n\033[31mStopping.\033[0m Without Tor the package offers no anonymity,\n'
    printf 'and shipping a privacy browser without it would mislead users.\n'
    printf 'Check your connection to dist.torproject.org and run this again.\n\n'
    exit 1
  fi
done

step "Building"

node scripts/build-mac.js || { bad "build failed"; exit 1; }

step "Verifying the packages"

for arch in arm64 x64; do
  ZIP="$DESKTOP/HidraNet-Browser-$VERSION-macOS-$arch.zip"
  printf '\n'
  bold "  $arch"

  if [ ! -f "$ZIP" ]; then bad "$ZIP not found"; continue; fi

  node - "$ZIP" <<'NODE'
const fs = require('fs');
const { execSync } = require('child_process');
const zip = process.argv[2];

// Read the entry names straight out of the central directory, so this needs
// no unzip and no temporary extraction.
const buf = fs.readFileSync(zip);
const names = [];
for (let i = 0; i < buf.length - 4; i++) {
  if (buf.readUInt32LE(i) === 0x02014b50) {
    const n = buf.readUInt16LE(i + 28);
    names.push(buf.slice(i + 46, i + 46 + n).toString('utf8'));
  }
}

const has = (re) => names.some((n) => re.test(n));
const OK   = (m) => console.log('  \x1b[32mok\x1b[0m    ' + m);
const BAD  = (m) => { console.log('  \x1b[31mFAIL\x1b[0m  ' + m); process.exitCode = 1; };

names.some((n) => /_CodeSignature/.test(n))
  ? BAD('stale Apple signature still packaged — macOS will call the app damaged')
  : OK('no invalid signature (0 _CodeSignature entries)');

has(/^HidraNet\.app\/Contents\/MacOS\/HidraNet$/)
  ? OK('main binary renamed to HidraNet')
  : BAD('main binary missing or still named Electron');

has(/Electron\.app\//) ? BAD('Electron.app paths left in the bundle')
                       : OK('no Electron.app remnants');

has(/Resources\/bin\/tor\/tor$/)
  ? OK('Tor binary bundled — the anonymity layer is present')
  : BAD('TOR MISSING — this package provides no anonymity. Do not ship it.');

has(/Resources\/bin\/tor\/geoip$/) ? OK('geoip present') : BAD('geoip missing');

has(/^README-macOS\.txt$/) ? OK('README-macOS.txt present')
                           : BAD('README-macOS.txt missing');
has(/^Start HidraNet\.command$/) ? OK('launcher present') : BAD('launcher missing');

// Info.plist and launcher contents, read via unzip -p when available.
let plist = '', launcher = '';
try { plist    = execSync(`unzip -p ${JSON.stringify(zip)} 'HidraNet.app/Contents/Info.plist'`, {maxBuffer: 1<<24}).toString(); } catch (e) {}
try { launcher = execSync(`unzip -p ${JSON.stringify(zip)} 'Start HidraNet.command'`,          {maxBuffer: 1<<20}).toString(); } catch (e) {}

if (plist) {
  const get = (k) => (plist.match(new RegExp('<key>' + k + '</key>\\s*<string>([^<]*)</string>')) || [])[1];
  get('CFBundleIdentifier') === 'net.hidra.browser'
    ? OK('bundle id net.hidra.browser')
    : BAD('bundle id is ' + get('CFBundleIdentifier') + ' — should be net.hidra.browser');
  get('CFBundleExecutable') === 'HidraNet' ? OK('CFBundleExecutable HidraNet')
                                           : BAD('CFBundleExecutable ' + get('CFBundleExecutable'));
  /com\.github\.Electron/i.test(plist) ? BAD('com.github.Electron left in Info.plist')
                                       : OK('no Electron identifier in Info.plist');
} else {
  console.log('  \x1b[33mwarn\x1b[0m  could not read Info.plist (unzip unavailable)');
}

if (launcher) {
  /codesign --force --deep --sign -/.test(launcher)
    ? OK('launcher applies an ad-hoc signature')
    : BAD('launcher does not codesign — the app will not open on Apple Silicon');
  /xattr -cr/.test(launcher) ? OK('launcher clears quarantine') : BAD('launcher does not clear quarantine');
}

const mb = (fs.statSync(zip).size / 1048576).toFixed(1);
console.log('  \x1b[2msize  ' + mb + ' MiB\x1b[0m');
NODE
  [ $? -ne 0 ] && FAIL=1
done

step "Checksums"

cd "$DESKTOP" || exit 1
for arch in arm64 x64; do
  F="HidraNet-Browser-$VERSION-macOS-$arch.zip"
  [ -f "$F" ] && shasum -a 256 "$F"
done

printf '\n'
if [ "$FAIL" -eq 0 ]; then
  bold "VERDICT: the packages passed every check."
  cat <<'TXT'

  They are on your Desktop. Next:

    1. Upload both to the v1.0.0 release, replacing the old assets.
    2. Copy the checksums above into landing/SHA256SUMS.txt (the macOS
       lines change; Windows and Linux stay as they are).
    3. Test-launch one of them before announcing it:
         xattr -cr HidraNet.app
         codesign --force --deep --sign - HidraNet.app
         open HidraNet.app

  Step 3 matters. These checks confirm the package is built correctly;
  only launching it confirms it runs.

TXT
else
  bold "VERDICT: something failed. Do not upload these."
  printf '\n  Fix what is marked FAIL above and run this again.\n\n'
  exit 1
fi
