'use strict';
/**
 * The two plain-text files that ride alongside HidraNet.app in a macOS
 * package: the double-clickable launcher and the README.
 *
 * They live here rather than inside the builder because two scripts produce
 * them — scripts/build-mac.js when it builds a package from scratch, and
 * scripts/patch-zip.js when it refreshes one that is already published. One
 * copy means the instructions cannot drift apart between the two.
 */

function launcherScript(APP_NAME) {
// ── Launcher script (0o755 → double-clickable on macOS) ──────────────────
//
// The codesign step is the one that matters and was missing. This bundle is
// an unsigned, renamed Electron.app, and on Apple Silicon the kernel refuses
// to load unsigned arm64 code — macOS reports the app as "damaged", which
// people reasonably read as a broken download. An ad-hoc signature (sign -)
// is what makes it loadable. Clearing quarantine alone is not enough.
var launcher = [
  '#!/bin/bash',
  '# HidraNet Browser — macOS launcher',
  'set -u',
  'DIR="$(cd "$(dirname "$0")" && pwd)"',
  'APP="$DIR/' + APP_NAME + '.app"',
  '',
  'if [ ! -d "$APP" ]; then',
  '  echo "Could not find ' + APP_NAME + '.app next to this script."',
  '  echo "Extract the whole ZIP first, then run this again."',
  '  read -n 1 -s -r -p "Press any key to close."',
  '  exit 1',
  'fi',
  '',
  'echo "Preparing ' + APP_NAME + ' ..."',
  'chmod -R 755 "$APP" 2>/dev/null',
  '',
  '# 1. Remove the download quarantine flag.',
  'xattr -cr "$APP" 2>/dev/null',
  '',
  '# 2. Ad-hoc sign. Required on Apple Silicon: unsigned arm64 code will not',
  '#    load, and macOS calls it "damaged" rather than unsigned.',
  '#',
  '#    The bundled Tor is signed FIRST and on its own. It lives in',
  '#    Contents/Resources/bin/tor/tor, and --deep does not reach there:',
  '#    --deep only descends into the standard nested-code locations',
  '#    (Frameworks, PlugIns, XPCServices, Helpers). A binary under',
  '#    Resources is not one of them, so signing only the bundle leaves Tor',
  '#    unsigned — the kernel then SIGKILLs it the moment the browser spawns',
  '#    it, and the panel reports "tor exited with code null". The app opens,',
  '#    and nothing can connect.',
  'if command -v codesign >/dev/null 2>&1; then',
  '  TOR="$APP/Contents/Resources/bin/tor/tor"',
  '  if [ -f "$TOR" ]; then',
  '    codesign --force --sign - "$TOR" >/dev/null 2>&1 \\',
  '      && echo "Signed the bundled Tor." \\',
  '      || echo "Could not sign Tor — connecting will fail."',
  '  else',
  '    echo "WARNING: no Tor in this package. It provides no anonymity."',
  '  fi',
  '  codesign --force --deep --sign - "$APP" >/dev/null 2>&1 \\',
  '    && echo "Signed the app (ad-hoc)." \\',
  '    || echo "Could not sign locally. See README-macOS.txt."',
  'else',
  '  echo "codesign not found — install Xcode Command Line Tools:"',
  '  echo "  xcode-select --install"',
  'fi',
  '',
  'echo "Opening ' + APP_NAME + ' ..."',
  'open "$APP" || {',
  '  echo',
  '  echo "macOS blocked it. Open System Settings > Privacy & Security,"',
  '  echo "scroll down, and click \'Open Anyway\'. See README-macOS.txt."',
  '  read -n 1 -s -r -p "Press any key to close."',
  '}',
  ''
].join('\n');
  return launcher;
}

function readmeText(APP_NAME, VERSION, arch) {
// ── README ────────────────────────────────────────────────────────────────
var archNote = arch === 'arm64'
  ? 'Apple Silicon (M1 / M2 / M3 / M4) — Macs from 2020 onwards'
  : 'Intel — Macs before 2020';
var readme = [
  'HidraNet Browser ' + VERSION + ' — macOS ' + arch,
  'For: ' + archNote,
  '',
  'READ THIS FIRST',
  '='.repeat(60),
  '',
  'This app is NOT signed with an Apple Developer ID and is NOT notarised.',
  'We say so plainly because macOS will not, and because the message it does',
  'show is misleading.',
  '',
  'What you may see, and what it actually means:',
  '',
  '  "HidraNet.app is damaged and can\'t be opened."',
  '      The download is fine. On Apple Silicon, macOS refuses to load code',
  '      that is not signed, and reports it as damaged. Step 1 below fixes it.',
  '',
  '  "cannot be opened because the developer cannot be verified."',
  '      Expected: we have no Apple Developer ID. Step 2 below.',
  '',
  'HOW TO OPEN IT',
  '='.repeat(60),
  '',
  'Easiest: extract the ZIP, then double-click "Start HidraNet.command".',
  'It does both steps below for you.',
  '',
  'If you prefer to do it by hand, open Terminal in the extracted folder:',
  '',
  '  Step 1 — clear the quarantine flag and sign locally:',
  '',
  '      xattr -cr ' + APP_NAME + '.app',
  '      codesign --force --sign - \\',
  '        ' + APP_NAME + '.app/Contents/Resources/bin/tor/tor',
  '      codesign --force --deep --sign - ' + APP_NAME + '.app',
  '',
  '    Both codesign commands are needed on Apple Silicon. They apply ad-hoc',
  '    signatures, which is what lets macOS load the code at all.',
  '',
  '    Tor has to be signed on its own, and BEFORE the app. It lives under',
  '    Contents/Resources/, and --deep does not reach there (it only descends',
  '    into Frameworks, PlugIns, XPCServices and Helpers). Sign only the app',
  '    bundle and it will open fine, but nothing will connect: the kernel',
  '    kills the unsigned Tor the moment the browser starts it, and the panel',
  '    reports "tor exited with code null".',
  '',
  '    If codesign is missing:  xcode-select --install',
  '',
  '  Step 2 — open it:',
  '',
  '      open ' + APP_NAME + '.app',
  '',
  'IF macOS STILL BLOCKS IT',
  '='.repeat(60),
  '',
  'On macOS 15 (Sequoia) and later, right-click > Open no longer works for',
  'unsigned apps. Apple removed that path. Instead:',
  '',
  '  1. Try to open the app once (it will be blocked).',
  '  2. Open  System Settings > Privacy & Security',
  '  3. Scroll down. There is a line about HidraNet being blocked.',
  '  4. Click "Open Anyway", then confirm with your password or Touch ID.',
  '',
  'On macOS 14 and earlier, right-click the app > Open > Open also works.',
  '',
  'VERIFY THE DOWNLOAD',
  '='.repeat(60),
  '',
  'Check the file you downloaded against the published SHA-256:',
  '',
  '      shasum -a 256 HidraNet-Browser-' + VERSION + '-macOS-' + arch + '.zip',
  '',
  'The expected value is in SHA256SUMS.txt next to the download, and on the',
  'release page. If it does not match, do not run the file.',
  '',
  'WHY NOT JUST SIGN IT PROPERLY',
  '='.repeat(60),
  '',
  'Signing and notarising needs a paid Apple Developer account. Until the',
  'project has one, these steps are the honest alternative. We would rather',
  'explain the extra two commands than pretend the app is signed.',
  '',
  '                                                  — The HidraNet team',
  ''
].join('\n');
  return readme;
}


/**
 * Rewrite the Electron Info.plist so the bundle identifies itself as HidraNet.
 * Shared by the builder and the release patcher: a package refreshed in place
 * has to end up with exactly the identity a fresh build would give it.
 */
function patchPlist(raw, appName, appId, version) {
  var plist = raw;
  plist = plist
    .replace(/(<key>CFBundleExecutable<\/key>\s*<string>)Electron(<\/string>)/g,
             '$1' + appName + '$2')
    .replace(/(<key>CFBundleDisplayName<\/key>\s*<string>)Electron(<\/string>)/g,
             '$1' + appName + '$2')
    .replace(/(<key>CFBundleName<\/key>\s*<string>)Electron(<\/string>)/g,
             '$1' + appName + '$2')
    // Case-insensitive on purpose: the plist ships "com.github.Electron"
    // with a capital E, so the lowercase-only pattern never matched and the
    // bundle stayed identified as Electron to macOS. A wrong bundle id
    // makes LaunchServices, TCC permissions, preferences and keychain items
    // land under com.github.Electron, shared with every other Electron app
    // that never changed its default.
    .replace(/com\.github\.electron(?:\.electron)?/gi, appId)
    .replace(/(<key>CFBundleShortVersionString<\/key>\s*<string>)[^<]*(<\/string>)/g,
             '$1' + version + '$2')
    .replace(/(<key>CFBundleVersion<\/key>\s*<string>)[^<]*(<\/string>)/g,
             '$1' + version + '$2');
  return plist;
}

module.exports = { launcherScript, readmeText, patchPlist };
