#!/usr/bin/env node
/**
 * HidraNet — rebuild the published release packages from the published ones.
 *
 * Downloads the four pinned base packages (lib/release-base.js), runs
 * scripts/patch-zip.js over each, and checks the result before telling you it
 * is good. What it does not rebuild — the Electron runtime, the bundled Tor —
 * comes from the package it started with, so this works on a machine that
 * cannot reach the Tor Project's servers, which is the whole reason it exists.
 *
 * That is also how the v1.0.0 packages went out on Electron 33.4.11 and Tor
 * 15.0.22 while the repository pinned 44.9.3 and 15.0.26: nothing compared
 * them. Now a base package is refused, before anything is built, unless every
 * Electron file in it is the file of the pinned official Electron zip, every
 * Tor file hashes to its pin in lib/tor.js, and the engine compiled into it is
 * the Chromium the user agent claims (lib/package-runtime.js). The same checks
 * run again on the packages it writes, with one more: app/src holds exactly
 * the tree's files. When a base package fails, build from scratch instead
 * (build-win.js, build-linux.js, build-mac.js), which enforce the pins.
 *
 * A refreshed package is a new build, so it gets the version package.json
 * says, which must not be the base packages' own: a published version is never
 * reused for different files.
 *
 * Usage:
 *   node scripts/refresh-release.js              # download, patch, verify
 *   node scripts/refresh-release.js --in <dir>   # use packages already on disk
 *   node scripts/refresh-release.js --engine <f> # skip the cross-compile
 *   node scripts/refresh-release.js --verify-inputs-only # verify, do not build
 *
 * Output lands in dist/release-out/, with the SHA-256 of each file to paste
 * into landing/SHA256SUMS.txt.
 */
'use strict';

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const { inflateRawSync } = require('zlib');
const { readZip, validDosDate } = require('./lib/zip');
const { download } = require('./lib/net');
const { verifyReleaseBase } = require('./lib/release-base');
const { electronZip, ELECTRON_VER } = require('./lib/electron');
const { TOR_VERSION } = require('./lib/tor');
const runtime = require('./lib/package-runtime');
const { patchZip } = require('./patch-zip');

// The version of the pinned base packages, and the version of what this
// writes: package.json's, which every builder uses.
const BASE_VERSION = '1.0.0';
const ROOT    = path.join(__dirname, '..');
const VERSION = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
const DIST    = path.join(ROOT, 'dist');
const BASE    = 'https://github.com/NeurexBK/HidraNet/releases/download/v' + BASE_VERSION + '/';
const ARCHES  = ['macOS-arm64', 'macOS-x64', 'Linux-x64', 'Windows-x64'];
const NAMES   = ARCHES.map(a => 'HidraNet-Browser-' + BASE_VERSION + '-' + a + '.zip');
const OUT_NAMES = ARCHES.map(a => 'HidraNet-Browser-' + VERSION + '-' + a + '.zip');

// Where support goes. It replaced a Bitcoin address, so the check below
// also refuses a package that still carries the old one.
const HNET_WALLET = 'ExYv4idyqxmuodpoZtxyGxeTGi6oYrqFAshAgCsRissc';
const OLD_BTC = 'bc1pqw46hh9fypk0wr4z7vnvcpjjk8xe8xnff25vusc23xt3j6ehfaaqx3ku3k';

// Only the Windows package ships the Rust engine; the others start the
// browser's own services and talk to Tor directly. The engine is where the
// post-quantum handshake lives, so a package refreshed only in its HTML would
// still be running the one built against the withdrawn pqc_kyber crate —
// where a chosen-ciphertext attacker recovers the decapsulation key
// (RUSTSEC-2026-0290). It gets rebuilt here, from this working tree.
const ENGINE_TARGET = 'x86_64-pc-windows-gnu';
const ENGINE_OUT = path.join(ROOT, '..', 'hidra-node', 'target', ENGINE_TARGET, 'release', 'hidra-node.exe');
const ENGINE_IN_ZIP = 'resources/bin/hidra-node.exe';

// The bundled Linux Tor is dynamically linked against libevent, which most
// distributions do not install by default. Without it Tor dies at startup and
// the browser opens with nothing connecting. See vendor/linux-x64/README.md.
const LIBEVENT_LOCAL  = path.join(ROOT, 'vendor', 'linux-x64', 'libevent-2.1.so.7');
const LIBEVENT_IN_ZIP = 'resources/bin/tor/libevent-2.1.so.7';

// HidraNet's icon for the macOS bundle, from brand/logo/ at the top of the
// repository (made from the master logo by the same script as every other
// icon).
const MAC_ICON_LOCAL  = path.join(ROOT, '..', 'brand', 'logo', 'hidranet.icns');
const MAC_ICON_IN_ZIP = 'HidraNet.app/Contents/Resources/electron.icns';

// Which build a package is: the commit it was made from and the day. The new
// tab page shows it in its footer (main.js, buildInfo), so whoever tests a
// package can tell it from an older copy still on their machine. A tree with
// uncommitted changes says so: "-dirty" is not something to publish.
const BUILD_JSON = path.join(DIST, 'build.json');
const buildInZip = (name) => (/macOS/.test(name) ? 'HidraNet.app/Contents/Resources/' : 'resources/') + 'app/build.json';
// The app's package.json, where Electron's app.getVersion() reads the version
// the new tab page shows and the update check compares.
const APP_PACKAGE_JSON = path.join(DIST, 'app-package.json');
const appPackageInZip = (name) => (/macOS/.test(name) ? 'HidraNet.app/Contents/Resources/' : 'resources/') + 'app/package.json';
function buildStamp() {
  let build = 'unknown';
  try {
    build = execFileSync('git', ['describe', '--always', '--dirty', '--abbrev=7', '--exclude', '*'],
      { cwd: ROOT, encoding: 'utf8' }).trim();
  } catch (e) { /* not a checkout */ }
  return { build, date: new Date().toISOString().slice(0, 10) };
}

/**
 * The engine that goes in the Windows package.
 *
 * Cross-compiling it needs the mingw-w64 toolchain and the
 * x86_64-pc-windows-gnu Rust target, which is a lot to ask of someone who
 * only wants to cut a release. --engine <path> takes one that was already
 * built, and the verify step afterwards is what keeps that honest: the engine
 * in the finished package has to hash to the file named here, so a stale or
 * swapped binary fails the build rather than shipping.
 */
function buildEngine() {
  const argIdx = process.argv.indexOf('--engine');
  if (argIdx !== -1) {
    const given = path.resolve(process.argv[argIdx + 1] || '');
    if (!fs.existsSync(given)) {
      console.error('  --engine: no such file: ' + given);
      process.exit(1);
    }
    fs.mkdirSync(path.dirname(ENGINE_OUT), { recursive: true });
    fs.copyFileSync(given, ENGINE_OUT);
    const sum = crypto.createHash('sha256').update(fs.readFileSync(given)).digest('hex');
    console.log('  using the engine at ' + given);
    console.log('  sha256 ' + sum);
    return ENGINE_OUT;
  }

  const dir = path.join(ROOT, '..', 'hidra-node');
  console.log('  building the engine for ' + ENGINE_TARGET + ' (needs the mingw-w64 cross-compiler)');
  console.log('  (or pass --engine <path> to use one that is already built)');
  execFileSync('cargo', ['build', '--release', '--target', ENGINE_TARGET], {
    cwd: dir, stdio: ['ignore', 'ignore', 'inherit'],
  });
  const size = fs.statSync(ENGINE_OUT).size;
  console.log('  built ' + path.relative(ROOT, ENGINE_OUT) + ' (' + size + ' bytes)');
  return ENGINE_OUT;
}

let failures = 0;
function check(cond, msg) {
  console.log((cond ? '    ok   ' : '    FAIL ') + msg);
  if (!cond) failures++;
}
function contents(e) { return e.method === 8 ? inflateRawSync(e.rawData) : e.rawData; }

// The official Electron zip for a package's system, checked against its pin
// (downloaded once into dist/electron-cache), read.
const electronEntries = new Map();
async function officialElectron(name) {
  const { platform, arch } = runtime.platformOf(name);
  const key = platform + '-' + arch;
  if (!electronEntries.has(key)) {
    const zip = await electronZip(platform, arch, path.join(DIST, 'electron-cache'));
    electronEntries.set(key, zip);
  }
  return readZip(fs.readFileSync(electronEntries.get(key)));
}

// What runs in the package is what the repository pins: the problems, or an
// empty list.
async function runtimeProblemsOf(file) {
  const name = path.basename(file);
  const { platform, arch } = runtime.platformOf(name);
  const es = readZip(fs.readFileSync(file));
  return [
    ...runtime.runtimeProblems(es, await officialElectron(name), platform),
    ...runtime.torProblems(es, platform, arch),
    ...runtime.engineProblems(es, platform),
  ];
}

// Every app/src entry of the package is a file of the tree with the same
// bytes, and every file of the tree is there.
function appSourceProblems(es, pfx) {
  const tree = new Map();
  (function walk(dir, rel) {
    for (const n of fs.readdirSync(dir).sort()) {
      const abs = path.join(dir, n);
      if (fs.statSync(abs).isDirectory()) walk(abs, rel + n + '/');
      else tree.set(rel + n, abs);
    }
  })(path.join(ROOT, 'src'), '');
  const problems = [];
  const seen = new Set();
  for (const e of es) {
    if (e.filename.indexOf(pfx) !== 0 || e.filename.endsWith('/')) continue;
    const rel = e.filename.slice(pfx.length);
    seen.add(rel);
    if (!tree.has(rel)) problems.push(rel + ' is not in the tree');
    else if (!contents(e).equals(fs.readFileSync(tree.get(rel)))) problems.push(rel + ' differs from the tree');
  }
  for (const rel of tree.keys()) if (!seen.has(rel)) problems.push(rel + ' is missing');
  return problems;
}

/**
 * Does this package actually hold together? Not "did the script run" — the
 * things that have gone wrong before: Tor missing or not executable, the app
 * sources not actually updated, paths that only extract correctly on Windows.
 */
async function verify(file) {
  const name = path.basename(file);
  const mac  = /macOS/.test(name);
  const win  = /Windows/.test(name);
  const es   = readZip(fs.readFileSync(file));
  const by   = new Map(es.map(e => [e.filename, e]));
  const mode = n => { const e = by.get(n); return e ? ((e.extAttr >>> 16) & 0xfff).toString(8) : null; };
  const pfx  = mac ? 'HidraNet.app/Contents/Resources/app/src/' : 'resources/app/src/';
  const res  = mac ? 'HidraNet.app/Contents/Resources' : 'resources';
  const tor  = res + '/bin/tor/' + (win ? 'tor.exe' : 'tor');

  console.log('\n  ' + name);
  check(es.every(e => e.filename.indexOf('\\') === -1), 'every path uses forward slashes');
  // Windows' own zip support refuses an archive with an impossible date
  // (1980-00-00, which a zeroed timestamp decodes to): the package would not
  // open on double-click. See lib/zip.js.
  check(es.every(e => validDosDate(e.dosDate)), 'every entry has a real date (Windows opens the zip)');
  check(by.has(tor), 'Tor is in the package (' + (by.has(tor) ? by.get(tor).uncompSz : 0) + ' bytes)');
  if (!win) check(mode(tor) === '755', 'Tor is executable (mode ' + mode(tor) + ')');
  check(by.has(res + '/bin/tor/geoip'), 'Tor geoip data present');
  const rt = await runtimeProblemsOf(file);
  check(rt.length === 0, 'Electron ' + ELECTRON_VER + ' and Tor ' + TOR_VERSION +
        ' exactly as pinned, on the Chromium the user agent claims' +
        (rt.length ? ':\n           ' + rt.join('\n           ') : ''));
  const stale = appSourceProblems(es, pfx);
  check(stale.length === 0, 'app/src is exactly the tree' + (stale.length ? ': ' + stale.join(', ') : ''));
  const ap = by.get(appPackageInZip(name));
  check(!!ap && JSON.parse(contents(ap).toString()).version === VERSION, 'the app says it is version ' + VERSION);

  if (!mac && !win) {
    check(mode('hidranet') === '755', 'hidranet is executable (mode ' + mode('hidranet') + ')');
    check(by.has('start.sh'), 'start.sh present');
    // The launcher that keeps the sandbox working where user namespaces are
    // restricted. Without it the browser aborts on Ubuntu 23.10 and later.
    const launcher = by.get('start.sh');
    check(!!launcher && contents(launcher).toString().indexOf(
      require('./lib/linux-launcher').SANDBOX_MARKER) !== -1,
      'start.sh handles the restricted-sandbox case (Ubuntu 23.10+)');
    check(by.has(LIBEVENT_IN_ZIP), 'libevent ships with Tor (it is not linked statically)');
  }
  if (mac) {
    const l = by.get('Start HidraNet.command');
    check(!!l, 'Start HidraNet.command present');
    if (l) {
      const t = contents(l).toString();
      check(t.indexOf('codesign --force --sign - "$TOR"') !== -1 &&
            t.indexOf('codesign --force --sign - "$TOR"') < t.indexOf('codesign --force --deep --sign - "$APP"'),
            'launcher signs Tor on its own, before the bundle');
    }
    const ip = by.get('HidraNet.app/Contents/Info.plist');
    check(!!ip && /<string>net\.hidra\.browser<\/string>/.test(contents(ip).toString()),
          'bundle id is net.hidra.browser');
  }

  if (win) {
    const eng = by.get(ENGINE_IN_ZIP);
    check(!!eng, 'the engine is in the package');
    if (eng) {
      const want = fs.readFileSync(ENGINE_OUT);
      check(crypto.createHash('sha256').update(contents(eng)).digest('hex') ===
            crypto.createHash('sha256').update(want).digest('hex'),
            'the engine is the one built from this tree, not the published one');
    }
  }

  const d = by.get(pfx + 'ui/donate.html');
  const donate = d ? contents(d).toString() : '';
  check(donate.indexOf(HNET_WALLET) !== -1, 'donate page carries the HNET support wallet');
  check(donate.indexOf(OLD_BTC) === -1, 'donate page no longer carries the retired Bitcoin address');
  check(by.has(pfx + 'main/network-lock.js'), 'network kill switch is in the package');
  check(by.has(pfx + 'ui/vendor/mqtt.min.js'), 'mqtt is vendored (no CDN at runtime)');
  const b = by.get(buildInZip(name));
  check(!!b && contents(b).toString() === fs.readFileSync(BUILD_JSON, 'utf8'),
        'says which build it is (' + (b ? JSON.parse(contents(b).toString()).build : 'none') + ')');

  // HidraVPN is back in the browser: its control-channel module, the page
  // and the installer must ride along, or hidra://vpn is a dead link.
  check(by.has(pfx + 'main/vpn-manager.js') && by.has(pfx + 'ui/hidravpn.html') && by.has(pfx + 'main/vpn-installer.js'),
        'HidraVPN is in the package');
}

(async function main() {
  const inArg  = process.argv.indexOf('--in');
  const inDir  = inArg !== -1 ? process.argv[inArg + 1] : path.join(DIST, 'release-in');
  const outDir = path.join(DIST, 'release-out');
  fs.mkdirSync(inDir,  { recursive: true });
  fs.mkdirSync(outDir, { recursive: true });

  console.log('HidraNet — refreshing the v' + BASE_VERSION + ' packages as ' + VERSION + '\n');

  for (const n of NAMES) {
    const src = path.join(inDir, n);
    if (!fs.existsSync(src)) {
      console.log('  downloading ' + n);
      await download(BASE + n, src);
    } else {
      console.log('  have ' + n);
    }
    // Both newly downloaded and cached inputs must match the repository's
    // pinned baseline before any ZIP parsing, patching or engine compilation.
    verifyReleaseBase(src);
    console.log('  verified base SHA-256: ' + n);
  }

  // What the base packages run, before anything is built on them.
  let runtimeFailures = 0;
  for (const n of NAMES) {
    const problems = await runtimeProblemsOf(path.join(inDir, n));
    if (problems.length) {
      runtimeFailures++;
      console.error('\n  ' + n + ' does not run what the repository pins:');
      for (const p of problems.slice(0, 20)) console.error('    ' + p);
      if (problems.length > 20) console.error('    … and ' + (problems.length - 20) + ' more');
    } else {
      console.log('  verified Electron, Tor and engine: ' + n);
    }
  }
  if (runtimeFailures) {
    console.error('\n  ' + runtimeFailures + ' base package(s) refused. Refreshing them would ship their old Electron');
    console.error('  and Tor under a new name. Build from scratch instead: build-win.js, build-linux.js, build-mac.js.\n');
    process.exit(1);
  }

  if (process.argv.includes('--verify-inputs-only')) {
    console.log('  All base packages match their pinned SHA-256, Electron and Tor. No build was run.');
    return;
  }

  if (VERSION === BASE_VERSION) {
    console.error('  package.json says ' + VERSION + ', the version of the packages this starts from. A refreshed');
    console.error('  package is a new build: give it a new version in package.json. A published version is');
    console.error('  never reused for different files.\n');
    process.exit(1);
  }

  console.log('');
  buildEngine();

  const stamp = buildStamp();
  fs.writeFileSync(BUILD_JSON, JSON.stringify(stamp) + '\n');
  console.log('\n  build ' + stamp.build + ' · ' + stamp.date);

  fs.writeFileSync(APP_PACKAGE_JSON, JSON.stringify(
    { name: 'hidra-browser', version: VERSION, main: 'src/main/main.js' }, null, 2));

  console.log('\n  patching\n');
  for (const [i, n] of NAMES.entries()) {
    const binaries = /Windows/.test(n) ? { [ENGINE_IN_ZIP]: ENGINE_OUT } : {};
    const extras = /Linux/.test(n) ? { [LIBEVENT_IN_ZIP]: LIBEVENT_LOCAL }
      // The bundle's icon: Electron's own until now. The binary is not
      // touched, only the picture the Dock and the Finder show for it.
      : /macOS/.test(n) ? { [MAC_ICON_IN_ZIP]: MAC_ICON_LOCAL }
      : {};
    extras[buildInZip(n)] = BUILD_JSON;
    extras[appPackageInZip(n)] = APP_PACKAGE_JSON;
    patchZip(path.join(inDir, n), path.join(outDir, OUT_NAMES[i]), { binaries, extras, version: VERSION });
  }

  console.log('\n  checking');
  for (const n of OUT_NAMES) await verify(path.join(outDir, n));

  console.log('\n  SHA-256 (node scripts/update-sums.js writes them into landing/SHA256SUMS.txt)\n');
  for (const n of OUT_NAMES) {
    const h = crypto.createHash('sha256').update(fs.readFileSync(path.join(outDir, n))).digest('hex');
    console.log('  ' + h + '  ' + n);
  }

  console.log('');
  if (failures) {
    console.log('  ' + failures + ' check(s) failed. Do not upload these.\n');
    process.exit(1);
  }
  console.log('  All checks passed. The packages are in ' + outDir + '.');
  console.log('  These packages are for review. No release assets were published or replaced.\n');
})().catch(e => { console.error('\n  failed: ' + e.message + '\n'); process.exit(1); });
