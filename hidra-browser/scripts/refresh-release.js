#!/usr/bin/env node
/**
 * HidraNet — rebuild the published release packages from the published ones.
 *
 * Downloads the four v1.0.0 assets, runs scripts/patch-zip.js over each, and
 * checks the result before telling you it is good. Everything it cannot
 * reproduce — the Electron runtime, the bundled Tor — comes from the package
 * it started with, so this works on a machine that cannot reach the Tor
 * Project's servers, which is the whole reason it exists.
 *
 * Usage:
 *   node scripts/refresh-release.js              # download, patch, verify
 *   node scripts/refresh-release.js --in <dir>   # use packages already on disk
 *   node scripts/refresh-release.js --engine <f> # skip the cross-compile
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
const { readZip } = require('./lib/zip');
const { download } = require('./lib/net');
const { patchZip } = require('./patch-zip');

const VERSION = '1.0.0';
const ROOT    = path.join(__dirname, '..');
const DIST    = path.join(ROOT, 'dist');
const BASE    = 'https://github.com/NeurexBK/HidraNet/releases/download/v' + VERSION + '/';
const NAMES   = ['macOS-arm64', 'macOS-x64', 'Linux-x64', 'Windows-x64']
                  .map(a => 'HidraNet-Browser-' + VERSION + '-' + a + '.zip');

const BTC = 'bc1pqw46hh9fypk0wr4z7vnvcpjjk8xe8xnff25vusc23xt3j6ehfaaqx3ku3k';

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

/**
 * Does this package actually hold together? Not "did the script run" — the
 * things that have gone wrong before: Tor missing or not executable, the app
 * sources not actually updated, paths that only extract correctly on Windows.
 */
function verify(file) {
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
  check(by.has(tor), 'Tor is in the package (' + (by.has(tor) ? by.get(tor).uncompSz : 0) + ' bytes)');
  if (!win) check(mode(tor) === '755', 'Tor is executable (mode ' + mode(tor) + ')');
  check(by.has(res + '/bin/tor/geoip'), 'Tor geoip data present');

  if (!mac && !win) {
    check(mode('hidranet') === '755', 'hidranet is executable (mode ' + mode('hidranet') + ')');
    check(by.has('start.sh'), 'start.sh present');
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
  check(!!d && contents(d).toString().indexOf(BTC) !== -1, 'donate page carries the current BTC address');
  check(by.has(pfx + 'main/network-lock.js'), 'network kill switch is in the package');
  check(by.has(pfx + 'ui/vendor/mqtt.min.js'), 'mqtt is vendored (no CDN at runtime)');
}

(async function main() {
  const inArg  = process.argv.indexOf('--in');
  const inDir  = inArg !== -1 ? process.argv[inArg + 1] : path.join(DIST, 'release-in');
  const outDir = path.join(DIST, 'release-out');
  fs.mkdirSync(inDir,  { recursive: true });
  fs.mkdirSync(outDir, { recursive: true });

  console.log('HidraNet — refreshing the v' + VERSION + ' packages\n');

  for (const n of NAMES) {
    const src = path.join(inDir, n);
    if (!fs.existsSync(src)) {
      console.log('  downloading ' + n);
      await download(BASE + n, src);
    } else {
      console.log('  have ' + n);
    }
  }

  console.log('');
  buildEngine();

  console.log('\n  patching\n');
  for (const n of NAMES) {
    const binaries = /Windows/.test(n) ? { [ENGINE_IN_ZIP]: ENGINE_OUT } : {};
    const extras = /Linux/.test(n) ? { [LIBEVENT_IN_ZIP]: LIBEVENT_LOCAL } : {};
    patchZip(path.join(inDir, n), path.join(outDir, n), { binaries, extras });
  }

  console.log('\n  checking');
  for (const n of NAMES) verify(path.join(outDir, n));

  console.log('\n  SHA-256 (paste into landing/SHA256SUMS.txt)\n');
  for (const n of NAMES) {
    const h = crypto.createHash('sha256').update(fs.readFileSync(path.join(outDir, n))).digest('hex');
    console.log('  ' + h + '  ' + n);
  }

  console.log('');
  if (failures) {
    console.log('  ' + failures + ' check(s) failed. Do not upload these.\n');
    process.exit(1);
  }
  console.log('  All checks passed. The packages are in ' + outDir + '.');
  console.log('  Upload them to the v' + VERSION + ' release, replacing the current assets,');
  console.log('  then update landing/SHA256SUMS.txt with the hashes above.\n');
})().catch(e => { console.error('\n  failed: ' + e.message + '\n'); process.exit(1); });
