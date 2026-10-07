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
 *
 * Output lands in dist/release-out/, with the SHA-256 of each file to paste
 * into landing/SHA256SUMS.txt.
 */
'use strict';

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
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

  console.log('\n  patching\n');
  for (const n of NAMES) {
    patchZip(path.join(inDir, n), path.join(outDir, n));
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
