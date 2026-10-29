#!/usr/bin/env node
/**
 * HidraNet Browser — macOS Package Builder (cross-platform)
 *
 * Runs on Windows/Linux/macOS. Downloads the official Electron macOS ZIP
 * from GitHub, renames Electron.app → HidraNet.app, patches Info.plist,
 * adds our app source, and produces a ZIP with correct Unix permissions
 * so macOS Archive Utility extracts a working .app bundle.
 *
 * Usage:
 *   node scripts/build-mac.js          # arm64 + x64
 *   node scripts/build-mac.js arm64
 *   node scripts/build-mac.js x64
 *   node scripts/build-mac.js all --out <folder>     # instead of the Desktop
 */
'use strict';

const fs    = require('fs');
const path  = require('path');
const { inflateRawSync } = require('zlib');
const { readZip, writeZip, mkFile, mkDir, patchEntry } = require('./lib/zip');
const { launcherScript, readmeText, patchPlist } = require('./lib/mac-extras');
const { buildJson } = require('./lib/build-stamp');
const { electronZip } = require('./lib/electron');
const { torDir, verifyTorDir } = require('./lib/tor');
const { outArgs, writePackage } = require('./lib/out-dir');

const APP_NAME     = 'HidraNet';
const APP_ID       = 'net.hidra.browser';
const ROOT         = path.join(__dirname, '..');
// Every published build has a version of its own, from package.json: a
// rebuild under a version already published would be told apart from the
// old files only by its hash.
const VERSION      = require(path.join(ROOT, 'package.json')).version;
const DIST         = path.join(ROOT, 'dist');
const ARGS         = outArgs(process.argv.slice(2));
const OUT_DIR      = ARGS.out;
const ARCH_ARG     = ARGS.rest[0] || 'all';

// HidraNet's icon for the bundle, from brand/logo/ at the top of the
// repository. Electron's Info.plist names electron.icns, so the file keeps
// that name and only its picture changes; without this the Dock and the
// Finder show Electron's atom.
const MAC_ICON = path.join(ROOT, '..', 'brand', 'logo', 'hidranet.icns');

function scanDir(dir, base) {
  base = base || dir;
  var result = [];
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function(ent) {
    var abs = path.join(dir, ent.name);
    var rel = path.relative(base, abs).replace(/\\/g, '/');
    if (ent.isDirectory()) {
      result.push({ rel: rel + '/', abs: abs, isDir: true });
      scanDir(abs, base).forEach(function(x) { result.push(x); });
    } else {
      result.push({ rel: rel, abs: abs, isDir: false });
    }
  });
  return result;
}

// ── Build one architecture ────────────────────────────────────────────────────
async function buildArch(arch) {
  console.log('\n' + '─'.repeat(54));
  console.log('  macOS ' + arch);
  console.log('─'.repeat(54));

  // Downloaded once, and checked against Electron's published SHA-256 on
  // every build (lib/electron.js).
  const zipCache = await electronZip('darwin', arch, path.join(DIST, 'electron-cache'));

  console.log('  Lendo ZIP ...');
  const srcBuf     = fs.readFileSync(zipCache);
  const srcEntries = readZip(srcBuf);
  console.log('  ' + srcEntries.length + ' entradas lidas.');

  const ePfx   = 'Electron.app/';
  const hPfx   = APP_NAME + '.app/';
  const ePlist = hPfx + 'Contents/Info.plist';
  const eBin   = hPfx + 'Contents/MacOS/Electron';
  const hBin   = hPfx + 'Contents/MacOS/' + APP_NAME;
  const eIcon  = hPfx + 'Contents/Resources/electron.icns';
  let iconDone = false;

  const outEntries = [];

  for (var i = 0; i < srcEntries.length; i++) {
    var e    = srcEntries[i];
    var name = e.filename;

    // rename Electron.app → HidraNet.app
    if (name.indexOf(ePfx) === 0) name = hPfx + name.slice(ePfx.length);

    // rename main binary entry
    if (name === eBin) name = hBin;

    // skip default app
    if (name.indexOf('default_app.asar') !== -1) continue;

    // Defensive: never carry a code signature through this rewriting.
    //
    // The bundle directory, the main binary and Info.plist all change above,
    // and any signature covering them would be invalidated by those edits.
    // The official Electron darwin zip happens to ship without one, so today
    // this drops nothing — it is here so a future upstream change that starts
    // shipping a signature cannot silently produce an invalidly-signed bundle,
    // which macOS rejects harder than an unsigned one.
    //
    // Being unsigned is itself enough to be refused on Apple Silicon: the
    // kernel will not load unsigned arm64 code, and macOS reports it as
    // "HidraNet.app is damaged and can't be opened" rather than as unsigned.
    // The launcher below applies an ad-hoc signature, which is what actually
    // makes the app loadable.
    if (name.indexOf('/_CodeSignature/') !== -1
        || name.indexOf('Contents/_CodeSignature') !== -1) continue;

    // patch Info.plist
    if (name === ePlist) {
      var raw   = e.method === 8 ? inflateRawSync(e.rawData) : e.rawData;
      var plist = patchPlist(raw.toString('utf8'), APP_NAME, APP_ID, VERSION);
      outEntries.push(patchEntry(e, ePlist, Buffer.from(plist, 'utf8')));
      continue;
    }

    if (name === eIcon && fs.existsSync(MAC_ICON)) {
      outEntries.push(patchEntry(e, eIcon, fs.readFileSync(MAC_ICON)));
      iconDone = true;
      continue;
    }

    outEntries.push(Object.assign({}, e, { filename: name }));
  }
  console.log(iconDone ? '  HidraNet icon in the bundle'
                       : '  [!!] HidraNet icon NOT in the bundle — it shows Electron\'s');

  // ── Add our app source ────────────────────────────────────────────────────
  console.log('  Adicionando fonte do app ...');
  var resPfx = hPfx + 'Contents/Resources/';

  outEntries.push(mkDir(resPfx + 'app'));
  outEntries.push(mkFile(
    resPfx + 'app/package.json',
    Buffer.from(JSON.stringify(
      { name: 'hidra-browser', version: VERSION, main: 'src/main/main.js' },
      null, 2
    ), 'utf8')
  ));

  scanDir(path.join(ROOT, 'src')).forEach(function(item) {
    var zp = resPfx + 'app/src/' + item.rel;
    if (item.isDir) {
      outEntries.push(mkDir(zp));
    } else {
      outEntries.push(mkFile(zp, fs.readFileSync(item.abs)));
    }
  });
  outEntries.push(mkFile(resPfx + 'app/build.json', buildJson()));

  // ── Tor daemon — what actually anonymises the browsing ───────────────────
  // Without it the package opens, but every request leaves from the user's
  // real IP.
  // Refused rather than left out: a package without it opens and then sends
  // everything from the user's own address. And only the pinned Tor
  // (lib/tor.js) goes in.
  var tor = torDir(ROOT, 'darwin', arch);
  verifyTorDir(tor, 'darwin', arch);
  outEntries.push(mkDir(resPfx + 'bin'));
  outEntries.push(mkDir(resPfx + 'bin/tor'));
  ['tor', 'geoip', 'geoip6'].forEach(function(f) {
    outEntries.push(mkFile(resPfx + 'bin/tor/' + f, fs.readFileSync(path.join(tor, f)), f === 'tor' ? 0o755 : 0o644));
  });
  console.log('  Tor included (darwin-' + arch + '), every file matches its pin');

  // ── Launcher + README (shared with scripts/patch-zip.js) ──────────────────
  var launcher = launcherScript(APP_NAME);
  outEntries.push(mkFile('Start HidraNet.command', Buffer.from(launcher, 'utf8'), 0o755));

  var readme = readmeText(APP_NAME, VERSION, arch);
  outEntries.push(mkFile('README-macOS.txt', Buffer.from(readme, 'utf8')));

  // ── Write output ZIP ──────────────────────────────────────────────────────
  console.log('  Writing ZIP (' + outEntries.length + ' entries) ...');
  var outBuf  = writeZip(outEntries);
  var outName = 'HidraNet-Browser-' + VERSION + '-macOS-' + arch + '.zip';
  var outPath = writePackage(OUT_DIR, outName, outBuf);
  console.log('  >>> ' + outName + ' (' + (outBuf.length / 1048576).toFixed(1) + ' MB) → ' + outPath);
}

// ── Main ──────────────────────────────────────────────────────────────────────
(async function main() {
  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║  HidraNet Browser — macOS Package Builder           ║');
  console.log('║  (cross-platform, pure Node.js, Unix perms OK)      ║');
  console.log('╚══════════════════════════════════════════════════════╝');

  fs.mkdirSync(DIST, { recursive: true });

  var archs = ARCH_ARG === 'arm64' ? ['arm64']
            : ARCH_ARG === 'x64'   ? ['x64']
            : ['arm64', 'x64'];

  for (var i = 0; i < archs.length; i++) await buildArch(archs[i]);

  console.log('\n╔══════════════════════════════════════════════════════╗');
  console.log('║  Done. The ZIPs are in the folder below.            ║');
  console.log('║                                                     ║');
  console.log('║  arm64 → Apple Silicon (M1/M2/M3/M4) — 2020 on      ║');
  console.log('║  x64   → Intel — before 2020                        ║');
  console.log('╚══════════════════════════════════════════════════════╝');
  console.log('  ' + OUT_DIR);
})().catch(function(e) {
  console.error('\nERROR:', e.message);
  process.exit(1);
});
