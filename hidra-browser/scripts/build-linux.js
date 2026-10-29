#!/usr/bin/env node
/**
 * HidraNet Browser — Linux Package Builder (cross-platform)
 *
 * Runs on Windows/Linux/macOS. Downloads the official Electron Linux ZIP
 * from GitHub, renames the binary to hidranet, adds our app source,
 * and produces a ZIP with correct Unix permissions (+x on the binary).
 *
 * Usage:
 *   node scripts/build-linux.js          # x64 only
 *   node scripts/build-linux.js x64
 *   node scripts/build-linux.js arm64
 *   node scripts/build-linux.js all      # x64 + arm64
 */
'use strict';

const fs    = require('fs');
const path  = require('path');
const { readZip, writeZip, mkFile, mkDir } = require('./lib/zip');
const { buildJson } = require('./lib/build-stamp');
const { electronZip } = require('./lib/electron');
const { torDir, verifyTorDir } = require('./lib/tor');

const APP_NAME     = 'hidranet';       // lowercase binary name
const APP_DISPLAY  = 'HidraNet';      // human-readable
const ROOT         = path.join(__dirname, '..');
// Every published build has a version of its own, from package.json: a
// rebuild under a version already published would be told apart from the
// old files only by its hash.
const VERSION      = require(path.join(ROOT, 'package.json')).version;
const DIST         = path.join(ROOT, 'dist');
const DESKTOP      = path.join(require('os').homedir(), 'Desktop');
const ARCH_ARG     = process.argv[2] || 'x64';

// The bundled Linux Tor is dynamically linked against libevent, which most
// distributions do not install by default. Without it Tor dies at startup and
// the browser opens with nothing connecting. tor-manager.js puts Tor's folder
// on LD_LIBRARY_PATH, so the library goes right beside it. Only an x64 copy
// is vendored. See vendor/linux-x64/README.md.
const LIBEVENT = 'libevent-2.1.so.7';

// The archive is written by lib/zip.js, as the other builders' are: it gives
// every entry a real date (the copy of the writer this file used to carry
// wrote zero, which decodes to a date that does not exist) and keeps the
// Electron entries' modes and symlinks byte for byte.

// ── Recursive dir scan ────────────────────────────────────────────────────────
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
  console.log('  Linux ' + arch);
  console.log('─'.repeat(54));

  // Downloaded once, and checked against Electron's published SHA-256 on
  // every build (lib/electron.js).
  var zipCache = await electronZip('linux', arch, path.join(DIST, 'electron-cache'));

  console.log('  Lendo ZIP ...');
  var srcBuf     = fs.readFileSync(zipCache);
  var srcEntries = readZip(srcBuf);
  console.log('  ' + srcEntries.length + ' entradas lidas.');

  // Top-level folder name in the output zip
  var PREFIX = APP_DISPLAY + '-Linux-' + arch + '/';

  var outEntries = [];

  // Add the top-level directory entry
  outEntries.push(mkDir(PREFIX));

  for (var i = 0; i < srcEntries.length; i++) {
    var e    = srcEntries[i];
    // Strip leading ./ if present
    var orig = e.filename.replace(/^\.\//, '');

    // Skip empty root directory entry (if any)
    if (orig === '' || orig === '.') continue;

    // Build new path with prefix
    var name = PREFIX + orig;

    // Rename Electron binary: PREFIX + 'electron' → PREFIX + 'hidranet'
    if (orig === 'electron') name = PREFIX + APP_NAME;

    // Skip default app
    if (orig.indexOf('default_app.asar') !== -1) continue;

    outEntries.push(Object.assign({}, e, { filename: name }));
  }

  // ── Add app source ────────────────────────────────────────────────────────
  console.log('  Adicionando fonte do app ...');
  var resPfx = PREFIX + 'resources/';
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
    if (item.isDir) outEntries.push(mkDir(zp));
    else outEntries.push(mkFile(zp, fs.readFileSync(item.abs)));
  });
  outEntries.push(mkFile(resPfx + 'app/build.json', buildJson()));

  // ── Tor daemon — what actually anonymises the browsing ───────────────────
  // Without it the package opens, but every request leaves from the user's
  // real IP.
  // Refused rather than left out: a package without it opens and then sends
  // everything from the user's own address. And only the pinned Tor
  // (lib/tor.js) goes in.
  var tor = torDir(ROOT, 'linux', arch);
  verifyTorDir(tor, 'linux', arch);
  outEntries.push(mkDir(resPfx + 'bin'));
  outEntries.push(mkDir(resPfx + 'bin/tor'));
  ['tor', 'geoip', 'geoip6'].forEach(function(f) {
    outEntries.push(mkFile(resPfx + 'bin/tor/' + f, fs.readFileSync(path.join(tor, f)), f === 'tor' ? 0o755 : 0o644));
  });
  console.log('  Tor included (linux-' + arch + '), every file matches its pin');
  // Without libevent beside it the pinned Tor cannot start on most systems,
  // so its absence stops the build too.
  var libevent = path.join(ROOT, 'vendor', 'linux-' + arch, LIBEVENT);
  if (!fs.existsSync(libevent)) throw new Error(LIBEVENT + ' missing for linux-' + arch + ' (vendor/linux-' + arch + '/)');
  outEntries.push(mkFile(resPfx + 'bin/tor/' + LIBEVENT, fs.readFileSync(libevent)));
  console.log('  ' + LIBEVENT + ' included beside Tor');

  // ── Launcher script (0o755) ───────────────────────────────────────────────
  // Shared with patch-zip.js and pack-portable.js — see lib/linux-launcher.js.
  var launcher = require('./lib/linux-launcher').launcherScript(APP_NAME);
  outEntries.push(mkFile(PREFIX + 'start.sh', Buffer.from(launcher, 'utf8'), 0o755));

  // ── README ────────────────────────────────────────────────────────────────
  var archNote = arch === 'arm64'
    ? 'Linux ARM64 (Raspberry Pi 4+, ARM servers, and so on)'
    : 'Linux x86-64 (standard desktop/laptop)';
  var readme = [
    APP_DISPLAY + ' Browser ' + VERSION + ' — Linux ' + arch,
    'For: ' + archNote,
    '',
    'HOW TO START IT',
    '─'.repeat(40),
    '',
    'Option A (script):',
    '  chmod +x start.sh && ./start.sh',
    '',
    'Option B (directly):',
    '  chmod +x ' + APP_NAME + ' && ./' + APP_NAME,
    '',
    'Option A is the safer one: it also makes the bundled Tor executable.',
    'Started directly, with Tor not executable, the browser opens and then',
    'cannot connect.',
    '',
    'DEPENDENCIES',
    '─'.repeat(40),
    'Needs the usual system libraries (GTK3, libX11, libnss3).',
    'On Ubuntu/Debian:',
    '  sudo apt install libgtk-3-0 libnss3 libasound2 libxss1',
    '',
    '                                          — The HidraNet team',
    ''
  ].join('\n');
  outEntries.push(mkFile(PREFIX + 'LEIA-ME.txt', Buffer.from(readme, 'utf8')));

  // ── Write ZIP ─────────────────────────────────────────────────────────────
  console.log('  Escrevendo ZIP (' + outEntries.length + ' entradas) ...');
  var outBuf  = writeZip(outEntries);
  var outName = 'HidraNet-Browser-' + VERSION + '-Linux-' + arch + '.zip';
  var outPath = path.join(DESKTOP, outName);
  fs.writeFileSync(outPath, outBuf);
  console.log('  >>> ' + outName + ' (' + (outBuf.length / 1048576).toFixed(1) + ' MB) → Desktop');
}

// ── Main ──────────────────────────────────────────────────────────────────────
(async function main() {
  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║  HidraNet Browser — Linux Package Builder           ║');
  console.log('║  (cross-platform, pure Node.js, Unix perms OK)      ║');
  console.log('╚══════════════════════════════════════════════════════╝');

  fs.mkdirSync(DIST, { recursive: true });

  var archs = ARCH_ARG === 'arm64' ? ['arm64']
            : ARCH_ARG === 'all'   ? ['x64', 'arm64']
            : ['x64'];

  for (var i = 0; i < archs.length; i++) await buildArch(archs[i]);

  console.log('\n╔══════════════════════════════════════════════════════╗');
  console.log('║  Done. The ZIP is on your Desktop.                  ║');
  console.log('║                                                     ║');
  console.log('║  Extract and run: chmod +x start.sh && ./start.sh   ║');
  console.log('╚══════════════════════════════════════════════════════╝');
})().catch(function(e) {
  console.error('\nERROR:', e.message);
  process.exit(1);
});
