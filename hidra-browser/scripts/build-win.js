#!/usr/bin/env node
/**
 * HidraNet Browser — Windows Package Builder (cross-platform)
 *
 * Runs on Windows/Linux/macOS. Downloads the official Electron win32 ZIP from
 * GitHub and lays the package out exactly as scripts/pack-portable.js does on
 * a Windows machine — the layout of the published package:
 *
 *   HidraNet.exe                    electron.exe, renamed and otherwise
 *                                   UNMODIFIED, so its hash and Electron's
 *                                   signature stay intact for SmartScreen
 *   resources/app/                  package.json, src/, build.json
 *   resources/bin/hidra-node.exe    the Rust engine, and its config.toml
 *   resources/bin/tor/              tor.exe, geoip, geoip6
 *   Start HidraNet.bat              a fallback launcher
 *
 * pack-portable.js copies node_modules/electron/dist, which is the Electron of
 * the machine it runs on — on Linux or macOS that is not a Windows one. This
 * takes the Windows runtime from Electron's release instead, so the package
 * can be built anywhere.
 *
 * The engine is cross-compiled beforehand (it needs the mingw-w64 toolchain):
 *   cd ../hidra-node && cargo build --release --target x86_64-pc-windows-gnu
 * or given with --engine <path>.
 *
 * Usage:
 *   node scripts/build-win.js
 *   node scripts/build-win.js --engine path/to/hidra-node.exe
 */
'use strict';

const fs    = require('fs');
const path  = require('path');
const { readZip, writeZip, mkFile, mkDir, UNIX_VER } = require('./lib/zip');
const { buildJson } = require('./lib/build-stamp');
const { electronZip } = require('./lib/electron');
const { torDir, verifyTorDir } = require('./lib/tor');

const VERSION      = '1.0.0';
const ROOT         = path.join(__dirname, '..');
const DIST         = path.join(ROOT, 'dist');
const DESKTOP      = path.join(require('os').homedir(), 'Desktop');
const NODE_ROOT    = path.join(ROOT, '..', 'hidra-node');

function argValue(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : null;
}

function scanDir(dir, base) {
  base = base || dir;
  let result = [];
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, ent.name);
    const rel = path.relative(base, abs).replace(/\\/g, '/');
    if (ent.isDirectory()) {
      result.push({ rel: rel + '/', abs, isDir: true });
      result = result.concat(scanDir(abs, base));
    } else {
      result.push({ rel, abs, isDir: false });
    }
  }
  return result;
}

(async function main() {
  console.log('HidraNet Browser — Windows Package Builder\n');

  // ── The engine first: without it there is nothing to build ───────────────
  const engine = path.resolve(argValue('--engine') ||
    path.join(NODE_ROOT, 'target', 'x86_64-pc-windows-gnu', 'release', 'hidra-node.exe'));
  if (!fs.existsSync(engine)) {
    console.error('  [!!] no engine at ' + engine);
    console.error('       cd ../hidra-node && cargo build --release --target x86_64-pc-windows-gnu');
    console.error('       (or pass --engine <path>)');
    process.exit(1);
  }
  const config = path.join(NODE_ROOT, 'config.toml');

  // ── Electron's Windows runtime ────────────────────────────────────────────
  // Downloaded once, and checked against Electron's published SHA-256 on
  // every build (lib/electron.js).
  const zipCache = await electronZip('win32', 'x64', path.join(DIST, 'electron-cache'));
  const zipName = path.basename(zipCache);

  const out = [];
  let exe = false;
  for (const e of readZip(fs.readFileSync(zipCache))) {
    let name = e.filename.replace(/\\/g, '/');
    if (name === 'electron.exe') { name = 'HidraNet.exe'; exe = true; }
    // As pack-portable.js writes them: Unix entries, 644 for files and 755
    // for folders, so a package unpacked on Linux or macOS is readable too.
    const dir = name.endsWith('/');
    out.push(Object.assign({}, e, {
      filename: name,
      versionMadeBy: UNIX_VER,
      extAttr: (((dir ? 0o040755 : 0o100644)) << 16) >>> 0,
    }));
  }
  if (!exe) throw new Error('no electron.exe in ' + zipName);
  console.log('  electron.exe -> HidraNet.exe (unmodified)');

  // ── The app ───────────────────────────────────────────────────────────────
  const res = 'resources/';
  out.push(mkDir(res + 'app'));
  out.push(mkFile(res + 'app/package.json', Buffer.from(JSON.stringify({
    name: 'hidra-browser',
    version: VERSION,
    main: 'src/main/main.js',
    description: 'HidraNet Browser'
  }, null, 2), 'utf8')));
  out.push(mkDir(res + 'app/src'));
  for (const item of scanDir(path.join(ROOT, 'src'))) {
    const zp = res + 'app/src/' + item.rel;
    out.push(item.isDir ? mkDir(zp) : mkFile(zp, fs.readFileSync(item.abs)));
  }
  out.push(mkFile(res + 'app/build.json', buildJson()));
  console.log('  app source added');

  // ── The engine and its configuration ─────────────────────────────────────
  out.push(mkDir(res + 'bin'));
  out.push(mkFile(res + 'bin/hidra-node.exe', fs.readFileSync(engine)));
  if (fs.existsSync(config)) out.push(mkFile(res + 'bin/config.toml', fs.readFileSync(config)));
  console.log('  engine added (' + fs.statSync(engine).size + ' bytes)');

  // ── Tor — what actually anonymises the browsing ───────────────────────────
  // Without it the package opens, but every request leaves from the user's
  // real IP.
  // Refused rather than left out, and only the pinned Tor (lib/tor.js).
  const tor = torDir(ROOT, 'win32', 'x64');
  verifyTorDir(tor, 'win32', 'x64');
  out.push(mkDir(res + 'bin/tor'));
  for (const f of ['tor.exe', 'geoip', 'geoip6', '.version']) {
    const abs = path.join(tor, f);
    if (fs.existsSync(abs)) out.push(mkFile(res + 'bin/tor/' + f, fs.readFileSync(abs)));
  }
  console.log('  Tor included (win32-x64), every file matches its pin');

  // ── Fallback launcher (CRLF: read by cmd.exe) ─────────────────────────────
  out.push(mkFile('Start HidraNet.bat', Buffer.from(
    '@echo off\r\n' +
    'title HidraNet Browser\r\n' +
    'echo Starting HidraNet Browser...\r\n' +
    'start "" "%~dp0HidraNet.exe"\r\n', 'utf8'), 0o755));

  // ── Write ─────────────────────────────────────────────────────────────────
  const outName = 'HidraNet-Browser-' + VERSION + '-Windows-x64.zip';
  const outPath = path.join(DESKTOP, outName);
  const buf = writeZip(out);
  fs.writeFileSync(outPath, buf);
  console.log('\n  >>> ' + outName + ' (' + (buf.length / 1048576).toFixed(1) + ' MB, ' +
              out.length + ' entries) → Desktop');
})().catch(function(e) {
  console.error('\nERROR:', e.message);
  process.exit(1);
});
