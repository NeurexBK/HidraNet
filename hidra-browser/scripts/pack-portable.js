#!/usr/bin/env node
/**
 * HidraNet Browser — Portable Packager
 *
 * Creates distributable ZIP packages WITHOUT modifying the Electron binary.
 * This keeps the original exe hash intact so Smart App Control / SmartScreen
 * don't block it.
 *
 * Usage: node scripts/pack-portable.js [win|linux|all]
 */
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const zlib = require('zlib');

const ROOT = path.join(__dirname, '..');
const DIST = path.join(ROOT, 'dist');
const DESKTOP = path.join(require('os').homedir(), 'Desktop');
const NODE_ROOT = path.join(ROOT, '..', 'hidra-node');
const VERSION = '1.0.0';

const platform = process.argv[2] || 'all';

console.log('╔══════════════════════════════════════════════════════╗');
console.log('║  HidraNet Browser — Portable Packager               ║');
console.log('╚══════════════════════════════════════════════════════╝\n');

// ── Ensure prepare-build ran ──
require('./prepare-build.js');
console.log('');

// ── Helper: recursive copy ──
function copyDir(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDir(s, d);
    } else {
      fs.copyFileSync(s, d);
    }
  }
}

// ── Helper: create asar from source ──
function createAppDir(destResources) {
  const appDir = path.join(destResources, 'app');
  fs.mkdirSync(appDir, { recursive: true });

  // Copy package.json (minimal)
  const pkg = {
    name: 'hidra-browser',
    version: VERSION,
    main: 'src/main/main.js',
    description: 'HidraNet Browser'
  };
  fs.writeFileSync(path.join(appDir, 'package.json'), JSON.stringify(pkg, null, 2));

  // Copy src/
  copyDir(path.join(ROOT, 'src'), path.join(appDir, 'src'));
  console.log('  [ok] App source copied');
}

// ── Helper: copy hidra-node binary + config ──
function copyNodeBinary(destBin, isWin) {
  fs.mkdirSync(destBin, { recursive: true });
  const binName = isWin ? 'hidra-node.exe' : 'hidra-node';

  // Prefer debug over release (debug has --apps flag from latest build)
  const candidates = [
    path.join(NODE_ROOT, 'target', 'debug', binName),
    path.join(NODE_ROOT, 'target', 'release', binName),
  ];
  for (const src of candidates) {
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, path.join(destBin, binName));
      const which = path.basename(path.dirname(src));
      console.log(`  [ok] ${binName} bundled (${which})`);

      // Also copy config.toml
      const cfgSrc = path.join(NODE_ROOT, 'config.toml');
      if (fs.existsSync(cfgSrc)) {
        fs.copyFileSync(cfgSrc, path.join(destBin, 'config.toml'));
        console.log('  [ok] config.toml bundled');
      }
      return true;
    }
  }
  console.log(`  [!!] ${binName} not found — users will need to compile`);
  return false;
}

// ── Build Windows package ──
function buildWindows() {
  console.log('=== Building Windows x64 package ===\n');

  const electronDir = path.join(ROOT, 'node_modules', 'electron', 'dist');
  if (!fs.existsSync(path.join(electronDir, 'electron.exe'))) {
    console.error('ERROR: electron.exe not found. Run: npm install');
    return;
  }

  const outDir = path.join(DIST, 'HidraNet-Windows-x64');
  if (fs.existsSync(outDir)) fs.rmSync(outDir, { recursive: true });
  fs.mkdirSync(outDir, { recursive: true });

  // Copy Electron distribution (UNMODIFIED — keeps hash/signature intact)
  console.log('  Copying Electron runtime (unmodified)...');
  copyDir(electronDir, outDir);

  // Rename electron.exe -> HidraNet.exe
  fs.renameSync(path.join(outDir, 'electron.exe'), path.join(outDir, 'HidraNet.exe'));
  console.log('  [ok] electron.exe -> HidraNet.exe');

  // Copy app source into resources/app/
  createAppDir(path.join(outDir, 'resources'));

  // Copy hidra-node binary
  copyNodeBinary(path.join(outDir, 'resources', 'bin'), true);

  // Create launcher bat (if HidraNet.exe gets blocked, this is a fallback)
  fs.writeFileSync(path.join(outDir, 'Iniciar HidraNet.bat'),
    '@echo off\r\n' +
    'title HidraNet Browser\r\n' +
    'echo Iniciando HidraNet Browser...\r\n' +
    'start "" "%~dp0HidraNet.exe"\r\n'
  );

  // ZIP it
  const zipName = `HidraNet-Browser-${VERSION}-Windows-x64.zip`;
  const zipPath = path.join(DESKTOP, zipName);
  if (fs.existsSync(zipPath)) fs.unlinkSync(zipPath);

  console.log('  Creating ZIP...');
  execSync(
    `powershell -NoProfile -Command "Compress-Archive -Path '${outDir}\\*' -DestinationPath '${zipPath}' -CompressionLevel Optimal"`,
    { stdio: 'inherit', timeout: 300000 }
  );

  const sizeMB = (fs.statSync(zipPath).size / 1024 / 1024).toFixed(1);
  console.log(`\n  >>> ${zipName} (${sizeMB} MB) -> Desktop\n`);
}

// ── Build Linux package ──
function buildLinux() {
  console.log('=== Building Linux x64 package ===\n');

  // Check if Linux Electron was downloaded by electron-builder
  const linuxDir = path.join(DIST, 'linux-unpacked');
  let hasLinuxBuild = fs.existsSync(linuxDir) && fs.existsSync(path.join(linuxDir, 'hidra-browser'));

  if (!hasLinuxBuild) {
    console.log('  Linux Electron not found locally.');
    console.log('  Building via electron-builder...');
    try {
      execSync('npx electron-builder --linux --x64 --config.linux.target=dir', {
        cwd: ROOT,
        stdio: 'inherit',
        timeout: 600000,
        env: { ...process.env, CSC_IDENTITY_AUTO_DISCOVERY: 'false' }
      });
      hasLinuxBuild = true;
    } catch (e) {
      console.log('  [!!] Linux build failed — skipping');
      return;
    }
  }

  if (!hasLinuxBuild) return;

  const outDir = path.join(DIST, 'HidraNet-Linux-x64');
  if (fs.existsSync(outDir)) fs.rmSync(outDir, { recursive: true });
  fs.mkdirSync(outDir, { recursive: true });

  // Copy Linux build
  copyDir(linuxDir, outDir);

  // Rename binary
  if (fs.existsSync(path.join(outDir, 'hidra-browser'))) {
    fs.renameSync(path.join(outDir, 'hidra-browser'), path.join(outDir, 'hidranet'));
    console.log('  [ok] hidra-browser -> hidranet');
  }

  // Overwrite app source (in case electron-builder modified it)
  const appAsarPath = path.join(outDir, 'resources', 'app.asar');
  if (fs.existsSync(appAsarPath)) fs.unlinkSync(appAsarPath);
  createAppDir(path.join(outDir, 'resources'));

  // Copy hidra-node binary (Linux)
  copyNodeBinary(path.join(outDir, 'resources', 'bin'), false);

  // Create launcher script
  fs.writeFileSync(path.join(outDir, 'iniciar.sh'),
    '#!/bin/bash\n' +
    'DIR="$(cd "$(dirname "$0")" && pwd)"\n' +
    'chmod +x "$DIR/hidranet" 2>/dev/null\n' +
    'chmod +x "$DIR/resources/bin/hidra-node" 2>/dev/null\n' +
    '"$DIR/hidranet" "$@"\n',
    { mode: 0o755 }
  );

  // ZIP
  const zipName = `HidraNet-Browser-${VERSION}-Linux-x64.zip`;
  const zipPath = path.join(DESKTOP, zipName);
  if (fs.existsSync(zipPath)) fs.unlinkSync(zipPath);

  console.log('  Creating ZIP...');
  execSync(
    `powershell -NoProfile -Command "Compress-Archive -Path '${outDir}\\*' -DestinationPath '${zipPath}' -CompressionLevel Optimal"`,
    { stdio: 'inherit', timeout: 300000 }
  );

  const sizeMB = (fs.statSync(zipPath).size / 1024 / 1024).toFixed(1);
  console.log(`\n  >>> ${zipName} (${sizeMB} MB) -> Desktop\n`);
}

// ── Build macOS packages ──
function buildMac() {
  execSync('node ' + path.join(__dirname, 'build-mac.js'), {
    cwd: ROOT, stdio: 'inherit', timeout: 900000
  });
}

// ── Run ──
if (platform === 'win' || platform === 'all') buildWindows();
if (platform === 'linux' || platform === 'all') buildLinux();
if (platform === 'mac') buildMac();

console.log('╔══════════════════════════════════════════════════════╗');
console.log('║  Done! ZIPs are on your Desktop.                    ║');
console.log('║                                                     ║');
console.log('║  Windows: Extract ZIP -> run HidraNet.exe           ║');
console.log('║  Linux:   Extract -> chmod +x hidranet -> ./hidranet║');
console.log('║  macOS:   Extract -> right-click app -> Open        ║');
console.log('╚══════════════════════════════════════════════════════╝');
