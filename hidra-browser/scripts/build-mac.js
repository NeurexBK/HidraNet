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
 */
'use strict';

const fs    = require('fs');
const path  = require('path');
const https = require('https');
const { deflateRawSync, inflateRawSync } = require('zlib');

const ELECTRON_VER = '33.4.11';
const APP_NAME     = 'HidraNet';
const APP_ID       = 'net.hidra.browser';
const VERSION      = '1.0.0';
const ROOT         = path.join(__dirname, '..');
const DIST         = path.join(ROOT, 'dist');
const DESKTOP      = path.join(require('os').homedir(), 'Desktop');
const ARCH_ARG     = process.argv[2] || 'all';

// ── CRC-32 ───────────────────────────────────────────────────────────────────
const CRC_TBL = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[i] = c;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) c = CRC_TBL[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

// ── ZIP Reader ────────────────────────────────────────────────────────────────
function readZip(buf) {
  // find End-of-Central-Directory record
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65558); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('EOCD not found — not a valid ZIP');

  const cdCount  = buf.readUInt16LE(eocd + 10);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  const entries  = [];
  let pos = cdOffset;

  for (let i = 0; i < cdCount; i++) {
    if (buf.readUInt32LE(pos) !== 0x02014b50) throw new Error('Bad CD signature at ' + pos);
    const versionMadeBy = buf.readUInt16LE(pos + 4);
    const method        = buf.readUInt16LE(pos + 10);
    const crc           = buf.readUInt32LE(pos + 16);
    const compSz        = buf.readUInt32LE(pos + 20);
    const uncompSz      = buf.readUInt32LE(pos + 24);
    const fnLen         = buf.readUInt16LE(pos + 28);
    const exLen         = buf.readUInt16LE(pos + 30);
    const cmLen         = buf.readUInt16LE(pos + 32);
    const extAttr       = buf.readUInt32LE(pos + 38);
    const lhOffset      = buf.readUInt32LE(pos + 42);
    const filename      = buf.slice(pos + 46, pos + 46 + fnLen).toString('utf8');

    // read compressed data from local header (use local header's own field lengths)
    const lhFnLen  = buf.readUInt16LE(lhOffset + 26);
    const lhExLen  = buf.readUInt16LE(lhOffset + 28);
    const dataStart = lhOffset + 30 + lhFnLen + lhExLen;
    const rawData  = Buffer.from(buf.slice(dataStart, dataStart + compSz));

    entries.push({ filename, method, crc, compSz, uncompSz, extAttr, versionMadeBy, rawData });
    pos += 46 + fnLen + exLen + cmLen;
  }
  return entries;
}

// ── ZIP Writer ────────────────────────────────────────────────────────────────
function writeZip(entries) {
  const lhParts = [];
  const cdParts = [];
  let offset = 0;

  for (const e of entries) {
    const nameBuf = Buffer.from(e.filename, 'utf8');

    // local file header
    const lh = Buffer.alloc(30 + nameBuf.length);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0, 6);
    lh.writeUInt16LE(e.method, 8);
    lh.writeUInt32LE(0, 10);       // mod time/date (zero)
    lh.writeUInt32LE(e.crc, 14);
    lh.writeUInt32LE(e.compSz, 18);
    lh.writeUInt32LE(e.uncompSz, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);
    nameBuf.copy(lh, 30);

    // central directory entry
    // versionMadeBy upper byte = 3 (Unix) → macOS unzip respects extAttr as Unix st_mode
    const cd = Buffer.alloc(46 + nameBuf.length);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(e.versionMadeBy || 0x0314, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(0, 8);
    cd.writeUInt16LE(e.method, 10);
    cd.writeUInt32LE(0, 12);
    cd.writeUInt32LE(e.crc, 16);
    cd.writeUInt32LE(e.compSz, 20);
    cd.writeUInt32LE(e.uncompSz, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt16LE(0, 30);
    cd.writeUInt16LE(0, 32);
    cd.writeUInt16LE(0, 34);
    cd.writeUInt16LE(0, 36);
    cd.writeUInt32LE(e.extAttr, 38); // Unix permissions in upper 2 bytes
    cd.writeUInt32LE(offset, 42);
    nameBuf.copy(cd, 46);

    lhParts.push(lh, e.rawData);
    cdParts.push(cd);
    offset += lh.length + e.rawData.length;
  }

  const cdBuf = Buffer.concat(cdParts);
  const eocd  = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...lhParts, cdBuf, eocd]);
}

// ── Entry helpers ─────────────────────────────────────────────────────────────
const UNIX_VER = 0x0314; // version made by: Unix 2.0

function mkFile(filename, data, mode) {
  mode = mode || 0o644;
  const comp    = deflateRawSync(data, { level: 6 });
  const useComp = comp.length < data.length;
  return {
    filename,
    method:        useComp ? 8 : 0,
    crc:           crc32(data),
    compSz:        useComp ? comp.length : data.length,
    uncompSz:      data.length,
    extAttr:       ((0o100000 | mode) << 16) >>> 0,
    versionMadeBy: UNIX_VER,
    rawData:       useComp ? comp : data
  };
}

function mkDir(filename) {
  if (!filename.endsWith('/')) filename += '/';
  return {
    filename,
    method: 0, crc: 0, compSz: 0, uncompSz: 0,
    extAttr:       (0o040755 << 16) >>> 0,
    versionMadeBy: UNIX_VER,
    rawData:       Buffer.alloc(0)
  };
}

function patchEntry(e, newFilename, newData) {
  if (newData === undefined) return Object.assign({}, e, { filename: newFilename });
  const comp    = deflateRawSync(newData, { level: 6 });
  const useComp = comp.length < newData.length;
  return Object.assign({}, e, {
    filename:  newFilename,
    method:    useComp ? 8 : 0,
    crc:       crc32(newData),
    compSz:    useComp ? comp.length : newData.length,
    uncompSz:  newData.length,
    rawData:   useComp ? comp : newData
  });
}

// ── HTTPS download with redirect + progress ───────────────────────────────────
function download(url, dest, redirects) {
  redirects = redirects === undefined ? 10 : redirects;
  return new Promise(function(resolve, reject) {
    const file = fs.createWriteStream(dest);
    const req = https.get(url, { headers: { 'User-Agent': 'HidraNet-macOS-Builder/1.0' } }, function(res) {
      if ((res.statusCode === 301 || res.statusCode === 302) && res.headers.location) {
        file.close();
        try { fs.unlinkSync(dest); } catch(_) {}
        if (redirects <= 0) return reject(new Error('Too many redirects'));
        return download(res.headers.location, dest, redirects - 1).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        file.close();
        try { fs.unlinkSync(dest); } catch(_) {}
        return reject(new Error('HTTP ' + res.statusCode + ' from ' + url));
      }
      const total = parseInt(res.headers['content-length'] || '0');
      let recv = 0, lastPct = -1;
      res.on('data', function(chunk) {
        recv += chunk.length;
        if (total > 0) {
          const pct = Math.floor(recv / total * 20) * 5;
          if (pct !== lastPct) {
            process.stdout.write('\r    ' + pct + '%  ' +
              (recv / 1048576).toFixed(1) + ' / ' + (total / 1048576).toFixed(1) + ' MB   ');
            lastPct = pct;
          }
        }
      });
      res.pipe(file);
      file.on('finish', function() { file.close(); process.stdout.write('\n'); resolve(); });
    });
    req.on('error', function(err) {
      file.close();
      try { fs.unlinkSync(dest); } catch(_) {}
      reject(err);
    });
  });
}

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
  console.log('  macOS ' + arch);
  console.log('─'.repeat(54));

  const cacheDir = path.join(DIST, 'electron-cache');
  fs.mkdirSync(cacheDir, { recursive: true });

  const zipName  = 'electron-v' + ELECTRON_VER + '-darwin-' + arch + '.zip';
  const zipCache = path.join(cacheDir, zipName);
  const dlUrl    = 'https://github.com/electron/electron/releases/download/v' +
                   ELECTRON_VER + '/' + zipName;

  if (!fs.existsSync(zipCache)) {
    console.log('  Descarregando ' + zipName + ' ...');
    console.log('  (GitHub → ~100 MB, pode demorar)');
    await download(dlUrl, zipCache);
    console.log('  Guardado em cache: ' + zipCache);
  } else {
    console.log('  Cache: ' + zipName);
  }

  console.log('  Lendo ZIP ...');
  const srcBuf     = fs.readFileSync(zipCache);
  const srcEntries = readZip(srcBuf);
  console.log('  ' + srcEntries.length + ' entradas lidas.');

  const ePfx   = 'Electron.app/';
  const hPfx   = APP_NAME + '.app/';
  const ePlist = hPfx + 'Contents/Info.plist';
  const eBin   = hPfx + 'Contents/MacOS/Electron';
  const hBin   = hPfx + 'Contents/MacOS/' + APP_NAME;

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

    // patch Info.plist
    if (name === ePlist) {
      var raw   = e.method === 8 ? inflateRawSync(e.rawData) : e.rawData;
      var plist = raw.toString('utf8');
      plist = plist
        .replace(/(<key>CFBundleExecutable<\/key>\s*<string>)Electron(<\/string>)/g,
                 '$1' + APP_NAME + '$2')
        .replace(/(<key>CFBundleDisplayName<\/key>\s*<string>)Electron(<\/string>)/g,
                 '$1' + APP_NAME + '$2')
        .replace(/(<key>CFBundleName<\/key>\s*<string>)Electron(<\/string>)/g,
                 '$1' + APP_NAME + '$2')
        .replace(/com\.github\.electron(?:\.Electron)?/g, APP_ID)
        .replace(/(<key>CFBundleShortVersionString<\/key>\s*<string>)[^<]*(<\/string>)/g,
                 '$1' + VERSION + '$2')
        .replace(/(<key>CFBundleVersion<\/key>\s*<string>)[^<]*(<\/string>)/g,
                 '$1' + VERSION + '$2');
      outEntries.push(patchEntry(e, ePlist, Buffer.from(plist, 'utf8')));
      continue;
    }

    outEntries.push(Object.assign({}, e, { filename: name }));
  }

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

  // ── Launcher script (0o755 → double-clickable on macOS) ──────────────────
  var launcher = [
    '#!/bin/bash',
    '# HidraNet Browser — Iniciador macOS',
    'DIR="$(cd "$(dirname "$0")" && pwd)"',
    'APP="$DIR/' + APP_NAME + '.app"',
    'echo "Corrigindo permissões..."',
    'chmod -R 755 "$APP" 2>/dev/null',
    'xattr -rd com.apple.quarantine "$APP" 2>/dev/null',
    'echo "Abrindo HidraNet Browser..."',
    'open "$APP"',
    ''
  ].join('\n');
  outEntries.push(mkFile('Iniciar HidraNet.command', Buffer.from(launcher, 'utf8'), 0o755));

  // ── README ────────────────────────────────────────────────────────────────
  var archNote = arch === 'arm64'
    ? 'Apple Silicon (M1 / M2 / M3 / M4) — Macs de 2020 em diante'
    : 'Intel — Macs anteriores a 2020';
  var readme = [
    'HidraNet Browser ' + VERSION + ' — macOS ' + arch,
    'Para: ' + archNote,
    '',
    'COMO INICIAR',
    '─'.repeat(40),
    '',
    'Opção A (mais simples):',
    '  1. Extraia o ZIP',
    '  2. Duplo clique em "Iniciar HidraNet.command"',
    '     • Se bloqueado pelo macOS: clique direito → Abrir',
    '',
    'Opção B (Terminal):',
    '  1. Abra o Terminal na pasta extraída',
    '  2. Cole e execute:',
    '       chmod -R 755 ' + APP_NAME + '.app',
    '       xattr -rd com.apple.quarantine ' + APP_NAME + '.app',
    '       open ' + APP_NAME + '.app',
    '',
    'NOTA — GATEKEEPER',
    '─'.repeat(40),
    'O macOS pode mostrar "não pode ser aberto porque o programador',
    'não pode ser verificado". Isto é normal — a app não está assinada.',
    '',
    'Solução: clique com o botão DIREITO no HidraNet.app → "Abrir" → "Abrir".',
    '',
    '                              — Equipa HidraNet',
    ''
  ].join('\n');
  outEntries.push(mkFile('LEIA-ME.txt', Buffer.from(readme, 'utf8')));

  // ── Write output ZIP ──────────────────────────────────────────────────────
  console.log('  Escrevendo ZIP (' + outEntries.length + ' entradas) ...');
  var outBuf  = writeZip(outEntries);
  var outName = 'HidraNet-Browser-' + VERSION + '-macOS-' + arch + '.zip';
  var outPath = path.join(DESKTOP, outName);
  fs.writeFileSync(outPath, outBuf);
  console.log('  >>> ' + outName + ' (' + (outBuf.length / 1048576).toFixed(1) + ' MB) → Desktop');
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
  console.log('║  Concluído! ZIPs no Desktop.                        ║');
  console.log('║                                                     ║');
  console.log('║  arm64 → Apple Silicon (M1/M2/M3/M4) — pós 2020    ║');
  console.log('║  x64   → Intel — anteriores a 2020                  ║');
  console.log('╚══════════════════════════════════════════════════════╝');
})().catch(function(e) {
  console.error('\nERRO:', e.message);
  process.exit(1);
});
