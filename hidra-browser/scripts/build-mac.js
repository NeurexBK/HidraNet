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
const { inflateRawSync } = require('zlib');
const { readZip, writeZip, mkFile, mkDir, patchEntry } = require('./lib/zip');
const { launcherScript, readmeText, patchPlist } = require('./lib/mac-extras');

const ELECTRON_VER = '33.4.11';
const APP_NAME     = 'HidraNet';
const APP_ID       = 'net.hidra.browser';
const VERSION      = '1.0.0';
const ROOT         = path.join(__dirname, '..');
const DIST         = path.join(ROOT, 'dist');
const DESKTOP      = path.join(require('os').homedir(), 'Desktop');
const ARCH_ARG     = process.argv[2] || 'all';

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

  // ── Tor daemon — o que de facto anonimiza a navegacao ────────────────────
  // Sem isto o pacote abre, mas sai sempre pelo IP real do utilizador.
  var torDir = path.join(ROOT, 'build', 'bin', 'tor', 'darwin-' + arch);
  if (fs.existsSync(path.join(torDir, 'tor'))) {
    outEntries.push(mkDir(resPfx + 'bin'));
    outEntries.push(mkDir(resPfx + 'bin/tor'));
    ['tor', 'geoip', 'geoip6'].forEach(function(f) {
      var abs = path.join(torDir, f);
      if (!fs.existsSync(abs)) return;
      outEntries.push(mkFile(resPfx + 'bin/tor/' + f, fs.readFileSync(abs), f === 'tor' ? 0o755 : 0o644));
    });
    console.log('  Tor incluido (darwin-' + arch + ')');
  } else {
    console.log('  [!!] Tor AUSENTE para darwin-' + arch + ' — este pacote nao tera anonimato.');
    console.log('       node scripts/fetch-tor.js --platform darwin --arch ' + arch);
  }

  // ── Launcher + README (shared with scripts/patch-zip.js) ──────────────────
  var launcher = launcherScript(APP_NAME);
  outEntries.push(mkFile('Start HidraNet.command', Buffer.from(launcher, 'utf8'), 0o755));

  var readme = readmeText(APP_NAME, VERSION, arch);
  outEntries.push(mkFile('README-macOS.txt', Buffer.from(readme, 'utf8')));

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
