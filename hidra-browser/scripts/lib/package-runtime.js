'use strict';
/**
 * What runs inside a package: the Electron runtime, the bundled Tor, and the
 * Chromium the user agent claims to be.
 *
 * The from-scratch builders take Electron through lib/electron.js and Tor
 * through lib/tor.js, so their pins hold by construction. A package refreshed
 * from an earlier one (refresh-release.js) carries whatever runtime and Tor
 * that one had, and the v1.0.0 packages turned out to carry Electron 33.4.11
 * (Chromium 130, out of support) and Tor 15.0.22 while the repository said
 * 44.9.3 and 15.0.26. These checks read the package itself:
 *
 *   runtimeProblems  every Electron file in the package is the file of the
 *                    pinned official zip (by SHA-256 of its contents), none
 *                    is missing, and nothing else is there that did not come
 *                    from that zip or from HidraNet
 *   torProblems      every Tor file hashes to its pin in lib/tor.js, and
 *                    the Tor folder holds nothing else
 *   engineProblems   the Electron and Chromium versions compiled into the
 *                    main binary are the pinned Electron and the Chrome major
 *                    the user agent advertises (src/fingerprint/engine.js):
 *                    a Chrome 152 user agent on a Chromium 130 engine is a
 *                    fingerprint any site can read by probing features
 *
 * Each returns a list of problems, empty when the package is what the
 * repository says it is.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { inflateRawSync } = require('zlib');
const tor = require('./tor');
const { ELECTRON_VER } = require('./electron');

const ROOT = path.join(__dirname, '..', '..');
const LIBEVENT = 'libevent-2.1.so.7';

function contents(e) { return e.method === 8 ? inflateRawSync(e.rawData) : e.rawData; }
function sha256(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }
const isDir = (e) => e.filename.endsWith('/');
const norm = (n) => n.replace(/\\/g, '/').replace(/^\.\//, '');

// Which system a package is for, from its file name.
function platformOf(zipName) {
  const m = /-(macOS|Linux|Windows)-(x64|arm64)\.zip$/.exec(zipName);
  if (!m) throw new Error('cannot tell the system of ' + zipName + ' from its name');
  return { platform: { macOS: 'darwin', Linux: 'linux', Windows: 'win32' }[m[1]], arch: m[2] };
}

/**
 * Where things are in a package. The published packages put everything at
 * the root of the archive; build-linux.js puts it under one folder. Both are
 * read here by finding the app.
 */
function layoutOf(entries, platform) {
  const names = entries.map((e) => norm(e.filename));
  const mark = platform === 'darwin' ? /^(.*?)HidraNet\.app\/Contents\/Resources\/app\// : /^(.*?)resources\/app\//;
  const found = names.map((n) => mark.exec(n)).find(Boolean);
  if (!found) throw new Error('no HidraNet app in the package');
  const prefix = found[1];
  const res = prefix + (platform === 'darwin' ? 'HidraNet.app/Contents/Resources/' : 'resources/');
  const binary = prefix + (platform === 'darwin'
    ? 'HidraNet.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework'
    : platform === 'win32' ? 'HidraNet.exe' : 'hidranet');
  return { prefix, res, binary };
}

/**
 * The name an entry of Electron's official zip has in a HidraNet package, as
 * the builders write it; null for an entry the builders drop or rewrite, whose
 * contents therefore differ from the official ones on purpose.
 */
function packagedName(official, platform) {
  let n = norm(official);
  if (n.indexOf('default_app.asar') !== -1) return null;
  if (platform === 'darwin') {
    if (n.indexOf('Electron.app/') === 0) n = 'HidraNet.app/' + n.slice('Electron.app/'.length);
    if (n === 'HidraNet.app/Contents/MacOS/Electron') n = 'HidraNet.app/Contents/MacOS/HidraNet';
    if (n.indexOf('/_CodeSignature/') !== -1) return null;
    // Patched (bundle id, name, version) and replaced (the icon).
    if (n === 'HidraNet.app/Contents/Info.plist') return null;
    if (n === 'HidraNet.app/Contents/Resources/electron.icns') return null;
  } else if (platform === 'win32') {
    if (n === 'electron.exe') n = 'HidraNet.exe';
  } else if (n === 'electron') {
    n = 'hidranet';
  }
  return n;
}

// Files a package carries beside the runtime that come from HidraNet: the app,
// what goes in bin/ (Tor, the engine), and the launchers and the README at the
// top. Tor's folder is checked on its own by torProblems.
function hidranetOwned(rel, layout, platform) {
  const res = layout.res.slice(layout.prefix.length);
  if (rel.indexOf(res + 'app/') === 0 || rel.indexOf(res + 'bin/') === 0) return true;
  if (platform === 'darwin' && rel === 'HidraNet.app/Contents/Info.plist') return true;
  if (platform === 'darwin' && rel === 'HidraNet.app/Contents/Resources/electron.icns') return true;
  return /^[^/]+\.(sh|bat|command|txt)$/.test(rel);
}

/**
 * pkgEntries: the package, read with lib/zip.js. electronEntries: the
 * official Electron zip for the same system, already checked against its pin
 * (lib/electron.js, electronZip).
 */
function runtimeProblems(pkgEntries, electronEntries, platform) {
  const layout = layoutOf(pkgEntries, platform);
  const problems = [];
  const pkg = new Map();
  for (const e of pkgEntries) {
    const n = norm(e.filename);
    if (isDir(e) || n.indexOf(layout.prefix) !== 0) continue;
    pkg.set(n.slice(layout.prefix.length), e);
  }
  const fromElectron = new Set();
  for (const e of electronEntries) {
    if (isDir(e)) continue;
    const name = packagedName(e.filename, platform);
    if (name === null) continue;
    fromElectron.add(name);
    const mine = pkg.get(name);
    if (!mine) { problems.push('the Electron file ' + name + ' is missing'); continue; }
    if (mine.uncompSz !== e.uncompSz || sha256(contents(mine)) !== sha256(contents(e))) {
      problems.push(name + ' is not the file of Electron ' + ELECTRON_VER);
    }
  }
  for (const name of pkg.keys()) {
    if (!fromElectron.has(name) && !hidranetOwned(name, layout, platform)) {
      problems.push(name + ' comes from neither Electron ' + ELECTRON_VER + ' nor HidraNet');
    }
  }
  return problems;
}

/** The Tor folder of the package is the pinned Tor, and only that. */
function torProblems(pkgEntries, platform, arch) {
  const layout = layoutOf(pkgEntries, platform);
  const pins = tor.PINS[platform + '-' + arch];
  if (!pins) return ['no pinned Tor for ' + platform + '-' + arch];
  const dir = layout.res + 'bin/tor/';
  const problems = [];
  const files = new Map();
  for (const e of pkgEntries) {
    const n = norm(e.filename);
    if (!isDir(e) && n.indexOf(dir) === 0) files.set(n.slice(dir.length), e);
  }
  for (const [file, want] of Object.entries(pins)) {
    const e = files.get(file);
    if (!e) { problems.push('Tor: ' + file + ' is missing'); continue; }
    const got = sha256(contents(e));
    if (got !== want) problems.push('Tor: ' + file + ' is not the pinned Tor ' + tor.TOR_VERSION + ' (got ' + got.slice(0, 16) + '…)');
  }
  for (const [file, e] of files) {
    if (Object.prototype.hasOwnProperty.call(pins, file)) continue;
    if (file === '.version') {
      const v = contents(e).toString('utf8').trim();
      if (v !== tor.TOR_VERSION) problems.push('Tor: .version says ' + JSON.stringify(v.slice(0, 20)) + ', not ' + tor.TOR_VERSION);
      continue;
    }
    if (platform === 'linux' && file === LIBEVENT) {
      const vendored = path.join(ROOT, 'vendor', 'linux-' + arch, LIBEVENT);
      if (!fs.existsSync(vendored) || sha256(contents(e)) !== sha256(fs.readFileSync(vendored))) {
        problems.push('Tor: ' + LIBEVENT + ' is not the one in vendor/linux-' + arch + '/');
      }
      continue;
    }
    problems.push('Tor: ' + file + ' is not part of the pinned Tor');
  }
  return problems;
}

/**
 * The Electron and Chromium versions compiled into a binary: Electron puts
 * "Electron/X.Y.Z" and "Chrome/A.B.C.D" in its default user agent. Null for
 * either when the binary does not say, or says two different things.
 */
function engineVersions(buf) {
  const scan = (needle, re) => {
    const seen = new Set();
    const tag = Buffer.from(needle, 'latin1');
    for (let at = buf.indexOf(tag); at !== -1; at = buf.indexOf(tag, at + 1)) {
      const m = re.exec(buf.subarray(at, at + 40).toString('latin1'));
      if (m) seen.add(m[1]);
    }
    return seen.size === 1 ? [...seen][0] : null;
  };
  return {
    electron: scan('Electron/', /^Electron\/(\d+\.\d+\.\d+)(?![\d.])/),
    chrome: scan('Chrome/', /^Chrome\/(\d+\.\d+\.\d+\.\d+)/),
  };
}

/** The Chrome major version the user agents in src/fingerprint/engine.js claim. */
function advertisedChromeMajor(engineSource) {
  const src = engineSource !== undefined ? engineSource
    : fs.readFileSync(path.join(ROOT, 'src', 'fingerprint', 'engine.js'), 'utf8');
  const majors = new Set([...src.matchAll(/'Mozilla\/5\.0 [^']*Chrome\/(\d+)\.[^']*'/g)].map((m) => m[1]));
  if (majors.size !== 1) throw new Error('src/fingerprint/engine.js does not advertise exactly one Chrome version');
  return [...majors][0];
}

/**
 * The engine in the package is the pinned Electron, on the Chromium the user
 * agent claims. `want` defaults to the repository's: ELECTRON_VER (which
 * test/build-pins.js keeps equal to package.json) and engine.js.
 */
function engineProblems(pkgEntries, platform, want) {
  want = want || {};
  const electron = want.electron || ELECTRON_VER;
  const chromeMajor = want.chromeMajor || advertisedChromeMajor();
  const layout = layoutOf(pkgEntries, platform);
  const bin = pkgEntries.find((e) => norm(e.filename) === layout.binary);
  if (!bin) return ['no ' + layout.binary + ' in the package to read the engine version from'];
  const got = engineVersions(contents(bin));
  const problems = [];
  if (!got.electron) problems.push(layout.binary + ' names no single Electron version');
  else if (got.electron !== electron) problems.push('the engine is Electron ' + got.electron + ', not ' + electron);
  if (!got.chrome) problems.push(layout.binary + ' names no single Chromium version');
  else if (got.chrome.split('.')[0] !== String(chromeMajor)) {
    problems.push('the engine is Chromium ' + got.chrome + ' but the user agent says Chrome ' + chromeMajor);
  }
  return problems;
}

module.exports = {
  platformOf, layoutOf, packagedName, runtimeProblems, torProblems,
  engineVersions, advertisedChromeMajor, engineProblems,
};
