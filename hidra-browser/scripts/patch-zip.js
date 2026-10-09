#!/usr/bin/env node
/**
 * HidraNet — refresh an already-published release package without rebuilding it.
 *
 * Why this exists: a release ZIP carries things a build box cannot always
 * reproduce — the Electron runtime, and above all the bundled Tor binary,
 * whose official host is not reachable from every network. Rebuilding from
 * scratch just to change one HTML file means fetching all of that again, and a
 * package built without Tor is worse than useless: it opens, and then nothing
 * connects.
 *
 * So this rewrites only what has to change and copies every other entry
 * through with its bytes untouched.
 *
 * What it does:
 *   1. Replaces the files under `.../app/src/` with the current working tree,
 *      adds files that are new, and leaves anything else alone.
 *   2. Normalises path separators. The published Windows and Linux packages
 *      were zipped on Windows (version-made-by says MS-DOS) and store
 *      `resources\app\...`. The ZIP spec requires forward slashes; Info-ZIP
 *      warns and guesses, other extractors produce files with backslashes in
 *      their names.
 *   3. Restores Unix permissions when the archive has none — same cause. With
 *      mode 0, the Linux package extracts with `hidranet` and `tor` not
 *      executable, so it cannot be launched by double-click at all.
 *   4. Replaces any binaries named in `opts.binaries`. The Windows package
 *      ships the compiled Rust engine, and the engine is where the
 *      post-quantum handshake lives: a package refreshed only in its HTML
 *      would still carry an engine built against the withdrawn Kyber crate.
 *
 * Usage:
 *   node scripts/patch-zip.js <in.zip> <out.zip> [--dry]
 */
'use strict';

const fs   = require('fs');
const path = require('path');
const { readZip, writeZip, mkFile, patchEntry, crc32 } = require('./lib/zip');
const { inflateRawSync } = require('zlib');
const { launcherScript, readmeText, patchPlist } = require('./lib/mac-extras');

const ROOT = path.join(__dirname, '..');
const SRC  = path.join(ROOT, 'src');

// Entries that have to carry the execute bit on a Unix extraction.
// chrome-sandbox is the Chromium SUID helper: upstream ships it 4755, and
// Electron refuses to use it otherwise (it then falls back to --no-sandbox).
const EXEC = new Map([
  ['chrome-sandbox',             0o4755],
  ['chrome_crashpad_handler',    0o755],
  ['hidranet',                   0o755],
  ['resources/bin/tor/tor',      0o755],
  ['resources/bin/hidra-node',   0o755]
]);
function modeFor(name) {
  if (name.endsWith('/')) return 0o755;
  if (EXEC.has(name)) return EXEC.get(name);
  if (/\.(sh|command)$/.test(name)) return 0o755;
  return 0o644;
}

// Files at the root of a package that this script regenerates rather than
// copies: the launchers (the published ones are in Portuguese, and the Linux
// one does not make Tor executable — fatal once the archive itself carries no
// permissions) and, on macOS, the README, whose opening instructions were
// wrong about why macOS blocks the app and left out the step that signs Tor.
//
// The macOS text comes from lib/mac-extras.js, the same source the builder
// uses, so a package refreshed here and one built from scratch say the same
// thing. Keyed by the name in the published archive; the value carries the
// name to write it under.
const APP_NAME = 'HidraNet';
const APP_ID   = 'net.hidra.browser';

function replacementsFor(zipName) {
  const r = {
    'iniciar.sh': {
      name: 'start.sh',
      body: [
        '#!/bin/bash',
        '# Starts HidraNet. Run:  bash start.sh',
        'DIR="$(cd "$(dirname "$0")" && pwd)"',
        '',
        '# The archive may arrive without permissions (some zip tools drop them),',
        '# so set them here rather than assume.',
        'chmod +x "$DIR/hidranet" 2>/dev/null',
        'chmod +x "$DIR/resources/bin/hidra-node" 2>/dev/null',
        'chmod +x "$DIR/resources/bin/tor/tor" 2>/dev/null',
        '',
        'if [ ! -f "$DIR/resources/bin/tor/tor" ]; then',
        '  echo "WARNING: no Tor in this package. It provides no anonymity."',
        'fi',
        '',
        'exec "$DIR/hidranet" "$@"',
        ''
      ].join('\n')
    },
    // CRLF: read by cmd.exe.
    'Iniciar HidraNet.bat': {
      name: 'Start HidraNet.bat',
      body: [
        '@echo off',
        'title HidraNet Browser',
        'echo Starting HidraNet Browser...',
        'start "" "%~dp0HidraNet.exe"',
        ''
      ].join('\r\n')
    }
  };

  const m = /-(\d+\.\d+\.\d+)-macOS-(arm64|x64)\./.exec(zipName);
  if (m) {
    const launcher = { name: 'Start HidraNet.command', body: launcherScript(APP_NAME) };
    const readme   = { name: 'README-macOS.txt',       body: readmeText(APP_NAME, m[1], m[2]), mode: 0o644 };
    r['Iniciar HidraNet.command'] = launcher;
    r['Start HidraNet.command']   = launcher;   // already-refreshed package
    r['LEIA-ME.txt']              = readme;
    r['LEIA-ME-macOS.txt']        = readme;
    r['README-macOS.txt']         = readme;
  }
  return r;
}

function scan(dir, base) {
  base = base || '';
  let out = [];
  for (const name of fs.readdirSync(dir).sort()) {
    const abs = path.join(dir, name);
    const rel = base ? base + '/' + name : name;
    if (fs.statSync(abs).isDirectory()) out = out.concat(scan(abs, rel));
    else out.push({ rel, abs });
  }
  return out;
}

// <anything>app/src/<rel> — the prefix differs per platform (macOS nests it
// inside the .app bundle), so read it from the archive instead of assuming.
const RE = /(^|.*\/)app\/src\/(.+)$/;

/**
 * @param {object} [opts]
 * @param {boolean} [opts.dry]
 * @param {Object<string,string>} [opts.binaries] archive path -> local file.
 *        The archive path is matched after separators are normalised, and the
 *        entry must already exist: this replaces a binary, it does not add one
 *        to a package that was not built to carry it.
 * @param {Object<string,string>} [opts.extras] archive path -> local file, for
 *        files the package does not have yet (a shared library beside Tor).
 */
function patchZip(inZip, outZip, opts) {
  opts = opts || {};
  const dry = !!opts.dry;
  const binaries = opts.binaries || {};
  const extras = opts.extras || {};
  // The package states its own version in its filename.
  const VERSION_OF = () => (/-(\d+\.\d+\.\d+)-/.exec(path.basename(inZip)) || [, '1.0.0'])[1];

  const LAUNCHERS = replacementsFor(path.basename(inZip));
  const entries = readZip(fs.readFileSync(inZip));
  const local   = scan(SRC);
  const byRel   = new Map(local.map(f => [f.rel, f]));

  // Does this archive carry Unix permissions at all? Upper byte 3 of
  // version-made-by means Unix; anything else means the modes are not ours to
  // trust, and every entry comes back as mode 0.
  const hasModes = entries.some(e => (e.versionMadeBy >> 8) === 3 && (e.extAttr >>> 16) !== 0);
  const hasBackslashes = entries.some(e => e.filename.indexOf('\\') !== -1);

  let prefix = null, replaced = 0, same = 0, stale = 0, renamed = 0, plists = 0;
  let binsDone = 0, extrasDone = 0;
  const seen = new Set();
  const binsWanted = new Set(Object.keys(binaries));
  const extrasWanted = new Set(Object.keys(extras));

  const out = entries.map(e => {
    const name = e.filename.replace(/\\/g, '/');
    let ent = e;

    // 1. launcher scripts
    const base = name.replace(/\/+$/, '');
    if (LAUNCHERS[base]) {
      const L = LAUNCHERS[base];
      renamed++;
      console.log('  rewrote       ' + base + ' -> ' + L.name);
      return mkFile(L.name, Buffer.from(L.body, 'utf8'), L.mode || 0o755);
    }

    // 2. the bundle's identity. The published macOS packages were built before
    //    the bundle-id patch landed, so they still say com.github.Electron —
    //    which is what LaunchServices, TCC permissions, preferences and
    //    keychain items get filed under, shared with every other Electron app
    //    that never changed its default.
    if (/\.app\/Contents\/Info\.plist$/.test(name)) {
      const raw = (e.method === 8 ? inflateRawSync(e.rawData) : e.rawData).toString('utf8');
      const fixed = patchPlist(raw, APP_NAME, APP_ID, VERSION_OF(e));
      if (fixed !== raw) {
        plists++;
        console.log('  rewrote       ' + name + ' (bundle id)');
        ent = patchEntry(e, name, Buffer.from(fixed, 'utf8'));
      }
    }

    // 3. shipped binaries (the Rust engine)
    if (Object.prototype.hasOwnProperty.call(binaries, name)) {
      const data = fs.readFileSync(binaries[name]);
      binsWanted.delete(name);
      if (data.length === e.uncompSz && crc32(data) === e.crc) {
        same++;
      } else {
        binsDone++;
        console.log('  engine        ' + name + ' (' + data.length + ' bytes)');
        ent = patchEntry(ent, name, data);
      }
    }

    // 3b. extra files that the package may or may not already carry
    if (Object.prototype.hasOwnProperty.call(extras, name)) {
      extrasWanted.delete(name);
      const data = fs.readFileSync(extras[name]);
      if (!(data.length === e.uncompSz && crc32(data) === e.crc)) {
        extrasDone++;
        console.log('  replaced      ' + name + ' (' + data.length + ' bytes)');
        ent = patchEntry(ent, name, data);
      }
    }

    // 4. app sources
    const m = RE.exec(name);
    if (m && !name.endsWith('/')) {
      const pfx = m[1] + 'app/src/';
      if (prefix === null) prefix = pfx;
      else if (prefix !== pfx) throw new Error('two app/src prefixes: ' + prefix + ' / ' + pfx);
      const rel = m[2];
      seen.add(rel);
      const f = byRel.get(rel);
      if (!f) {
        stale++;
        console.log('  stale (kept)  ' + rel);
      } else {
        const data = fs.readFileSync(f.abs);
        if (data.length === e.uncompSz && crc32(data) === e.crc) same++;
        else {
          replaced++;
          console.log('  updated       ' + rel);
          ent = patchEntry(e, name, data);
        }
      }
    }

    // 5. name + permissions
    ent = Object.assign({}, ent, { filename: name });
    if (!hasModes) {
      const isDir = name.endsWith('/');
      ent.versionMadeBy = 0x0314;                                  // Unix
      ent.extAttr = (((isDir ? 0o040000 : 0o100000) | modeFor(name)) << 16) >>> 0;
    }
    return ent;
  });

  for (const name of extrasWanted) {
    extrasDone++;
    console.log('  added         ' + name + ' (' + fs.statSync(extras[name]).size + ' bytes)');
    out.push(mkFile(name, fs.readFileSync(extras[name]), modeFor(name)));
  }

  let added = 0;
  if (!prefix) throw new Error('no app/src/ entries in ' + inZip + ' — wrong archive?');
  // Silence here would mean shipping the old engine and believing otherwise.
  if (binsWanted.size)
    throw new Error('not in ' + path.basename(inZip) + ': ' + [...binsWanted].join(', '));
  for (const f of local) {
    if (seen.has(f.rel)) continue;
    added++;
    console.log('  added         ' + f.rel);
    out.push(mkFile(prefix + f.rel, fs.readFileSync(f.abs)));
  }

  console.log('\n  ' + path.basename(inZip));
  console.log('  entries ' + entries.length + ' -> ' + out.length +
              ' | updated ' + replaced + ' | added ' + added +
              ' | unchanged ' + same + ' | stale kept ' + stale +
              ' | launchers ' + renamed + ' | plists ' + plists +
              ' | engines ' + binsDone + ' | extras ' + extrasDone);
  console.log('  separators fixed: ' + (hasBackslashes ? 'yes (were backslashes)' : 'no (already /)') +
              ' | permissions restored: ' + (hasModes ? 'no (archive had them)' : 'yes (archive had none)'));

  if (dry) return null;
  fs.writeFileSync(outZip, writeZip(out));
  console.log('  wrote ' + outZip + ' (' + fs.statSync(outZip).size + ' bytes)');
  return outZip;
}

module.exports = { patchZip };

if (require.main === module) {
  const inZip  = process.argv[2];
  const outZip = process.argv[3];
  const dry    = process.argv.indexOf('--dry') !== -1;
  if (!inZip || (!outZip && !dry)) {
    console.error('usage: node scripts/patch-zip.js <in.zip> <out.zip> [--dry]');
    process.exit(2);
  }
  patchZip(inZip, outZip, { dry: dry });
}
