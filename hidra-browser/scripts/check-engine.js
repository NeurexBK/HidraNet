#!/usr/bin/env node
/**
 * HidraNet — which Electron and which Tor are really inside these packages?
 *
 * Reads the Electron and Chromium versions compiled into the main binary of
 * each package given, and fails unless every one is the Electron package.json
 * pins, on the Chromium major the browser's user agent claims. The v1.0.0
 * packages said Electron 44 in the repository and ran Electron 33.4.11
 * (Chromium 130) under a Chrome 152 user agent; nothing read the binary.
 * They also carried Tor 15.0.22 while lib/tor.js pinned 15.0.26, so the
 * package's Tor folder is held to its pins here too (lib/package-runtime.js,
 * torProblems, the check update-sums.js makes): a package with the right
 * Electron and another Tor used to pass this check.
 * Run in CI on the packages a build produced and on the ones published.
 *
 * Usage:
 *   node scripts/check-engine.js <package.zip>...
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { readZip } = require('./lib/zip');
const { platformOf, layoutOf, engineProblems, engineVersions, advertisedChromeMajor, torProblems } = require('./lib/package-runtime');
const { TOR_VERSION } = require('./lib/tor');
const { inflateRawSync } = require('zlib');

const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));

/**
 * What one package runs. `problems` is empty when its engine is the pinned
 * Electron on the Chromium the user agent claims and its Tor is the pinned
 * Tor; `seen` says what was read.
 */
function checkPackage(file, want) {
  want = want || { electron: pkg.devDependencies.electron, chromeMajor: advertisedChromeMajor() };
  const name = path.basename(file);
  let problems;
  let seen = '';
  try {
    const { platform, arch } = platformOf(name);
    const entries = readZip(fs.readFileSync(file));
    problems = engineProblems(entries, platform, want);
    const bin = entries.find((e) => e.filename.replace(/\\/g, '/') === layoutOf(entries, platform).binary);
    if (bin) {
      const v = engineVersions(bin.method === 8 ? inflateRawSync(bin.rawData) : bin.rawData);
      seen = 'Electron ' + (v.electron || '?') + ', Chromium ' + (v.chrome || '?');
    }
    const torP = torProblems(entries, platform, arch);
    seen += (seen ? ', ' : '') + (torP.length ? 'not the pinned Tor' : 'Tor ' + TOR_VERSION);
    problems = problems.concat(torP);
  } catch (e) {
    problems = [e.message];
  }
  return { name, problems, seen: seen ? ' (' + seen + ')' : '' };
}

function main() {
  const want = { electron: pkg.devDependencies.electron, chromeMajor: advertisedChromeMajor() };
  const files = process.argv.slice(2);
  if (!files.length) {
    console.error('usage: check-engine.js <package.zip>...');
    process.exit(2);
  }

  console.log('  package.json pins Electron ' + want.electron + '; the user agent says Chrome ' + want.chromeMajor +
              '; lib/tor.js pins Tor ' + TOR_VERSION + '\n');
  let bad = 0;
  for (const file of files) {
    const { name, problems, seen } = checkPackage(file, want);
    if (problems.length) {
      bad++;
      console.log('  FAIL ' + name + seen);
      for (const p of problems) console.log('       ' + p);
    } else {
      console.log('  ok   ' + name + seen);
    }
  }
  console.log('');
  if (bad) {
    console.log('  ' + bad + ' package(s) do not run the Electron and the Tor the repository pins. Do not publish them.\n');
    process.exit(1);
  }
}

if (require.main === module) main();

module.exports = { checkPackage };
