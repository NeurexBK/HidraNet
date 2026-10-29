#!/usr/bin/env node
/**
 * HidraNet — rewrite the checksum table from the packages that were built.
 *
 * refresh-release.js prints the hashes and tells you to paste them in by
 * hand. That is fine on a laptop and wrong in CI, where nobody is reading the
 * log: the three packages without the engine repack byte for byte, but the
 * Windows one carries a freshly compiled Rust binary and hashes differently
 * on every machine. Published a table copied from somewhere else and the
 * instruction "verify before running" becomes a lie that fails closed — the
 * user checks, the hash does not match, and the honest conclusion for them is
 * that the download was tampered with.
 *
 * So the table is generated from the files that are actually going out, and
 * only once each of them is shown to run what the repository pins: the
 * Electron and Chromium compiled into its main binary are the pinned Electron
 * and the Chrome the user agent claims, and its Tor is the pinned Tor
 * (lib/package-runtime.js). Every package reaches the table through here,
 * whichever script built it, so this is the check no package skips. When the
 * pinned official Electron zip is in dist/electron-cache (the builders leave
 * it there; HIDRA_ELECTRON_CACHE names another folder), every Electron file
 * in the package is compared with it as well.
 *
 * The paragraph that says which commit the files were built from is
 * rewritten for the commit given, and on a new version the commit is
 * required and the previous version's "What changed" history goes: neither
 * is true of the new files, and both would be signed with them.
 *
 * The packages are the version package.json says, and a version already in
 * the table is never given other files: a rebuild gets a new version. The
 * signed record near the top (what the browser's update notice reads, see
 * src/main/update-check.js) follows: latest-version becomes this version,
 * valid-until moves forward, and minimum-safe-version changes only when
 * --minimum says so. The table then has to be signed again
 * (scripts/sign-sums.ps1): the old SHA256SUMS.txt.sig no longer matches.
 *
 * Usage:
 *   node scripts/update-sums.js <dir-with-the-four-zips> [commit-sha]
 *        [--minimum X.Y.Z] [--valid-until YYYY-MM-DD]
 *   (the commit is required when package.json's version is not the table's)
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..', '..');
const VERSION = require(path.join(ROOT, 'hidra-browser', 'package.json')).version;
const SUMS = process.env.HIDRA_SUMS_FILE || path.join(ROOT, 'landing', 'SHA256SUMS.txt');
const { compareVersions, parseVersion } = require('../src/main/update-check');
const { readZip } = require('./lib/zip');
const runtime = require('./lib/package-runtime');
const electron = require('./lib/electron');
// Where the builders leave the official Electron zips.
const ELECTRON_CACHE = process.env.HIDRA_ELECTRON_CACHE || path.join(ROOT, 'hidra-browser', 'dist', 'electron-cache');

// How long a record stays valid when --valid-until is not given. A browser
// ignores an expired record, so the table must be signed again before then.
const DEFAULT_VALID_DAYS = 180;

// The order the table lists them in, which is not the order they were built.
const ROWS = [
  ['macOS-arm64', 'macOS arm64'],
  ['macOS-x64', 'macOS x64'],
  ['Linux-x64', 'Linux x64'],
  ['Windows-x64', 'Windows x64'],
];

function fail(msg) {
  console.error('  ' + msg);
  process.exit(1);
}

const args = process.argv.slice(2);
const flag = (name) => {
  const i = args.indexOf(name);
  if (i === -1) return null;
  const v = args[i + 1];
  if (!v || v.startsWith('--')) fail(name + ' needs a value');
  args.splice(i, 2);
  return v;
};
const minimum = flag('--minimum');
const validUntil = flag('--valid-until') ||
  new Date(Date.now() + DEFAULT_VALID_DAYS * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
const dir = args[0];
if (!dir) {
  console.error('usage: update-sums.js <dir-with-the-four-zips> [commit-sha] [--minimum X.Y.Z] [--valid-until YYYY-MM-DD]');
  process.exit(1);
}
const commit = (args[1] || '').trim().slice(0, 7);
if (!parseVersion(VERSION)) fail('package.json has no X.Y.Z version');
if (minimum !== null && (!parseVersion(minimum) || compareVersions(minimum, VERSION) > 0)) {
  fail('--minimum must be X.Y.Z, and not above ' + VERSION);
}
if (!/^\d{4}-\d{2}-\d{2}$/.test(validUntil) || new Date(validUntil + 'T00:00:00Z').toISOString().slice(0, 10) !== validUntil ||
    new Date(validUntil + 'T23:59:59Z').getTime() < Date.now()) {
  fail('--valid-until must be a date (YYYY-MM-DD) that has not passed');
}

// ── Read what is actually there, and what it runs ─────────────────────────

// The reasons a package does not run what the repository pins, or an empty
// list, and how far it was compared.
function runtimeOf(name, bytes) {
  let depth = 'engine and Tor';
  try {
    const { platform, arch } = runtime.platformOf(name);
    const es = readZip(bytes);
    const problems = [...runtime.engineProblems(es, platform), ...runtime.torProblems(es, platform, arch)];
    const official = path.join(ELECTRON_CACHE, electron.zipName(platform, arch));
    if (fs.existsSync(official)) {
      electron.verifyElectronZip(official);
      problems.push(...runtime.runtimeProblems(es, readZip(fs.readFileSync(official)), platform));
      depth = 'every Electron file, engine and Tor';
    }
    return { problems, depth };
  } catch (e) {
    return { problems: [e.message], depth };
  }
}

const facts = ROWS.map(([arch, label]) => {
  const name = `HidraNet-Browser-${VERSION}-${arch}.zip`;
  const file = path.join(dir, name);
  if (!fs.existsSync(file)) {
    console.error('  missing: ' + file);
    process.exit(1);
  }
  const bytes = fs.readFileSync(file);
  return {
    name,
    label,
    sha: crypto.createHash('sha256').update(bytes).digest('hex'),
    size: bytes.length,
    ...runtimeOf(name, bytes),
  };
});

let refused = 0;
for (const f of facts) {
  if (!f.problems.length) {
    console.log('  checked ' + f.depth + ': ' + f.name);
    continue;
  }
  refused++;
  console.error('  ' + f.name + ' does not run what the repository pins:');
  for (const p of f.problems.slice(0, 20)) console.error('    ' + p);
  if (f.problems.length > 20) console.error('    … and ' + (f.problems.length - 20) + ' more');
}
if (refused) {
  fail(refused + ' package(s) refused; the table is unchanged. Do not publish them: build them again\n' +
       '  with build-win.js, build-linux.js and build-mac.js, which take the pinned Electron and Tor.');
}

// ── Rewrite only the first table ──────────────────────────────────────────
//
// Only the published table may be touched, not the signing notes after it, so
// the rewrite is bounded by that section's heading rather than a line count.
// It used to stop at a second table listing the September hashes; that table
// was removed once those packages left the release page, because a stale
// download would have matched it and read as genuine.

let text = fs.readFileSync(SUMS, 'utf8');
const marker = 'NONE OF THESE BUILDS ARE SIGNED OR NOTARISED';
const cut = text.indexOf(marker);
if (cut === -1) {
  console.error('  cannot find the signing notes; refusing to guess where the table ends');
  process.exit(1);
}
let head = text.slice(0, cut);
const tail = text.slice(cut);

const group = (n) => n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
const mib = (n) => (n / 1048576).toFixed(1);

// A version the table already lists keeps its files. Publishing other bytes
// under it is what made every rebuild "1.0.0", told apart only by its hash.
for (const f of facts) {
  const listed = new RegExp(`^([0-9a-f]{64})  ${f.name.replace(/\./g, '\\.')}$`, 'm').exec(head);
  if (listed && listed[1] !== f.sha) {
    fail(f.name + ' is already in the table with other contents. ' + VERSION + ' has been published:\n' +
         '  give this build a new version in hidra-browser/package.json and build it again.');
  }
}

let changed = 0;
for (const f of facts) {
  // The hash line: 64 hex, two spaces, the file name, of whichever version
  // the table lists now.
  const arch = f.name.replace(/^HidraNet-Browser-[0-9.]+-/, '').replace(/\.zip$/, '');
  const hashLine = new RegExp(`^[0-9a-f]{64}  HidraNet-Browser-\\d+\\.\\d+\\.\\d+-${arch}\\.zip$`, 'm');
  if (!hashLine.test(head)) {
    console.error('  no hash line for ' + f.name);
    process.exit(1);
  }
  head = head.replace(hashLine, `${f.sha}  ${f.name}`);

  // The size line, which is indented and padded into a column.
  const sizeLine = new RegExp(`^(  ${f.label}\\s+)[\\d,]+ bytes\\s+\\([\\d.]+ MiB\\)$`, 'm');
  if (!sizeLine.test(head)) {
    console.error('  no size line for ' + f.label);
    process.exit(1);
  }
  head = head.replace(
    sizeLine,
    (_, lead) => `${lead}${group(f.size)} bytes  (${mib(f.size)} MiB)`
  );
  changed++;
}

// What the table says about where the files came from, and what changed in
// them, is about the version it listed. A new version gets the commit it was
// built from and nothing of the old prose: whoever signs the table would
// otherwise sign another release's date and history as this one's.
const listedVersion = (/^HidraNet Browser (\d+\.\d+\.\d+) — SHA-256 checksums$/m.exec(head) || [])[1];
const newVersion = listedVersion !== VERSION;
if (newVersion && !commit) fail('a new version needs the commit its packages were built from (the second argument)');
if (commit && !/^[0-9a-f]{7}$/.test(commit)) fail('the commit must be hexadecimal, as git prints it');
if (commit) {
  // The whole paragraph, up to the blank line after it.
  const provenance = /^  Built from commit [0-9a-f]{7,40}\.[^\n]*(?:\n(?!\n)[^\n]*)*/m;
  if (!provenance.test(head)) fail('cannot find the "Built from commit" line');
  head = head.replace(provenance, () => [
    `  Built from commit ${commit}. These are the hashes and sizes of the four`,
    `  files built from it, the ones the release v${VERSION} publishes and its`,
    '  description lists.',
  ].join('\n'));
}
if (newVersion) {
  // From "What changed ..." to the rule before the signing notes.
  const history = /^What changed [^\n]*\n[\s\S]*?(?=^-{20,}$)/m;
  if (history.test(head)) {
    head = head.replace(history, () => `What changed in ${VERSION}: the release notes on the tag v${VERSION} list it.\n\n`);
  }
}

// The title, and the record the browser reads.
const title = /^HidraNet Browser \d+\.\d+\.\d+ — SHA-256 checksums$/m;
if (!title.test(head)) fail('cannot find the title line');
head = head.replace(title, `HidraNet Browser ${VERSION} — SHA-256 checksums`);
const record = (name, value) => {
  const line = new RegExp(`^(  ${name}:[ \\t]+)\\S+[ \\t]*$`, 'm');
  if (!line.test(head)) fail('cannot find the record line ' + name);
  head = head.replace(line, (_, lead) => lead + value);
};
record('latest-version', VERSION);
if (minimum !== null) record('minimum-safe-version', minimum);
record('valid-until', validUntil);
const floor = /^  minimum-safe-version:[ \t]+(\S+)/m.exec(head);
if (!floor || !parseVersion(floor[1]) || compareVersions(floor[1], VERSION) > 0) {
  fail('the record\'s minimum-safe-version must be X.Y.Z and not above ' + VERSION + ' (use --minimum)');
}

const before = fs.readFileSync(SUMS, 'utf8');
fs.writeFileSync(SUMS, head + tail);

console.log(`  rewrote ${changed} row(s) in ${path.relative(ROOT, SUMS)}`);
for (const f of facts) console.log(`  ${f.sha}  ${f.name}`);
console.log(`  record: latest-version ${VERSION}, minimum-safe-version ${floor[1]}, valid-until ${validUntil}`);
// Prose about another version's packages is not rewritten: it may still be
// true of copies people have, but whoever signs the table must read it first.
for (const m of (head + tail).matchAll(/^KNOWN PROBLEMS WITH THE (\d+\.\d+\.\d+) PACKAGES$/gm)) {
  if (m[1] !== VERSION) {
    console.log('\n  The table still has a section "' + m[0] + '". It is not about the ' + VERSION + ' packages');
    console.log('  listed now: read it, and change or remove it, before signing the table.');
  }
}
if (fs.existsSync(SUMS + '.sig') && before !== head + tail) {
  console.log('\n  The table changed, so ' + path.basename(SUMS) + '.sig no longer matches it. Sign it again');
  console.log('  offline (hidra-browser/scripts/sign-sums.ps1) before publishing; CI refuses it until then.');
}
