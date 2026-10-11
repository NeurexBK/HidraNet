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
 * So the table is generated from the files that are actually going out.
 *
 * Usage:
 *   node scripts/update-sums.js <dir-with-the-four-zips> [commit-sha]
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const VERSION = '1.0.0';
const ROOT = path.join(__dirname, '..', '..');
const SUMS = path.join(ROOT, 'landing', 'SHA256SUMS.txt');

// The order the table lists them in, which is not the order they were built.
const ROWS = [
  ['macOS-arm64', 'macOS arm64'],
  ['macOS-x64', 'macOS x64'],
  ['Linux-x64', 'Linux x64'],
  ['Windows-x64', 'Windows x64'],
];

const dir = process.argv[2];
if (!dir) {
  console.error('usage: update-sums.js <dir-with-the-four-zips> [commit-sha]');
  process.exit(1);
}
const commit = (process.argv[3] || '').trim().slice(0, 7);

// ── Read what is actually there ───────────────────────────────────────────

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
  };
});

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

let changed = 0;
for (const f of facts) {
  // The hash line: 64 hex, two spaces, the file name.
  const hashLine = new RegExp(`^[0-9a-f]{64}  ${f.name.replace(/\./g, '\\.')}$`, 'm');
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

if (commit) {
  const commitLine = /Built from commit [0-9a-f]{7,40}\./;
  if (commitLine.test(head)) head = head.replace(commitLine, `Built from commit ${commit}.`);
}

fs.writeFileSync(SUMS, head + tail);

console.log(`  rewrote ${changed} row(s) in landing/SHA256SUMS.txt`);
for (const f of facts) console.log(`  ${f.sha}  ${f.name}`);
