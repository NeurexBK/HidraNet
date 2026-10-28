#!/usr/bin/env node
/**
 * HidraNet — compose the release page's description.
 *
 * The description on the v1.0.0 release page was one sentence, in Portuguese,
 * from June, and said nothing about what the packages now contain or how to
 * check them. It is written here from two parts: the notes kept in
 * .github/release-notes.md, which say what is in the build and how to run it,
 * and a table of the packages' hashes computed from the files given — the
 * ones on the release page, downloaded, or the ones a publish run uploaded —
 * so the table on the page is always the table of what the page serves.
 *
 * Usage:
 *   node scripts/release-notes.js <dir-with-the-zips> [commit-sha] [--preview] > notes.md
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..', '..');
const NOTES = path.join(ROOT, '.github', 'release-notes.md');

// Same order as landing/SHA256SUMS.txt.
const FILES = [
  'HidraNet-Browser-1.0.0-macOS-arm64.zip',
  'HidraNet-Browser-1.0.0-macOS-x64.zip',
  'HidraNet-Browser-1.0.0-Linux-x64.zip',
  'HidraNet-Browser-1.0.0-Windows-x64.zip',
];

const dir = process.argv[2];
if (!dir) {
  console.error('usage: release-notes.js <dir-with-the-zips> [commit-sha]');
  process.exit(1);
}
const preview = process.argv.includes('--preview');
const commit = (process.argv[3] === '--preview' ? '' : process.argv[3] || '').trim().slice(0, 7);

const rows = FILES.map((name) => {
  const file = path.join(dir, name);
  if (!fs.existsSync(file)) {
    console.error('  missing: ' + file);
    process.exit(1);
  }
  const bytes = fs.readFileSync(file);
  return {
    name,
    sha: crypto.createHash('sha256').update(bytes).digest('hex'),
    mib: (bytes.length / 1048576).toFixed(1),
  };
});

const date = new Date().toISOString().slice(0, 10);
const notes = fs.readFileSync(NOTES, 'utf8').trimEnd();

let out = preview ? '# Release notes preview\n\nThis document is a preview only; this run did not publish or replace any release assets.\n\n' : '';
out += notes + '\n\n## Packages\n\n';
if (preview) {
  out += `Preview generated ${date}${commit ? ` using notes from commit \`${commit}\`` : ''}. `;
  out += 'The hashes below describe the downloaded public packages, not a new build.\n\n';
} else {
  out += `Published ${date}${commit ? ` from commit \`${commit}\`` : ''}. `;
  out += 'The hashes below were computed from these exact files; the same table is in `landing/SHA256SUMS.txt`.\n\n';
}
out += '```\n';
for (const r of rows) out += `${r.sha}  ${r.name}  (${r.mib} MiB)\n`;
out += '```\n';

process.stdout.write(out);
