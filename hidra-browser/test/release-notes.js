'use strict';

// Exercise the real CLI with package fixtures. A preview must not attribute
// existing packages to the notes commit or report that it published a build.
const assert = require('assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-release-notes-'));
const names = ['macOS-arm64', 'macOS-x64', 'Linux-x64', 'Windows-x64']
  .map(a => `HidraNet-Browser-1.0.0-${a}.zip`);
const script = path.join(__dirname, '..', 'scripts', 'release-notes.js');
const run = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });

try {
  for (const name of names) fs.writeFileSync(path.join(dir, name), `fixture for ${name}`);

  const preview = run(dir, '123456789abcdef', '--preview');
  assert.equal(preview.status, 0, preview.stderr);
  assert.match(preview.stdout, /^# Release notes preview/);
  assert.match(preview.stdout, /using notes from commit `1234567`/);
  assert.match(preview.stdout, /not a new build/);
  assert.doesNotMatch(preview.stdout, /Published \d{4}-\d{2}-\d{2}/);
  for (const name of names) {
    const sha = crypto.createHash('sha256').update(fs.readFileSync(path.join(dir, name))).digest('hex');
    assert.ok(preview.stdout.includes(`${sha}  ${name}`), `incorrect checksum for ${name}`);
  }

  const withoutCommit = run(dir, '--preview');
  assert.equal(withoutCommit.status, 0, withoutCommit.stderr);
  assert.doesNotMatch(withoutCommit.stdout, /commit `--previ/);

  const original = run(dir, '123456789abcdef');
  assert.equal(original.status, 0, original.stderr);
  assert.match(original.stdout, /Published \d{4}-\d{2}-\d{2} from commit `1234567`/);

  fs.unlinkSync(path.join(dir, names[0]));
  const missing = run(dir, '--preview');
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /missing:/);
  assert.equal(missing.stdout, '');
  console.log('ok: preview, checksums, legacy CLI and missing-package rejection');
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
