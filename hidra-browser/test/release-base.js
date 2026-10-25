'use strict';

const assert = require('assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { SHA256, verifySha256, verifyReleaseBase } = require('../scripts/lib/release-base');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-release-base-'));
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

try {
  const file = path.join(tmp, 'fixture.zip');
  const original = Buffer.from('known base package bytes');
  fs.writeFileSync(file, original);
  assert.equal(verifySha256(file, hash(original)), hash(original));
  fs.appendFileSync(file, 'tampered');
  assert.throws(() => verifySha256(file, hash(original)), /SHA-256 mismatch/);
  fs.writeFileSync(file, original.subarray(0, 4));
  assert.throws(() => verifySha256(file, hash(original)), /SHA-256 mismatch/);
  assert.throws(() => verifySha256(file, ''), /No valid pinned SHA-256/);
  assert.throws(() => verifyReleaseBase(file), /No valid pinned SHA-256/);
  assert.throws(() => verifySha256(path.join(tmp, 'missing.zip'), hash(original)), /ENOENT/);

  const table = fs.readFileSync(path.join(__dirname, '../../landing/SHA256SUMS.txt'), 'utf8');
  assert.equal(Object.keys(SHA256).length, 4);
  for (const [name, expected] of Object.entries(SHA256)) {
    assert.ok(table.includes(`${expected}  ${name}`), `baseline differs from tracked table: ${name}`);
    fs.writeFileSync(path.join(tmp, name), 'untrusted cached package');
    assert.throws(() => verifyReleaseBase(path.join(tmp, name)), /SHA-256 mismatch/);
  }

  // Exercise the actual command: bad cached inputs must abort before cargo,
  // archive parsing or patching, including when --engine is supplied.
  const script = path.join(__dirname, '../scripts/refresh-release.js');
  for (const flags of [[], ['--verify-inputs-only'], ['--engine', file]]) {
    const result = spawnSync(process.execPath, [script, '--in', tmp, ...flags], {
      encoding: 'utf8', timeout: 10000,
    });
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /Release base SHA-256 mismatch/);
    assert.doesNotMatch(result.stdout, /building the engine|patching|All checks passed/);
  }
  console.log('ok: valid bytes, tampering, truncation, unknown/missing inputs and CLI refusal before build');
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
