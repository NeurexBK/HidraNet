'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Reference: docs/release-base-provenance.md, run 39805862641 / commit 423f0ce.
// These pins detect changes to the legacy build inputs; they are not a code
// signature or an independent security audit of those binaries. Never refresh
// them automatically from the same release being downloaded. A mismatch needs
// investigation and a reviewed change with evidence of the replacement's origin.
const SHA256 = Object.freeze({
  'HidraNet-Browser-1.0.0-macOS-arm64.zip': '9c067cbdb0050a2e4b93f871065444fd7c2105ac5fa2291a18132ad2578f3dd8',
  'HidraNet-Browser-1.0.0-macOS-x64.zip': 'b85f2339e353823310b76e5912a1b8ff5d4f6a437849e2d97f95570e189c014a',
  'HidraNet-Browser-1.0.0-Linux-x64.zip': 'c1cce02007a6fa0eb1ad278c379244710dbf37f1e9522ea89ada24252ebb71bb',
  'HidraNet-Browser-1.0.0-Windows-x64.zip': 'd140f2fa40e978223e2a5c65021ac4ce6774a14b5e19a2cd6bdf72a1cf26af43',
});

function verifySha256(file, expected) {
  if (!/^[0-9a-f]{64}$/.test(expected || '')) {
    throw new Error('No valid pinned SHA-256 for ' + path.basename(file));
  }
  const actual = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  if (actual !== expected) {
    throw new Error('Release base SHA-256 mismatch for ' + path.basename(file) +
      '\n  expected: ' + expected + '\n  actual:   ' + actual +
      '\n  Stop and investigate the package origin; do not adopt its hash automatically.');
  }
  return actual;
}

function verifyReleaseBase(file) {
  return verifySha256(file, SHA256[path.basename(file)]);
}

module.exports = { SHA256, verifySha256, verifyReleaseBase };
