'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Reference: landing/SHA256SUMS.txt at b7e595efcb100ba59000703bb688c8e2111c3840.
// These pins detect changes to the legacy build inputs; they are not a code
// signature or an independent security audit of those binaries. Never refresh
// them automatically from the same release being downloaded. A mismatch needs
// investigation and a reviewed change with evidence of the replacement's origin.
const SHA256 = Object.freeze({
  'HidraNet-Browser-1.0.0-macOS-arm64.zip': 'fa0998beb47d833186c0b49703dd555a081393a6de15a6bdef77b7cc6db76a47',
  'HidraNet-Browser-1.0.0-macOS-x64.zip': '48f20cd6d38643991d2466a54893c3a6e8d8d940026f6292645395c3d1cd6cb9',
  'HidraNet-Browser-1.0.0-Linux-x64.zip': 'edefe4363d9c862d283e7f95086519d7e5ee48f8a564902ae642a8c817a5405b',
  'HidraNet-Browser-1.0.0-Windows-x64.zip': 'f33c386a919b3fc8e6ebcc0207e281674d79b846b2e126020064c0026695386a',
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
