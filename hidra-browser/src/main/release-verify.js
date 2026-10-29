// Verifying what HidraVPN ships, before the browser trusts it.
//
// HidraVPN's release files are signed with Ed25519 by `hidravpn-sign`
// (hidravpn/crates/hidravpn-sign): beside each FILE there is a FILE.sig, the
// signature in base64. This module checks them with the release public key,
// and it is the same key, and the same format, the command line verifies with
// — so a file the browser accepts is a file `hidravpn-sign verify` accepts,
// and the other way round.
//
// The public key below is embedded in the browser on purpose: a signed node
// list, or a signed release, is only worth something if the key that checks it
// did not come from the same place as the file. It is printed once by
// `hidravpn-sign keygen` on an offline machine. The secret half never touches
// a build machine, a server or this repository.
//
// Until the founders have generated that key, the constant is empty — and with
// no key, nothing verifies. That is deliberate: a browser that accepted
// unsigned files "for now" would be a browser that accepts unsigned files.

'use strict';

const crypto = require('crypto');
const fs = require('fs');

// Base64 of the 32-byte Ed25519 public key, exactly as `hidravpn-sign keygen`
// printed it. Keep it identical to RELEASE_PUBLIC_KEY_B64 in
// hidravpn/crates/hidravpn-core/src/release.rs; a test checks the two match.
const RELEASE_PUBLIC_KEY = 'denZsjS2YtKOo4LRIGGTaKuHIWDFigChoLa71o0jBq8=';

// The DER prefix that turns a raw Ed25519 public key into the SPKI form
// Node's crypto wants: SEQUENCE { AlgorithmIdentifier(id-Ed25519), BIT STRING }.
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function publicKeyFromBase64(b64) {
  const raw = Buffer.from(String(b64 || '').trim(), 'base64');
  if (raw.length !== 32) throw new Error('an Ed25519 public key is 32 bytes');
  return crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

// True only when `signatureB64` is a valid signature of `data` by the key.
// Anything malformed is simply "not valid"; nothing here throws for bad input
// in the signature, because bad input is exactly what a verifier is for.
function verifyBytes(data, signatureB64, publicKeyB64) {
  let key;
  try {
    key = publicKeyFromBase64(publicKeyB64);
  } catch {
    return false;
  }
  const sig = Buffer.from(String(signatureB64 || '').trim(), 'base64');
  if (sig.length !== 64) return false;
  try {
    return crypto.verify(null, Buffer.isBuffer(data) ? data : Buffer.from(data), key, sig);
  } catch {
    return false;
  }
}

// The browser's checksum table (landing/SHA256SUMS.txt) is signed with the
// same release key, but never over its bare bytes: the signature covers this
// label, a zero byte, then the file. The key also signs HidraVPN's manifest
// and its own SHA256SUMS-hidravpn-*.txt over their bare bytes, so without the
// label a signature made for one could be presented as the other. With it, a
// signature of the browser table checks out as nothing else, and nothing else
// checks out as the browser table. scripts/sign-sums.ps1 adds the same label.
const BROWSER_SUMS_CONTEXT = Buffer.concat([Buffer.from('hidranet-browser-sums-v1', 'ascii'), Buffer.from([0])]);

// The bytes a signature of the browser's checksum table is made over.
function browserSumsMessage(data) {
  return Buffer.concat([BROWSER_SUMS_CONTEXT, Buffer.isBuffer(data) ? data : Buffer.from(data)]);
}

// True only when `signatureB64` is the release key's signature of the
// browser's checksum table `data`, label and all.
function verifyBrowserSums(data, signatureB64, publicKeyB64 = RELEASE_PUBLIC_KEY) {
  if (!publicKeyB64) return false;
  return verifyBytes(browserSumsMessage(data), signatureB64, publicKeyB64);
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Checks FILE against FILE.sig (or a given signature path) with the release
// key, or with a key passed explicitly. Never throws for the ordinary
// failures; the answer says which:
//
//   { ok: true,  sha256 }
//   { ok: false, reason: 'no-release-key' | 'no-signature' | 'unreadable' | 'bad-signature', detail }
async function verifyFile(filePath, options = {}) {
  const publicKey = options.publicKey !== undefined ? options.publicKey : RELEASE_PUBLIC_KEY;
  const sigPath = options.sigPath || filePath + '.sig';
  if (!publicKey) {
    return {
      ok: false,
      reason: 'no-release-key',
      detail: 'this build of the browser carries no release key, so it cannot verify anything; nothing is accepted',
    };
  }
  let data;
  let sig;
  try {
    data = await fs.promises.readFile(filePath);
  } catch (e) {
    return { ok: false, reason: 'unreadable', detail: `could not read ${filePath}: ${e.code || e.message}` };
  }
  try {
    sig = await fs.promises.readFile(sigPath, 'utf8');
  } catch (e) {
    return { ok: false, reason: 'no-signature', detail: `no signature at ${sigPath}: ${e.code || e.message}` };
  }
  if (!verifyBytes(data, sig, publicKey)) {
    return { ok: false, reason: 'bad-signature', detail: 'the signature does not match the file or was not made with the release key: do not use this file' };
  }
  return { ok: true, sha256: sha256Hex(data) };
}

module.exports = {
  RELEASE_PUBLIC_KEY, verifyBytes, verifyFile, sha256Hex, publicKeyFromBase64, SPKI_PREFIX,
  BROWSER_SUMS_CONTEXT, browserSumsMessage, verifyBrowserSums,
};
