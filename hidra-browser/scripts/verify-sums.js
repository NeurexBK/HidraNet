#!/usr/bin/env node
/**
 * HidraNet — is landing/SHA256SUMS.txt signed, and does its record hold?
 *
 * Once the maintainers have signed the table (scripts/sign-sums.ps1) and
 * SHA256SUMS.txt.sig sits beside it, any change to the table must come with a
 * new signature made offline with the release key. CI runs this on every
 * change: it checks the signature exactly as the browser does
 * (release-verify.js, verifyBrowserSums: the release key, over the label and
 * the file), and the record the update notice reads (update-check.js).
 *
 * No .sig yet passes, with a note, unless --require-signature is given; CI
 * gives it when the commit before the change already had one, so deleting the
 * signature is not a way around it. A record that has expired, or soon will,
 * is reported but not refused: the browser ignores an expired record, so
 * the fix is to sign a renewed one, not to break unrelated changes.
 *
 * Usage:
 *   node scripts/verify-sums.js [--require-signature] [path/to/SHA256SUMS.txt]
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { verifyBrowserSums, RELEASE_PUBLIC_KEY } = require('../src/main/release-verify');
const { parseRecord, compareVersions } = require('../src/main/update-check');

const SOON = 30 * 24 * 60 * 60 * 1000;
const DEFAULT_SUMS = path.join(__dirname, '..', '..', 'landing', 'SHA256SUMS.txt');

/**
 * Checks the table at `file` and its .sig. Returns { ok, lines }, where
 * lines are what to print; `ok` false means refuse. `publicKey` defaults to
 * the key the browser embeds.
 */
function checkSums(file, { requireSignature = false, publicKey = RELEASE_PUBLIC_KEY, now = Date.now(), version } = {}) {
  const lines = [];
  const refuse = (msg) => { lines.push('  FAIL ' + msg); return { ok: false, lines }; };
  const name = path.basename(file);
  const table = fs.readFileSync(file);
  if (table.includes(Buffer.from('\r'))) {
    return refuse(name + ' has CR line endings; the signature is over the bytes as served, which are LF');
  }

  // The record is checked whether or not it is signed yet, so a table that
  // would not be usable once signed is caught on the change that broke it.
  let record;
  try {
    record = parseRecord(table.toString('utf8'));
  } catch (e) {
    return refuse(name + ': the record the browser reads is not usable: ' + e.message);
  }
  version = version || require(path.join(__dirname, '..', 'package.json')).version;
  if (compareVersions(version, record.latest) < 0) {
    return refuse('hidra-browser/package.json says ' + version + ', older than the published ' + record.latest +
                  ': a build must never go back to an earlier version');
  }
  lines.push('  record: latest ' + record.latest + ', minimum safe ' + record.minimum + ', valid until ' + record.validUntil);

  const sigFile = file + '.sig';
  if (!fs.existsSync(sigFile)) {
    if (requireSignature) return refuse(name + '.sig was there before this change and is gone: sign the table again');
    lines.push('  no ' + name + '.sig yet: nothing to verify (the browser shows no notice until there is)');
    return { ok: true, lines };
  }
  if (!publicKey) return refuse('release-verify.js carries no release key');
  if (!verifyBrowserSums(table, fs.readFileSync(sigFile, 'utf8'), publicKey)) {
    return refuse(name + ' changed without a new signature, or ' + name + '.sig' +
                  ' was not made with the release key over it.\n       Sign it again offline: hidra-browser/scripts/sign-sums.ps1');
  }
  lines.push('  ok   ' + name + '.sig is the release key\'s signature of ' + name);

  const left = record.expires - now;
  if (left <= 0) {
    lines.push('::warning::the signed record in ' + name + ' expired on ' + record.validUntil +
               '; browsers ignore it until a renewed one is signed');
  } else if (left < SOON) {
    lines.push('::warning::the signed record in ' + name + ' expires on ' + record.validUntil +
               '; sign a renewed one before then');
  }
  return { ok: true, lines };
}

module.exports = { checkSums };

if (require.main === module) {
  const args = process.argv.slice(2);
  const file = path.resolve(args.find((a) => !a.startsWith('--')) || DEFAULT_SUMS);
  const r = checkSums(file, { requireSignature: args.includes('--require-signature') });
  for (const l of r.lines) (r.ok ? console.log : console.error)(l);
  process.exit(r.ok ? 0 : 1);
}
