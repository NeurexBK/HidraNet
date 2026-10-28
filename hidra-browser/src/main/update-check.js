// Is there a newer HidraNet Browser than this one? A notice, never an update.
//
// The maintainers publish landing/SHA256SUMS.txt, the table of the packages'
// hashes, and sign it offline with the release key (scripts/sign-sums.ps1);
// the signature sits beside it as SHA256SUMS.txt.sig. Near its top the table
// names three things the browser reads:
//
//   latest-version:        the build on the download page
//   minimum-safe-version:  anything older has known security problems
//   valid-until:           the last day the record may be believed
//
// Once Tor is carrying the traffic, main.js fetches both files through it and
// this module decides. The page is told "a newer build exists" or "this build
// is below the minimum"; nothing is ever downloaded or installed, and the
// person goes to the site and checks the file themselves.
//
// The key that checks the record is the one built into this browser
// (release-verify.js), so whoever can change the site cannot make a record
// this browser believes, and cannot hide a fix from it for longer than the
// last record they replay stays valid. A record that does not verify, does
// not parse or has expired is set aside without a notice. A table with no
// signature yet is how things stand until the maintainers sign one, so that
// shows nothing either, not even an error.

'use strict';

const releaseVerify = require('./release-verify');

const SUMS_URL = 'https://hidranet.org/SHA256SUMS.txt';
// The table is a few kilobytes; a signature is 88 characters of base64.
const SUMS_MAX_BYTES = 256 * 1024;
const SIG_MAX_BYTES = 4096;

const VERSION_RE = /^(\d{1,4})\.(\d{1,4})\.(\d{1,4})$/;

function parseVersion(v) {
  const m = VERSION_RE.exec(String(v || ''));
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

// Negative when a < b, zero when equal, positive when a > b. Both must parse.
function compareVersions(a, b) {
  const x = parseVersion(a);
  const y = parseVersion(b);
  if (!x || !y) throw new Error('not a version: ' + (x ? b : a));
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
}

// The one line `  name:   value` of the record, or an error if there is not
// exactly one.
function field(text, name) {
  const re = new RegExp('^  ' + name + ':[ \\t]+(\\S+)[ \\t]*$', 'gm');
  const found = [...text.matchAll(re)];
  if (found.length !== 1) throw new Error(found.length ? name + ' appears more than once' : 'no ' + name);
  return found[0][1];
}

// The record inside the table, checked for being complete and consistent.
// Throws with the reason when it is not.
function parseRecord(text) {
  text = String(text).replace(/\r\n/g, '\n');
  const latest = field(text, 'latest-version');
  const minimum = field(text, 'minimum-safe-version');
  const validUntil = field(text, 'valid-until');
  if (!parseVersion(latest)) throw new Error('latest-version is not X.Y.Z');
  if (!parseVersion(minimum)) throw new Error('minimum-safe-version is not X.Y.Z');
  if (compareVersions(minimum, latest) > 0) throw new Error('minimum-safe-version is above latest-version');
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(validUntil);
  const day = m && new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
  if (!day || day.toISOString().slice(0, 10) !== validUntil) throw new Error('valid-until is not a date (YYYY-MM-DD)');
  // The version it calls the latest is the one the table lists.
  const listed = new RegExp('^[0-9a-f]{64}  HidraNet-Browser-' + latest.replace(/\./g, '\\.') + '-[A-Za-z0-9-]+\\.zip$', 'm');
  if (!listed.test(text)) throw new Error('the table lists no package of ' + latest);
  // Believed through the end of that day, UTC.
  return { latest, minimum, validUntil, expires: day.getTime() + 24 * 60 * 60 * 1000 };
}

// What the browser makes of a table, its signature and its own version.
//
//   { state: 'no-signature' }                       nothing signed yet
//   { state: 'invalid', reason }                    set aside, no notice
//   { state: 'expired', validUntil }                set aside, no notice
//   { state: 'current', latest, minimum }           nothing to say
//   { state: 'update', current, latest, minimum, unsafe }
//
// `unsafe` is true when this build is below the minimum safe version.
function evaluate({ table, signature, currentVersion, now = Date.now(), publicKey = releaseVerify.RELEASE_PUBLIC_KEY }) {
  if (signature === null || signature === undefined) return { state: 'no-signature' };
  const bytes = Buffer.isBuffer(table) ? table : Buffer.from(String(table || ''), 'utf8');
  if (!publicKey) return { state: 'invalid', reason: 'this build carries no release key' };
  if (!releaseVerify.verifyBrowserSums(bytes, String(signature), publicKey)) {
    return { state: 'invalid', reason: 'the signature does not match the table or was not made with the release key' };
  }
  let record;
  try {
    record = parseRecord(bytes.toString('utf8'));
  } catch (e) {
    return { state: 'invalid', reason: 'the signed table has no usable record: ' + e.message };
  }
  if (now >= record.expires) return { state: 'expired', validUntil: record.validUntil };
  if (!parseVersion(currentVersion)) return { state: 'invalid', reason: 'this build has no version to compare' };
  const { latest, minimum } = record;
  const unsafe = compareVersions(currentVersion, minimum) < 0;
  if (unsafe || compareVersions(latest, currentVersion) > 0) {
    return { state: 'update', current: currentVersion, latest, minimum, unsafe };
  }
  return { state: 'current', latest, minimum };
}

// Runs the check when asked (main.js asks each time the network lock opens)
// and keeps the answer for the new tab page. An answer is kept for the
// session; only a failed fetch is tried again on the next connect.
class UpdateCheck {
  // fetchBytes(url, maxBytes) -> Buffer, through Tor; throws on failure, with
  // `status` set when the server answered with an HTTP error.
  constructor({ fetchBytes, currentVersion, url = SUMS_URL, publicKey, now = () => Date.now(), log = () => {} }) {
    this.fetchBytes = fetchBytes;
    this.currentVersion = currentVersion;
    this.url = url;
    this.publicKey = publicKey;
    this.now = now;
    this.log = log;
    this.result = null;
    this.running = null;
  }

  run() {
    if (this.result && this.result.state !== 'unreachable') return Promise.resolve(this.result);
    if (!this.running) {
      this.running = this.runOnce()
        .then((r) => { this.result = r; this.log(describe(r)); return r; })
        .finally(() => { this.running = null; });
    }
    return this.running;
  }

  async runOnce() {
    let signature;
    try {
      signature = (await this.fetchBytes(this.url + '.sig', SIG_MAX_BYTES)).toString('utf8');
    } catch (e) {
      // Not signed yet: no notice, and nothing to report to the person.
      if (e && e.status === 404) return { state: 'no-signature' };
      return { state: 'unreachable', reason: (e && e.message) || String(e) };
    }
    let table;
    try {
      table = await this.fetchBytes(this.url, SUMS_MAX_BYTES);
    } catch (e) {
      return { state: 'unreachable', reason: (e && e.message) || String(e) };
    }
    const options = { table, signature, currentVersion: this.currentVersion, now: this.now() };
    if (this.publicKey !== undefined) options.publicKey = this.publicKey;
    return evaluate(options);
  }

  // What the new tab page shows, or null for nothing.
  notice() {
    const r = this.result;
    if (!r || r.state !== 'update') return null;
    return { current: r.current, latest: r.latest, minimum: r.minimum, unsafe: r.unsafe };
  }
}

function describe(r) {
  switch (r.state) {
    case 'update': return `[update] ${r.latest} is available (this is ${r.current}${r.unsafe ? ', below the minimum safe ' + r.minimum : ''})`;
    case 'current': return `[update] up to date (latest ${r.latest})`;
    case 'no-signature': return '[update] the checksum table is not signed yet; no check made';
    case 'expired': return `[update] the signed record expired on ${r.validUntil}; ignored`;
    default: return `[update] ${r.state}: ${r.reason}`;
  }
}

module.exports = { SUMS_URL, SUMS_MAX_BYTES, SIG_MAX_BYTES, parseVersion, compareVersions, parseRecord, evaluate, UpdateCheck };
