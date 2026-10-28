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
// this module decides. The page is told "a newer build exists", "this build
// is below the minimum" or "this could not be confirmed"; nothing is ever
// downloaded or installed, and the person goes to the site and checks the
// file themselves.
//
// The key that checks the record is the one built into this browser
// (release-verify.js), so whoever can change the site cannot make a record
// this browser believes. They can still take the record away, or serve one
// that does not verify, has expired or is older than one this browser has
// seen. Two things keep that from passing silently:
//
//   - the highest versions and the latest valid-until this browser has
//     verified are kept in its data folder, and a record with lower versions
//     is set aside: the last record seen holds until its own valid-until,
//     and no longer
//   - with no record to go by after that, the page says it could not confirm
//     this browser is up to date, and to check the site
//
// The one exception is a table with no signature at all, in a build made
// before the maintainers first signed one (SUMS_SIGNED below) that has never
// verified a record: that is simply how things stood, and shows nothing.

'use strict';

const fs = require('fs');
const path = require('path');
const releaseVerify = require('./release-verify');

const SUMS_URL = 'https://hidranet.org/SHA256SUMS.txt';
// The table is a few kilobytes; a signature is 88 characters of base64.
const SUMS_MAX_BYTES = 256 * 1024;
const SIG_MAX_BYTES = 4096;

// Whether the checksum table was already signed when this build was made.
// A build made before the first signature cannot tell "not signed yet" from
// "the signature was taken away", so a missing one shows nothing; a build
// made after it knows there must be one. scripts/verify-sums.js refuses a
// signed table while this still says false, so the release that follows the
// first signature carries true.
const SUMS_SIGNED = false;

// Where this browser keeps the most it has verified, in its data folder.
const STATE_FILE = 'hidranet-update.json';

const VERSION_RE = /^(\d{1,4})\.(\d{1,4})\.(\d{1,4})$/;
const DAY = 24 * 60 * 60 * 1000;

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
const higher = (a, b) => (compareVersions(a, b) >= 0 ? a : b);

// When a valid-until day ends (it is believed through that day, UTC), or
// null when it is not a real YYYY-MM-DD date.
function endOfDay(validUntil) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(validUntil || ''));
  const day = m && new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
  if (!day || day.toISOString().slice(0, 10) !== validUntil) return null;
  return day.getTime() + DAY;
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
  const expires = endOfDay(validUntil);
  if (expires === null) throw new Error('valid-until is not a date (YYYY-MM-DD)');
  // The version it calls the latest is the one the table lists.
  const listed = new RegExp('^[0-9a-f]{64}  HidraNet-Browser-' + latest.replace(/\./g, '\\.') + '-[A-Za-z0-9-]+\\.zip$', 'm');
  if (!listed.test(text)) throw new Error('the table lists no package of ' + latest);
  return { latest, minimum, validUntil, expires };
}

// What a record says about this build: an update (marked unsafe below the
// minimum), or nothing to say.
function decide(record, currentVersion) {
  const { latest, minimum } = record;
  const unsafe = compareVersions(currentVersion, minimum) < 0;
  if (unsafe || compareVersions(latest, currentVersion) > 0) {
    return { state: 'update', current: currentVersion, latest, minimum, unsafe };
  }
  return { state: 'current', latest, minimum };
}

// What the browser makes of a table, its signature and its own version.
//
//   { state: 'no-signature' }                       nothing signed (yet)
//   { state: 'invalid', reason }                    set aside
//   { state: 'stale', latest, minimum }             set aside: older than `saved`
//   { state: 'expired', validUntil }                set aside
//   { state: 'current', latest, minimum, record }   nothing to say
//   { state: 'update', current, latest, minimum, unsafe, record }
//
// `unsafe` is true when this build is below the minimum safe version.
// `saved` is the most this browser has verified before (readSaved): a
// record whose versions are below it is one an attacker replays.
function evaluate({ table, signature, currentVersion, now = Date.now(), publicKey = releaseVerify.RELEASE_PUBLIC_KEY, saved = null }) {
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
  // Versions only go up. A genuine record with lower ones is an old one
  // served again, to hide what the newer one says.
  if (saved && (compareVersions(record.latest, saved.latest) < 0 || compareVersions(record.minimum, saved.minimum) < 0)) {
    return { state: 'stale', latest: record.latest, minimum: record.minimum };
  }
  if (now >= record.expires) return { state: 'expired', validUntil: record.validUntil };
  if (!parseVersion(currentVersion)) return { state: 'invalid', reason: 'this build has no version to compare' };
  return { ...decide(record, currentVersion), record };
}

// The most this browser has verified, from its data folder: the highest
// latest-version and minimum-safe-version of any record, and the latest
// valid-until. Null when there is none, or it is not usable.
function readSaved(file) {
  try {
    const s = JSON.parse(fs.readFileSync(file, 'utf8'));
    const expires = endOfDay(s.validUntil);
    if (!parseVersion(s.latest) || !parseVersion(s.minimum) || compareVersions(s.minimum, s.latest) > 0 || expires === null) return null;
    return { latest: s.latest, minimum: s.minimum, validUntil: s.validUntil, expires };
  } catch (e) {
    return null;
  }
}

// `saved` raised by a verified `record`: never lowered.
function merge(saved, record) {
  if (!saved) return { latest: record.latest, minimum: record.minimum, validUntil: record.validUntil, expires: record.expires };
  const later = record.expires > saved.expires ? record : saved;
  return {
    latest: higher(record.latest, saved.latest),
    minimum: higher(record.minimum, saved.minimum),
    validUntil: later.validUntil,
    expires: later.expires,
  };
}

// Written whole and then renamed into place, so a crash leaves the old file
// or the new one, never half of one.
function writeSaved(file, s) {
  const tmp = file + '.tmp';
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(tmp, JSON.stringify({ latest: s.latest, minimum: s.minimum, validUntil: s.validUntil }) + '\n');
  fs.renameSync(tmp, file);
}

// Runs the check when asked (main.js asks each time the network lock opens)
// and keeps the answer for the new tab page. An answer is kept for the
// session; only a failed fetch is tried again on the next connect.
class UpdateCheck {
  // fetchBytes(url, maxBytes) -> Buffer, through Tor; throws on failure, with
  // `status` set when the server answered with an HTTP error. stateFile:
  // where the most this browser has verified is kept (null keeps nothing).
  // signedBuild: SUMS_SIGNED, unless a test says otherwise.
  constructor({ fetchBytes, currentVersion, url = SUMS_URL, publicKey, now = () => Date.now(), log = () => {},
                stateFile = null, signedBuild = SUMS_SIGNED }) {
    this.fetchBytes = fetchBytes;
    this.currentVersion = currentVersion;
    this.url = url;
    this.publicKey = publicKey;
    this.now = now;
    this.log = log;
    this.stateFile = stateFile;
    this.signedBuild = signedBuild;
    this.saved = stateFile ? readSaved(stateFile) : null;
    this.result = null;
    this.running = null;
  }

  run() {
    if (this.result && this.result.state !== 'unreachable') return Promise.resolve(this.result);
    if (!this.running) {
      this.running = this.runOnce()
        .then((r) => { this.result = r; this.keep(r); this.log(describe(r)); return r; })
        .finally(() => { this.running = null; });
    }
    return this.running;
  }

  async runOnce() {
    let signature;
    try {
      signature = (await this.fetchBytes(this.url + '.sig', SIG_MAX_BYTES)).toString('utf8');
    } catch (e) {
      if (e && e.status === 404) return { state: 'no-signature' };
      return { state: 'unreachable', reason: (e && e.message) || String(e) };
    }
    let table;
    try {
      table = await this.fetchBytes(this.url, SUMS_MAX_BYTES);
    } catch (e) {
      return { state: 'unreachable', reason: (e && e.message) || String(e) };
    }
    const options = { table, signature, currentVersion: this.currentVersion, now: this.now(), saved: this.saved };
    if (this.publicKey !== undefined) options.publicKey = this.publicKey;
    return evaluate(options);
  }

  // A verified record raises what is kept. Failing to write it costs only
  // the memory of it after a restart.
  keep(r) {
    if (!r.record) return;
    const next = merge(this.saved, r.record);
    const same = this.saved && next.latest === this.saved.latest && next.minimum === this.saved.minimum &&
                 next.validUntil === this.saved.validUntil;
    this.saved = next;
    if (same || !this.stateFile) return;
    try { writeSaved(this.stateFile, next); } catch (e) { this.log('[update] could not keep the record: ' + e.message); }
  }

  // What the new tab page shows, or null for nothing:
  //   { state: 'update', current, latest, minimum, unsafe }
  //   { state: 'unconfirmed' }   no record to go by; check the site
  notice() {
    const r = this.result;
    const update = (d) => (d.state === 'update'
      ? { state: 'update', current: d.current, latest: d.latest, minimum: d.minimum, unsafe: d.unsafe } : null);
    if (r && (r.state === 'update' || r.state === 'current')) return update(r);
    // Nothing usable from the site, or not asked yet: the last record this
    // browser verified holds until its valid-until.
    if (this.saved && this.now() < this.saved.expires && parseVersion(this.currentVersion)) {
      return update(decide(this.saved, this.currentVersion));
    }
    if (!r) return null;
    // A missing signature, or a site that does not answer, is only a reason
    // to doubt in a build that knows the table is signed, or once this
    // browser has verified a record. Anything else that came back is.
    if ((r.state === 'no-signature' || r.state === 'unreachable') && !this.signedBuild && !this.saved) return null;
    return { state: 'unconfirmed' };
  }
}

function describe(r) {
  switch (r.state) {
    case 'update': return `[update] ${r.latest} is available (this is ${r.current}${r.unsafe ? ', below the minimum safe ' + r.minimum : ''})`;
    case 'current': return `[update] up to date (latest ${r.latest})`;
    case 'no-signature': return '[update] the checksum table has no signature; no record to go by';
    case 'expired': return `[update] the signed record expired on ${r.validUntil}; ignored`;
    case 'stale': return `[update] a signed record older than one already seen (latest ${r.latest}); ignored`;
    default: return `[update] ${r.state}: ${r.reason}`;
  }
}

module.exports = {
  SUMS_URL, SUMS_MAX_BYTES, SIG_MAX_BYTES, SUMS_SIGNED, STATE_FILE,
  parseVersion, compareVersions, parseRecord, evaluate, readSaved, UpdateCheck,
};
