// The update notice believes only a signed, current record, and says only
// what the record says.
//
// landing/SHA256SUMS.txt carries a small record (latest version, minimum safe
// version, valid until) that the browser reads through Tor once the network
// lock opens (src/main/update-check.js). This checks the decision: below the
// minimum shows the notice as a security problem, a newer build shows it as
// an update, a record that does not verify, does not parse, has expired or is
// older than one already verified is set aside and the page says it cannot
// confirm the build is current, the last verified record is kept across
// restarts and holds until its own valid-until, and a table with no signature
// yet shows nothing at all in a build from before the first signature. It
// also checks the CI gate on the table (scripts/verify-sums.js) and the writer
// of the table (scripts/update-sums.js), which must never give a published
// version other files nor list a package that runs another Electron or Tor.
// No network.
//
//   node hidra-browser/test/update-check.js

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const rv = require('../src/main/release-verify');
const uc = require('../src/main/update-check');
const { checkSums } = require('../scripts/verify-sums');

let passed = 0, failed = 0;
async function check(name, fn) {
  try { await fn(); passed++; console.log('ok    ' + name); } catch (e) { failed++; console.log('FAIL  ' + name + '\n      ' + ((e && e.stack) || e)); }
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-update-'));
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const pub = publicKey.export({ format: 'der', type: 'spki' }).slice(-32).toString('base64');
const sign = (bytes) => crypto.sign(null, rv.browserSumsMessage(bytes), privateKey).toString('base64');

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.UTC(2026, 9, 28, 12);
function table({ latest = '1.2.0', minimum = '1.1.0', validUntil = '2027-01-31', listed = latest, extra = '' } = {}) {
  return Buffer.from([
    'HidraNet Browser ' + latest + ' — SHA-256 checksums',
    '',
    'SIGNED RECORD',
    '  latest-version:        ' + latest,
    '  minimum-safe-version:  ' + minimum,
    '  valid-until:           ' + validUntil,
    extra,
    '',
    'a'.repeat(64) + '  HidraNet-Browser-' + listed + '-Linux-x64.zip',
    '',
  ].join('\n'));
}
const decide = (t, current, opts = {}) => {
  const r = uc.evaluate({ table: t, signature: 'signature' in opts ? opts.signature : sign(t), currentVersion: current,
                          now: opts.now || NOW, publicKey: pub, saved: opts.saved || null });
  delete r.record;
  return r;
};

(async () => {
  // ── The decision ────────────────────────────────────────────────────────
  await check('below the minimum safe version: the notice, marked unsafe', async () => {
    const r = decide(table(), '1.0.0');
    assert.deepStrictEqual(r, { state: 'update', current: '1.0.0', latest: '1.2.0', minimum: '1.1.0', unsafe: true });
  });
  await check('above the minimum but older than the latest: the notice, as an update', async () => {
    const r = decide(table(), '1.1.0');
    assert.strictEqual(r.state, 'update');
    assert.strictEqual(r.unsafe, false);
    assert.strictEqual(decide(table(), '1.1.9').unsafe, false);
  });
  await check('the latest, or newer (a build not yet published): nothing to say', async () => {
    assert.strictEqual(decide(table(), '1.2.0').state, 'current');
    assert.strictEqual(decide(table(), '1.3.0').state, 'current');
  });
  await check('versions compare as numbers, not as text', async () => {
    assert.strictEqual(decide(table({ latest: '1.10.0', minimum: '1.9.0' }), '1.9.0').state, 'update');
    assert.strictEqual(decide(table({ latest: '1.10.0', minimum: '1.10.0' }), '1.9.0').unsafe, true);
    assert.strictEqual(decide(table({ latest: '1.10.0', minimum: '1.2.0' }), '1.10.0').state, 'current');
  });

  await check('an expired record is rejected, even one that would say "unsafe"', async () => {
    const t = table({ validUntil: '2026-10-27' });
    assert.deepStrictEqual(decide(t, '1.0.0'), { state: 'expired', validUntil: '2026-10-27' });
    // Valid through the last day, UTC.
    assert.strictEqual(decide(table({ validUntil: '2026-10-28' }), '1.0.0').state, 'update');
    assert.strictEqual(decide(table({ validUntil: '2026-10-28' }), '1.0.0', { now: Date.UTC(2026, 9, 29) }).state, 'expired');
  });

  await check('an invalid signature is rejected: changed byte, other key, bare-bytes signature, garbage', async () => {
    const t = table();
    const changed = Buffer.from(t); changed[changed.indexOf('1.1.0')] = '0'.charCodeAt(0);
    assert.strictEqual(decide(changed, '1.0.0', { signature: sign(t) }).state, 'invalid');
    const other = crypto.generateKeyPairSync('ed25519').privateKey;
    assert.strictEqual(decide(t, '1.0.0', { signature: crypto.sign(null, rv.browserSumsMessage(t), other).toString('base64') }).state, 'invalid');
    assert.strictEqual(decide(t, '1.0.0', { signature: crypto.sign(null, t, privateKey).toString('base64') }).state, 'invalid');
    assert.strictEqual(decide(t, '1.0.0', { signature: 'not a signature' }).state, 'invalid');
    assert.strictEqual(decide(t, '1.0.0', { signature: '' }).state, 'invalid');
  });

  await check('the embedded release key does not accept a test signature', async () => {
    const t = table();
    assert.strictEqual(uc.evaluate({ table: t, signature: sign(t), currentVersion: '1.0.0', now: NOW }).state, 'invalid');
  });

  await check('a signed record that does not hold together is rejected', async () => {
    const bad = {
      'no minimum': Buffer.from(table().toString().replace(/^  minimum-safe-version:.*$/m, '')),
      'two latest lines': table({ extra: '  latest-version:        9.9.9' }),
      'minimum above latest': table({ latest: '1.2.0', minimum: '1.3.0' }),
      'not a version': table({ latest: '1.2', listed: '1.2' }),
      'not a date': table({ validUntil: '2027-02-30' }),
      'latest not in the table': table({ latest: '1.2.0', listed: '1.1.0' }),
    };
    for (const [why, t] of Object.entries(bad)) {
      const r = decide(t, '1.0.0');
      assert.strictEqual(r.state, 'invalid', why + ': ' + JSON.stringify(r));
    }
  });

  await check('no signature at all: no notice and no error', async () => {
    assert.deepStrictEqual(decide(table(), '1.0.0', { signature: null }), { state: 'no-signature' });
  });

  await check('a genuine record older than one already verified is rejected as stale', async () => {
    const saved = { latest: '1.3.0', minimum: '1.2.0', validUntil: '2027-02-28' };
    assert.deepStrictEqual(decide(table(), '1.0.0', { saved }), { state: 'stale', latest: '1.2.0', minimum: '1.1.0' });
    assert.strictEqual(decide(table({ latest: '1.3.0', minimum: '1.1.0' }), '1.0.0', { saved }).state, 'stale');
    // Same versions, or higher: believed, whatever its valid-until.
    assert.strictEqual(decide(table({ latest: '1.3.0', minimum: '1.2.0', validUntil: '2026-12-01' }), '1.0.0', { saved }).state, 'update');
    assert.strictEqual(decide(table({ latest: '1.4.0', minimum: '1.2.0' }), '1.4.0', { saved }).state, 'current');
  });

  // ── The check as main.js runs it ────────────────────────────────────────
  const served = (files) => {
    const asked = [];
    const fetchBytes = async (url, max) => {
      asked.push([url, max]);
      const f = files[url];
      if (f instanceof Error) throw f;
      if (f === undefined) throw Object.assign(new Error(url + ': 404'), { status: 404 });
      return Buffer.from(f);
    };
    return { asked, fetchBytes };
  };

  await check('a 404 for the .sig, in a build from before the first signature: no notice, no error, no table fetched', async () => {
    const s = served({ [uc.SUMS_URL]: table() });
    const u = new uc.UpdateCheck({ fetchBytes: s.fetchBytes, currentVersion: '1.0.0', publicKey: pub, now: () => NOW, signedBuild: false });
    assert.strictEqual((await u.run()).state, 'no-signature');
    assert.strictEqual(u.notice(), null);
    assert.deepStrictEqual(s.asked.map((a) => a[0]), [uc.SUMS_URL + '.sig']);
  });
  await check('… but in a build made after it, a missing signature says it cannot confirm', async () => {
    const s = served({ [uc.SUMS_URL]: table() });
    const u = new uc.UpdateCheck({ fetchBytes: s.fetchBytes, currentVersion: '1.0.0', publicKey: pub, now: () => NOW, signedBuild: true });
    assert.strictEqual((await u.run()).state, 'no-signature');
    assert.deepStrictEqual(u.notice(), { state: 'unconfirmed' });
  });
  await check('this tree says the table is not signed yet, and must say so until it is', async () => {
    const signed = fs.existsSync(path.join(ROOT, '..', 'landing', 'SHA256SUMS.txt.sig'));
    assert.strictEqual(uc.SUMS_SIGNED, signed, 'SUMS_SIGNED does not match whether landing/SHA256SUMS.txt.sig exists');
  });

  await check('a signed record names a newer build: the notice, with the sizes capped', async () => {
    const t = table();
    const s = served({ [uc.SUMS_URL]: t, [uc.SUMS_URL + '.sig']: sign(t) + '\n' });
    const u = new uc.UpdateCheck({ fetchBytes: s.fetchBytes, currentVersion: '1.0.0', publicKey: pub, now: () => NOW });
    await u.run();
    assert.deepStrictEqual(u.notice(), { state: 'update', current: '1.0.0', latest: '1.2.0', minimum: '1.1.0', unsafe: true });
    assert.deepStrictEqual(s.asked, [[uc.SUMS_URL + '.sig', uc.SIG_MAX_BYTES], [uc.SUMS_URL, uc.SUMS_MAX_BYTES]]);
    assert.strictEqual(uc.SUMS_URL, 'https://hidranet.org/SHA256SUMS.txt');
  });

  await check('an expired or forged record is rejected, and the page says it cannot confirm, in any build', async () => {
    for (const signedBuild of [false, true]) {
      for (const [t, sig] of [[table({ validUntil: '2026-01-01' }), null], [table(), 'x'.repeat(88)]]) {
        const s = served({ [uc.SUMS_URL]: t, [uc.SUMS_URL + '.sig']: sig || sign(t) });
        const u = new uc.UpdateCheck({ fetchBytes: s.fetchBytes, currentVersion: '1.0.0', publicKey: pub, now: () => NOW, signedBuild });
        const r = await u.run();
        assert.ok(r.state === 'expired' || r.state === 'invalid', JSON.stringify(r));
        assert.deepStrictEqual(u.notice(), { state: 'unconfirmed' });
      }
    }
  });

  // ── What it keeps ───────────────────────────────────────────────────────
  await check('the record verified is kept, and a site serving an older one later is caught, also after a restart', async () => {
    const stateFile = path.join(tmp, 'state', uc.STATE_FILE);
    const newer = table({ latest: '1.3.0', minimum: '1.2.0', validUntil: '2027-03-31' });
    const older = table({ latest: '1.2.0', minimum: '1.0.0', validUntil: '2027-04-30' });
    const opts = (files, extra = {}) => ({ fetchBytes: served(files).fetchBytes, currentVersion: '1.1.0', publicKey: pub,
      now: () => NOW, stateFile, signedBuild: false, ...extra });
    const first = new uc.UpdateCheck(opts({ [uc.SUMS_URL]: newer, [uc.SUMS_URL + '.sig']: sign(newer) }));
    await first.run();
    assert.deepStrictEqual(JSON.parse(fs.readFileSync(stateFile, 'utf8')), { latest: '1.3.0', minimum: '1.2.0', validUntil: '2027-03-31' });
    const warning = { state: 'update', current: '1.1.0', latest: '1.3.0', minimum: '1.2.0', unsafe: true };
    assert.deepStrictEqual(first.notice(), warning);

    // A restart, and the site replays the older record, still valid and
    // signed: set aside, and what was kept still says unsafe.
    const replay = new uc.UpdateCheck(opts({ [uc.SUMS_URL]: older, [uc.SUMS_URL + '.sig']: sign(older) }));
    assert.deepStrictEqual(replay.notice(), warning, 'what was kept is not shown before the check');
    assert.strictEqual((await replay.run()).state, 'stale');
    assert.deepStrictEqual(replay.notice(), warning);
    assert.strictEqual(JSON.parse(fs.readFileSync(stateFile, 'utf8')).latest, '1.3.0', 'the kept record went down');

    // The site takes the signature away: the same, in a build from before
    // the first signature too, because this browser has seen one.
    const gone = new uc.UpdateCheck(opts({ [uc.SUMS_URL]: older }));
    assert.strictEqual((await gone.run()).state, 'no-signature');
    assert.deepStrictEqual(gone.notice(), warning);

    // Once what was kept has expired, nothing the site serves is believed
    // and the page says it cannot confirm.
    const later = Date.UTC(2027, 3, 1, 12);
    const after = new uc.UpdateCheck(opts({ [uc.SUMS_URL]: older }, { now: () => later }));
    await after.run();
    assert.deepStrictEqual(after.notice(), { state: 'unconfirmed' });
    const stale = new uc.UpdateCheck(opts({ [uc.SUMS_URL]: older, [uc.SUMS_URL + '.sig']: sign(older) }, { now: () => later }));
    assert.strictEqual((await stale.run()).state, 'stale');
    assert.deepStrictEqual(stale.notice(), { state: 'unconfirmed' });
  });
  await check('what is kept only goes up, and a damaged file is ignored', async () => {
    const stateFile = path.join(tmp, 'state2', uc.STATE_FILE);
    const run = async (t, current = '1.3.0') => {
      const u = new uc.UpdateCheck({ fetchBytes: served({ [uc.SUMS_URL]: t, [uc.SUMS_URL + '.sig']: sign(t) }).fetchBytes,
        currentVersion: current, publicKey: pub, now: () => NOW, stateFile });
      await u.run();
      return JSON.parse(fs.readFileSync(stateFile, 'utf8'));
    };
    assert.deepStrictEqual(await run(table({ latest: '1.2.0', minimum: '1.1.0', validUntil: '2027-03-31' })),
      { latest: '1.2.0', minimum: '1.1.0', validUntil: '2027-03-31' });
    // A newer record with an earlier valid-until keeps the later date.
    assert.deepStrictEqual(await run(table({ latest: '1.3.0', minimum: '1.1.0', validUntil: '2027-01-31' })),
      { latest: '1.3.0', minimum: '1.1.0', validUntil: '2027-03-31' });
    for (const bad of ['not json', '{"latest":"1.3.0","minimum":"1.4.0","validUntil":"2027-01-01"}', '{"latest":"x"}']) {
      fs.writeFileSync(stateFile, bad);
      assert.strictEqual(uc.readSaved(stateFile), null, bad);
    }
    assert.strictEqual(uc.readSaved(path.join(tmp, 'nothing-here.json')), null);
  });

  await check('an unreachable site is tried again on the next connect; an answer is kept', async () => {
    const t = table();
    const files = { [uc.SUMS_URL + '.sig']: new Error('blocked until Tor is ready') };
    const s = served(files);
    const u = new uc.UpdateCheck({ fetchBytes: s.fetchBytes, currentVersion: '1.1.0', publicKey: pub, now: () => NOW, signedBuild: false });
    assert.strictEqual((await u.run()).state, 'unreachable');
    assert.strictEqual(u.notice(), null);
    u.signedBuild = true;
    assert.deepStrictEqual(u.notice(), { state: 'unconfirmed' }, 'a build made after the first signature says nothing');
    files[uc.SUMS_URL + '.sig'] = sign(t);
    files[uc.SUMS_URL] = t;
    assert.strictEqual((await u.run()).state, 'update');
    const before = s.asked.length;
    await u.run();
    assert.strictEqual(s.asked.length, before, 'asked again after an answer');
  });

  // ── Wired in where the audit trail says ─────────────────────────────────
  await check('main.js runs the check once the lock opens, through the Tor-only fetch, and hands the page the notice', async () => {
    const main = fs.readFileSync(path.join(ROOT, 'src', 'main', 'main.js'), 'utf8');
    assert.ok(/!networkLock\.release\(generation\)\) \{[\s\S]*?\n {2}\}\s*checkForUpdate\(\);/.test(main), 'checkForUpdate() does not follow a successful networkLock.release()');
    assert.ok(/new UpdateCheck\(\{\s*fetchBytes: fetchSmall,\s*currentVersion: app\.getVersion\(\)/.test(main), 'the check does not use fetchSmall and the app version');
    assert.ok(/stateFile: path\.join\(app\.getPath\('userData'\), UPDATE_STATE_FILE\)/.test(main), 'what was verified is not kept');
    assert.ok(/async function fetchSmall\(url, maxBytes\) \{\s*vpnFetchAllowed\(url\);/.test(main), 'fetchSmall does not refuse while the lock is closed');
    assert.ok(/update: updater\(\)\.notice\(\)/.test(main), 'apps:status does not carry the notice');
    assert.ok(!/autoUpdater|electron-updater|downloadURL|shell\.openExternal\(.*update/.test(main), 'something that installs or downloads updates');
    const page = fs.readFileSync(path.join(ROOT, 'src', 'ui', 'newtab.html'), 'utf8');
    assert.ok(/showUpdate\(status\.update\)/.test(page) && /id="update-notice"[^>]*hidden/.test(page), 'the new tab page does not show it');
    assert.ok(!/update-text'\)\.innerHTML|update-title'\)\.innerHTML/.test(page), 'the notice is written as HTML');
  });

  // ── The published table ─────────────────────────────────────────────────
  const SUMS = path.join(ROOT, '..', 'landing', 'SHA256SUMS.txt');
  const pkg = require('../package.json');
  await check('the published table has a usable record, and package.json is not behind it', async () => {
    const r = uc.parseRecord(fs.readFileSync(SUMS, 'utf8'));
    assert.ok(uc.compareVersions(pkg.version, r.latest) >= 0, pkg.version + ' < ' + r.latest);
    const r2 = checkSums(SUMS);
    assert.ok(r2.ok, r2.lines.join('\n'));
  });
  await check('the table says what a match proves, and no longer that it proves origin', async () => {
    const text = fs.readFileSync(SUMS, 'utf8');
    assert.ok(!/is the one we published/.test(text), 'still claims the checksum proves the file is the one we published');
    assert.ok(/same maintainers/.test(text) && /does not\s+prove who built the file/.test(text), 'the caveat is missing');
    assert.ok(/Electron 33\.4\.11/.test(text) && /Tor 15\.0\.22/.test(text), 'the 1.0.0 runtime is not disclosed');
  });

  // ── The CI gate ─────────────────────────────────────────────────────────
  const copy = path.join(tmp, 'SHA256SUMS.txt');
  await check('CI: unsigned passes, unless a signature was there before', async () => {
    fs.writeFileSync(copy, table({ latest: '1.1.0', minimum: '1.1.0' }));
    assert.strictEqual(checkSums(copy, { publicKey: pub, now: NOW, version: '1.1.0' }).ok, true);
    assert.strictEqual(checkSums(copy, { publicKey: pub, now: NOW, version: '1.1.0', requireSignature: true }).ok, false);
  });
  await check('CI: a signed table passes; changed after signing, or with SUMS_SIGNED still false, it is refused', async () => {
    const t = table({ latest: '1.1.0', minimum: '1.1.0' });
    fs.writeFileSync(copy, t);
    fs.writeFileSync(copy + '.sig', sign(t));
    const ok = checkSums(copy, { publicKey: pub, now: NOW, version: '1.1.0', requireSignature: true, signedBuild: true });
    assert.strictEqual(ok.ok, true, ok.lines.join('\n'));
    // Signed, while the browser's source still says it is not.
    const early = checkSums(copy, { publicKey: pub, now: NOW, version: '1.1.0', signedBuild: false });
    assert.strictEqual(early.ok, false);
    assert.ok(/SUMS_SIGNED .* still says false/.test(early.lines.join('\n')), early.lines.join('\n'));
    fs.writeFileSync(copy, Buffer.concat([t, Buffer.from('one more line\n')]));
    const r = checkSums(copy, { publicKey: pub, now: NOW, version: '1.1.0', signedBuild: true });
    assert.strictEqual(r.ok, false);
    assert.ok(/changed without a new signature/.test(r.lines.join('\n')));
    // The real key does not accept this test signature either.
    fs.writeFileSync(copy, t);
    assert.strictEqual(checkSums(copy, { now: NOW, version: '1.1.0' }).ok, false);
  });
  await check('CI: CRLF, an unusable record or a version going backwards is refused; expiry only warns', async () => {
    fs.rmSync(copy + '.sig', { force: true });
    fs.writeFileSync(copy, Buffer.from(table({ latest: '1.1.0', minimum: '1.1.0' }).toString().replace(/\n/g, '\r\n')));
    assert.strictEqual(checkSums(copy, { publicKey: pub, now: NOW, version: '1.1.0' }).ok, false);
    fs.writeFileSync(copy, table({ latest: '1.1.0', minimum: '1.2.0' }));
    assert.strictEqual(checkSums(copy, { publicKey: pub, now: NOW, version: '1.1.0' }).ok, false);
    fs.writeFileSync(copy, table({ latest: '1.2.0', minimum: '1.1.0' }));
    assert.strictEqual(checkSums(copy, { publicKey: pub, now: NOW, version: '1.1.0' }).ok, false);
    const t = table({ latest: '1.1.0', minimum: '1.1.0', validUntil: '2026-01-01' });
    fs.writeFileSync(copy, t);
    fs.writeFileSync(copy + '.sig', sign(t));
    const r = checkSums(copy, { publicKey: pub, now: NOW, version: '1.1.0', signedBuild: true });
    assert.strictEqual(r.ok, true, r.lines.join('\n'));
    assert.ok(/::warning::.*expired/.test(r.lines.join('\n')));
  });
  await check('CI: the command line exits non-zero on refusal', async () => {
    const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'verify-sums.js'), copy], { encoding: 'utf8' });
    assert.strictEqual(r.status, 1, r.stdout + r.stderr); // signed with the test key, not the release key
    fs.rmSync(copy + '.sig');
    const r2 = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'verify-sums.js'), '--require-signature', copy], { encoding: 'utf8' });
    assert.strictEqual(r2.status, 1);
    const r3 = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'verify-sums.js'), SUMS], { encoding: 'utf8' });
    assert.strictEqual(r3.status, 0, r3.stdout + r3.stderr);
  });

  // ── Writing the table ───────────────────────────────────────────────────
  // Stand-in packages that run what is pinned: the Electron and the Chromium
  // the repository names in the main binary, and a Tor whose pins the run
  // below swaps for these files' hashes (as test/release-runtime.js does).
  const rt = require('../scripts/lib/package-runtime');
  const { ELECTRON_VER } = require('../scripts/lib/electron');
  const { writeZip, mkFile } = require('../scripts/lib/zip');
  const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
  const engineOf = (e, c) => 'Mozilla/5.0 (%s) Chrome/' + c + ' Electron/' + e + ' Safari/537.36\0';
  const GOOD = engineOf(ELECTRON_VER, rt.advertisedChromeMajor() + '.0.7977.167');
  const TOR = { geoip: 'geoip data', geoip6: 'geoip6 data' };
  const torName = (a) => (/Windows/.test(a) ? 'tor.exe' : 'tor');
  const torBody = (a) => 'the tor we ship for ' + a;
  const pinsFor = {
    'macOS-arm64': 'darwin-arm64', 'macOS-x64': 'darwin-x64', 'Linux-x64': 'linux-x64', 'Windows-x64': 'win32-x64',
  };
  const fakePins = {};
  for (const [a, k] of Object.entries(pinsFor)) {
    fakePins[k] = { [torName(a)]: sha256(torBody(a)), geoip: sha256(TOR.geoip), geoip6: sha256(TOR.geoip6) };
  }
  function packageFor(a, { bin = GOOD, build = 'one' } = {}) {
    const mac = /macOS/.test(a);
    const res = mac ? 'HidraNet.app/Contents/Resources/' : 'resources/';
    const binary = mac ? 'HidraNet.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework'
      : /Windows/.test(a) ? 'HidraNet.exe' : 'hidranet';
    return writeZip([
      mkFile(binary, Buffer.from(bin)),
      mkFile(res + 'app/package.json', Buffer.from('{"build":"' + build + '"}')),
      mkFile(res + 'bin/tor/' + torName(a), Buffer.from(torBody(a))),
      mkFile(res + 'bin/tor/geoip', Buffer.from(TOR.geoip)),
      mkFile(res + 'bin/tor/geoip6', Buffer.from(TOR.geoip6)),
    ]);
  }
  // update-sums.js, with the Tor pins swapped for the stand-ins'.
  const wrapper = path.join(tmp, 'run-update-sums.js');
  fs.writeFileSync(wrapper, [
    "Object.assign(require(" + JSON.stringify(path.join(ROOT, 'scripts', 'lib', 'tor.js')) + ").PINS, " + JSON.stringify(fakePins) + ");",
    "require(" + JSON.stringify(path.join(ROOT, 'scripts', 'update-sums.js')) + ");", '',
  ].join('\n'));

  await check('update-sums.js writes the new version and its record, and never gives a published version other files', async () => {
    // Run only a writer that can be pointed at a copy: one that cannot would
    // rewrite the real landing/SHA256SUMS.txt with this test's fixtures.
    const writer = fs.readFileSync(path.join(ROOT, 'scripts', 'update-sums.js'), 'utf8');
    assert.ok(/process\.env\.HIDRA_SUMS_FILE/.test(writer), 'update-sums.js writes only landing/SHA256SUMS.txt; not running it');
    const sums = path.join(tmp, 'landing-SHA256SUMS.txt');
    fs.copyFileSync(SUMS, sums);
    fs.writeFileSync(sums + '.sig', 'old');
    const zips = path.join(tmp, 'zips');
    fs.mkdirSync(zips);
    fs.mkdirSync(path.join(tmp, 'no-electron-cache'));
    const arches = ['macOS-arm64', 'macOS-x64', 'Linux-x64', 'Windows-x64'];
    const zipFile = (a) => path.join(zips, `HidraNet-Browser-${pkg.version}-${a}.zip`);
    for (const a of arches) fs.writeFileSync(zipFile(a), packageFor(a));
    const run = (...args) => spawnSync(process.execPath, [wrapper, zips, ...args],
      { encoding: 'utf8', env: { ...process.env, HIDRA_SUMS_FILE: sums, HIDRA_ELECTRON_CACHE: path.join(tmp, 'no-electron-cache') } });

    const r = run('abcdef1234', '--minimum', pkg.version, '--valid-until', '2099-01-01');
    assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    assert.ok(/no longer matches/.test(r.stdout), 'does not say the old signature is void');
    assert.ok(/checked engine and Tor: HidraNet-Browser-.*-Windows-x64\.zip/.test(r.stdout), r.stdout);
    assert.ok(/still has a section "KNOWN PROBLEMS WITH THE 1\.0\.0 PACKAGES"/.test(r.stdout), 'no word about the 1.0.0 prose');
    const text = fs.readFileSync(sums, 'utf8');
    const rec = uc.parseRecord(text);
    assert.deepStrictEqual([rec.latest, rec.minimum, rec.validUntil], [pkg.version, pkg.version, '2099-01-01']);
    assert.ok(text.startsWith(`HidraNet Browser ${pkg.version} — SHA-256 checksums\n`));
    for (const a of arches) {
      const name = `HidraNet-Browser-${pkg.version}-${a}.zip`;
      assert.ok(text.includes(`${sha256(fs.readFileSync(zipFile(a)))}  ${name}\n`), 'no row for ' + name);
    }
    assert.ok(!/HidraNet-Browser-1\.0\.0-/.test(text.slice(0, text.indexOf('NONE OF THESE BUILDS'))), 'an old row survived');

    // The same files again: nothing to refuse (only the date moves on).
    assert.strictEqual(run('--valid-until', '2099-01-01').status, 0);
    assert.strictEqual(fs.readFileSync(sums, 'utf8'), text);
    // Other files under the same version: refused, and the table untouched.
    fs.writeFileSync(zipFile('Linux-x64'), packageFor('Linux-x64', { build: 'a rebuild' }));
    const again = run();
    assert.strictEqual(again.status, 1);
    assert.ok(/already in the table with other contents/.test(again.stderr), again.stderr);
    assert.strictEqual(fs.readFileSync(sums, 'utf8'), text);
    fs.writeFileSync(zipFile('Linux-x64'), packageFor('Linux-x64'));
    // A minimum above the version, or a date gone by: refused.
    assert.strictEqual(run('--minimum', '99.0.0').status, 1);
    assert.strictEqual(run('--valid-until', '2001-01-01').status, 1);

    // A package on another Electron, or with another Tor: refused, by name,
    // and the table untouched.
    const bad = {
      'macOS-x64': [packageFor('macOS-x64', { bin: engineOf('33.4.11', '130.0.6723.191') }), /the engine is Electron 33\.4\.11/],
      'Windows-x64': [packageFor('Windows-x64', { bin: engineOf(ELECTRON_VER, '151.0.1.2') }), /Chromium 151\.0\.1\.2 but the user agent says Chrome/],
    };
    for (const [a, [bytes, why]] of Object.entries(bad)) {
      const good = fs.readFileSync(zipFile(a));
      fs.writeFileSync(zipFile(a), bytes);
      const refused = run('--valid-until', '2099-01-01');
      assert.strictEqual(refused.status, 1, refused.stdout);
      assert.ok(why.test(refused.stderr) && /package\(s\) refused; the table is unchanged/.test(refused.stderr), refused.stderr);
      assert.strictEqual(fs.readFileSync(sums, 'utf8'), text);
      fs.writeFileSync(zipFile(a), good);
    }
    const linux = fs.readFileSync(zipFile('Linux-x64'));
    fs.writeFileSync(zipFile('Linux-x64'), writeZip([
      mkFile('hidranet', Buffer.from(GOOD)), mkFile('resources/app/package.json', Buffer.from('{}')),
      mkFile('resources/bin/tor/tor', Buffer.from('tor 15.0.22')), mkFile('resources/bin/tor/geoip', Buffer.from(TOR.geoip)),
      mkFile('resources/bin/tor/geoip6', Buffer.from(TOR.geoip6)),
    ]));
    const torRefused = run('--valid-until', '2099-01-01');
    assert.strictEqual(torRefused.status, 1);
    assert.ok(/Tor: tor is not the pinned Tor/.test(torRefused.stderr), torRefused.stderr);
    assert.strictEqual(fs.readFileSync(sums, 'utf8'), text);
    fs.writeFileSync(zipFile('Linux-x64'), linux);
  });

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})();
