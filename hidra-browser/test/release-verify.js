// The browser verifies releases with the same key and format as
// hidravpn-sign, and refuses everything while it has no key.
//
//   node hidra-browser/test/release-verify.js
//
// The cross-check with the real `hidravpn-sign` binary runs when it has been
// built (hidravpn/target/release/hidravpn-sign) and says so when it has not.

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const rv = require('../src/main/release-verify');

let passed = 0, failed = 0;
const ok = (n) => { passed++; console.log('ok    ' + n); };
const bad = (n, why) => { failed++; console.log('FAIL  ' + n + '\n      ' + why); };
async function check(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, (e && e.stack) || String(e)); } }

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-rv-'));
const rawPublic = (pub) => pub.export({ format: 'der', type: 'spki' }).slice(-32);

(async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubB64 = rawPublic(publicKey).toString('base64');
  const file = path.join(tmp, 'hidravpn.exe');
  const data = crypto.randomBytes(5000);
  fs.writeFileSync(file, data);
  const sigB64 = crypto.sign(null, data, privateKey).toString('base64');
  fs.writeFileSync(file + '.sig', sigB64);

  await check('a good signature verifies, and the hash is reported', async () => {
    const r = await rv.verifyFile(file, { publicKey: pubB64 });
    assert.strictEqual(r.ok, true, JSON.stringify(r));
    assert.strictEqual(r.sha256, crypto.createHash('sha256').update(data).digest('hex'));
  });

  await check('a changed byte fails', async () => {
    const tampered = Buffer.from(data); tampered[100] ^= 1;
    assert.strictEqual(rv.verifyBytes(tampered, sigB64, pubB64), false);
  });

  await check('another key fails', async () => {
    const other = rawPublic(crypto.generateKeyPairSync('ed25519').publicKey).toString('base64');
    assert.strictEqual(rv.verifyBytes(data, sigB64, other), false);
    const r = await rv.verifyFile(file, { publicKey: other });
    assert.strictEqual(r.reason, 'bad-signature');
  });

  await check('garbage where a signature or a key should be is just "not valid", never a throw', async () => {
    assert.strictEqual(rv.verifyBytes(data, 'not base64 at all!!', pubB64), false);
    assert.strictEqual(rv.verifyBytes(data, Buffer.alloc(63).toString('base64'), pubB64), false);
    assert.strictEqual(rv.verifyBytes(data, '', pubB64), false);
    assert.strictEqual(rv.verifyBytes(data, sigB64, 'short'), false);
    assert.strictEqual(rv.verifyBytes(data, sigB64, ''), false);
    assert.strictEqual(rv.verifyBytes(data, sigB64, null), false);
  });

  await check('a missing .sig is reported as such', async () => {
    const lonely = path.join(tmp, 'lonely.bin'); fs.writeFileSync(lonely, 'x');
    const r = await rv.verifyFile(lonely, { publicKey: pubB64 });
    assert.strictEqual(r.ok, false); assert.strictEqual(r.reason, 'no-signature');
  });

  await check('a missing file is reported as such', async () => {
    const r = await rv.verifyFile(path.join(tmp, 'absent'), { publicKey: pubB64 });
    assert.strictEqual(r.reason, 'unreadable');
  });

  await check('an empty key verifies nothing (fail closed); the embedded key is real and refuses a test signature', async () => {
    const r2 = await rv.verifyFile(file, { publicKey: '' });
    assert.strictEqual(r2.ok, false); assert.strictEqual(r2.reason, 'no-release-key');
    assert.strictEqual(Buffer.from(rv.RELEASE_PUBLIC_KEY, 'base64').length, 32, 'the embedded key is a 32-byte Ed25519 public key');
    const r = await rv.verifyFile(file); // signed by this test's key, not the maintainers'
    assert.strictEqual(r.ok, false); assert.notStrictEqual(r.reason, 'no-release-key');
  });

  await check('the key constant matches the one the Rust side embeds', async () => {
    const rs = fs.readFileSync(path.join(__dirname, '..', '..', 'hidravpn', 'crates', 'hidravpn-core', 'src', 'release.rs'), 'utf8');
    const m = rs.match(/pub const RELEASE_PUBLIC_KEY_B64: &str = "([^"]*)";/);
    assert.ok(m, 'release.rs has no RELEASE_PUBLIC_KEY_B64');
    assert.strictEqual(m[1], rv.RELEASE_PUBLIC_KEY);
  });

  // ── The browser's checksum table: the same key, its own label ───────────
  const sums = Buffer.from('HidraNet Browser 1.1.0 — SHA-256 checksums\n  latest-version:        1.1.0\n');
  const sumsSig = crypto.sign(null, rv.browserSumsMessage(sums), privateKey).toString('base64');

  await check('the table\'s signature covers the label, a zero byte, then the file', async () => {
    assert.strictEqual(rv.BROWSER_SUMS_CONTEXT.toString('latin1'), 'hidranet-browser-sums-v1\0');
    assert.strictEqual(rv.verifyBrowserSums(sums, sumsSig, pubB64), true);
    const tampered = Buffer.from(sums); tampered[30] ^= 1;
    assert.strictEqual(rv.verifyBrowserSums(tampered, sumsSig, pubB64), false);
  });

  await check('a signature of the bare bytes (a manifest\'s, a VPN SHA256SUMS\'s) is not one of the table', async () => {
    const bare = crypto.sign(null, sums, privateKey).toString('base64');
    assert.strictEqual(rv.verifyBytes(sums, bare, pubB64), true);
    assert.strictEqual(rv.verifyBrowserSums(sums, bare, pubB64), false);
  });

  await check('and the table\'s signature passes for nothing signed over its bare bytes', async () => {
    assert.strictEqual(rv.verifyBytes(sums, sumsSig, pubB64), false);
    const r = await (async () => {
      const f = path.join(tmp, 'SHA256SUMS.txt');
      fs.writeFileSync(f, sums);
      fs.writeFileSync(f + '.sig', sumsSig);
      return rv.verifyFile(f, { publicKey: pubB64 });
    })();
    assert.strictEqual(r.reason, 'bad-signature');
  });

  await check('another key, an empty key or garbage verifies no table', async () => {
    const other = rawPublic(crypto.generateKeyPairSync('ed25519').publicKey).toString('base64');
    assert.strictEqual(rv.verifyBrowserSums(sums, sumsSig, other), false);
    assert.strictEqual(rv.verifyBrowserSums(sums, sumsSig, ''), false);
    assert.strictEqual(rv.verifyBrowserSums(sums, 'garbage', pubB64), false);
    assert.strictEqual(rv.verifyBrowserSums(sums, sumsSig), false, 'a test signature passed as the release key\'s');
  });

  await check('the signing script, the published table and the browser use the same label and key', async () => {
    const ps = fs.readFileSync(path.join(__dirname, '..', 'scripts', 'sign-sums.ps1'), 'utf8');
    assert.ok(ps.includes('GetBytes("hidranet-browser-sums-v1")') && /\$message\[\$label\.Length\] = 0/.test(ps),
      'sign-sums.ps1 does not build label + zero byte + file');
    const table = fs.readFileSync(path.join(__dirname, '..', '..', 'landing', 'SHA256SUMS.txt'), 'utf8');
    assert.ok(table.includes('"hidranet-browser-sums-v1", a zero byte'), 'SHA256SUMS.txt does not describe the label');
    assert.ok(table.includes("printf 'hidranet-browser-sums-v1\\0'"), 'SHA256SUMS.txt does not show how to check it');
    assert.ok(table.includes('  ' + rv.RELEASE_PUBLIC_KEY + '\n'), 'SHA256SUMS.txt names another release key');
  });

  // ── The same format as hidravpn-sign, both ways ──────────────────────────
  const signBin = path.join(__dirname, '..', '..', 'hidravpn', 'target', 'release', 'hidravpn-sign');
  if (fs.existsSync(signBin)) {
    await check('a file signed by hidravpn-sign verifies here', async () => {
      const keyFile = path.join(tmp, 'release.key');
      const printed = execFileSync(signBin, ['keygen', '--out', keyFile], { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
      const f = path.join(tmp, 'nodes.json'); fs.writeFileSync(f, '{"version":1}');
      execFileSync(signBin, ['sign', '--key', keyFile, f], { stdio: 'ignore' });
      const r = await rv.verifyFile(f, { publicKey: printed });
      assert.strictEqual(r.ok, true, JSON.stringify(r));
      fs.writeFileSync(f, '{"version":2}');
      const r2 = await rv.verifyFile(f, { publicKey: printed });
      assert.strictEqual(r2.reason, 'bad-signature');
    });
    await check('the table signed the way sign-sums.ps1 does it (label + 0 + file, by hidravpn-sign) verifies here', async () => {
      const keyFile = path.join(tmp, 'sums.key');
      const printed = execFileSync(signBin, ['keygen', '--out', keyFile], { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
      const msg = path.join(tmp, 'SHA256SUMS.msg');
      fs.writeFileSync(msg, rv.browserSumsMessage(sums));
      execFileSync(signBin, ['sign', '--key', keyFile, msg], { stdio: 'ignore' });
      const sig = fs.readFileSync(msg + '.sig', 'utf8');
      assert.strictEqual(rv.verifyBrowserSums(sums, sig, printed), true);
      // Signed bare, as `hidravpn-sign sign SHA256SUMS.txt` would, it is refused.
      const bare = path.join(tmp, 'bare.txt');
      fs.writeFileSync(bare, sums);
      execFileSync(signBin, ['sign', '--key', keyFile, bare], { stdio: 'ignore' });
      assert.strictEqual(rv.verifyBrowserSums(sums, fs.readFileSync(bare + '.sig', 'utf8'), printed), false);
      // And the check SHA256SUMS.txt tells a reader to run accepts it.
      const dir = fs.mkdtempSync(path.join(tmp, 'by-hand-'));
      fs.writeFileSync(path.join(dir, 'SHA256SUMS.txt'), sums);
      fs.writeFileSync(path.join(dir, 'SHA256SUMS.txt.sig'), sig);
      const out = execFileSync('bash', ['-c',
        "{ printf 'hidranet-browser-sums-v1\\0'; cat SHA256SUMS.txt; } > sums.msg && cp SHA256SUMS.txt.sig sums.msg.sig && " +
        '"$0" verify --pubkey "$1" sums.msg', signBin, printed], { cwd: dir }).toString();
      assert.ok(/^OK /m.test(out), out);
    });
    await check('a signature made here is accepted by hidravpn-sign verify', async () => {
      let out;
      try {
        out = execFileSync(signBin, ['verify', '--pubkey', pubB64, file], { stdio: ['ignore', 'pipe', 'pipe'] }).toString();
      } catch (e) { throw new Error('hidravpn-sign rejected it: ' + (e.stdout || '') + (e.stderr || '')); }
      assert.ok(/^OK /m.test(out), out);
    });
  } else {
    console.log('skip  hidravpn-sign is not built; the cross-check with the command line did not run');
  }

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})();
