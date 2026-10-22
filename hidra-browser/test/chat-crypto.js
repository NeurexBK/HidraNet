// The room cryptography, run under Node with the same Web Crypto the pages
// use. Three kinds of check:
//
//   - scrypt against the vectors published in RFC 7914 and against Node's
//     own scrypt on random inputs, because a hand-written KDF that is merely
//     deterministic could still be wrong everywhere in the same way;
//   - the envelope: what a member can and cannot do with the room key alone
//     (read, yes; forge a signature, replay, change a field, no);
//   - the two shipped copies of the file, and of the page, are the same
//     bytes, since the engine serves its own copy of what the browser ships.
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..');
const room = require(path.join(ROOT, 'hidra-browser', 'src', 'ui', 'hidrachat-crypto.js'));

const hex = (b) => Buffer.from(b).toString('hex');
const bytes = (s) => new TextEncoder().encode(s);
let passed = 0;

async function test(name, fn) {
  await fn();
  console.log('ok    ' + name);
  passed++;
}

(async () => {
  // ── scrypt ──────────────────────────────────────────────────────────────

  await test('scrypt matches RFC 7914 vector 1 (empty password, N=16)', async () => {
    const dk = await room.scrypt(bytes(''), bytes(''), 16, 1, 1, 64);
    assert.strictEqual(hex(dk),
      '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442' +
      'fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906');
  });

  await test('scrypt matches RFC 7914 vector 2 (N=1024, r=8, p=16)', async () => {
    const dk = await room.scrypt(bytes('password'), bytes('NaCl'), 1024, 8, 16, 64);
    assert.strictEqual(hex(dk),
      'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162' +
      '2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640');
  });

  await test('scrypt matches RFC 7914 vector 3 (N=16384, r=8, p=1)', async () => {
    const dk = await room.scrypt(bytes('pleaseletmein'), bytes('SodiumChloride'), 16384, 8, 1, 64);
    assert.strictEqual(hex(dk),
      '7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2' +
      'd5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887');
  });

  await test('scrypt agrees with Node on random inputs', async () => {
    for (let i = 0; i < 6; i++) {
      const pw = crypto.randomBytes(1 + (i * 7) % 40);
      const salt = crypto.randomBytes(i * 3);
      const N = 1 << (4 + i);
      const r = 1 + (i % 3);
      const p = 1 + (i % 2);
      const want = crypto.scryptSync(pw, salt, 40, { N, r, p, maxmem: 256 * 1024 * 1024 });
      const got = await room.scrypt(new Uint8Array(pw), new Uint8Array(salt), N, r, p, 40);
      assert.strictEqual(hex(got), want.toString('hex'), `N=${N} r=${r} p=${p}`);
    }
  });

  await test('scrypt at the shipped parameters costs what it should', async () => {
    const P = room.SCRYPT;
    assert.strictEqual(P.N, 65536);
    assert.strictEqual(P.r, 8);
    assert.strictEqual(P.p, 1);
    const t0 = Date.now();
    const got = await room.scrypt(bytes('tiger-wind-moon-abc'), bytes('hidrachat-room-v2'), P.N, P.r, P.p, 32);
    const ms = Date.now() - t0;
    const want = crypto.scryptSync('tiger-wind-moon-abc', 'hidrachat-room-v2', 32, { N: P.N, r: P.r, p: P.p, maxmem: 256 * 1024 * 1024 });
    assert.strictEqual(hex(got), want.toString('hex'));
    console.log('      64 MiB derivation took ' + ms + ' ms here');
  });

  // ── Room derivation ─────────────────────────────────────────────────────

  // Small parameters: the tests cannot afford a second and 64 MiB per case.
  const FAST = { N: 16, r: 1, p: 1, dkLen: 32 };

  await test('the same password gives the same room; a different one, a different room', async () => {
    const a = await room.deriveRoom('one password', FAST);
    const b = await room.deriveRoom('one password', FAST);
    const c = await room.deriveRoom('one password.', FAST);
    assert.strictEqual(a.topic, b.topic);
    assert.strictEqual(a.roomId, b.roomId);
    assert.notStrictEqual(a.topic, c.topic);
    assert.notStrictEqual(a.roomId, c.roomId);
    assert.match(a.topic, /^hidra-[0-9a-f]{32}$/);
    assert.match(a.roomId, /^[0-9a-f]{12}$/);
  });

  await test('the topic is not a fast hash of the password', async () => {
    // The old scheme: anyone could test a guess against the topic list with
    // one SHA-256. The topic now only comes out of the slow derivation.
    const r = await room.deriveRoom('password', FAST);
    const sha = crypto.createHash('sha256').update('hidra-topic-v1:password').digest('hex');
    assert.notStrictEqual(r.topic, 'hidra-' + sha.slice(0, 32));
    assert.notStrictEqual(r.topic, 'hidra-' + crypto.createHash('sha256').update('password').digest('hex').slice(0, 32));
  });

  await test('an empty password is refused, not turned into a room', async () => {
    await assert.rejects(() => room.deriveRoom('', FAST));
  });

  // ── Envelope ────────────────────────────────────────────────────────────

  const alice = await room.newIdentity();
  const bob = await room.newIdentity();
  const key = (await room.deriveRoom('shared', FAST)).key;
  const otherKey = (await room.deriveRoom('shared!', FAST)).key;

  function fresh() {
    return { trust: new room.TrustStore(), guard: new room.ReplayGuard() };
  }

  await test('a member reads what another member sent', async () => {
    const { wire } = await room.seal(key, alice, { k: 'msg', nick: 'alice', color: '#00d4aa', text: 'hello' });
    const r = fresh();
    const got = await room.open(key, r.trust, r.guard, wire);
    assert.ok(got.ok, got.reason);
    assert.strictEqual(got.msg.text, 'hello');
    assert.strictEqual(got.msg.cid, alice.cid);
  });

  await test('another room sees nothing', async () => {
    const { wire } = await room.seal(key, alice, { k: 'msg', nick: 'alice', text: 'hello' });
    const r = fresh();
    assert.deepStrictEqual(await room.open(otherKey, r.trust, r.guard, wire), { ok: false, reason: 'foreign' });
    assert.deepStrictEqual(await room.open(key, r.trust, r.guard, 'not base64 at all!'), { ok: false, reason: 'foreign' });
  });

  await test('a flipped byte is a foreign envelope, not a different message', async () => {
    const { wire } = await room.seal(key, alice, { k: 'msg', nick: 'alice', text: 'hello' });
    const raw = Buffer.from(wire, 'base64');
    raw[raw.length - 1] ^= 1;
    const r = fresh();
    assert.deepStrictEqual(await room.open(key, r.trust, r.guard, raw.toString('base64')), { ok: false, reason: 'foreign' });
  });

  await test('the same message twice is a replay', async () => {
    const { wire } = await room.seal(key, alice, { k: 'msg', nick: 'alice', text: 'hello' });
    const r = fresh();
    assert.ok((await room.open(key, r.trust, r.guard, wire)).ok);
    assert.deepStrictEqual(await room.open(key, r.trust, r.guard, wire), { ok: false, reason: 'replay' });
  });

  await test('a message from outside the time window is a replay', async () => {
    const { wire } = await room.seal(key, alice, { k: 'msg', nick: 'alice', text: 'old' });
    const later = new room.ReplayGuard(room.REPLAY_WINDOW_MS, () => Date.now() + room.REPLAY_WINDOW_MS + 1000);
    assert.deepStrictEqual(await room.open(key, new room.TrustStore(), later, wire), { ok: false, reason: 'replay' });
  });

  await test('a member with the room key cannot speak as another session', async () => {
    // Bob knows the key. He builds an envelope that claims alice's session
    // id, signed with his own key, and one with alice's public key pasted in
    // but a signature he cannot make.
    const r = fresh();
    const first = await room.seal(key, alice, { k: 'join', nick: 'alice' });
    assert.ok((await room.open(key, r.trust, r.guard, first.wire)).ok);

    const forgedId = { k: 'msg', cid: alice.cid, nick: 'alice', text: 'not me', n: 'aa', t: Date.now(), pk: bob.pub };
    forgedId.sig = await room.sign(bob, forgedId);
    const w1 = await room.encrypt(key, JSON.stringify(forgedId));
    assert.deepStrictEqual(await room.open(key, r.trust, r.guard, w1), { ok: false, reason: 'identity' });

    const forgedSig = { k: 'msg', cid: alice.cid, nick: 'alice', text: 'not me', n: 'bb', t: Date.now(), pk: alice.pub };
    forgedSig.sig = await room.sign(bob, forgedSig);
    const w2 = await room.encrypt(key, JSON.stringify(forgedSig));
    assert.deepStrictEqual(await room.open(key, r.trust, r.guard, w2), { ok: false, reason: 'signature' });
  });

  await test('a signed message cannot be edited by someone holding the key', async () => {
    const { msg } = await room.seal(key, alice, { k: 'msg', nick: 'alice', color: '#00d4aa', text: 'yes' });
    for (const [field, value] of [['text', 'no'], ['nick', 'mallory'], ['color', '#ff0000'], ['t', msg.t + 1], ['k', 'typing']]) {
      const edited = Object.assign({}, msg, { [field]: value });
      const r = fresh();
      const got = await room.open(key, r.trust, r.guard, await room.encrypt(key, JSON.stringify(edited)));
      assert.deepStrictEqual(got, { ok: false, reason: 'signature' }, field);
    }
  });

  await test('a message with the pieces missing is malformed', async () => {
    const r = fresh();
    for (const plain of ['42', '"text"', '{}', '{"k":"msg"}', JSON.stringify({ k: 'msg', cid: 'x', pk: 'y', sig: 'z', n: 'n' })]) {
      const got = await room.open(key, r.trust, r.guard, await room.encrypt(key, plain));
      assert.deepStrictEqual(got, { ok: false, reason: 'malformed' }, plain);
    }
  });

  await test('a session id is its key\'s hash, so no key can wear another\'s id', async () => {
    assert.strictEqual(alice.cid, await room.cidFor(alice.pub));
    assert.strictEqual(alice.cid.length, 16);
    assert.ok(alice.cid.startsWith(alice.fingerprint));
    // Validly signed by Mallory, but carrying Alice's id: refused before any
    // state is touched, in a page that has never heard of Alice.
    const r = fresh();
    const worn = { k: 'join', cid: alice.cid, nick: 'alice', n: 'cc', t: Date.now(), pk: bob.pub };
    worn.sig = await room.sign(bob, worn);
    assert.deepStrictEqual(await room.open(key, r.trust, r.guard, await room.encrypt(key, JSON.stringify(worn))), { ok: false, reason: 'identity' });
    // Alice's real message still gets through to that page afterwards.
    const real = await room.seal(key, alice, { k: 'msg', nick: 'alice', text: 'still me' });
    const got = await room.open(key, r.trust, r.guard, real.wire);
    assert.ok(got.ok, got.reason);
    assert.strictEqual(got.msg.text, 'still me');
  });

  await test('a message that fails verification leaves nothing behind', async () => {
    const r = fresh();
    const junk = { k: 'msg', cid: alice.cid, nick: 'alice', text: 'x', n: 'dd', t: Date.now(), pk: alice.pub, sig: 'AAAA' };
    assert.deepStrictEqual(await room.open(key, r.trust, r.guard, await room.encrypt(key, JSON.stringify(junk))), { ok: false, reason: 'signature' });
    assert.deepStrictEqual(r.trust.keys, {}, 'no binding was recorded');
    assert.deepStrictEqual(r.guard.seen, {}, 'no nonce was recorded');
    const real = await room.seal(key, alice, { k: 'msg', nick: 'alice', text: 'after junk' });
    assert.ok((await room.open(key, r.trust, r.guard, real.wire)).ok);
  });

  await test('a public key is accepted in exactly one encoding', async () => {
    assert.ok(room.canonicalPub(alice.pub));
    const raw = room.fromB64(alice.pub);
    const compressed = new Uint8Array(33); compressed[0] = 2 + (raw[64] & 1); compressed.set(raw.slice(1, 33), 1);
    // The last character before the padding carries two bits that must be
    // zero; flipping one changes the string but not the bytes it decodes to.
    const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const flipped = alice.pub.slice(0, 86) + B64[B64.indexOf(alice.pub[86]) ^ 1] + '=';
    assert.notStrictEqual(flipped, alice.pub);
    assert.deepStrictEqual(room.fromB64(flipped), raw, 'same bytes, different string');
    for (const odd of [room.toB64(compressed), alice.pub.slice(0, 10) + ' ' + alice.pub.slice(10), alice.pub.replace(/=$/, ''), flipped, '', 'AAAA']) {
      assert.strictEqual(room.canonicalPub(odd), null, odd.slice(0, 20));
    }
    const sig = await room.sign(alice, { k: 'msg', cid: alice.cid, text: 'x', n: 'n', t: 1 });
    assert.strictEqual(await room.verify(alice.pub, { k: 'msg', cid: alice.cid, text: 'x', n: 'n', t: 1 }, sig), true);
    assert.strictEqual(await room.verify(room.toB64(compressed), { k: 'msg', cid: alice.cid, text: 'x', n: 'n', t: 1 }, sig), false);
  });

  await test('nicknames that read the same compare the same', async () => {
    assert.strictEqual(room.normalizeNick('  alice  '), 'alice');
    assert.strictEqual(room.normalizeNick('al​ice'), 'alice');
    assert.strictEqual(room.normalizeNick('al  ice'), 'al ice');
    assert.strictEqual(room.nickKey('ALICE⁠'), 'alice');
    assert.strictEqual(room.nickKey('Ａlice'), 'alice'); // fullwidth A folds under NFKC
    assert.notStrictEqual(room.nickKey('alice'), room.nickKey('alice2'));
    assert.strictEqual(room.normalizeNick('x'.repeat(40)).length, 24);
    // The same strings hidra-node tests against nick_key: the two sides agree.
    for (const lookAlike of ['al\u200bice', 'al\ufe0fice', 'al\u034fice', 'al\u3164ice', 'al\u{e0041}ice', 'al\u180eice', 'al\u061cice', 'al\ufff9ice', '\uff21lice', 'al\u{f0000}ice', 'al\u00adice', 'al\ufeffice', 'al\u2060ice', 'al\u115fice']) {
      assert.strictEqual(room.nickKey(lookAlike), 'alice', JSON.stringify(lookAlike));
    }
    assert.strictEqual(room.nickKey('  al\u00a0 ice '), 'al ice');
    assert.notStrictEqual(room.nickKey('ali\u00e7a'), 'alica', 'a real accent stays');
  });

  await test('fingerprints tell two sessions with the same nickname apart', async () => {
    assert.match(alice.fingerprint, /^[0-9a-f]{8}$/);
    assert.notStrictEqual(alice.fingerprint, bob.fingerprint);
    assert.strictEqual(await room.fingerprint(alice.pub), alice.fingerprint);
  });

  // ── Small guards ────────────────────────────────────────────────────────

  await test('only a six-digit hex colour reaches a style attribute', async () => {
    assert.strictEqual(room.safeColor('#00d4aa', 'x'), '#00d4aa');
    assert.strictEqual(room.safeColor('#ABCDEF', 'x'), '#ABCDEF');
    for (const bad of ['red', '#fff', '#00d4aa"', 'red"><img src=x onerror="alert(1)', '', null, undefined, 42, '#00d4aa;background:url(x)']) {
      assert.strictEqual(room.safeColor(bad, '#111111'), '#111111', String(bad));
    }
    assert.match(room.colorFor('anyone'), /^#[0-9a-f]{6}$/);
  });

  await test('a generated password has three words and twelve random characters', async () => {
    const seen = new Set();
    for (let i = 0; i < 50; i++) {
      const p = room.genPassword();
      assert.match(p, /^[a-z]+-[a-z]+-[a-z]+-[0-9a-z]{12}$/, p);
      seen.add(p);
    }
    assert.strictEqual(seen.size, 50);
  });

  // ── Shipped copies ──────────────────────────────────────────────────────

  await test('the engine ships the same bytes the browser does', async () => {
    const pairs = [
      ['hidra-browser/src/ui/hidrachat-crypto.js', 'hidra-node/assets/hidrachat-crypto.js'],
      ['hidra-browser/src/ui/hidra-store.js', 'hidra-node/assets/hidra-store.js'],
      ['hidra-browser/src/ui/hidra-relays.js', 'hidra-node/assets/hidra-relays.js'],
      ['hidra-browser/src/ui/hidrachat.html', 'hidra-node/assets/hidrachat.html'],
      ['hidra-browser/src/ui/vendor/mqtt.min.js', 'hidra-node/assets/vendor/mqtt.min.js'],
    ];
    for (const [a, b] of pairs) {
      const fa = fs.readFileSync(path.join(ROOT, a));
      const fb = fs.readFileSync(path.join(ROOT, b));
      assert.ok(fa.equals(fb), a + ' and ' + b + ' differ');
    }
  });

  console.log('\n' + passed + ' checks passed');
})().catch((e) => {
  console.log('FAIL  ' + (e && e.stack || e));
  process.exit(1);
});
