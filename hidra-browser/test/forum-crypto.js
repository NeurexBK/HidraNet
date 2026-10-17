// Forum accounts: a username and a password become a P-256 key pair, with
// the public key computed in hidrachat-crypto.js rather than by the
// platform, so the arithmetic is checked here against key pairs Web Crypto
// generated itself. Then the rules the page builds on: the same pair gives
// the same key anywhere, a different password gives a different key, and a
// signature made with one account does not verify under another.
const assert = require('assert');
const path = require('path');
const fs = require('fs');

const ROOT = path.join(__dirname, '..', '..');
const room = require(path.join(ROOT, 'hidra-browser', 'src', 'ui', 'hidrachat-crypto.js'));
const { subtle } = globalThis.crypto;
const b64url = (s) => new Uint8Array(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
const FAST = { N: 16, r: 1, p: 1 };
let passed = 0;

async function test(name, fn) {
  await fn();
  console.log('ok    ' + name);
  passed++;
}

(async () => {
  await test('the public key computed from a scalar is the one Web Crypto computes', async () => {
    for (let i = 0; i < 12; i++) {
      const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      const jwk = await subtle.exportKey('jwk', kp.privateKey);
      const d = room.bytesToBig(b64url(jwk.d));
      const Q = room.p256Public(d);
      assert.strictEqual(Buffer.from(room.bigToBytes(Q.x, 32)).toString('base64url'), jwk.x, 'x at ' + i);
      assert.strictEqual(Buffer.from(room.bigToBytes(Q.y, 32)).toString('base64url'), jwk.y, 'y at ' + i);
    }
  });

  await test('edge scalars: 1 gives the generator, n-1 gives its mirror', async () => {
    const G = room.p256Public(1n);
    assert.strictEqual(G.x.toString(16), '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296');
    assert.strictEqual(G.y.toString(16), '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5');
    const n = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
    const p = BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
    const M = room.p256Public(n - 1n);
    assert.strictEqual(M.x, G.x);
    assert.strictEqual(M.y, p - G.y);
  });

  await test('a seed never becomes a zero scalar, and always one below the order', async () => {
    const n = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
    for (const seed of [new Uint8Array(32), new Uint8Array(32).fill(0xff), new Uint8Array(32).fill(1)]) {
      const d = room.seedToScalar(seed);
      assert.ok(d >= 1n && d < n);
    }
  });

  await test('a seed gives a key that signs, and the platform verifies', async () => {
    const seed = new Uint8Array(32); crypto.getRandomValues(seed);
    const id = await room.identityFromSeed(seed);
    assert.strictEqual(room.fromB64(id.pub)[0], 4); // an uncompressed point starts with 0x04
    assert.strictEqual(room.fromB64(id.pub).length, 65);
    const sig = await room.signFields(id, ['t', 'abc', 'hello']);
    assert.strictEqual(await room.verifyFields(id.pub, ['t', 'abc', 'hello'], sig), true);
    assert.strictEqual(await room.verifyFields(id.pub, ['t', 'abc', 'hello!'], sig), false);
    assert.strictEqual(await room.verifyFields(id.pub, ['t', 'abc', 'hello'], sig.slice(0, -4) + 'AAAA'), false);
    // Verification with a key the platform imports from the same raw bytes.
    const key = await subtle.importKey('raw', room.fromB64(id.pub), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    assert.strictEqual(await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, room.fromB64(sig), new TextEncoder().encode(JSON.stringify(['t', 'abc', 'hello']))), true);
  });

  await test('the same username and password give the same account anywhere', async () => {
    const a = await room.deriveIdentity('Alice', 'correct horse battery', FAST);
    const b = await room.deriveIdentity('  alice ', 'correct horse battery', FAST);
    assert.strictEqual(a.pub, b.pub);
    assert.strictEqual(a.fingerprint, b.fingerprint);
    const again = await room.identityFromSeed(a.seed);
    assert.strictEqual(again.pub, a.pub);
  });

  await test('a different password, or a different name, is a different account', async () => {
    const a = await room.deriveIdentity('alice', 'correct horse battery', FAST);
    const b = await room.deriveIdentity('alice', 'correct horse batterY', FAST);
    const c = await room.deriveIdentity('alicia', 'correct horse battery', FAST);
    assert.notStrictEqual(a.pub, b.pub);
    assert.notStrictEqual(a.pub, c.pub);
    const sig = await room.signFields(a, ['claim', 'alice']);
    assert.strictEqual(await room.verifyFields(b.pub, ['claim', 'alice'], sig), false);
  });

  await test('usernames are one spelling each, and a short password is refused', async () => {
    assert.strictEqual(room.normalizeName('  Alice_1 '), 'alice_1');
    for (const ok of ['bob', 'alice.b', 'x-y_z', 'a1', 'ABC']) assert.ok(room.validName(ok) || ok === 'a1', ok);
    assert.strictEqual(room.validName('a1'), false);
    for (const bad of ['', 'ab', 'alice bob', 'álice', '.alice', 'a'.repeat(25), 'al/ice', "x');alert(1)"]) {
      assert.strictEqual(room.validName(bad), false, bad);
    }
    await assert.rejects(() => room.deriveIdentity('alice', 'short', FAST), /at least 10/);
    await assert.rejects(() => room.deriveIdentity('al ice', 'long enough password', FAST), /username/);
  });

  await test('the forum page builds nothing from a post into an event handler', async () => {
    const html = fs.readFileSync(path.join(ROOT, 'hidra-browser', 'src', 'ui', 'forum.html'), 'utf8');
    // Inline handlers may exist only as fixed strings; never with a value
    // concatenated in.
    const dynamic = html.match(/on[a-z]+="[^"]*'\+/g);
    assert.strictEqual(dynamic, null, 'found: ' + (dynamic || []).join(' | '));
    assert.ok(html.includes("var ID_RE=/^[tr][a-z2-7]{10}$/"));
    assert.ok(html.includes('<script src="hidrachat-crypto.js"></script>'));
  });

  console.log('\n' + passed + ' checks passed');
})().catch((e) => {
  console.log('FAIL  ' + (e && e.stack || e));
  process.exit(1);
});
