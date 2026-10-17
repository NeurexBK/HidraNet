// What keeps a HidraChat room closed.
//
// A room is its password: everyone who types the same one derives the same
// key, and the relay in between carries only ciphertext. This file holds
// everything that follows from that, with no page in it, so the same code
// runs in the browser, in the page the engine serves, and under Node for the
// tests in hidra-browser/test/chat-crypto.js.
//
// Threats it answers, and the limits it has:
//
// 1. Offline guessing. Anyone can subscribe to the relay and collect every
//    room's traffic, then try passwords at home for as long as they like.
//    The key used to be PBKDF2 at 100k rounds, and the room's public topic
//    name was a bare SHA-256 of the password: one fast hash per guess, with
//    the answer sitting in the topic list. The key is now scrypt (RFC 7914)
//    at 64 MiB per guess, which a graphics card cannot run thousands of in
//    parallel, and the topic is derived from that same slow output, so the
//    topic name gives a guesser nothing cheaper to test against.
//
// 2. Impersonation. The room key is shared, so anyone in the room could once
//    send a message carrying any nickname. Each session now signs what it
//    sends with a key made for that session (ECDSA P-256), the first message
//    seen from a session fixes its public key, and a message whose signature
//    does not match is dropped before it is shown. The limit is that a second
//    session may still choose the same nickname: the page shows a fingerprint
//    beside a nickname that two sessions share, and a careful reader checks
//    it out of band.
//
// 3. Replay. The relay, or anyone who recorded the traffic, could send an old
//    message again and it would read as new. Every message now carries a
//    random nonce and a timestamp; a nonce seen before from the same session
//    is dropped, and so is a timestamp more than ten minutes from now.
//
// What it cannot do: forward secrecy. A shared password means that whoever
// learns it later reads everything they recorded earlier. Rotate the password
// when someone leaves who should not keep reading.
(function (root) {
  'use strict';

  var subtle = root.crypto && root.crypto.subtle;
  var te = new TextEncoder();
  var td = new TextDecoder();

  // ── Parameters ─────────────────────────────────────────────────────────
  //
  // scrypt N=2^16, r=8, p=1: 64 MiB and about a second in a browser. The same
  // memory the engine's own Argon2id uses for the room check. Changing any of
  // these makes a new, incompatible room from the same password, which is
  // why they are versioned in the labels below rather than tunable.
  var SCRYPT = { N: 65536, r: 8, p: 1, dkLen: 32 };
  var SALT = 'hidrachat-room-v2';
  var INFO_KEY = 'hidrachat-key-v2';
  var INFO_TOPIC = 'hidrachat-topic-v2';
  var INFO_ID = 'hidrachat-id-v2';
  var REPLAY_WINDOW_MS = 10 * 60 * 1000;
  var SEEN_PER_SESSION = 512;

  // ── Encoding helpers ───────────────────────────────────────────────────

  function toB64(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  function fromB64(s) {
    var raw = atob(s);
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  function toHex(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
    return s;
  }

  function randomBytes(n) {
    var b = new Uint8Array(n);
    root.crypto.getRandomValues(b);
    return b;
  }

  function assertSubtle() {
    if (!subtle) throw new Error('Web Crypto is not available in this context');
  }

  // ── scrypt, RFC 7914 ───────────────────────────────────────────────────
  //
  // Written out here rather than fetched: the whole point of the file is to
  // be read, and a third-party build of a memory-hard hash is a large blob
  // that nobody reads. The reference vectors from the RFC run in the tests.

  function rotl(a, b) {
    return (a << b) | (a >>> (32 - b));
  }

  // Salsa20/8 core over sixteen 32-bit words, in place.
  function salsa20_8(B, x) {
    var i;
    for (i = 0; i < 16; i++) x[i] = B[i];
    for (i = 0; i < 8; i += 2) {
      x[4] ^= rotl((x[0] + x[12]) | 0, 7); x[8] ^= rotl((x[4] + x[0]) | 0, 9);
      x[12] ^= rotl((x[8] + x[4]) | 0, 13); x[0] ^= rotl((x[12] + x[8]) | 0, 18);
      x[9] ^= rotl((x[5] + x[1]) | 0, 7); x[13] ^= rotl((x[9] + x[5]) | 0, 9);
      x[1] ^= rotl((x[13] + x[9]) | 0, 13); x[5] ^= rotl((x[1] + x[13]) | 0, 18);
      x[14] ^= rotl((x[10] + x[6]) | 0, 7); x[2] ^= rotl((x[14] + x[10]) | 0, 9);
      x[6] ^= rotl((x[2] + x[14]) | 0, 13); x[10] ^= rotl((x[6] + x[2]) | 0, 18);
      x[3] ^= rotl((x[15] + x[11]) | 0, 7); x[7] ^= rotl((x[3] + x[15]) | 0, 9);
      x[11] ^= rotl((x[7] + x[3]) | 0, 13); x[15] ^= rotl((x[11] + x[7]) | 0, 18);
      x[1] ^= rotl((x[0] + x[3]) | 0, 7); x[2] ^= rotl((x[1] + x[0]) | 0, 9);
      x[3] ^= rotl((x[2] + x[1]) | 0, 13); x[0] ^= rotl((x[3] + x[2]) | 0, 18);
      x[6] ^= rotl((x[5] + x[4]) | 0, 7); x[7] ^= rotl((x[6] + x[5]) | 0, 9);
      x[4] ^= rotl((x[7] + x[6]) | 0, 13); x[5] ^= rotl((x[4] + x[7]) | 0, 18);
      x[11] ^= rotl((x[10] + x[9]) | 0, 7); x[8] ^= rotl((x[11] + x[10]) | 0, 9);
      x[9] ^= rotl((x[8] + x[11]) | 0, 13); x[10] ^= rotl((x[9] + x[8]) | 0, 18);
      x[12] ^= rotl((x[15] + x[14]) | 0, 7); x[13] ^= rotl((x[12] + x[15]) | 0, 9);
      x[14] ^= rotl((x[13] + x[12]) | 0, 13); x[15] ^= rotl((x[14] + x[13]) | 0, 18);
    }
    for (i = 0; i < 16; i++) B[i] = (B[i] + x[i]) | 0;
  }

  // BlockMix over 2r blocks of 16 words held in B at offset `off`.
  // X and Y are scratch: 16 and 32r words.
  function blockMix(B, off, r, X, Y, scratch) {
    var i, k;
    var words = 32 * r;
    for (i = 0; i < 16; i++) X[i] = B[off + words - 16 + i];
    for (i = 0; i < 2 * r; i++) {
      for (k = 0; k < 16; k++) X[k] ^= B[off + i * 16 + k];
      salsa20_8(X, scratch);
      for (k = 0; k < 16; k++) Y[i * 16 + k] = X[k];
    }
    for (i = 0; i < r; i++) {
      for (k = 0; k < 16; k++) B[off + i * 16 + k] = Y[(2 * i) * 16 + k];
      for (k = 0; k < 16; k++) B[off + (r + i) * 16 + k] = Y[(2 * i + 1) * 16 + k];
    }
  }

  // ROMix over the 32r words at `off` in B, with N blocks of memory.
  function roMix(B, off, r, N) {
    var words = 32 * r;
    var V = new Uint32Array(words * N);
    var X = new Uint32Array(16);
    var Y = new Uint32Array(words);
    var scratch = new Uint32Array(16);
    var i, k, j;
    for (i = 0; i < N; i++) {
      for (k = 0; k < words; k++) V[i * words + k] = B[off + k];
      blockMix(B, off, r, X, Y, scratch);
    }
    for (i = 0; i < N; i++) {
      j = B[off + words - 16] % N;
      for (k = 0; k < words; k++) B[off + k] ^= V[j * words + k];
      blockMix(B, off, r, X, Y, scratch);
    }
  }

  function bytesToWordsLE(bytes) {
    var w = new Uint32Array(bytes.length >>> 2);
    for (var i = 0; i < w.length; i++) {
      w[i] = bytes[4 * i] | (bytes[4 * i + 1] << 8) | (bytes[4 * i + 2] << 16) | (bytes[4 * i + 3] << 24);
    }
    return w;
  }

  function wordsToBytesLE(words) {
    var b = new Uint8Array(words.length * 4);
    for (var i = 0; i < words.length; i++) {
      b[4 * i] = words[i] & 0xff;
      b[4 * i + 1] = (words[i] >>> 8) & 0xff;
      b[4 * i + 2] = (words[i] >>> 16) & 0xff;
      b[4 * i + 3] = (words[i] >>> 24) & 0xff;
    }
    return b;
  }

  async function pbkdf2(password, salt, iterations, dkLen) {
    var km = await subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
    var bits = await subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: iterations },
      km,
      dkLen * 8
    );
    return new Uint8Array(bits);
  }

  // scrypt(P, S, N, r, p, dkLen) -> Uint8Array. The two PBKDF2 passes are
  // the platform's; the memory-hard middle is the code above.
  async function scrypt(password, salt, N, r, p, dkLen) {
    assertSubtle();
    if (!(N > 1) || (N & (N - 1)) !== 0) throw new Error('scrypt: N must be a power of two above 1');
    if (!(r > 0) || !(p > 0) || !(dkLen > 0)) throw new Error('scrypt: r, p and dkLen must be positive');
    var B = await pbkdf2(password, salt, 1, p * 128 * r);
    var W = bytesToWordsLE(B);
    for (var i = 0; i < p; i++) roMix(W, i * 32 * r, r, N);
    return pbkdf2(password, wordsToBytesLE(W), 1, dkLen);
  }

  // ── Room derivation ────────────────────────────────────────────────────

  async function hkdfBits(ikm, info, bits) {
    var k = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    var out = await subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode(info) },
      k,
      bits
    );
    return new Uint8Array(out);
  }

  async function hkdfAesKey(ikm, info) {
    var k = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode(info) },
      k,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // Everything a page needs for a room, from its password:
  //   key     the AES-256-GCM key, not extractable
  //   topic   the relay topic, 'hidra-' + 32 hex, public but useless alone
  //   roomId  12 hex, what the page shows as the room code
  // `params` is for the tests, which cannot afford 64 MiB per case.
  async function deriveRoom(password, params) {
    assertSubtle();
    var P = params || SCRYPT;
    if (typeof password !== 'string' || password.length === 0) {
      throw new Error('a room needs a password');
    }
    var seed = await scrypt(te.encode(password), te.encode(SALT), P.N, P.r, P.p, P.dkLen);
    var key = await hkdfAesKey(seed, INFO_KEY);
    var topic = 'hidra-' + toHex(await hkdfBits(seed, INFO_TOPIC, 128));
    var roomId = toHex(await hkdfBits(seed, INFO_ID, 48));
    seed.fill(0);
    return { key: key, topic: topic, roomId: roomId };
  }

  // ── Message encryption ─────────────────────────────────────────────────

  async function encrypt(key, text) {
    var iv = randomBytes(12);
    var ct = await subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, te.encode(text));
    var out = new Uint8Array(12 + ct.byteLength);
    out.set(iv);
    out.set(new Uint8Array(ct), 12);
    return toB64(out);
  }

  // null for anything that is not ours: another room, a tampered envelope,
  // or not base64 at all.
  async function decrypt(key, b64) {
    try {
      var raw = fromB64(b64);
      if (raw.length < 13) return null;
      var pt = await subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) }, key, raw.slice(12));
      return td.decode(pt);
    } catch (e) {
      return null;
    }
  }

  // ── Session identity and signatures ────────────────────────────────────

  async function fingerprint(pubB64) {
    var h = await subtle.digest('SHA-256', fromB64(pubB64));
    return toHex(new Uint8Array(h).slice(0, 4));
  }

  async function newIdentity() {
    assertSubtle();
    var pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    var pub = toB64(new Uint8Array(await subtle.exportKey('raw', pair.publicKey)));
    return {
      cid: toHex(randomBytes(8)),
      privateKey: pair.privateKey,
      pub: pub,
      fingerprint: await fingerprint(pub),
    };
  }

  // The bytes a signature covers. A fixed list in a fixed order, so a field
  // left out cannot be slipped in later and read as signed.
  function canonical(o) {
    return te.encode(JSON.stringify([
      String(o.k || ''),
      String(o.cid || ''),
      String(o.nick || ''),
      String(o.color || ''),
      String(o.text || ''),
      Number(o.t) || 0,
      String(o.n || ''),
      o.state === true,
    ]));
  }

  async function sign(identity, obj) {
    var sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, identity.privateKey, canonical(obj));
    return toB64(new Uint8Array(sig));
  }

  async function verify(pubB64, obj, sigB64) {
    try {
      var key = await subtle.importKey('raw', fromB64(pubB64), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      return await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, fromB64(sigB64), canonical(obj));
    } catch (e) {
      return false;
    }
  }

  // ── Trust on first sight, and replay ───────────────────────────────────

  // Which public key each session id spoke with first. A second key under
  // the same id is someone else wearing it.
  function TrustStore() {
    this.keys = {};
  }
  TrustStore.prototype.bind = function (cid, pub) {
    if (!cid || !pub) return false;
    if (!Object.prototype.hasOwnProperty.call(this.keys, cid)) {
      this.keys[cid] = pub;
      return true;
    }
    return this.keys[cid] === pub;
  };
  TrustStore.prototype.forget = function (cid) {
    delete this.keys[cid];
  };

  function ReplayGuard(windowMs, now) {
    this.window = windowMs || REPLAY_WINDOW_MS;
    this.now = now || function () { return Date.now(); };
    this.seen = {};
  }
  ReplayGuard.prototype.accept = function (cid, nonce, t) {
    if (!cid || !nonce || typeof t !== 'number') return false;
    if (Math.abs(this.now() - t) > this.window) return false;
    var list = this.seen[cid];
    if (!list) list = this.seen[cid] = [];
    if (list.indexOf(nonce) >= 0) return false;
    list.push(nonce);
    if (list.length > SEEN_PER_SESSION) list.splice(0, list.length - SEEN_PER_SESSION);
    return true;
  };

  // ── Envelopes: what actually goes over the relay ───────────────────────

  // Fills in the sender, a nonce, the time, the public key and the
  // signature, encrypts the lot, and returns the base64 to publish. The
  // object is also returned, as sent, for the local echo.
  async function seal(key, identity, obj) {
    var msg = {};
    for (var f in obj) if (Object.prototype.hasOwnProperty.call(obj, f)) msg[f] = obj[f];
    msg.cid = identity.cid;
    msg.n = toHex(randomBytes(8));
    msg.t = Date.now();
    msg.pk = identity.pub;
    msg.sig = await sign(identity, msg);
    return { wire: await encrypt(key, JSON.stringify(msg)), msg: msg };
  }

  // The reverse, with every check. Returns { ok: true, msg } or
  // { ok: false, reason } where reason is one of:
  //   'foreign'   not this room's key (or not an envelope at all)
  //   'malformed' decrypted, but not a message
  //   'identity'  the session id is already bound to a different key
  //   'signature' the signature does not verify
  //   'replay'    seen before, or too far from now
  async function open(key, trust, guard, wire) {
    var plain = await decrypt(key, wire);
    if (plain === null) return { ok: false, reason: 'foreign' };
    var msg;
    try { msg = JSON.parse(plain); } catch (e) { return { ok: false, reason: 'malformed' }; }
    if (!msg || typeof msg !== 'object' || typeof msg.k !== 'string'
      || typeof msg.cid !== 'string' || typeof msg.pk !== 'string'
      || typeof msg.sig !== 'string' || typeof msg.n !== 'string' || typeof msg.t !== 'number') {
      return { ok: false, reason: 'malformed' };
    }
    if (!trust.bind(msg.cid, msg.pk)) return { ok: false, reason: 'identity' };
    if (!(await verify(msg.pk, msg, msg.sig))) return { ok: false, reason: 'signature' };
    if (!guard.accept(msg.cid, msg.n, msg.t)) return { ok: false, reason: 'replay' };
    return { ok: true, msg: msg };
  }

  // ── Forum accounts: a key pair from a username and a password ──────────
  //
  // The forum has no server to keep accounts, so an account has to be
  // something a user can carry: the same username and password, typed on
  // any device, must give the same signing key. scrypt turns them into a
  // seed, the seed is the private scalar, and the public key is computed
  // from it here, because Web Crypto can generate a random key pair but
  // cannot make one from a seed. The arithmetic below is P-256 scalar
  // multiplication, checked in the tests against key pairs the platform
  // generated itself.
  //
  // The public key is published, so a weak password can be guessed against
  // it offline. scrypt at 64 MiB makes each guess expensive; the page still
  // insists on a password of some length.

  var P256 = {
    p: BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff'),
    n: BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'),
    b: BigInt('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'),
    gx: BigInt('0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'),
    gy: BigInt('0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'),
  };

  function mod(a, m) {
    var r = a % m;
    return r < 0n ? r + m : r;
  }

  function modPow(base, exp, m) {
    var result = 1n;
    base = mod(base, m);
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % m;
      base = (base * base) % m;
      exp >>= 1n;
    }
    return result;
  }

  function modInv(a, m) {
    return modPow(a, m - 2n, m);
  }

  // Jacobian coordinates, so that only the final step needs an inversion.
  function jacDouble(P) {
    var p = P256.p;
    if (P[2] === 0n) return P;
    var X = P[0], Y = P[1], Z = P[2];
    var Y2 = (Y * Y) % p;
    var S = (4n * X * Y2) % p;
    var Z2 = (Z * Z) % p;
    // a = -3: M = 3(X - Z^2)(X + Z^2)
    var M = (3n * ((X - Z2) % p) * ((X + Z2) % p)) % p;
    var X3 = mod(M * M - 2n * S, p);
    var Y3 = mod(M * (S - X3) - 8n * Y2 * Y2, p);
    var Z3 = mod(2n * Y * Z, p);
    return [X3, Y3, Z3];
  }

  function jacAdd(P, Q) {
    var p = P256.p;
    if (P[2] === 0n) return Q;
    if (Q[2] === 0n) return P;
    var Z1Z1 = (P[2] * P[2]) % p, Z2Z2 = (Q[2] * Q[2]) % p;
    var U1 = (P[0] * Z2Z2) % p, U2 = (Q[0] * Z1Z1) % p;
    var S1 = (P[1] * Q[2] * Z2Z2) % p, S2 = (Q[1] * P[2] * Z1Z1) % p;
    var H = mod(U2 - U1, p), R = mod(S2 - S1, p);
    if (H === 0n) {
      if (R === 0n) return jacDouble(P);
      return [0n, 1n, 0n];
    }
    var H2 = (H * H) % p, H3 = (H2 * H) % p, U1H2 = (U1 * H2) % p;
    var X3 = mod(R * R - H3 - 2n * U1H2, p);
    var Y3 = mod(R * (U1H2 - X3) - S1 * H3, p);
    var Z3 = mod(H * P[2] * Q[2], p);
    return [X3, Y3, Z3];
  }

  // d * G, as affine x and y.
  function p256Public(d) {
    var R = [0n, 1n, 0n];
    var G = [P256.gx, P256.gy, 1n];
    for (var i = 255; i >= 0; i--) {
      R = jacDouble(R);
      if ((d >> BigInt(i)) & 1n) R = jacAdd(R, G);
    }
    var zi = modInv(R[2], P256.p);
    var zi2 = (zi * zi) % P256.p;
    return { x: mod(R[0] * zi2, P256.p), y: mod(R[1] * zi2 * zi, P256.p) };
  }

  function bigToBytes(v, len) {
    var out = new Uint8Array(len);
    for (var i = len - 1; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
    return out;
  }

  function bytesToBig(b) {
    var v = 0n;
    for (var i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i]);
    return v;
  }

  function b64url(bytes) {
    return toB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  // The seed is 32 bytes from scrypt; the scalar is the seed reduced into
  // the curve's order, never zero.
  function seedToScalar(seed) {
    var d = mod(bytesToBig(seed), P256.n - 1n) + 1n;
    return d;
  }

  // A signing identity from a 32-byte seed. The seed is what a page keeps
  // in its vault between visits, so that the password is typed once.
  async function identityFromSeed(seed) {
    assertSubtle();
    if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error('a seed is 32 bytes');
    var d = seedToScalar(seed);
    var Q = p256Public(d);
    var jwk = { kty: 'EC', crv: 'P-256', d: b64url(bigToBytes(d, 32)), x: b64url(bigToBytes(Q.x, 32)), y: b64url(bigToBytes(Q.y, 32)) };
    var privateKey = await subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    var raw = new Uint8Array(65);
    raw[0] = 4;
    raw.set(bigToBytes(Q.x, 32), 1);
    raw.set(bigToBytes(Q.y, 32), 33);
    var pub = toB64(raw);
    return { privateKey: privateKey, pub: pub, fingerprint: await fingerprint(pub), seed: seed };
  }

  // Usernames are compared in this form: one spelling per name, so that
  // "Alice" and "alice " cannot be two accounts.
  function normalizeName(name) {
    return String(name || '').trim().toLowerCase();
  }

  var NAME_RE = /^[a-z0-9][a-z0-9._-]{2,23}$/;
  function validName(name) {
    return NAME_RE.test(normalizeName(name));
  }

  async function deriveIdentity(name, password, params) {
    assertSubtle();
    var norm = normalizeName(name);
    if (!validName(norm)) throw new Error('a username is 3 to 24 characters: letters, digits, dot, dash or underscore');
    if (typeof password !== 'string' || password.length < 10) throw new Error('a password is at least 10 characters');
    var P = params || SCRYPT;
    var seed = await scrypt(te.encode(password), te.encode('hforum-identity-v1:' + norm), P.N, P.r, P.p, 32);
    return identityFromSeed(seed);
  }

  // Signatures over a list of fields, in a fixed order the caller sets.
  async function signFields(identity, fields) {
    var sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, identity.privateKey, te.encode(JSON.stringify(fields)));
    return toB64(new Uint8Array(sig));
  }

  async function verifyFields(pubB64, fields, sigB64) {
    try {
      var key = await subtle.importKey('raw', fromB64(pubB64), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      return await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, fromB64(sigB64), te.encode(JSON.stringify(fields)));
    } catch (e) {
      return false;
    }
  }

  // ── The name registry ──────────────────────────────────────────────────
  //
  // The relay keeps claims for nobody: anyone can overwrite one. So a
  // registrar (hidra-browser/tools/forum-registrar.js), run by the project,
  // watches the claims, records the first key seen for each name, and
  // publishes the whole list signed with a key whose public half ships in
  // the forum page. A page that holds the registry believes it over anything
  // else on the relay; a page without one falls back to first-seen.
  //
  //   { v: 1, seq, ts, names: [[norm, name, pk, ts], ...], admin, sig }
  //
  // `names` is sorted by norm so that the signed bytes are the same on both
  // sides. `seq` only ever grows: an older registry cannot be replayed over
  // a newer one.

  function registryFields(reg) {
    return ['registry', Number(reg.seq) || 0, Number(reg.ts) || 0, reg.names, typeof reg.admin === 'string' ? reg.admin : ''];
  }

  async function signRegistry(identity, reg) {
    reg.v = 1;
    reg.names = reg.names.slice().sort(function (a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0; });
    reg.sig = await signFields(identity, registryFields(reg));
    return reg;
  }

  // The shape, then the signature. Returns the registry or null.
  async function verifyRegistry(pubB64, reg) {
    if (!reg || typeof reg !== 'object' || reg.v !== 1) return null;
    if (!Number.isInteger(reg.seq) || reg.seq < 0 || typeof reg.ts !== 'number') return null;
    if (!Array.isArray(reg.names) || typeof reg.sig !== 'string') return null;
    if (reg.admin !== null && reg.admin !== undefined && typeof reg.admin !== 'string') return null;
    var last = '';
    for (var i = 0; i < reg.names.length; i++) {
      var e = reg.names[i];
      if (!Array.isArray(e) || e.length !== 4) return null;
      if (typeof e[0] !== 'string' || !validName(e[0]) || e[0] !== normalizeName(e[0])) return null;
      if (typeof e[1] !== 'string' || normalizeName(e[1]) !== e[0]) return null;
      if (typeof e[2] !== 'string' || typeof e[3] !== 'number') return null;
      if (e[0] <= last) return null;             // sorted, no duplicates
      last = e[0];
    }
    if (!(await verifyFields(pubB64, registryFields(reg), reg.sig))) return null;
    return reg;
  }

  // ── Small guards the pages share ───────────────────────────────────────

  // A colour arrives from another member and is written into a style
  // attribute. Only the one shape the pages ever produce is allowed through;
  // anything else, including a closing quote, gets the fallback.
  function safeColor(c, fallback) {
    return typeof c === 'string' && /^#[0-9a-fA-F]{6}$/.test(c) ? c : fallback;
  }

  var PALETTE = ['#00d4aa', '#ff6b6b', '#4ecdc4', '#45b7d1', '#f9ca24', '#fd79a8', '#6c5ce7',
    '#e17055', '#0984e3', '#00b894', '#e84393', '#00cec9', '#fdcb6e', '#a29bfe', '#74b9ff'];

  function colorFor(s) {
    var h = 0;
    s = s || '';
    for (var i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
    return PALETTE[h % PALETTE.length];
  }

  // Three words to say it aloud, then twelve random characters that carry
  // the strength: about 76 bits in all, which no amount of recorded traffic
  // brings within reach even at a fast hash, and far less at scrypt.
  var WORDS = ['tiger', 'wind', 'moon', 'river', 'stone', 'fire', 'snow', 'wave', 'storm', 'leaf',
    'gold', 'silver', 'night', 'sun', 'sea', 'flower', 'ice', 'train', 'cloud', 'pine', 'eagle',
    'wolf', 'valley', 'mountain', 'flame'];

  function genPassword() {
    var r = randomBytes(15);
    var w = function (i) { return WORDS[r[i] % WORDS.length]; };
    var suffix = '';
    for (var i = 3; i < 15; i++) suffix += (r[i] % 36).toString(36);
    return w(0) + '-' + w(1) + '-' + w(2) + '-' + suffix;
  }

  var api = {
    SCRYPT: SCRYPT,
    REPLAY_WINDOW_MS: REPLAY_WINDOW_MS,
    scrypt: scrypt,
    deriveRoom: deriveRoom,
    encrypt: encrypt,
    decrypt: decrypt,
    newIdentity: newIdentity,
    fingerprint: fingerprint,
    sign: sign,
    verify: verify,
    canonical: canonical,
    TrustStore: TrustStore,
    ReplayGuard: ReplayGuard,
    seal: seal,
    open: open,
    safeColor: safeColor,
    colorFor: colorFor,
    genPassword: genPassword,
    // Forum accounts.
    p256Public: p256Public,
    seedToScalar: seedToScalar,
    identityFromSeed: identityFromSeed,
    deriveIdentity: deriveIdentity,
    normalizeName: normalizeName,
    validName: validName,
    signFields: signFields,
    verifyFields: verifyFields,
    registryFields: registryFields,
    signRegistry: signRegistry,
    verifyRegistry: verifyRegistry,
    bigToBytes: bigToBytes,
    bytesToBig: bytesToBig,
    toB64: toB64,
    fromB64: fromB64,
    toHex: toHex,
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.hidraRoom = api;
})(typeof globalThis !== 'undefined' ? globalThis : window);
