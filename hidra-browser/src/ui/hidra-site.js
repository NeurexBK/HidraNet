// A .hidra site that only its owner can change.
//
// A site used to be named by sixteen random bytes, and both the relay topic
// and the encryption key came from that name alone. Everyone who visits a
// site knows its name, so every visitor held everything needed to replace
// it: publish under the same topic, encrypted with the same key, and the
// next visitor saw theirs instead.
//
// Now a site has a signing key (ECDSA P-256), and its address is a hash of
// that key: 20 bytes, 32 base32 characters. What is published is signed, and
// the viewer checks the signature against the key the address is made of
// before it shows anything. Knowing the address lets you read the site, as
// before; only the key lets you change it.
//
// The old 26-character addresses had no key behind them. They still open,
// with a warning, because there is nothing to check them against; a 32-
// character address is never shown unsigned, so nobody can turn a new site
// back into an old, unprotected one.
//
//   wire (encrypted with the key derived from the address, as before):
//     { v: 2, pk: base64(raw P-256 key), body: '{"files":{...},"ts":...}',
//       sig: base64(ECDSA-SHA256 over "hidra-site-v2\n" + address + "\n" + body) }
(function (root) {
  'use strict';
  var subtle = crypto.subtle, enc = new TextEncoder(), dec = new TextDecoder();
  var SIGNED_LABEL = 32, LEGACY_LABEL = 26;
  var ECDSA = { name: 'ECDSA', namedCurve: 'P-256' };
  var SIG = { name: 'ECDSA', hash: 'SHA-256' };

  function b32(bytes) {
    var A = 'abcdefghijklmnopqrstuvwxyz234567', o = '', bits = 0, v = 0;
    for (var i = 0; i < bytes.length; i++) {
      v = (v << 8) | bytes[i]; bits += 8;
      while (bits >= 5) { o += A[(v >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) o += A[(v << (5 - bits)) & 31];
    return o;
  }
  function toB64(u) { var s = ''; for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); }
  function fromB64(s) { var r = atob(s), u = new Uint8Array(r.length); for (var i = 0; i < r.length; i++) u[i] = r.charCodeAt(i); return u; }

  /** The label of an address, without .hidra, or '' if it is not one. */
  function labelOf(addr) {
    var a = String(addr || '').trim().toLowerCase().replace(/\.hidra$/, '');
    return /^[a-z2-7]+$/.test(a) ? a : '';
  }
  /** 'signed' for a key-made address, 'legacy' for the old random kind, '' otherwise. */
  function kindOf(addr) {
    var l = labelOf(addr);
    if (l.length === SIGNED_LABEL) return 'signed';
    if (l.length === LEGACY_LABEL) return 'legacy';
    return '';
  }

  var ADDR_DOMAIN = enc.encode('hidra-site-addr-v2\n');
  async function addressOf(pkRaw) {
    var data = new Uint8Array(ADDR_DOMAIN.length + pkRaw.length);
    data.set(ADDR_DOMAIN);
    data.set(pkRaw, ADDR_DOMAIN.length);
    var h = new Uint8Array(await subtle.digest('SHA-256', data));
    return b32(h.slice(0, 20)) + '.hidra';
  }

  /** A new site: its key, and the address the key makes. */
  async function newSite() {
    var kp = await subtle.generateKey(ECDSA, true, ['sign', 'verify']);
    var pkRaw = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
    return {
      addr: await addressOf(pkRaw),
      pk: toB64(pkRaw),
      privJwk: await subtle.exportKey('jwk', kp.privateKey),
    };
  }

  function signedBytes(addr, body) { return enc.encode('hidra-site-v2\n' + addr + '\n' + body); }

  /** What to publish for a site: its files, signed by its key. */
  async function sealFiles(site, files, ts) {
    var priv = await subtle.importKey('jwk', site.privJwk, ECDSA, false, ['sign']);
    var body = JSON.stringify({ files: files, ts: ts || Date.now() });
    var sig = new Uint8Array(await subtle.sign(SIG, priv, signedBytes(site.addr, body)));
    return JSON.stringify({ v: 2, pk: site.pk, body: body, sig: toB64(sig) });
  }

  /**
   * Opens what the relay held for `addr`. Returns { ok, files, ts, signed }
   * or { ok: false, reason }. A signed address accepts only a valid
   * signature by the key it is made of; a legacy address accepts the old
   * unsigned bundle and says it is unsigned.
   */
  async function openFiles(addr, plaintext) {
    var kind = kindOf(addr);
    if (!kind) return { ok: false, reason: 'not a .hidra address' };
    var o;
    try { o = JSON.parse(plaintext); } catch (e) { return { ok: false, reason: 'invalid content' }; }
    if (!o || typeof o !== 'object') return { ok: false, reason: 'invalid content' };
    if (o.v === 2) {
      try {
        if (typeof o.pk !== 'string' || typeof o.body !== 'string' || typeof o.sig !== 'string') throw 0;
        var pkRaw = fromB64(o.pk);
        if ((await addressOf(pkRaw)) !== labelOf(addr) + '.hidra') return { ok: false, reason: 'signed by a key this address is not made of' };
        var pub = await subtle.importKey('raw', pkRaw, ECDSA, false, ['verify']);
        if (!(await subtle.verify(SIG, pub, fromB64(o.sig), signedBytes(labelOf(addr) + '.hidra', o.body)))) {
          return { ok: false, reason: 'the signature does not match' };
        }
        var b = JSON.parse(o.body);
        return { ok: true, files: cleanFiles(b.files), ts: typeof b.ts === 'number' ? b.ts : 0, signed: true };
      } catch (e) {
        return { ok: false, reason: 'the signature does not match' };
      }
    }
    // Unsigned: only ever acceptable for an address with no key behind it.
    if (kind === 'signed') return { ok: false, reason: 'unsigned content for an address that requires a signature' };
    return { ok: true, files: cleanFiles(o), ts: 0, signed: false };
  }

  /** Page name to HTML, strings only. */
  function cleanFiles(f) {
    var out = {};
    if (!f || typeof f !== 'object') return out;
    for (var k in f) {
      if (Object.prototype.hasOwnProperty.call(f, k) && /^[\w.-]{1,64}$/.test(k) && typeof f[k] === 'string') out[k] = f[k];
    }
    return out;
  }

  root.hidraSite = {
    newSite: newSite, sealFiles: sealFiles, openFiles: openFiles, addressOf: addressOf,
    kindOf: kindOf, labelOf: labelOf, SIGNED_LABEL: SIGNED_LABEL, LEGACY_LABEL: LEGACY_LABEL,
  };
})(typeof window !== 'undefined' ? window : globalThis);
