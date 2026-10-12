/**
 * The vault: where HidraNet's own apps keep what identifies you.
 *
 * HidraMail's address is a key pair; the forum name is a token; the chat
 * remembers room passwords; the publisher keeps the addresses that are the
 * only way to reach the sites you published. All of it used to sit in the
 * apps' localStorage, which Chromium writes to disk as it is — anyone who
 * could read this account's files could read the keys, and with them every
 * mail ever sent to that address.
 *
 * Each app now gets one compartment here, written through Electron's
 * safeStorage: the macOS Keychain, Windows DPAPI, or the keyring on Linux
 * (GNOME Keyring, KWallet). The key never touches this process; the OS does
 * the work and ties it to the user's login. Where no keyring exists — a bare
 * Linux without a desktop keyring — the data is written as it is, the file
 * says so, and the apps tell the user so. Pretending otherwise with a key
 * kept next to the data would protect nothing and claim to.
 *
 * Files are written whole, to a temporary name, then renamed into place: a
 * crash mid-write leaves the previous version, never half of the new one.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// The apps that hold an identity, and nothing else. main.js decides which
// one a page is from the page's own URL, so an app can only ever open its
// own compartment.
const NAMESPACES = new Set(['chat', 'mail', 'forum', 'publish']);

// Mail can hold a mailbox; nothing legitimate here is bigger than this.
const MAX_BYTES = 16 * 1024 * 1024;

const LINUX_BACKENDS = {
  gnome_libsecret: 'GNOME Keyring',
  kwallet: 'KWallet',
  kwallet5: 'KWallet',
  kwallet6: 'KWallet',
};

class VaultStore {
  /**
   * @param {string} dir where the compartments live
   * @param {object} safe Electron's safeStorage, or a stand-in for tests
   */
  constructor(dir, safe, platform = process.platform) {
    this.dir = dir;
    this.safe = safe;
    this.platform = platform;
    // One write at a time per compartment, in the order asked. Two writes
    // racing through rename could land the older one on top.
    this._chains = new Map();
  }

  encryptionAvailable() {
    try {
      return Boolean(this.safe && this.safe.isEncryptionAvailable());
    } catch (e) {
      return false;
    }
  }

  // What protects the data right now, in words the apps can show.
  status() {
    const encrypted = this.encryptionAvailable();
    if (!encrypted) return { encrypted: false, backend: 'none' };
    if (this.platform === 'darwin') return { encrypted, backend: 'the macOS Keychain' };
    if (this.platform === 'win32') return { encrypted, backend: 'Windows (DPAPI)' };
    let name = '';
    try {
      name = this.safe.getSelectedStorageBackend();
    } catch (e) {}
    // basic_text is Chromium's stand-in when no keyring exists: a key that is
    // the same on every machine. That is not protection, so it is not called
    // protection here, whatever isEncryptionAvailable() says.
    if (name === 'basic_text') return { encrypted: false, backend: 'none' };
    return { encrypted, backend: LINUX_BACKENDS[name] || 'the system keyring' };
  }

  file(ns) {
    if (!NAMESPACES.has(ns)) throw new Error('unknown vault compartment: ' + ns);
    return path.join(this.dir, ns + '.json');
  }

  /**
   * The stored string, or null when nothing was stored yet.
   *
   * Throws when something is stored but cannot be read — a keyring that is
   * locked or gone, a file that is not what this wrote. The app must then
   * stop and say so rather than carry on with a fresh identity, because its
   * next save would write over the one that could not be read.
   */
  get(ns) {
    const file = this.file(ns);
    let raw;
    try {
      raw = fs.readFileSync(file, 'utf8');
    } catch (e) {
      if (e.code === 'ENOENT') return null;
      throw e;
    }
    let rec = null;
    try {
      rec = JSON.parse(raw);
    } catch (e) {}
    if (!rec || rec.v !== 1 || typeof rec.data !== 'string' || typeof rec.enc !== 'boolean') {
      throw new Error(`${file} is not something this browser wrote`);
    }
    if (!rec.enc) return rec.data;
    if (!this.encryptionAvailable()) {
      throw new Error(
        'these keys are protected by the system keychain, which is not available right now'
      );
    }
    return this.safe.decryptString(Buffer.from(rec.data, 'base64'));
  }

  /** Stores the string. Resolves once it is on disk. */
  set(ns, value) {
    const file = this.file(ns);
    if (typeof value !== 'string') return Promise.reject(new Error('the vault stores strings'));
    if (Buffer.byteLength(value, 'utf8') > MAX_BYTES) {
      return Promise.reject(new Error('too large for the vault'));
    }
    const prev = this._chains.get(ns) || Promise.resolve();
    const next = prev.catch(() => {}).then(() => this._write(file, value));
    this._chains.set(ns, next);
    return next;
  }

  _write(file, value) {
    const enc = this.encryptionAvailable();
    const rec = {
      v: 1,
      enc,
      data: enc ? this.safe.encryptString(value).toString('base64') : value,
    };
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    const tmp = `${file}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(rec), { mode: 0o600 });
    fs.renameSync(tmp, file);
  }
}

module.exports = { VaultStore, NAMESPACES, MAX_BYTES };
