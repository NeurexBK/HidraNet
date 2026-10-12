// The vault: the apps' keys are encrypted at rest, and an app opens only its
// own compartment.
//
//   cd hidra-browser && node test/vault.js
//
// safeStorage is Electron's and needs a running app, so it is stood in for
// here with a real cipher; test/vault-electron.js runs the same store against
// the real thing.

require('./lib/no-electron');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { VaultStore, NAMESPACES } = require('../src/main/vault');
const { appNamespace, vaultNamespaceOf } = require('../src/main/tab-manager');

let failed = 0;
const check = (ok, label, detail) => {
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${label}${ok || !detail ? '' : `\n        ${detail}`}`);
};
const throws = (fn, rx) => {
  try {
    fn();
  } catch (e) {
    return rx.test(e.message) ? true : `threw the wrong thing: ${e.message}`;
  }
  return 'did not throw';
};

// A stand-in for safeStorage with a real cipher, and a switch for "no
// keyring on this machine".
function fakeSafeStorage() {
  const key = crypto.randomBytes(32);
  return {
    available: true,
    backend: 'gnome_libsecret',
    isEncryptionAvailable() { return this.available; },
    getSelectedStorageBackend() { return this.backend; },
    encryptString(s) {
      const iv = crypto.randomBytes(12);
      const c = crypto.createCipheriv('aes-256-gcm', key, iv);
      const ct = Buffer.concat([c.update(s, 'utf8'), c.final()]);
      return Buffer.concat([iv, c.getAuthTag(), ct]);
    },
    decryptString(buf) {
      const d = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
      d.setAuthTag(buf.subarray(12, 28));
      return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
    },
  };
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-vault-'));
const safe = fakeSafeStorage();
const vault = new VaultStore(dir, safe, 'linux');

(async () => {
  // ── Encrypted at rest ───────────────────────────────────────────────────
  const secret = JSON.stringify({ ids: [{ addr: 'abc@hidra', privJwk: { d: 'the-private-key' } }] });
  check(vault.get('mail') === null, 'nothing stored reads as null');
  await vault.set('mail', secret);
  check(vault.get('mail') === secret, 'what was stored is read back');
  const onDisk = fs.readFileSync(path.join(dir, 'mail.json'), 'utf8');
  check(!onDisk.includes('the-private-key') && !onDisk.includes('abc@hidra'),
    'the file on disk carries neither the key nor the address in clear');
  check(JSON.parse(onDisk).enc === true, 'the file says it is encrypted');
  check((fs.statSync(path.join(dir, 'mail.json')).mode & 0o777) === 0o600, 'the file is readable by this user only');
  check((fs.statSync(dir).mode & 0o777) === 0o700, 'so is the directory');
  check(!fs.readdirSync(dir).some((f) => f.endsWith('.tmp')), 'no temporary file is left behind');

  // ── Many quick writes land in order ─────────────────────────────────────
  const writes = [];
  for (let i = 0; i < 40; i++) writes.push(vault.set('forum', 'v' + i));
  await Promise.all(writes);
  check(vault.get('forum') === 'v39', 'the last of forty rapid writes is what remains', vault.get('forum'));

  // ── Each app has its own compartment, and nothing else does ────────────
  check([...NAMESPACES].sort().join() === 'chat,forum,mail,publish', 'the compartments are the four apps that hold an identity');
  check(throws(() => vault.get('search'), /unknown vault compartment/) === true, 'an unknown compartment is refused');
  check(throws(() => vault.get('../mail'), /unknown vault compartment/) === true, 'a path is not a compartment');
  let rejected = false;
  await vault.set('chat', { not: 'a string' }).catch(() => { rejected = true; });
  check(rejected, 'only strings are stored');
  rejected = false;
  await vault.set('chat', 'x'.repeat(17 * 1024 * 1024)).catch(() => { rejected = true; });
  check(rejected, 'an absurd size is refused');

  // ── Which page may open which compartment ───────────────────────────────
  const APPS = 'http://127.0.0.1:8090';
  const NS = [
    [`${APPS}/mail`, 'mail'], [`${APPS}/mail/`, 'mail'], [`${APPS}/mail?x#y`, 'mail'],
    [`${APPS}/`, 'chat'], [`${APPS}`, 'chat'],
    [`${APPS}/forum`, 'forum'], [`${APPS}/publish`, 'publish'], [`${APPS}/sites`, 'publish'],
    [`${APPS}/search`, null], [`${APPS}/reviews`, null], [`${APPS}/site?addr=x`, null], [`${APPS}/donate`, null],
    [`${APPS}/mailbox`, null], ['http://localhost:8090/mail', null], ['https://127.0.0.1:8090/mail', null],
    ['http://127.0.0.1:8084/', null], ['https://example.com/mail', null], ['file:///tmp/x.html', null], ['nonsense', null],
  ];
  for (const [url, want] of NS) {
    check(appNamespace(url) === want, `${url} → ${want === null ? 'no compartment' : want}`, String(appNamespace(url)));
  }

  // The rule main.js applies to every IPC call: the top frame's own URL.
  const frame = (url) => ({ url });
  const top = frame(`${APPS}/mail`);
  const sub = frame(`${APPS}/mail`);
  check(vaultNamespaceOf({ senderFrame: top, sender: { mainFrame: top } }) === 'mail', 'a call from the mail page opens mail');
  check(vaultNamespaceOf({ senderFrame: sub, sender: { mainFrame: top } }) === null, 'a call from a subframe opens nothing, whatever its URL');
  check(vaultNamespaceOf({ senderFrame: null, sender: { mainFrame: top } }) === null, 'a call with no frame opens nothing');
  const web = frame('https://example.com/');
  check(vaultNamespaceOf({ senderFrame: web, sender: { mainFrame: web } }) === null, 'a website opens nothing');

  // ── Unreadable means stop, never start over ─────────────────────────────
  safe.available = false;
  check(throws(() => vault.get('mail'), /keychain.*not available/) === true,
    'encrypted data with the keychain gone is an error, not null');
  await vault.set('publish', 'plain-list');
  check(JSON.parse(fs.readFileSync(path.join(dir, 'publish.json'), 'utf8')).enc === false,
    'with no keychain the file says so');
  check(vault.get('publish') === 'plain-list', 'and reads back');
  check(vault.status().encrypted === false && vault.status().backend === 'none', 'status says unprotected');
  safe.available = true;
  fs.writeFileSync(path.join(dir, 'chat.json'), 'not json at all');
  check(throws(() => vault.get('chat'), /not something this browser wrote/) === true, 'a file that is not ours is an error');
  fs.writeFileSync(path.join(dir, 'chat.json'), JSON.stringify({ v: 1, enc: 'yes', data: 'x' }));
  check(throws(() => vault.get('chat'), /not something this browser wrote/) === true, 'a record with the wrong shape is an error');

  // ── Status names the thing protecting the data ──────────────────────────
  check(new VaultStore(dir, safe, 'darwin').status().backend === 'the macOS Keychain', 'macOS: the Keychain');
  check(new VaultStore(dir, safe, 'win32').status().backend === 'Windows (DPAPI)', 'Windows: DPAPI');
  check(new VaultStore(dir, safe, 'linux').status().backend === 'GNOME Keyring', 'Linux: the keyring found');
  safe.backend = 'kwallet6';
  check(new VaultStore(dir, safe, 'linux').status().backend === 'KWallet', 'Linux: KWallet');
  safe.backend = 'basic_text';
  check(new VaultStore(dir, safe, 'linux').status().encrypted === false,
    'Linux: Chromium\'s fixed fallback key is not called protection');

  fs.rmSync(dir, { recursive: true, force: true });
  console.log(failed ? `\n${failed} check(s) failed` : '\nthe vault keeps the keys encrypted, one compartment per app');
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error('vault test crashed:', e.stack);
  process.exit(1);
});
