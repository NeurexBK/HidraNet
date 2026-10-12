// The vault against Electron's real safeStorage.
//
//   cd hidra-browser && xvfb-run -a npx electron test/vault-electron.js
//
// test/vault.js proves the store's logic with a stand-in cipher. This proves
// the store speaks safeStorage's actual API — Buffer in, Buffer out, base64
// round trip — on the Electron that ships. A test machine has no keyring, so
// safeStorage is told to use its in-memory key here; that makes the result
// worthless as protection and fine for checking the plumbing, and the product
// never does it: see the status() in vault.js.

const { app, safeStorage } = require('electron');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { VaultStore } = require('../src/main/vault');

if (process.platform === 'linux' && typeof safeStorage.setUsePlainTextEncryption === 'function') {
  safeStorage.setUsePlainTextEncryption(true); // TEST ONLY
}

let failed = 0;
const check = (ok, label, detail) => {
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${label}${ok || !detail ? '' : `\n        ${detail}`}`);
};

app.on('window-all-closed', () => {});

app.whenReady().then(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-vault-e-'));
  const vault = new VaultStore(dir, safeStorage);
  check(vault.encryptionAvailable(), 'safeStorage reports encryption available', 'without it this test proves nothing');

  // A mailbox-sized record, with characters outside ASCII.
  const big = JSON.stringify({ ids: [{ addr: 'zz@hidra', d: 'private-key-bytes' }], box: { inbox: Array.from({ length: 200 }, (_, i) => ({ mid: 'm' + i, body: 'Olá, 世界 — message ' + i + ' ' + 'x'.repeat(400) })) } });
  await vault.set('mail', big);
  check(vault.get('mail') === big, `a ${Math.round(big.length / 1024)} KB record round-trips through safeStorage`);
  const onDisk = fs.readFileSync(path.join(dir, 'mail.json'), 'utf8');
  check(JSON.parse(onDisk).enc === true, 'the file says it is encrypted');
  check(!onDisk.includes('private-key-bytes') && !onDisk.includes('zz@hidra'), 'and holds neither the key nor the address in clear');

  // A second store over the same directory reads what the first wrote: the
  // key is the OS's, not this process's.
  const again = new VaultStore(dir, safeStorage);
  check(again.get('mail') === big, 'a fresh store reads the same file back');

  const st = vault.status();
  console.log(`      backend reported: ${st.backend} (encrypted: ${st.encrypted})`);

  fs.rmSync(dir, { recursive: true, force: true });
  console.log(failed ? `\n${failed} check(s) failed` : '\nthe vault works against the real safeStorage');
  app.exit(failed ? 1 : 0);
});
