// Installing HidraVPN from the browser: nothing runs that the release key did
// not sign, every file is checked against the signed manifest, and the only
// thing executed with administrator rights is the service from that folder,
// with arguments that cannot be turned into a command.
//
//   node hidra-browser/test/vpn-installer.js

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { VpnInstaller, parseManifest, compareVersions, installedService } = require('../src/main/vpn-installer');

let passed = 0;
let failed = 0;
async function check(name, fn) {
  try {
    await fn();
    passed++;
    console.log('ok    ' + name);
  } catch (e) {
    failed++;
    console.log('FAIL  ' + name + '\n      ' + (e && e.stack ? e.stack.split('\n').slice(0, 3).join('\n      ') : e));
  }
}

// A release key of our own for the test, made the way hidravpn-sign does:
// Ed25519, the public half as raw base64.
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const PUB = publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64');
const sign = (text) => crypto.sign(null, Buffer.from(text, 'utf8'), privateKey).toString('base64');
const other = crypto.generateKeyPairSync('ed25519').privateKey;

const FILES = {
  'hidravpn-service': Buffer.from('#!/bin/sh\necho service\n'),
  hidravpn: Buffer.from('#!/bin/sh\necho client\n'),
  'hidravpn-service.exe': Buffer.from('MZ service'),
  'hidravpn.exe': Buffer.from('MZ client'),
  'wintun.dll': Buffer.from('MZ wintun'),
};
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const entry = (name) => ({ name, url: `https://hidranet.org/vpn/release/0.5.0/${name}`, sha256: sha(FILES[name]), size: FILES[name].length });

function manifest(overrides = {}) {
  return JSON.stringify({
    product: 'hidravpn',
    version: '0.5.0',
    generated: '2026-10-14T00:00:00Z',
    platforms: {
      'linux-x64': { files: [entry('hidravpn-service'), entry('hidravpn')], service: 'hidravpn-service', client: 'hidravpn' },
      'win32-x64': {
        files: [entry('hidravpn-service.exe'), entry('hidravpn.exe'), entry('wintun.dll')],
        service: 'hidravpn-service.exe',
        client: 'hidravpn.exe',
      },
    },
    ...overrides,
  }, null, 2);
}

// A fake release server and a fake elevation: what was fetched and what was
// run, and what the folder held when it ran.
function rig({ text = manifest(), sig, files = FILES, platform = 'linux', runCode = 0, user = 'joao' } = {}) {
  const fetched = [];
  const ran = [];
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hv-inst-test-'));
  const inst = new VpnInstaller({
    manifestUrl: 'https://hidranet.org/vpn/release/manifest.json',
    publicKey: PUB,
    platform,
    arch: 'x64',
    tmpRoot,
    user,
    env: { ProgramFiles: 'C:\\Program Files' },
    fetchText: async (url) => {
      fetched.push(url);
      if (url.endsWith('.sig')) return sig !== undefined ? sig : sign(text);
      return text;
    },
    fetchBuffer: async (url) => {
      fetched.push(url);
      const name = url.split('/').pop();
      if (!files[name]) throw new Error('404');
      return files[name];
    },
    run: async (file, args, env) => {
      const folder = args.length && fs.existsSync(path.dirname(args[0])) ? path.dirname(args[0]) : null;
      const svc = env.HV_FILE || args[0];
      ran.push({ file, args, env, present: svc && fs.existsSync(svc) ? fs.readFileSync(svc) : null, folder });
      return { code: runCode, stdout: 'installed', stderr: runCode ? 'boom' : '' };
    },
  });
  return { inst, fetched, ran, tmpRoot };
}

(async () => {
  await check('a signed manifest is read; its version and this platform are reported', async () => {
    const { inst } = rig();
    const r = await inst.checkRelease();
    assert.deepStrictEqual([r.ok, r.version, r.supported], [true, '0.5.0', true]);
  });

  await check('a manifest signed by another key is refused before a file is fetched', async () => {
    const t = manifest();
    const { inst, fetched, ran } = rig({ text: t, sig: crypto.sign(null, Buffer.from(t), other).toString('base64') });
    const r = await inst.install();
    assert.strictEqual(r.ok, false);
    assert.ok(/not signed by the HidraVPN release key/.test(r.error), r.error);
    assert.ok(fetched.every((u) => /manifest\.json(\.sig)?$/.test(u)), fetched.join(' '));
    assert.strictEqual(ran.length, 0);
  });

  await check('a manifest changed after signing is refused', async () => {
    const good = manifest();
    const { inst, ran } = rig({ text: good.replace('0.5.0', '0.5.1'), sig: sign(good) });
    const r = await inst.install();
    assert.strictEqual(r.ok, false);
    assert.strictEqual(ran.length, 0);
  });

  await check('with no release key built in, nothing is trusted', async () => {
    const { inst } = rig();
    inst.publicKey = '';
    const r = await inst.checkRelease();
    assert.strictEqual(r.ok, false);
    assert.ok(/no release key/.test(r.error), r.error);
  });

  await check('a file that does not match the signed SHA-256 stops the install, and nothing runs', async () => {
    const tampered = { ...FILES, hidravpn: Buffer.from('#!/bin/sh\necho EVIL\n') };
    // Same size, other bytes: only the hash can tell.
    tampered.hidravpn = Buffer.alloc(FILES.hidravpn.length, 0x41);
    const { inst, ran } = rig({ files: tampered });
    const r = await inst.install();
    assert.strictEqual(r.ok, false);
    assert.ok(/does not match the signed manifest/.test(r.error), r.error);
    assert.strictEqual(ran.length, 0);
  });

  await check('a file of the wrong size stops the install, and nothing runs', async () => {
    const { inst, ran } = rig({ files: { ...FILES, hidravpn: Buffer.from('short') } });
    const r = await inst.install();
    assert.strictEqual(r.ok, false);
    assert.ok(/bytes; the signed manifest says/.test(r.error), r.error);
    assert.strictEqual(ran.length, 0);
  });

  await check('Linux: pkexec runs the checked service from its folder, with the client and this user', async () => {
    const { inst, ran, tmpRoot } = rig();
    const r = await inst.install();
    assert.strictEqual(r.ok, true, r.error);
    assert.strictEqual(ran.length, 1);
    const [{ file, args, present }] = ran;
    assert.strictEqual(file, 'pkexec');
    assert.ok(args[0].startsWith(tmpRoot) && args[0].endsWith('/hidravpn-service'), args[0]);
    assert.deepStrictEqual(args.slice(1), ['install', '--client', path.join(path.dirname(args[0]), 'hidravpn'), '--user', 'joao']);
    assert.deepStrictEqual(present, FILES['hidravpn-service'], 'the file that ran is the one the manifest vouched for');
    assert.ok(/Log out and in once/.test(r.note), r.note);
    assert.deepStrictEqual(fs.readdirSync(tmpRoot), [], 'the download folder is removed afterwards');
  });

  await check('the download folder is private to this account', async () => {
    const { inst, tmpRoot } = rig();
    let mode = null;
    inst.run = async (file, args) => {
      mode = fs.statSync(path.dirname(args[0])).mode & 0o777;
      return { code: 0, stdout: '', stderr: '' };
    };
    await inst.install();
    assert.strictEqual(mode, 0o700, mode && mode.toString(8));
    assert.deepStrictEqual(fs.readdirSync(tmpRoot), []);
  });

  await check('Linux: a dismissed password prompt is reported as cancelled, not as a failure', async () => {
    const { inst } = rig({ runCode: 126 });
    const r = await inst.install();
    assert.deepStrictEqual([r.ok, r.cancelled], [false, true]);
  });

  await check('Windows: UAC runs the service with the arguments passed as data, never inside the command', async () => {
    const { inst, ran } = rig({ platform: 'win32' });
    const r = await inst.install();
    assert.strictEqual(r.ok, true, r.error);
    const [{ file, args, env }] = ran;
    assert.strictEqual(file, 'powershell.exe');
    const script = args[args.length - 1];
    assert.ok(/-Verb RunAs/.test(script) && /\$env:HV_FILE/.test(script), script);
    assert.ok(!script.includes('hidravpn-service.exe'), 'no path inside the command');
    assert.ok(env.HV_FILE.endsWith('hidravpn-service.exe'));
    const passedArgs = JSON.parse(env.HV_ARGS);
    assert.deepStrictEqual(passedArgs.slice(0, 2), ['install', '--client']);
    assert.ok(!passedArgs.includes('--user'), 'the group step is Linux only');
  });

  await check('Windows: saying no to UAC is reported as cancelled', async () => {
    const { inst } = rig({ platform: 'win32', runCode: 1223 });
    const r = await inst.install();
    assert.deepStrictEqual([r.ok, r.cancelled], [false, true]);
  });

  await check('macOS is refused plainly', async () => {
    const { inst, ran } = rig({ platform: 'darwin' });
    const r = await inst.install();
    assert.strictEqual(r.ok, false);
    assert.ok(/macOS/.test(r.error));
    assert.strictEqual(ran.length, 0);
  });

  await check('a release with no build for this platform installs nothing', async () => {
    const { inst, ran } = rig({ text: manifest({ platforms: { 'win32-x64': JSON.parse(manifest()).platforms['win32-x64'] } }) });
    const r = await inst.install();
    assert.strictEqual(r.ok, false);
    assert.ok(/no build for linux-x64/.test(r.error), r.error);
    assert.strictEqual(ran.length, 0);
  });

  await check('uninstall runs the installed service; --purge only when asked', async () => {
    const { inst, ran } = rig();
    assert.strictEqual((await inst.uninstall(false)).ok, true);
    assert.strictEqual((await inst.uninstall(true)).ok, true);
    assert.deepStrictEqual(ran[0].args, ['/usr/local/bin/hidravpn-service', 'uninstall']);
    assert.deepStrictEqual(ran[1].args, ['/usr/local/bin/hidravpn-service', 'uninstall', '--purge']);
    assert.strictEqual(installedService('win32', { ProgramFiles: 'C:\\Program Files' }), path.join('C:\\Program Files', 'HidraVPN', 'hidravpn-service.exe'));
  });

  await check('the manifest refuses names that climb, plain http, bad hashes and an unnamed service', async () => {
    const base = JSON.parse(manifest());
    const variants = [
      (m) => { m.platforms['linux-x64'].files[1].name = '../hidravpn'; },
      (m) => { m.platforms['linux-x64'].files[1].url = 'http://hidranet.org/x'; },
      (m) => { m.platforms['linux-x64'].files[1].sha256 = 'zz'; },
      (m) => { m.platforms['linux-x64'].service = 'missing'; },
      (m) => { m.platforms['linux-x64'].files[1].size = 10 ** 12; },
      (m) => { m.product = 'other'; },
      (m) => { m.version = 'latest'; },
    ];
    for (const change of variants) {
      const m = JSON.parse(JSON.stringify(base));
      change(m);
      assert.throws(() => parseManifest(JSON.stringify(m)), undefined, change.toString());
    }
    assert.strictEqual(parseManifest(JSON.stringify(base)).version, '0.5.0');
  });

  await check('versions compare as numbers', async () => {
    assert.strictEqual(compareVersions('0.4.10', '0.4.9'), 1);
    assert.strictEqual(compareVersions('0.5.0', '0.5.0'), 0);
    assert.strictEqual(compareVersions('', '0.1.0'), -1);
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})();
