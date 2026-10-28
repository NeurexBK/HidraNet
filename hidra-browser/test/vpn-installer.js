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

const { VpnInstaller, parseManifest, compareVersions, installedService, LINUX_INSTALL_SCRIPT } = require('../src/main/vpn-installer');
const { execFile } = require('child_process');

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
// What the elevated step was told: on Linux the arguments after the script,
// on Windows the base64 payload inside the encoded command.
function elevatedPlan(file, args, env) {
  if (file === 'pkexec') {
    const [, , , , base, src, service, client, user, ...pairs] = args;
    const files = [];
    for (let i = 0; i + 1 < pairs.length; i += 2) files.push({ name: pairs[i], sha256: pairs[i + 1] });
    return { base, src, service, client, user, files };
  }
  const inner = Buffer.from(env.HV_CMD || '', 'base64').toString('utf16le');
  const b64 = (inner.match(/FromBase64String\('([A-Za-z0-9+/=]+)'\)/) || [])[1] || '';
  return { inner, ...JSON.parse(Buffer.from(b64, 'base64').toString('utf8') || '{}') };
}

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
      let plan = null;
      let present = null;
      if (args[0] !== installedService(platform, { ProgramFiles: 'C:\\Program Files' })) {
        plan = elevatedPlan(file, args, env);
        const svc = plan.src && plan.service ? path.join(plan.src, plan.service) : null;
        present = svc && fs.existsSync(svc) ? fs.readFileSync(svc) : null;
      }
      ran.push({ file, args, env, plan, present, folder: plan && plan.src });
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

  await check('Linux: one pkexec, running the fixed copy-and-check script with the manifest\'s hashes as data', async () => {
    const { inst, ran, tmpRoot } = rig();
    const r = await inst.install();
    assert.strictEqual(r.ok, true, r.error);
    assert.strictEqual(ran.length, 1, 'one prompt, one elevated run');
    const [{ file, args, plan, present }] = ran;
    assert.strictEqual(file, 'pkexec');
    assert.deepStrictEqual(args.slice(0, 4), ['/bin/sh', '-c', LINUX_INSTALL_SCRIPT, 'hidravpn-install'],
      'the script is the fixed one; nothing about this release is spliced into it');
    assert.strictEqual(plan.base, '/var/lib', 'the copy is made in a root-only folder, not the download folder');
    assert.ok(plan.src.startsWith(tmpRoot), plan.src);
    assert.deepStrictEqual([plan.service, plan.client, plan.user], ['hidravpn-service', 'hidravpn', 'joao']);
    const signed = JSON.parse(manifest()).platforms['linux-x64'].files.map((f) => ({ name: f.name, sha256: f.sha256 }));
    assert.deepStrictEqual(plan.files, signed, 'the hashes the root step checks are the signed manifest\'s');
    assert.deepStrictEqual(present, FILES['hidravpn-service']);
    assert.ok(/Log out and in once/.test(r.note), r.note);
    assert.deepStrictEqual(fs.readdirSync(tmpRoot), [], 'the download folder is removed afterwards');
  });

  await check('the download folder is private to this account', async () => {
    const { inst, tmpRoot } = rig();
    let mode = null;
    inst.run = async (file, args, env) => {
      mode = fs.statSync(elevatedPlan(file, args, env).src).mode & 0o777;
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

  // ── The swap, for real ─────────────────────────────────────────────────
  // Another program running as this user swaps the service in the download
  // folder after the browser checked it and before the root step runs. The
  // real script runs here (without pkexec, which would only ask for the
  // password); the stand-in for the root-only folder is a fresh temp folder.
  const realLinux = (swap) => {
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'hv-swap-'));
    const privRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hv-priv-'));
    const marker = path.join(work, 'ran.txt');
    const files = {
      'hidravpn-service': Buffer.from(`#!/bin/sh\necho "genuine $*" >> '${marker}'\n`),
      hidravpn: Buffer.from('#!/bin/sh\nexit 0\n'),
    };
    const own = (name) => ({ name, url: `https://hidranet.org/vpn/release/0.5.0/${name}`, sha256: sha(files[name]), size: files[name].length });
    const text = JSON.stringify({ product: 'hidravpn', version: '0.5.0', generated: '2026-10-14T00:00:00Z',
      platforms: { 'linux-x64': { files: [own('hidravpn-service'), own('hidravpn')], service: 'hidravpn-service', client: 'hidravpn' } } });
    const inst = new VpnInstaller({
      manifestUrl: 'https://hidranet.org/vpn/release/manifest.json', publicKey: PUB, platform: 'linux', arch: 'x64',
      tmpRoot: work, privRoot, user: 'joao',
      fetchText: async (url) => (url.endsWith('.sig') ? sign(text) : text),
      fetchBuffer: async (url) => files[url.split('/').pop()],
      run: (file, args) => new Promise((resolve) => {
        assert.strictEqual(file, 'pkexec');
        if (swap) swap(args[5], work, marker);
        execFile(args[0], args.slice(1), (e, stdout, stderr) =>
          resolve({ code: e ? (typeof e.code === 'number' ? e.code : 1) : 0, stdout, stderr }));
      }),
    });
    return { inst, work, privRoot, marker };
  };
  const evilScript = (marker) => `#!/bin/sh\necho "EVIL $*" >> '${marker}'\n`;

  await check('Linux, for real: the checked files run from the root-only copy', async () => {
    const { inst, privRoot, marker } = realLinux(null);
    const r = await inst.install();
    assert.strictEqual(r.ok, true, r.error);
    const ran = fs.readFileSync(marker, 'utf8').trim();
    const m = ran.match(/^genuine install --client (\S+) --user joao$/);
    assert.ok(m, ran);
    assert.ok(m[1].startsWith(privRoot + path.sep) && m[1].endsWith('/hidravpn'), `the client came from ${m[1]}`);
    assert.deepStrictEqual(fs.readdirSync(privRoot), [], 'the root-only copy is removed afterwards');
  });

  await check('Linux, for real: a service swapped after the check is never run', async () => {
    const { inst, privRoot, marker } = realLinux((dir, _work, mk) => {
      fs.writeFileSync(path.join(dir, 'hidravpn-service'), evilScript(mk), { mode: 0o700 });
    });
    const r = await inst.install();
    assert.strictEqual(r.ok, false, 'the install went ahead');
    assert.ok(/changed after it was checked/.test(r.error), r.error);
    assert.ok(!fs.existsSync(marker), `something ran: ${fs.existsSync(marker) ? fs.readFileSync(marker, 'utf8') : ''}`);
    assert.deepStrictEqual(fs.readdirSync(privRoot), [], 'nothing is left in the root-only folder');
  });

  await check('Linux, for real: a client swapped after the check stops the install too', async () => {
    const { inst, marker } = realLinux((dir, _work, mk) => {
      fs.writeFileSync(path.join(dir, 'hidravpn'), evilScript(mk), { mode: 0o700 });
    });
    const r = await inst.install();
    assert.strictEqual(r.ok, false);
    assert.ok(/changed after it was checked/.test(r.error), r.error);
    assert.ok(!fs.existsSync(marker), 'the service ran with a swapped client beside it');
  });

  await check('Linux, for real: a service swapped for a link to another program is never run', async () => {
    const { inst, marker } = realLinux((dir, work, mk) => {
      const elsewhere = path.join(work, 'elsewhere.sh');
      fs.writeFileSync(elsewhere, evilScript(mk), { mode: 0o700 });
      fs.rmSync(path.join(dir, 'hidravpn-service'));
      fs.symlinkSync(elsewhere, path.join(dir, 'hidravpn-service'));
    });
    const r = await inst.install();
    assert.strictEqual(r.ok, false);
    assert.ok(!fs.existsSync(marker), 'the program behind the link ran');
  });

  await check('Windows: one UAC prompt, for Windows\' own PowerShell, which copies, checks and only then runs', async () => {
    const { inst, ran } = rig({ platform: 'win32' });
    const r = await inst.install();
    assert.strictEqual(r.ok, true, r.error);
    assert.strictEqual(ran.length, 1, 'one prompt, one elevated run');
    const [{ file, args, env, plan }] = ran;
    assert.strictEqual(file, 'powershell.exe');
    const outer = args[args.length - 1];
    assert.ok(/-Verb RunAs/.test(outer) && /GetFolderPath\('System'\)/.test(outer) && /\$env:HV_CMD/.test(outer), outer);
    assert.ok(!/hidravpn/i.test(outer), 'no file name inside the command');
    const inner = plan.inner;
    assert.ok(/GetFolderPath\('ProgramFiles'\)/.test(inner), 'the copy goes under Program Files, found without an environment variable');
    assert.ok(!/\$env:/.test(inner), 'the elevated script reads no environment variable this user could set');
    const checkAt = inner.indexOf('Get-FileHash');
    const mismatchAt = inner.indexOf('if($h -ne $f.sha256){exit 65}');
    const runAt = inner.indexOf('Start-Process');
    assert.ok(checkAt > 0 && mismatchAt > checkAt && runAt > mismatchAt, 'the copy is checked, and a mismatch exits, before anything runs');
    assert.ok(!inner.replace(/'[A-Za-z0-9+/=]+'/, "''").includes('hidravpn-service.exe'), 'file names travel only inside the base64 payload');
    const signed = JSON.parse(manifest()).platforms['win32-x64'].files.map((f) => ({ name: f.name, sha256: f.sha256 }));
    assert.deepStrictEqual(plan.files, signed);
    assert.deepStrictEqual([plan.service, plan.client], ['hidravpn-service.exe', 'hidravpn.exe']);
    assert.ok(env.HV_CMD && !('HV_FILE' in env), 'the plan travels encoded, not as a path to run');
  });

  await check('Windows: a copy that does not match is reported, not run', async () => {
    const { inst } = rig({ platform: 'win32', runCode: 65 });
    const r = await inst.install();
    assert.strictEqual(r.ok, false);
    assert.ok(/changed after it was checked/.test(r.error), r.error);
  });

  await check('Windows: a service that installed but never answered is not reported as running', async () => {
    const { inst } = rig({ platform: 'win32', runCode: 69 });
    const r = await inst.install();
    assert.deepStrictEqual([r.ok, r.installed, r.version], [false, true, '0.5.0']);
    assert.ok(/is installed, but its service did not answer/.test(r.error), r.error);
    assert.ok(/restart this computer/.test(r.error), r.error);
    assert.ok(!/installed and running/.test(r.error), r.error);
  });

  await check('Linux: the same, with where to look', async () => {
    const { inst } = rig({ runCode: 69 });
    const r = await inst.install();
    assert.deepStrictEqual([r.ok, r.installed], [false, true]);
    assert.ok(/systemctl status hidravpn/.test(r.error), r.error);
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
