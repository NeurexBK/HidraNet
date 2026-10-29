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

const { VpnInstaller, parseManifest, compareVersions, versionMark, installable, NOT_INSTALLABLE, installedService, LINUX_INSTALL_SCRIPT, MIN_VERSION } = require('../src/main/vpn-installer');
const { RELEASE_PUBLIC_KEY } = require('../src/main/release-verify');
const { execFile } = require('child_process');

const VERSION_OK = (v) => /^\d{1,4}\.\d{1,4}\.\d{1,4}$/.test(v);

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
    const [, , , , base, src, service, client, user, downgrade, ...pairs] = args;
    const files = [];
    for (let i = 0; i + 1 < pairs.length; i += 2) files.push({ name: pairs[i], sha256: pairs[i + 1] });
    return { base, src, service, client, user, downgrade: downgrade === '1', files };
  }
  const inner = Buffer.from(env.HV_CMD || '', 'base64').toString('utf16le');
  const b64 = (inner.match(/FromBase64String\('([A-Za-z0-9+/=]+)'\)/) || [])[1] || '';
  return { inner, ...JSON.parse(Buffer.from(b64, 'base64').toString('utf8') || '{}') };
}

// What the page passes install() after checkRelease() showed it `text`.
const approval = (text) => ({ version: JSON.parse(text).version, digest: sha(Buffer.from(text, 'utf8')) });

// The installed copy on this machine, if any, is never read: `installedMark`
// is stood in for unless a test passes its own (or undefined, for the real one).
function rig({ text = manifest(), sig, files = FILES, platform = 'linux', runCode = 0, user = 'joao', env = { ProgramFiles: 'C:\\Program Files' }, ...more } = {}) {
  const fetched = [];
  const ran = [];
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hv-inst-test-'));
  const inst = new VpnInstaller({
    installedMark: async () => null,
    ...more,
    manifestUrl: 'https://hidranet.org/vpn/release/manifest.json',
    publicKey: PUB,
    platform,
    arch: 'x64',
    tmpRoot,
    user,
    env,
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
  // The server's answer can change between fetches: `serve` swaps it.
  const serve = (t, g) => { text = t; sig = g; };
  return { inst, fetched, ran, tmpRoot, approved: approval(text), serve };
}

(async () => {
  await check('a signed manifest is read; its version and this platform are reported', async () => {
    const { inst } = rig();
    const r = await inst.checkRelease();
    assert.deepStrictEqual([r.ok, r.version, r.supported], [true, '0.5.0', true]);
  });

  await check('a manifest signed by another key is refused before a file is fetched', async () => {
    const t = manifest();
    const { inst, fetched, ran, approved } = rig({ text: t, sig: crypto.sign(null, Buffer.from(t), other).toString('base64') });
    const r = await inst.install(approved);
    assert.strictEqual(r.ok, false);
    assert.ok(/not signed by the HidraVPN release key/.test(r.error), r.error);
    assert.ok(fetched.every((u) => /manifest\.json(\.sig)?$/.test(u)), fetched.join(' '));
    assert.strictEqual(ran.length, 0);
  });

  await check('a manifest changed after signing is refused', async () => {
    const good = manifest();
    const { inst, ran, approved } = rig({ text: good.replace('0.5.0', '0.5.1'), sig: sign(good) });
    const r = await inst.install(approved);
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
    const { inst, approved, ran } = rig({ files: tampered });
    const r = await inst.install(approved);
    assert.strictEqual(r.ok, false);
    assert.ok(/does not match the signed manifest/.test(r.error), r.error);
    assert.strictEqual(ran.length, 0);
  });

  await check('a file of the wrong size stops the install, and nothing runs', async () => {
    const { inst, approved, ran } = rig({ files: { ...FILES, hidravpn: Buffer.from('short') } });
    const r = await inst.install(approved);
    assert.strictEqual(r.ok, false);
    assert.ok(/bytes; the signed manifest says/.test(r.error), r.error);
    assert.strictEqual(ran.length, 0);
  });

  await check('Linux: one pkexec, running the fixed copy-and-check script with the manifest\'s hashes as data', async () => {
    const { inst, approved, ran, tmpRoot } = rig();
    const r = await inst.install(approved);
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
    const { inst, approved, tmpRoot } = rig();
    let mode = null;
    inst.run = async (file, args, env) => {
      mode = fs.statSync(elevatedPlan(file, args, env).src).mode & 0o777;
      return { code: 0, stdout: '', stderr: '' };
    };
    await inst.install(approved);
    assert.strictEqual(mode, 0o700, mode && mode.toString(8));
    assert.deepStrictEqual(fs.readdirSync(tmpRoot), []);
  });

  await check('Linux: a dismissed password prompt is reported as cancelled, not as a failure', async () => {
    const { inst, approved } = rig({ runCode: 126 });
    const r = await inst.install(approved);
    assert.deepStrictEqual([r.ok, r.cancelled], [false, true]);
  });

  // ── The swap, for real ─────────────────────────────────────────────────
  // Another program running as this user swaps the service in the download
  // folder after the browser checked it and before the root step runs. The
  // real script runs here (without pkexec, which would only ask for the
  // password); the stand-in for the root-only folder is a fresh temp folder.
  const realLinux = (swap, { tail = '', ...opts } = {}) => {
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'hv-swap-'));
    const privRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hv-priv-'));
    const marker = path.join(work, 'ran.txt');
    const files = {
      'hidravpn-service': Buffer.from(`#!/bin/sh\necho "genuine $*" >> '${marker}'\n${tail}`, 'latin1'),
      hidravpn: Buffer.from('#!/bin/sh\nexit 0\n'),
    };
    const own = (name) => ({ name, url: `https://hidranet.org/vpn/release/0.5.0/${name}`, sha256: sha(files[name]), size: files[name].length });
    const text = JSON.stringify({ product: 'hidravpn', version: '0.5.0', generated: '2026-10-14T00:00:00Z',
      platforms: { 'linux-x64': { files: [own('hidravpn-service'), own('hidravpn')], service: 'hidravpn-service', client: 'hidravpn' } } });
    const inst = new VpnInstaller({
      manifestUrl: 'https://hidranet.org/vpn/release/manifest.json', publicKey: PUB, platform: 'linux', arch: 'x64',
      tmpRoot: work, privRoot, user: 'joao', installedMark: async () => null, ...opts,
      fetchText: async (url) => (url.endsWith('.sig') ? sign(text) : text),
      fetchBuffer: async (url) => files[url.split('/').pop()],
      run: (file, args) => new Promise((resolve) => {
        assert.strictEqual(file, 'pkexec');
        if (swap) swap(args[5], work, marker);
        execFile(args[0], args.slice(1), (e, stdout, stderr) =>
          resolve({ code: e ? (typeof e.code === 'number' ? e.code : 1) : 0, stdout, stderr }));
      }),
    });
    return { inst, work, privRoot, marker, approved: approval(text) };
  };
  const evilScript = (marker) => `#!/bin/sh\necho "EVIL $*" >> '${marker}'\n`;

  await check('Linux, for real: the checked files run from the root-only copy', async () => {
    const { inst, approved, privRoot, marker } = realLinux(null);
    const r = await inst.install(approved);
    assert.strictEqual(r.ok, true, r.error);
    const ran = fs.readFileSync(marker, 'utf8').trim();
    const m = ran.match(/^genuine install --client (\S+) --user joao$/);
    assert.ok(m, ran);
    assert.ok(m[1].startsWith(privRoot + path.sep) && m[1].endsWith('/hidravpn'), `the client came from ${m[1]}`);
    assert.deepStrictEqual(fs.readdirSync(privRoot), [], 'the root-only copy is removed afterwards');
  });

  await check('Linux, for real: a service swapped after the check is never run', async () => {
    const { inst, approved, privRoot, marker } = realLinux((dir, _work, mk) => {
      fs.writeFileSync(path.join(dir, 'hidravpn-service'), evilScript(mk), { mode: 0o700 });
    });
    const r = await inst.install(approved);
    assert.strictEqual(r.ok, false, 'the install went ahead');
    assert.ok(/changed after it was checked/.test(r.error), r.error);
    assert.ok(!fs.existsSync(marker), `something ran: ${fs.existsSync(marker) ? fs.readFileSync(marker, 'utf8') : ''}`);
    assert.deepStrictEqual(fs.readdirSync(privRoot), [], 'nothing is left in the root-only folder');
  });

  await check('Linux, for real: a client swapped after the check stops the install too', async () => {
    const { inst, approved, marker } = realLinux((dir, _work, mk) => {
      fs.writeFileSync(path.join(dir, 'hidravpn'), evilScript(mk), { mode: 0o700 });
    });
    const r = await inst.install(approved);
    assert.strictEqual(r.ok, false);
    assert.ok(/changed after it was checked/.test(r.error), r.error);
    assert.ok(!fs.existsSync(marker), 'the service ran with a swapped client beside it');
  });

  await check('Linux, for real: a service swapped for a link to another program is never run', async () => {
    const { inst, approved, marker } = realLinux((dir, work, mk) => {
      const elsewhere = path.join(work, 'elsewhere.sh');
      fs.writeFileSync(elsewhere, evilScript(mk), { mode: 0o700 });
      fs.rmSync(path.join(dir, 'hidravpn-service'));
      fs.symlinkSync(elsewhere, path.join(dir, 'hidravpn-service'));
    });
    const r = await inst.install(approved);
    assert.strictEqual(r.ok, false);
    assert.ok(!fs.existsSync(marker), 'the program behind the link ran');
  });

  await check('Windows: one UAC prompt, for Windows\' own PowerShell, which copies, checks and only then runs', async () => {
    const { inst, approved, ran } = rig({ platform: 'win32' });
    const r = await inst.install(approved);
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
    const { inst, approved } = rig({ platform: 'win32', runCode: 65 });
    const r = await inst.install(approved);
    assert.strictEqual(r.ok, false);
    assert.ok(/changed after it was checked/.test(r.error), r.error);
  });

  await check('Windows: a service that installed but never answered is not reported as running', async () => {
    const { inst, approved } = rig({ platform: 'win32', runCode: 69 });
    const r = await inst.install(approved);
    assert.deepStrictEqual([r.ok, r.installed, r.version], [false, true, '0.5.0']);
    assert.ok(/is installed, but its service did not answer/.test(r.error), r.error);
    assert.ok(/restart this computer/.test(r.error), r.error);
    assert.ok(!/installed and running/.test(r.error), r.error);
  });

  await check('Linux: the same, with where to look', async () => {
    const { inst, approved } = rig({ runCode: 69 });
    const r = await inst.install(approved);
    assert.deepStrictEqual([r.ok, r.installed], [false, true]);
    assert.ok(/systemctl status hidravpn/.test(r.error), r.error);
  });

  await check('Windows: saying no to UAC is reported as cancelled', async () => {
    const { inst, approved } = rig({ platform: 'win32', runCode: 1223 });
    const r = await inst.install(approved);
    assert.deepStrictEqual([r.ok, r.cancelled], [false, true]);
  });

  await check('macOS is refused plainly', async () => {
    const { inst, approved, ran } = rig({ platform: 'darwin' });
    const r = await inst.install(approved);
    assert.strictEqual(r.ok, false);
    assert.ok(/macOS/.test(r.error));
    assert.strictEqual(ran.length, 0);
  });

  await check('the page is told the same: only Windows and Linux have an installer', async () => {
    assert.deepStrictEqual(['win32', 'linux', 'darwin'].map((p) => installable(p)), [true, true, false]);
    const { inst, approved } = rig({ platform: 'darwin' });
    assert.strictEqual((await inst.install(approved)).error, NOT_INSTALLABLE);
  });

  await check('a release with no build for this platform installs nothing', async () => {
    const { inst, approved, ran } = rig({ text: manifest({ platforms: { 'win32-x64': JSON.parse(manifest()).platforms['win32-x64'] } }) });
    const r = await inst.install(approved);
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

  // ── Only forward, only what was shown ───────────────────────────────────
  await check('install() needs the release check-release reported; without it nothing is fetched', async () => {
    const { inst, fetched, ran } = rig();
    for (const bad of [undefined, null, {}, { version: '0.5.0' }, { version: '0.5.0', digest: 'zz' }, { version: 'x', digest: sha(Buffer.from('x')) }]) {
      const r = await inst.install(bad);
      assert.strictEqual(r.ok, false);
      assert.ok(/check for the release first/.test(r.error), r.error);
    }
    assert.deepStrictEqual([fetched.length, ran.length], [0, 0]);
  });

  await check('a manifest that changed between the check and the install stops it before a download', async () => {
    // The page was shown 0.5.0; the next answer is an older, genuinely
    // signed release.
    const { inst, fetched, ran, serve } = rig();
    const c = await inst.checkRelease();
    assert.ok(c.ok && /^[0-9a-f]{64}$/.test(c.digest), JSON.stringify(c));
    const older = manifest({ version: '0.4.0' });
    serve(older, sign(older));
    const r = await inst.install({ version: c.version, digest: c.digest });
    assert.strictEqual(r.ok, false);
    assert.ok(/changed between the check \(0\.5\.0\) and the install \(0\.4\.0\)/.test(r.error), r.error);
    // The same version with other content is a different manifest too.
    const other050 = manifest({ generated: '2026-10-15T00:00:00Z' });
    serve(other050, sign(other050));
    const r2 = await inst.install({ version: c.version, digest: c.digest });
    assert.ok(!r2.ok && /changed between the check/.test(r2.error), r2.error);
    assert.ok(fetched.every((u) => /manifest\.json(\.sig)?$/.test(u)), fetched.join(' '));
    assert.strictEqual(ran.length, 0);
  });

  await check('a signed release older than the installed service is refused, unless the person agrees to go back', async () => {
    const asked = [];
    const { inst, fetched, ran, approved } = rig({
      text: manifest({ version: '0.4.0' }),
      installedVersion: async () => '0.5.0',
      confirmDowngrade: async (q) => { asked.push(q); return false; },
    });
    const r = await inst.install(approved);
    assert.strictEqual(r.ok, false);
    assert.ok(/HidraVPN 0\.5\.0 is installed, which is newer than the release offered \(0\.4\.0\)/.test(r.error), r.error);
    assert.deepStrictEqual(asked, [{ installed: '0.5.0', offered: '0.4.0' }]);
    assert.ok(fetched.every((u) => /manifest\.json(\.sig)?$/.test(u)), 'nothing was downloaded');
    assert.strictEqual(ran.length, 0);
    // With nobody to ask, the answer is no.
    const quiet = rig({ text: manifest({ version: '0.4.0' }), installedVersion: async () => '0.5.0' });
    const r2 = await quiet.inst.install(quiet.approved);
    assert.ok(!r2.ok && quiet.ran.length === 0, JSON.stringify(r2));
    // Agreeing goes ahead; the service is told it may replace a newer one
    // only when it carries its version, the mark of a build that knows how.
    for (const [service, told] of [[Buffer.from('MZ old service'), false], [Buffer.from('MZ service\0hidravpn-service-version=0.4.0\0', 'latin1'), true]]) {
      const files = { ...FILES, 'hidravpn-service': service };
      const t = JSON.parse(manifest({ version: '0.4.0' }));
      t.platforms['linux-x64'].files[0] = { ...t.platforms['linux-x64'].files[0], sha256: sha(service), size: service.length };
      const text = JSON.stringify(t);
      const yes = rig({ text, files, installedVersion: async () => '0.5.0', confirmDowngrade: async () => true });
      const r3 = await yes.inst.install(yes.approved);
      assert.strictEqual(r3.ok, true, r3.error);
      assert.strictEqual(yes.ran[0].plan.downgrade, told, `downgrade flag for ${service}`);
    }
  });

  await check('the same or a newer release installs without a question, and the service is not told to downgrade', async () => {
    for (const installed of ['0.5.0', '0.4.9', null, 'garbage']) {
      const asked = [];
      const { inst, ran, approved } = rig({ installedVersion: async () => installed, confirmDowngrade: async (q) => { asked.push(q); return true; } });
      const r = await inst.install(approved);
      assert.strictEqual(r.ok, true, `${installed}: ${r.error}`);
      assert.deepStrictEqual([asked.length, ran[0].plan.downgrade], [0, false], String(installed));
    }
    // A service that cannot be asked, with no version on disk either (a
    // build from before the mark, or nothing installed), is no reason to
    // refuse.
    const { inst, approved } = rig({ installedVersion: async () => { throw new Error('no service'); } });
    assert.strictEqual((await inst.install(approved)).ok, true);
  });

  await check('a service that does not answer is still not gone back over: its version is read from the installed copy', async () => {
    // Stopped, or this account not yet in its group: status has no version.
    for (const status of [async () => null, async () => { throw new Error('no-permission'); }]) {
      const asked = [];
      const { inst, fetched, ran, approved } = rig({
        installedVersion: status,
        installedMark: async () => '0.6.0',
        confirmDowngrade: async (q) => { asked.push(q); return false; },
      });
      const r = await inst.install(approved);
      assert.ok(!r.ok && /HidraVPN 0\.6\.0 is installed, which is newer than the release offered \(0\.5\.0\)/.test(r.error), r.error);
      assert.deepStrictEqual(asked, [{ installed: '0.6.0', offered: '0.5.0' }]);
      assert.ok(fetched.every((u) => /manifest\.json(\.sig)?$/.test(u)) && ran.length === 0);
    }
    // The real reader: the installed service's own file (here on Windows,
    // under a Program Files of the test's own), never run.
    const pf = fs.mkdtempSync(path.join(os.tmpdir(), 'hv-pf-'));
    const exe = installedService('win32', { ProgramFiles: pf });
    fs.mkdirSync(path.dirname(exe), { recursive: true });
    const cases = [
      [Buffer.from('MZ service\0hidravpn-service-version=0.6.0\0', 'latin1'), 1],
      [Buffer.from('MZ service from before the mark', 'latin1'), 0],
      [null, 0],
    ];
    for (const [bytes, questions] of cases) {
      fs.rmSync(exe, { force: true });
      if (bytes) fs.writeFileSync(exe, bytes);
      const asked = [];
      const { inst, approved } = rig({
        platform: 'win32', env: { ProgramFiles: pf }, installedMark: undefined,
        installedVersion: async () => null,
        confirmDowngrade: async (q) => { asked.push(q); return false; },
      });
      const r = await inst.install(approved);
      assert.strictEqual(asked.length, questions, String(bytes));
      assert.strictEqual(r.ok, questions === 0, r.error);
    }
    // What the service says comes first when it does answer.
    const { inst, approved } = rig({ installedVersion: async () => '0.5.0', installedMark: async () => { throw new Error('not read'); } });
    assert.strictEqual((await inst.install(approved)).ok, true);
    fs.rmSync(pf, { recursive: true, force: true });
  });

  await check('Linux, for real: going back, agreed to, reaches the service as --allow-downgrade', async () => {
    const { inst, approved, marker } = realLinux(null, {
      tail: 'exit 0\n\0hidravpn-service-version=0.5.0\0',
      installedVersion: async () => '0.6.0',
      confirmDowngrade: async () => true,
    });
    const r = await inst.install(approved);
    assert.strictEqual(r.ok, true, r.error);
    const ran = fs.readFileSync(marker, 'utf8').trim();
    assert.ok(/^genuine install --client \S+ --user joao --allow-downgrade$/.test(ran), ran);
  });

  await check('Windows: going back, agreed to, is in the elevated plan, and the script passes it on', async () => {
    const service = Buffer.from('MZ service\0hidravpn-service-version=0.5.0\0', 'latin1');
    const t = JSON.parse(manifest());
    t.platforms['win32-x64'].files[0] = { ...t.platforms['win32-x64'].files[0], sha256: sha(service), size: service.length };
    const text = JSON.stringify(t);
    const { inst, ran, approved } = rig({ platform: 'win32', text, files: { ...FILES, 'hidravpn-service.exe': service },
      installedVersion: async () => '0.6.0', confirmDowngrade: async () => true });
    const r = await inst.install(approved);
    assert.strictEqual(r.ok, true, r.error);
    assert.strictEqual(ran[0].plan.downgrade, true);
    assert.ok(ran[0].plan.inner.includes("if($d.downgrade){$a+='--allow-downgrade'}"), ran[0].plan.inner);
  });

  await check('an expired manifest is refused, by the check and by the install', async () => {
    const text = manifest({ sequence: 3, expires: '2026-11-01T00:00:00Z' });
    const before = Date.parse('2026-10-31T23:00:00Z');
    const after = Date.parse('2026-11-01T00:00:01Z');
    const ok = rig({ text, now: () => before });
    const c = await ok.inst.checkRelease();
    assert.deepStrictEqual([c.ok, c.expires], [true, '2026-11-01T00:00:00Z'], JSON.stringify(c));
    const { inst, ran, fetched, approved } = rig({ text, now: () => after });
    const c2 = await inst.checkRelease();
    assert.strictEqual(c2.ok, false);
    assert.ok(/expired on 2026-11-01T00:00:00Z/.test(c2.error), c2.error);
    const r = await inst.install(approved);
    assert.ok(!r.ok && /expired/.test(r.error), r.error);
    assert.ok(fetched.every((u) => /manifest\.json(\.sig)?$/.test(u)) && ran.length === 0);
    // An expiry that is not a date is not "no expiry".
    for (const expires of ['soon', '2027-01-01', 20270101, '2027-13-01T00:00:00Z']) {
      assert.throws(() => parseManifest(manifest({ expires })), /expiry/, String(expires));
    }
    for (const sequence of [-1, 1.5, '7', 2 ** 60]) {
      assert.throws(() => parseManifest(manifest({ sequence })), /sequence/, String(sequence));
    }
  });

  await check('a manifest with a lower sequence than one already accepted is refused, across restarts', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hv-state-'));
    const stateFile = path.join(dir, 'vpn-release.json');
    const seq5 = manifest({ version: '0.5.0', sequence: 5 });
    const a = rig({ text: seq5, stateFile });
    assert.strictEqual((await a.inst.checkRelease()).ok, true);
    assert.deepStrictEqual(JSON.parse(fs.readFileSync(stateFile, 'utf8')), { sequence: 5 });
    assert.strictEqual(fs.statSync(stateFile).mode & 0o077, 0, 'the file is this account\'s alone');
    // The browser restarts; the server now answers with an older signed one.
    const seq4 = manifest({ version: '0.4.0', sequence: 4 });
    const b = rig({ text: seq4, stateFile });
    const c = await b.inst.checkRelease();
    assert.strictEqual(c.ok, false);
    assert.ok(/older \(sequence 4\) than one this browser already accepted \(sequence 5\)/.test(c.error), c.error);
    const r = await b.inst.install(b.approved);
    assert.ok(!r.ok && /refusing to go back/.test(r.error) && b.ran.length === 0, r.error);
    // So is one from before sequences: it counts as 0.
    const none = manifest({ version: '0.4.0' });
    const n = rig({ text: none, stateFile });
    assert.ok(/sequence 0/.test((await n.inst.checkRelease()).error || ''), 'a manifest without a sequence after sequence 5');
    // The same sequence again, and a higher one, are fine; the file only
    // ever goes up.
    assert.strictEqual((await rig({ text: seq5, stateFile }).inst.checkRelease()).ok, true);
    const seq9 = manifest({ version: '0.6.0', sequence: 9 });
    assert.strictEqual((await rig({ text: seq9, stateFile }).inst.checkRelease()).ok, true);
    assert.strictEqual(JSON.parse(fs.readFileSync(stateFile, 'utf8')).sequence, 9);
    await rig({ text: seq5, stateFile }).inst.checkRelease();
    assert.strictEqual(JSON.parse(fs.readFileSync(stateFile, 'utf8')).sequence, 9);
    // A write that failed is tried again on the next accept, not lost
    // because this run already knows the sequence.
    const gone = path.join(dir, 'not-yet', 'vpn-release.json');
    const w = rig({ text: seq9, stateFile: gone });
    assert.strictEqual((await w.inst.checkRelease()).ok, true);
    assert.ok(!fs.existsSync(gone));
    fs.mkdirSync(path.dirname(gone));
    assert.strictEqual((await w.inst.checkRelease()).ok, true);
    assert.deepStrictEqual(JSON.parse(fs.readFileSync(gone, 'utf8')), { sequence: 9 });
    // Without a file the floor holds for the run.
    const mem = rig({ text: seq5 });
    assert.strictEqual((await mem.inst.checkRelease()).ok, true);
    mem.serve(seq4, sign(seq4));
    assert.strictEqual((await mem.inst.checkRelease()).ok, false);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  await check('a release below the oldest this browser installs is refused', async () => {
    assert.ok(VERSION_OK(MIN_VERSION), MIN_VERSION);
    const { inst, ran, approved } = rig({ minVersion: '0.6.0' });
    const c = await inst.checkRelease();
    assert.ok(!c.ok && /0\.5\.0 is older than 0\.6\.0, the oldest this browser installs/.test(c.error), c.error);
    assert.ok(!(await inst.install(approved)).ok && ran.length === 0);
  });

  await check('the published manifest is accepted; the 0.1.0 one, from before sequence and expiry, as sequence 0', async () => {
    const dir = path.join(__dirname, '..', '..', 'landing', 'vpn', 'release');
    const text = fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8');
    const sig = fs.readFileSync(path.join(dir, 'manifest.json.sig'), 'utf8');
    const parsed = JSON.parse(text);
    // As on the day it was made: a later one expires in time.
    const { inst } = rig({ text, sig, now: () => Date.parse(parsed.generated) });
    inst.publicKey = RELEASE_PUBLIC_KEY;
    const c = await inst.checkRelease();
    assert.strictEqual(c.ok, true, c.error);
    assert.strictEqual(c.digest, sha(Buffer.from(text, 'utf8')));
    if (parsed.sequence === undefined) {
      assert.deepStrictEqual([c.version, c.expires, parseManifest(text).sequence], ['0.1.0', null, 0], JSON.stringify(c));
    } else {
      // Every manifest after 0.1.0 carries both.
      assert.ok(parsed.sequence > 0 && c.expires, JSON.stringify(c));
    }
  });

  await check('a service build\'s version is read from its bytes; a build from before the mark has none', async () => {
    assert.strictEqual(versionMark(Buffer.from('MZ\0hidravpn-service-version=0.4.10\0rest', 'latin1')), '0.4.10');
    assert.strictEqual(versionMark(Buffer.from('MZ hidravpn-service 0.1.0', 'latin1')), null);
    assert.strictEqual(versionMark(Buffer.from('\0hidravpn-service-version=0.4\0', 'latin1')), null);
    assert.strictEqual(versionMark(Buffer.from('\0hidravpn-service-version=junk\0\0hidravpn-service-version=0.2.0\0', 'latin1')), '0.2.0');
    // The same mark the service writes (install/mod.rs).
    const rs = fs.readFileSync(path.join(__dirname, '..', '..', 'hidravpn', 'crates', 'hidravpn-service', 'src', 'install', 'mod.rs'), 'utf8');
    assert.ok(rs.includes('"\\0hidravpn-service-version=",'), 'VERSION_MARK in install/mod.rs differs');
  });

  await check('versions compare as numbers', async () => {
    assert.strictEqual(compareVersions('0.4.10', '0.4.9'), 1);
    assert.strictEqual(compareVersions('0.5.0', '0.5.0'), 0);
    assert.strictEqual(compareVersions('', '0.1.0'), -1);
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})();
