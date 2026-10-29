// A package is refused unless it runs the Electron and the Tor the repository
// pins, on the Chromium its user agent claims, with no stale app code.
//
// The v1.0.0 packages were refreshed from older ones by refresh-release.js,
// which swapped the app and kept the runtime: they went out on Electron
// 33.4.11 (Chromium 130) and Tor 15.0.22 while lib/electron.js and lib/tor.js
// said 44.9.3 and 15.0.26, under a Chrome 152 user agent. This checks the
// refusals in lib/package-runtime.js on small stand-in packages, that
// refresh-release.js applies them to its inputs before building anything
// and to its outputs, that patch-zip.js refuses app/src files the tree no
// longer has and leaves a macOS package's helper apps as Electron made them,
// and that check-engine.js reads the version out of the binary. With the
// official Electron zip in a cache, it also checks a package laid out from
// it passes; with the published 1.0.0 Linux package in dist/release-in, that
// it is refused. No network.
//
//   node hidra-browser/test/release-runtime.js

'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const { readZip, writeZip, mkFile, mkDir } = require('../scripts/lib/zip');
const rt = require('../scripts/lib/package-runtime');
const tor = require('../scripts/lib/tor');
const electron = require('../scripts/lib/electron');
const { patchZip } = require('../scripts/patch-zip');

let passed = 0, failed = 0;
async function check(name, fn) {
  try { await fn(); passed++; console.log('ok    ' + name); } catch (e) { failed++; console.log('FAIL  ' + name + '\n      ' + ((e && e.stack) || e)); }
}
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-runtime-'));
const contentsOf = (e) => (e.method === 8 ? require('zlib').inflateRawSync(e.rawData) : e.rawData);
const zipOf = (files) => readZip(writeZip(files.map(([n, d, m]) => (n.endsWith('/') ? mkDir(n) : mkFile(n, Buffer.from(d), m)))));

// What Electron writes into its main binary, and so what the check reads.
const engine = (e, c) => 'ELF\0padding\0Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/' + c +
  ' Electron/' + e + ' Safari/537.36\0more\0Chrome/' + c + '\0Electron/' + e + '\0';
const GOOD_ENGINE = engine(electron.ELECTRON_VER, rt.advertisedChromeMajor() + '.0.7977.167');

// A stand-in for the pinned Tor: its pins are swapped for the fixture's.
const TOR = { tor: 'the tor we ship', geoip: 'geoip data', geoip6: 'geoip6 data' };
const realPins = tor.PINS['linux-x64'];
tor.PINS['linux-x64'] = { tor: sha(TOR.tor), geoip: sha(TOR.geoip), geoip6: sha(TOR.geoip6) };
const LIBEVENT = fs.readFileSync(path.join(ROOT, 'vendor', 'linux-x64', 'libevent-2.1.so.7'));

const officialLinux = (bin = GOOD_ENGINE) => zipOf([
  ['electron', bin, 0o755], ['libffmpeg.so', 'ffmpeg'], ['chrome-sandbox', 'sandbox', 0o4755],
  ['locales/', ''], ['locales/en-US.pak', 'en'], ['locales/pt-BR.pak', 'pt'],
  ['resources/', ''], ['resources/default_app.asar', 'the default app'], ['version', electron.ELECTRON_VER],
]);
function linuxPackage({ prefix = '', bin = GOOD_ENGINE, drop = [], swap = {}, add = [], torFiles = TOR } = {}) {
  const files = [
    ['hidranet', bin, 0o755], ['libffmpeg.so', 'ffmpeg'], ['chrome-sandbox', 'sandbox', 0o4755],
    ['locales/en-US.pak', 'en'], ['locales/pt-BR.pak', 'pt'], ['version', electron.ELECTRON_VER],
    ['resources/app/package.json', '{}'], ['resources/app/src/main/main.js', 'main'], ['resources/app/build.json', '{}'],
    ['resources/bin/tor/libevent-2.1.so.7', LIBEVENT],
    ...Object.entries(torFiles).map(([n, d]) => ['resources/bin/tor/' + n, d]),
    ['start.sh', '#!/bin/sh', 0o755], ['LEIA-ME.txt', 'readme'],
    ...add,
  ].filter(([n]) => !drop.includes(n)).map(([n, d, m]) => [prefix + n, n in swap ? swap[n] : d, m]);
  return zipOf(files);
}

(async () => {
  // ── The runtime ─────────────────────────────────────────────────────────
  await check('a package laid out from the pinned Electron, with the pinned Tor, passes', async () => {
    const pkg = linuxPackage();
    assert.deepStrictEqual(rt.runtimeProblems(pkg, officialLinux(), 'linux'), []);
    assert.deepStrictEqual(rt.torProblems(pkg, 'linux', 'x64'), []);
    assert.deepStrictEqual(rt.engineProblems(pkg, 'linux'), []);
  });
  await check('so does one under a top folder, as build-linux.js writes it', async () => {
    const pkg = linuxPackage({ prefix: 'HidraNet-Linux-x64/' });
    assert.deepStrictEqual(rt.runtimeProblems(pkg, officialLinux(), 'linux'), []);
    assert.deepStrictEqual(rt.torProblems(pkg, 'linux', 'x64'), []);
    assert.deepStrictEqual(rt.engineProblems(pkg, 'linux'), []);
  });
  await check('an Electron file that differs from the pinned zip is refused', async () => {
    const p = rt.runtimeProblems(linuxPackage({ swap: { 'libffmpeg.so': 'an older ffmpeg' } }), officialLinux(), 'linux');
    assert.deepStrictEqual(p, ['libffmpeg.so is not the file of Electron ' + electron.ELECTRON_VER]);
  });
  await check('the main binary of another Electron is refused', async () => {
    const old = engine('33.4.11', '130.0.6723.191');
    const pkg = linuxPackage({ bin: old });
    assert.ok(rt.runtimeProblems(pkg, officialLinux(), 'linux').includes('hidranet is not the file of Electron ' + electron.ELECTRON_VER));
    assert.deepStrictEqual(rt.engineProblems(pkg, 'linux'), [
      'the engine is Electron 33.4.11, not ' + electron.ELECTRON_VER,
      'the engine is Chromium 130.0.6723.191 but the user agent says Chrome ' + rt.advertisedChromeMajor(),
    ]);
  });
  await check('a missing Electron file, or one from somewhere else, is refused', async () => {
    const p = rt.runtimeProblems(linuxPackage({ drop: ['locales/pt-BR.pak'], add: [['libevil.so', 'x']] }), officialLinux(), 'linux');
    assert.deepStrictEqual(p.sort(), ['libevil.so comes from neither Electron ' + electron.ELECTRON_VER + ' nor HidraNet',
      'the Electron file locales/pt-BR.pak is missing'].sort());
  });
  await check('an engine whose Chromium is not the one the user agent claims is refused', async () => {
    const p = rt.engineProblems(linuxPackage({ bin: engine(electron.ELECTRON_VER, '151.0.1.2') }), 'linux');
    assert.deepStrictEqual(p, ['the engine is Chromium 151.0.1.2 but the user agent says Chrome ' + rt.advertisedChromeMajor()]);
    assert.ok(rt.engineProblems(linuxPackage({ bin: 'no version in here' }), 'linux').length === 2);
    const two = engine(electron.ELECTRON_VER, '152.0.1.2') + engine('33.4.11', '152.0.1.2');
    assert.ok(/names no single Electron version/.test(rt.engineProblems(linuxPackage({ bin: two }), 'linux').join()));
  });
  await check('the user agent the check compares with is the one engine.js advertises', async () => {
    assert.strictEqual(rt.advertisedChromeMajor("'Mozilla/5.0 (X11) Chrome/152.0.0.0 Safari' 'Mozilla/5.0 (Win) Chrome/152.0.0.0 S'"), '152');
    assert.throws(() => rt.advertisedChromeMajor("'Mozilla/5.0 Chrome/152.0.0.0' 'Mozilla/5.0 Chrome/151.0.0.0'"), /exactly one/);
  });

  // ── Tor ─────────────────────────────────────────────────────────────────
  await check('a Tor that is not the pinned one is refused, file by file', async () => {
    const p = rt.torProblems(linuxPackage({ torFiles: { ...TOR, tor: 'tor 15.0.22' } }), 'linux', 'x64');
    assert.strictEqual(p.length, 1);
    assert.ok(/^Tor: tor is not the pinned Tor 15\.0\.26/.test(p[0]), p[0]);
    const q = rt.torProblems(linuxPackage({ torFiles: { tor: TOR.tor, geoip: TOR.geoip } }), 'linux', 'x64');
    assert.deepStrictEqual(q, ['Tor: geoip6 is missing']);
  });
  await check('Tor\'s folder holds nothing else: no stray file, an honest .version, the vendored libevent', async () => {
    assert.deepStrictEqual(rt.torProblems(linuxPackage({ torFiles: { ...TOR, torrc: 'x' } }), 'linux', 'x64'),
      ['Tor: torrc is not part of the pinned Tor']);
    assert.deepStrictEqual(rt.torProblems(linuxPackage({ torFiles: { ...TOR, '.version': '15.0.22\n' } }), 'linux', 'x64'),
      ['Tor: .version says "15.0.22", not ' + tor.TOR_VERSION]);
    assert.deepStrictEqual(rt.torProblems(linuxPackage({ torFiles: { ...TOR, '.version': tor.TOR_VERSION + '\n' } }), 'linux', 'x64'), []);
    assert.deepStrictEqual(rt.torProblems(linuxPackage({ swap: { 'resources/bin/tor/libevent-2.1.so.7': 'other' } }), 'linux', 'x64'),
      ['Tor: libevent-2.1.so.7 is not the one in vendor/linux-x64/']);
  });

  // ── Names the builders change ───────────────────────────────────────────
  await check('macOS and Windows: the renamed binaries and the patched plist and icon are expected', async () => {
    const mac = zipOf([
      ['Electron.app/Contents/MacOS/Electron', 'stub'], ['Electron.app/Contents/Info.plist', 'com.github.Electron'],
      ['Electron.app/Contents/Resources/electron.icns', 'atom'], ['Electron.app/Contents/Resources/default_app.asar', 'x'],
      ['Electron.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework', GOOD_ENGINE],
      ['Electron.app/Contents/_CodeSignature/CodeResources', 'sig'],
    ]);
    const macPkg = zipOf([
      ['HidraNet.app/Contents/MacOS/HidraNet', 'stub'], ['HidraNet.app/Contents/Info.plist', 'net.hidra.browser'],
      ['HidraNet.app/Contents/Resources/electron.icns', 'hydra'],
      ['HidraNet.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework', GOOD_ENGINE],
      ['HidraNet.app/Contents/Resources/app/package.json', '{}'], ['Start HidraNet.command', 'x'], ['README-macOS.txt', 'x'],
    ]);
    assert.deepStrictEqual(rt.runtimeProblems(macPkg, mac, 'darwin'), []);
    assert.deepStrictEqual(rt.engineProblems(macPkg, 'darwin'), []);
    const win = zipOf([['electron.exe', GOOD_ENGINE], ['ffmpeg.dll', 'f'], ['resources/default_app.asar', 'x']]);
    const winPkg = zipOf([['HidraNet.exe', GOOD_ENGINE], ['ffmpeg.dll', 'f'], ['resources/app/package.json', '{}'],
      ['resources/bin/hidra-node.exe', 'engine'], ['Start HidraNet.bat', 'x']]);
    assert.deepStrictEqual(rt.runtimeProblems(winPkg, win, 'win32'), []);
    assert.deepStrictEqual(rt.engineProblems(winPkg, 'win32'), []);
    assert.deepStrictEqual(rt.platformOf('HidraNet-Browser-1.1.0-macOS-arm64.zip'), { platform: 'darwin', arch: 'arm64' });
  });

  // ── Stale app code ──────────────────────────────────────────────────────
  await check('patch-zip.js refuses a package carrying app/src files the tree no longer has', async () => {
    const zip = path.join(tmp, 'HidraNet-Browser-1.0.0-Linux-x64.zip');
    const main = fs.readFileSync(path.join(ROOT, 'src', 'main', 'main.js'));
    fs.writeFileSync(zip, writeZip([mkFile('resources/app/src/main/main.js', main),
      mkFile('resources/app/src/main/removed-for-a-reason.js', Buffer.from('old code'))]));
    assert.throws(() => patchZip(zip, path.join(tmp, 'out.zip'), { dry: true }), /no longer has: main\/removed-for-a-reason\.js/);
    fs.writeFileSync(zip, writeZip([mkFile('resources/app/src/main/main.js', main)]));
    assert.doesNotThrow(() => patchZip(zip, path.join(tmp, 'out.zip'), { dry: true }));
  });

  // ── refresh-release.js applies all of it ────────────────────────────────
  const refresher = require('../scripts/refresh-release');
  const baseName = 'HidraNet-Browser-' + refresher.BASE_VERSION + '-Linux-x64.zip';
  // A base package on disk, the official zip it is checked against, and
  // stand-ins for the engine build and patch-zip that record being called.
  async function refreshWith(pkgOpts, opts) {
    const inDir = fs.mkdtempSync(path.join(tmp, 'in-'));
    fs.writeFileSync(path.join(inDir, baseName), writeZip(linuxPackage(pkgOpts)));
    const calls = [];
    const r = await refresher.refresh({
      inDir, outDir: path.join(inDir, 'out'), names: [baseName],
      electronFor: async () => officialLinux(),
      engine: () => { calls.push('engine'); throw new Error('stopped before building'); },
      patch: () => { calls.push('patch'); },
      ...opts,
    }).catch((e) => ({ thrown: e.message }));
    return { r, calls };
  }
  await check('refresh-release.js refuses a base package on a Tor that is not pinned, before building anything', async () => {
    const { r, calls } = await refreshWith({ torFiles: { ...TOR, tor: 'tor 15.0.22' } }, { version: '9.9.9' });
    assert.deepStrictEqual(r, { ok: false, stage: 'base' });
    assert.deepStrictEqual(calls, []);
  });
  await check('… and one on another Electron, also with --verify-inputs-only', async () => {
    const old = engine('33.4.11', '130.0.6723.191');
    for (const verifyOnly of [false, true]) {
      const { r, calls } = await refreshWith({ bin: old }, { version: '9.9.9', verifyOnly });
      assert.deepStrictEqual(r, { ok: false, stage: 'base' });
      assert.deepStrictEqual(calls, []);
    }
  });
  await check('refresh-release.js refuses to give a refreshed package the base version', async () => {
    const { r, calls } = await refreshWith({}, { version: refresher.BASE_VERSION });
    assert.deepStrictEqual(r, { ok: false, stage: 'version' });
    assert.deepStrictEqual(calls, []);
  });
  await check('a base package that runs what is pinned passes the input checks, and only then is built on', async () => {
    assert.deepStrictEqual((await refreshWith({}, { version: '9.9.9', verifyOnly: true })).r, { ok: true, stage: 'verified' });
    const { r, calls } = await refreshWith({}, { version: '9.9.9' });
    assert.deepStrictEqual(r, { thrown: 'stopped before building' });
    assert.deepStrictEqual(calls, ['engine']);
  });
  await check('refresh-release.js checks every output with the same runtime checks and against the tree', async () => {
    const src = fs.readFileSync(path.join(ROOT, 'scripts', 'refresh-release.js'), 'utf8');
    assert.ok(/for \(const n of names\) await verify\(path\.join\(outDir, outName\(n\)\), version, electronFor\)/.test(src), 'the outputs are not verified');
    assert.ok(/const rt = await runtimeProblemsOf\(file, electronFor\)/.test(src), 'the outputs\' runtime is not checked');
    assert.ok(/appSourceProblems\(es, pfx\)/.test(src), 'the outputs\' app/src is not compared with the tree');
  });

  // ── macOS: what patch-zip changes is what the check expects ─────────────
  await check('a macOS package refreshed by patch-zip.js still has Electron\'s own helper apps', async () => {
    const { patchPlist } = require('../scripts/lib/mac-extras');
    const plist = (id) => '<plist><dict><key>CFBundleIdentifier</key><string>' + id + '</string>' +
      '<key>CFBundleShortVersionString</key><string>' + electron.ELECTRON_VER + '</string></dict></plist>';
    const HELPER = 'Contents/Frameworks/Electron Helper.app/Contents/Info.plist';
    const FRAMEWORK = 'Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework';
    const official = zipOf([
      ['Electron.app/Contents/MacOS/Electron', 'stub'], ['Electron.app/Contents/Info.plist', plist('com.github.Electron')],
      ['Electron.app/' + HELPER, plist('com.github.Electron.helper')], ['Electron.app/' + FRAMEWORK, GOOD_ENGINE],
    ]);
    // Laid out as build-mac.js writes it: only the outer plist patched.
    const files = [
      mkFile('HidraNet.app/Contents/MacOS/HidraNet', Buffer.from('stub')),
      mkFile('HidraNet.app/Contents/Info.plist', Buffer.from(patchPlist(plist('com.github.Electron'), 'HidraNet', 'net.hidra.browser', '1.0.0'))),
      mkFile('HidraNet.app/' + HELPER, Buffer.from(plist('com.github.Electron.helper'))),
      mkFile('HidraNet.app/' + FRAMEWORK, Buffer.from(GOOD_ENGINE)),
    ];
    (function walk(dir, rel) {
      for (const n of fs.readdirSync(dir).sort()) {
        const abs = path.join(dir, n);
        if (fs.statSync(abs).isDirectory()) walk(abs, rel + n + '/');
        else files.push(mkFile('HidraNet.app/Contents/Resources/app/src/' + rel + n, fs.readFileSync(abs)));
      }
    })(path.join(ROOT, 'src'), '');
    const base = path.join(tmp, 'HidraNet-Browser-1.0.0-macOS-arm64.zip');
    const out = path.join(tmp, 'HidraNet-Browser-9.9.9-macOS-arm64.zip');
    fs.writeFileSync(base, writeZip(files));
    assert.deepStrictEqual(rt.runtimeProblems(readZip(fs.readFileSync(base)), official, 'darwin'), []);
    patchZip(base, out, { version: '9.9.9' });
    const es = readZip(fs.readFileSync(out));
    assert.deepStrictEqual(rt.runtimeProblems(es, official, 'darwin'), []);
    const main = es.find((e) => e.filename === 'HidraNet.app/Contents/Info.plist');
    const text = (main.method === 8 ? require('zlib').inflateRawSync(main.rawData) : main.rawData).toString();
    assert.ok(/net\.hidra\.browser/.test(text) && /<string>9\.9\.9<\/string>/.test(text), text);
  });

  // ── check-engine.js ─────────────────────────────────────────────────────
  await check('check-engine.js fails a package on another Electron or another Tor and passes the pinned ones', async () => {
    const pkg = require('../package.json');
    const write = (name, bin) => {
      const f = path.join(tmp, name);
      fs.writeFileSync(f, writeZip([mkFile('hidranet', Buffer.from(bin), 0o755), mkFile('resources/app/package.json', Buffer.from('{}'))]));
      return f;
    };
    const old = write(`HidraNet-Browser-${pkg.version}-Linux-x64.zip`, engine('33.4.11', '130.0.6723.191'));
    const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'check-engine.js'), old], { encoding: 'utf8' });
    assert.strictEqual(r.status, 1, r.stdout);
    assert.ok(/Electron 33\.4\.11, not 44\.9\.3/.test(r.stdout), r.stdout);
    // The pinned Electron with no Tor, or another Tor, does not pass either:
    // the 1.0.0 packages carried Tor 15.0.22, and the launch checklist reads
    // this check's output for the Tor version as well as Electron's.
    const noTor = write('HidraNet-Browser-9.9.9-Linux-x64.zip', GOOD_ENGINE);
    const r2 = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'check-engine.js'), noTor], { encoding: 'utf8' });
    assert.strictEqual(r2.status, 1, r2.stdout);
    assert.ok(/not the pinned Tor/.test(r2.stdout) && /Tor: tor is missing/.test(r2.stdout), r2.stdout);
    // In this process the fixture's Tor is the pinned one (see TOR above), so
    // the same package with it passes, and says which Tor it found.
    const { checkPackage } = require('../scripts/check-engine');
    const ok = path.join(tmp, 'HidraNet-Browser-9.9.9-Linux-x64.zip');
    fs.writeFileSync(ok, writeZip(linuxPackage().map((e) => mkFile(e.filename, contentsOf(e), e.filename === 'hidranet' ? 0o755 : 0o644))));
    const good = checkPackage(ok);
    assert.deepStrictEqual(good.problems, []);
    assert.ok(/Electron 44\.9\.3, Chromium 152\.[\d.]+, Tor /.test(good.seen) && good.seen.indexOf(tor.TOR_VERSION) !== -1, good.seen);
    fs.writeFileSync(ok, writeZip(linuxPackage({ torFiles: Object.assign({}, TOR, { tor: 'another tor' }) })
      .map((e) => mkFile(e.filename, contentsOf(e)))));
    const swapped = checkPackage(ok);
    assert.ok(swapped.problems.some((p) => /Tor: tor is not the pinned Tor/.test(p)), swapped.problems.join('; '));
  });

  // ── build-win.js ────────────────────────────────────────────────────────
  // update-sums.js compares every Electron file of a package with the
  // official zip, and build-win.js used to keep Electron's default_app.asar,
  // which that comparison expects the builders to drop: every Windows
  // package it built was refused, so the table could not be written.
  await check('build-win.js lays Electron\'s win32 zip out the way the runtime check expects', async () => {
    const { runtimeEntries } = require('../scripts/build-win');
    const win = zipOf([['electron.exe', GOOD_ENGINE], ['ffmpeg.dll', 'f'], ['resources/', ''],
      ['resources/default_app.asar', 'the default app'], ['locales/', ''], ['locales/en-US.pak', 'en']]);
    const laid = runtimeEntries(win, 'win32 fixture');
    assert.ok(!laid.some((e) => /default_app\.asar/.test(e.filename)), laid.map((e) => e.filename).join(', '));
    assert.ok(laid.some((e) => e.filename === 'HidraNet.exe') && !laid.some((e) => e.filename === 'electron.exe'));
    laid.push(mkFile('resources/app/package.json', Buffer.from('{}')));
    assert.deepStrictEqual(rt.runtimeProblems(laid, win, 'win32'), []);
    assert.deepStrictEqual(rt.engineProblems(laid, 'win32'), []);
    assert.throws(() => runtimeEntries(zipOf([['ffmpeg.dll', 'f']])), /no electron\.exe/);
  });

  // ── Where the builders write ────────────────────────────────────────────
  await check('the builders take --out <folder>, make it, and default to the Desktop', async () => {
    const { outArgs, writePackage } = require('../scripts/lib/out-dir');
    assert.deepStrictEqual(outArgs(['x64', '--out', 'pkgs']), { out: path.resolve('pkgs'), rest: ['x64'] });
    assert.deepStrictEqual(outArgs(['--out', '/tmp/a', 'arm64']), { out: path.resolve('/tmp/a'), rest: ['arm64'] });
    assert.deepStrictEqual(outArgs([]), { out: path.join(os.homedir(), 'Desktop'), rest: [] });
    assert.throws(() => outArgs(['--out']), /--out needs a folder/);
    assert.throws(() => outArgs(['--out', '--engine', 'x']), /--out needs a folder/);
    const where = path.join(tmp, 'no', 'such', 'folder');
    const file = writePackage(where, 'p.zip', Buffer.from('zip'));
    assert.strictEqual(fs.readFileSync(file, 'utf8'), 'zip');
    for (const b of ['build-linux.js', 'build-mac.js', 'build-win.js']) {
      const src = fs.readFileSync(path.join(ROOT, 'scripts', b), 'utf8');
      assert.ok(/outArgs\(process\.argv\.slice\(2\)\)/.test(src) && /writePackage\(OUT_DIR, outName/.test(src) &&
                !/homedir\(\)/.test(src), b + ' does not write through lib/out-dir.js');
    }
  });

  // ── Against the real files, when they are on this machine ───────────────
  tor.PINS['linux-x64'] = realPins;
  const zipName = electron.zipName('linux', 'x64');
  const cacheDirs = [path.join(ROOT, 'dist', 'electron-cache'), path.join(os.homedir(), '.cache', 'electron')];
  let official = null;
  for (const d of cacheDirs) {
    const found = [path.join(d, zipName), ...(fs.existsSync(d) ? fs.readdirSync(d).map((s) => path.join(d, s, zipName)) : [])]
      .find((f) => fs.existsSync(f));
    if (found) { official = found; break; }
  }
  if (official) {
    await check('the official Electron ' + electron.ELECTRON_VER + ' zip, laid out as build-linux.js does, passes', async () => {
      electron.verifyElectronZip(official);
      const entries = readZip(fs.readFileSync(official));
      const laid = entries.filter((e) => e.filename.indexOf('default_app.asar') === -1)
        .map((e) => Object.assign({}, e, { filename: e.filename === 'electron' ? 'hidranet' : e.filename }));
      laid.push(mkFile('resources/app/package.json', Buffer.from('{}')));
      assert.deepStrictEqual(rt.runtimeProblems(laid, entries, 'linux'), []);
      assert.deepStrictEqual(rt.engineProblems(laid, 'linux'), []);
    });
  } else {
    console.log('skip  no official ' + zipName + ' in a cache to lay a package out from');
  }
  const officialWin = path.join(ROOT, 'dist', 'electron-cache', electron.zipName('win32', 'x64'));
  if (fs.existsSync(officialWin)) {
    await check('the official Electron ' + electron.ELECTRON_VER + ' win32 zip, laid out by build-win.js, passes', async () => {
      electron.verifyElectronZip(officialWin);
      const entries = readZip(fs.readFileSync(officialWin));
      const laid = require('../scripts/build-win').runtimeEntries(entries);
      laid.push(mkFile('resources/app/package.json', Buffer.from('{}')));
      assert.deepStrictEqual(rt.runtimeProblems(laid, entries, 'win32'), []);
      assert.deepStrictEqual(rt.engineProblems(laid, 'win32'), []);
    });
  } else {
    console.log('skip  no official ' + electron.zipName('win32', 'x64') + ' in dist/electron-cache to lay a package out from');
  }
  const published = path.join(ROOT, 'dist', 'release-in', 'HidraNet-Browser-1.0.0-Linux-x64.zip');
  if (fs.existsSync(published)) {
    await check('the published 1.0.0 Linux package is refused: Electron 33, Chromium 130, Tor 15.0.22', async () => {
      const es = readZip(fs.readFileSync(published));
      const engineP = rt.engineProblems(es, 'linux');
      assert.ok(engineP.some((p) => /Electron 33\.4\.11/.test(p)) && engineP.some((p) => /Chromium 130\./.test(p)), engineP.join('; '));
      assert.ok(rt.torProblems(es, 'linux', 'x64').some((p) => /tor is not the pinned Tor/.test(p)));
      if (official) assert.ok(rt.runtimeProblems(es, readZip(fs.readFileSync(official)), 'linux').length > 0);
    });
  } else {
    console.log('skip  no published 1.0.0 Linux package in dist/release-in to check');
  }

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})();
