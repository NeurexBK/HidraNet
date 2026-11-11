'use strict';

// scripts/launch-check.js: the checks run on launch day before the release
// branch is merged. A tree with everything in place passes; each thing left
// undone fails its own check, and only that one. The fixtures are signed
// with a key made here, never the release key.
const assert = require('assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const { launchCheck } = require('../scripts/launch-check');
const { browserSumsMessage } = require('../src/main/release-verify');
const { writeZip, mkFile, mkDir } = require('../scripts/lib/zip');

let passed = 0;
let failed = 0;
function check(name, fn) {
  try {
    fn();
    passed++;
    console.log('ok    ' + name);
  } catch (e) {
    failed++;
    console.log('FAIL  ' + name + '\n      ' + (e && e.stack ? e.stack.split('\n').slice(0, 3).join('\n      ') : e));
  }
}

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const PUB = publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('base64');
const other = crypto.generateKeyPairSync('ed25519').privateKey;
const signBytes = (bytes, key = privateKey) => crypto.sign(null, bytes, key).toString('base64');

const NOW = Date.parse('2026-11-01T12:00:00Z');
const RELEASES = 'https://github.com/NeurexBK/HidraNet/releases/download';
const PACKAGES = [
  // [platform, table label, megabytes of padding: a size of its own each]
  ['macOS-arm64', 'macOS arm64', 3],
  ['macOS-x64', 'macOS x64', 4],
  ['Linux-x64', 'Linux x64', 2],
  ['Windows-x64', 'Windows x64', 5],
];
const zip = (v, p) => `HidraNet-Browser-${v}-${p}.zip`;
const mb = (bytes) => String(Math.round(bytes / 1e6));
const group = (n) => n.toLocaleString('en-US');
const COMMIT = 'abc1234';

// A package as the builders lay it out (Linux under a folder of its own,
// Windows at the root, macOS inside the bundle), with the two lines the
// browser compiles in, its build.json and its app's package.json. The
// padding gives each a size of its own in megabytes.
const PAD = new Map(PACKAGES.map(([p, , m]) => [p, crypto.randomBytes(m * 1e6 + 123456)]));
function packageZip(p, { version = '1.1.0', min = '0.1.2', signed = true, build = COMMIT, appVersion = version, leave = [] } = {}) {
  const res = { 'macOS-arm64': 'HidraNet.app/Contents/Resources/', 'macOS-x64': 'HidraNet.app/Contents/Resources/',
    'Linux-x64': 'HidraNet-Linux-x64/resources/', 'Windows-x64': 'resources/' }[p];
  const app = res + 'app/';
  const files = {
    'package.json': JSON.stringify({ name: 'hidra-browser', version: appVersion, main: 'src/main/main.js' }),
    'build.json': JSON.stringify({ build, date: '2026-11-01' }) + '\n',
    'src/main/vpn-installer.js': `'use strict';\nconst MIN_VERSION = '${min}';\n`,
    'src/main/update-check.js': `'use strict';\nconst SUMS_SIGNED = ${signed};\n`,
  };
  const entries = [mkDir(app), mkDir(app + 'src/'), mkDir(app + 'src/main/')];
  for (const [rel, text] of Object.entries(files)) if (!leave.includes(rel)) entries.push(mkFile(app + rel, Buffer.from(text, 'utf8')));
  entries.push({ ...mkFile(res + 'pad', Buffer.alloc(0)), method: 0, crc: 0, compSz: PAD.get(p).length, uncompSz: PAD.get(p).length, rawData: PAD.get(p) });
  return writeZip(entries);
}

const dirs = [];
// A folder with the four packages; `change` maps a platform to packageZip's
// options, or to null to leave it out.
function packages(change = {}, version = '1.1.0') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-launch-packages-'));
  dirs.push(dir);
  for (const [p] of PACKAGES) {
    if (change[p] === null) continue;
    fs.writeFileSync(path.join(dir, zip(version, p)), packageZip(p, { version, ...change[p] }));
  }
  return dir;
}
// What the table says of each package in a folder: its hash and size.
function factsOf(dir, version = '1.1.0') {
  return new Map(PACKAGES.map(([p]) => {
    const file = path.join(dir, zip(version, p));
    const bytes = fs.existsSync(file) ? fs.readFileSync(file) : Buffer.from(p);
    return [p, { sha: crypto.createHash('sha256').update(bytes).digest('hex'), size: bytes.length }];
  }));
}
const DEFAULT_PACKAGES = packages();
const FACTS = factsOf(DEFAULT_PACKAGES);

function table(version = '1.1.0', { validUntil = '2027-04-30', extra = '', facts = FACTS, commit = COMMIT } = {}) {
  return [
    `HidraNet Browser ${version} — SHA-256 checksums`,
    '',
    'SIGNED RECORD',
    '',
    `  latest-version:        ${version}`,
    `  minimum-safe-version:  ${version}`,
    `  valid-until:           ${validUntil}`,
    '',
    extra,
    'ON THE RELEASE PAGE NOW',
    '',
    ...PACKAGES.map(([p]) => facts.get(p).sha + '  ' + zip(version, p)),
    '',
    ...PACKAGES.map(([p, label]) => `  ${label.padEnd(13)}  ${group(facts.get(p).size)} bytes  (${(facts.get(p).size / 1048576).toFixed(1)} MiB)`),
    '',
    ...(commit === null ? [] : [`  Built from commit ${commit}. These are the four files on the release page.`, '']),
  ].join('\n');
}

// The download blocks, in the markup of landing/index.html and /r/.
function homepage(version = '1.1.0', { size = (b) => mb(b), tag = `v${version}`, skip = null, download = (n) => n } = {}) {
  return '<html><body>\n' + PACKAGES.filter(([p]) => p !== skip).map(([p]) => [p, null, FACTS.get(p).size]).map(([p, , bytes]) =>
    `        <article class="dl reveal">\n          <h3>${p}</h3>\n` +
    `          <div class="meta">v${version} · x64 · ${size(bytes, p)} MB</div>\n` +
    `          <a class="b" href="${RELEASES}/${tag}/${zip(version, p)}" download="${download(zip(version, p))}" data-download="${p}">\n` +
    '            Free download\n          </a>\n        </article>\n').join('') + '</body></html>\n';
}
function reviewPage(version = '1.1.0', { size = (b) => mb(b) } = {}) {
  return '<div class="dl">\n' + PACKAGES.map(([p]) => [p, null, FACTS.get(p).size]).map(([p, , bytes]) =>
    `        <a href="${RELEASES}/v${version}/${zip(version, p)}"><span class="os">+</span>${p}<span class="sz">${size(bytes, p)} MB</span></a>\n`).join('') +
    '</div>\n';
}
const guide = (version = '1.1.0') =>
  '```bash\n' + `sha256sum ${zip(version, 'Linux-x64')}\n` + `Get-FileHash .\\${zip(version, 'Windows-x64')} -Algorithm SHA256\n` + '```\n';

function manifest({ version = '0.1.2', sequence = 2026110101, expires = '2027-01-01T00:00:00Z', url = null, platforms = ['linux-x64', 'win32-x64'] } = {}) {
  // `url(platform, name)` gives another address; the default is the asset
  // of the release's own tag, as the published 0.1.0 manifest has it.
  const file = (key, name) => ({ name, url: url ? url(key, name) : `${RELEASES}/hidravpn-v${version}/${name}`, sha256: 'a'.repeat(64), size: 1000 });
  const m = { product: 'hidravpn', version, generated: '2026-11-01T00:00:00Z' };
  // null leaves the field out, as in the manifests from before it existed.
  if (sequence !== null) m.sequence = sequence;
  if (expires !== null) m.expires = expires;
  const all = {
    'linux-x64': { service: 'hidravpn-service', client: 'hidravpn', files: ['hidravpn-service', 'hidravpn'] },
    'win32-x64': { service: 'hidravpn-service.exe', client: 'hidravpn.exe', files: ['hidravpn-service.exe', 'hidravpn.exe', 'wintun.dll'] },
  };
  m.platforms = {};
  for (const key of platforms) m.platforms[key] = { ...all[key], files: all[key].files.map((n) => file(key, n)) };
  return JSON.stringify(m, null, 2) + '\n';
}

const roots = [];
const packagesOf = new Map();
// A tree as it should be on launch day, with `change` applied on top:
// `change.packages` is packages()'s argument, and the table is then written
// from those packages; `change.packagesDir` gives a folder as it is (null:
// no --packages at all).
function tree(change = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-launch-check-'));
  roots.push(root);
  const pkgDir = 'packagesDir' in change ? change.packagesDir : change.packages ? packages(change.packages) : DEFAULT_PACKAGES;
  packagesOf.set(root, pkgDir);
  const files = {
    'landing/index.html': homepage(),
    'landing/r/index.html': reviewPage(),
    'docs/technical/07-installation-guide.md': guide(),
    'landing/vpn/release/manifest.json': manifest(),
    'landing/SHA256SUMS.txt': change.packages ? table('1.1.0', { facts: factsOf(pkgDir) }) : table(),
    'hidra-browser/package.json': JSON.stringify({ name: 'hidranet-browser', version: '1.1.0' }) + '\n',
    'hidra-browser/src/main/vpn-installer.js': "'use strict';\nconst MIN_VERSION = '0.1.2';\n",
    'hidra-browser/src/main/update-check.js': "'use strict';\nconst SUMS_SIGNED = true;\n",
    ...change.files,
  };
  for (const [rel, text] of Object.entries(files)) {
    if (text === null) continue;
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), text);
  }
  const sigs = {
    'landing/vpn/release/manifest.json.sig': () => signBytes(Buffer.from(files['landing/vpn/release/manifest.json'], 'utf8')),
    'landing/SHA256SUMS.txt.sig': () => signBytes(browserSumsMessage(Buffer.from(files['landing/SHA256SUMS.txt'], 'utf8'))),
    ...change.sigs,
  };
  for (const [rel, make] of Object.entries(sigs)) {
    if (make === null) continue;
    fs.writeFileSync(path.join(root, rel), make() + '\n');
  }
  if (change.after) change.after(root);
  return root;
}

const run = (root, now = NOW) => launchCheck({ root, packages: packagesOf.get(root), publicKey: PUB, now });
const failing = (r) => r.results.filter((x) => !x.ok).map((x) => x.name);
// Exactly one check fails, and its reason says why.
function failsOnly(r, name, reason) {
  assert.deepStrictEqual(failing(r), [name], JSON.stringify(r.results.filter((x) => !x.ok), null, 1));
  assert.equal(r.ok, false);
  const detail = r.results.find((x) => x.name === name).detail;
  assert.match(detail, reason);
}

const C = {
  min: 'MIN_VERSION is the HidraVPN release the site serves',
  msig: 'the HidraVPN manifest is signed by the release key',
  seq: 'the HidraVPN manifest has a sequence of at least 1',
  exp: 'the HidraVPN manifest has not expired',
  urls: 'the HidraVPN manifest\'s downloads are its own release\'s assets, for Linux and Windows',
  links: 'every download on the site and in the guide is a file the table lists',
  sizes: 'the size each page shows is the table\'s',
  flag: 'SUMS_SIGNED is true',
  ssig: 'SHA256SUMS.txt.sig is the release key\'s signature of the table',
  prose: 'the table no longer says it has no signature',
  ver: 'package.json\'s version is the table\'s latest-version',
  valid: 'the table\'s record has not expired',
  pkgs: 'the packages are the files the table lists',
  built: 'every package was built from the table\'s commit, from a clean tree, as its version',
  floor: 'every package refuses HidraVPN older than the published release and wants the table signed',
};

try {
  check('a tree with everything in place passes every check', () => {
    const r = run(tree());
    assert.deepStrictEqual(failing(r), []);
    assert.equal(r.ok, true);
    assert.deepStrictEqual(r.results.map((x) => x.name), Object.values(C));
  });

  check('MIN_VERSION other than the published HidraVPN fails', () => {
    for (const v of ['0.1.0', '0.1.3']) {
      const r = run(tree({ files: { 'hidra-browser/src/main/vpn-installer.js': `const MIN_VERSION = '${v}';\n` } }));
      failsOnly(r, C.min, new RegExp(`MIN_VERSION ${v.replace(/\./g, '\\.')}, .*HidraVPN 0\\.1\\.2`));
    }
  });

  check('a manifest without a signature, or not signed by the release key, fails', () => {
    failsOnly(run(tree({ sigs: { 'landing/vpn/release/manifest.json.sig': null } })), C.msig, /no landing.*manifest\.json\.sig/);
    failsOnly(run(tree({ sigs: { 'landing/vpn/release/manifest.json.sig': () => signBytes(Buffer.from(manifest(), 'utf8'), other) } })),
      C.msig, /not the release key's signature/);
    // Edited after it was signed.
    failsOnly(run(tree({ after: (root) => fs.appendFileSync(path.join(root, 'landing/vpn/release/manifest.json'), ' ') })),
      C.msig, /not the release key's signature/);
  });

  check('a manifest with no sequence, or sequence 0, fails', () => {
    failsOnly(run(tree({ files: { 'landing/vpn/release/manifest.json': manifest({ sequence: null }) } })), C.seq, /sequence is 0 \(it has none\)/);
    failsOnly(run(tree({ files: { 'landing/vpn/release/manifest.json': manifest({ sequence: 0 }) } })), C.seq, /sequence is 0:/);
  });

  check('a manifest with no expiry, or one that has passed, fails', () => {
    failsOnly(run(tree({ files: { 'landing/vpn/release/manifest.json': manifest({ expires: null }) } })), C.exp, /no expires/);
    failsOnly(run(tree({ files: { 'landing/vpn/release/manifest.json': manifest({ expires: '2026-11-01T00:00:00Z' }) } })),
      C.exp, /expired on 2026-11-01/);
  });

  check('today\'s site, the 0.1.0 manifest with neither, fails all three of its checks, and the packages built for 0.1.2', () => {
    const r = run(tree({ files: { 'landing/vpn/release/manifest.json': manifest({ version: '0.1.0', sequence: null, expires: null }) } }));
    assert.deepStrictEqual(failing(r), [C.min, C.seq, C.exp, C.floor]);
  });

  check('a manifest whose files are not the assets of its own release, or that lacks Linux or Windows, fails', () => {
    // What make-release-manifest.sh writes before the folders are taken out
    // by hand: a GitHub release has no folders, so every download is a 404.
    const folders = manifest({ url: (key, name) => `${RELEASES}/hidravpn-v0.1.2/${key}/${name}` });
    let r = run(tree({ files: { 'landing/vpn/release/manifest.json': folders } }));
    failsOnly(r, C.urls, /linux-x64\/hidravpn-service is at https:\/\/github\.com\/NeurexBK\/HidraNet\/releases\/download\/hidravpn-v0\.1\.2\/linux-x64\/hidravpn-service, not .*hidravpn-v0\.1\.2\/hidravpn-service/);
    assert.equal((r.results.find((x) => x.name === C.urls).detail.match(/ is at /g) || []).length, 5);
    // Signed and valid, but pointing at another release's files.
    failsOnly(run(tree({ files: { 'landing/vpn/release/manifest.json': manifest({ url: (key, name) => `${RELEASES}/hidravpn-v0.1.0/${name}` }) } })),
      C.urls, /win32-x64\/wintun\.dll is at .*hidravpn-v0\.1\.0\/wintun\.dll, not .*hidravpn-v0\.1\.2\/wintun\.dll/);
    // Somewhere else altogether.
    failsOnly(run(tree({ files: { 'landing/vpn/release/manifest.json': manifest({ url: (key, name) => `https://hidranet.org/vpn/release/0.1.2/${name}` }) } })),
      C.urls, /linux-x64\/hidravpn is at https:\/\/hidranet\.org\//);
    for (const [present, missing] of [['linux-x64', 'win32-x64'], ['win32-x64', 'linux-x64']]) {
      failsOnly(run(tree({ files: { 'landing/vpn/release/manifest.json': manifest({ platforms: [present] }) } })),
        C.urls, new RegExp(`it has no ${missing}: nobody on it could install or update`));
    }
  });

  check('a download the table does not list fails, on every page and in the guide', () => {
    // The pages still on 1.0.0 while the table is 1.1.0's.
    for (const [rel, text] of [['landing/index.html', homepage('1.0.0')], ['landing/r/index.html', reviewPage('1.0.0')]]) {
      const r = run(tree({ files: { [rel]: text } }));
      // The sizes cannot be compared either for a file the table lacks.
      assert.deepStrictEqual(failing(r), [C.links, C.sizes], rel);
      const detail = r.results.find((x) => x.name === C.links).detail;
      assert.match(detail, new RegExp(`${rel.replace(/\//g, '\\/')} names HidraNet-Browser-1\\.0\\.0-Windows-x64\\.zip, which landing\\/SHA256SUMS\\.txt does not list`));
      assert.match(detail, new RegExp(`${rel.replace(/\//g, '\\/')} does not link HidraNet-Browser-1\\.1\\.0-Linux-x64\\.zip`));
    }
    failsOnly(run(tree({ files: { 'docs/technical/07-installation-guide.md': guide('1.0.0') } })), C.links,
      /07-installation-guide\.md names HidraNet-Browser-1\.0\.0-Linux-x64\.zip/);
  });

  check('a link on the wrong tag, a page missing a package, or a page with none, fails', () => {
    failsOnly(run(tree({ files: { 'landing/index.html': homepage('1.1.0', { tag: 'v1.0.0' }) } })), C.links,
      /links HidraNet-Browser-1\.1\.0-macOS-arm64\.zip on the tag v1\.0\.0, not v1\.1\.0/);
    failsOnly(run(tree({ files: { 'landing/index.html': homepage('1.1.0', { skip: 'macOS-x64' }) } })), C.links,
      /landing\/index\.html does not link HidraNet-Browser-1\.1\.0-macOS-x64\.zip/);
    const r = run(tree({ files: { 'landing/r/index.html': '<p>nothing here</p>\n' } }));
    assert.deepStrictEqual(failing(r), [C.links, C.sizes]);
    assert.match(r.results.find((x) => x.name === C.links).detail, /landing\/r\/index\.html names no package/);
    assert.match(r.results.find((x) => x.name === C.sizes).detail, /landing\/r\/index\.html links no package/);
  });

  check('a size other than the table\'s, or a link with no size beside it, fails', () => {
    const stale = (bytes, p) => (p === 'Windows-x64' ? '157' : mb(bytes));
    const win = FACTS.get('Windows-x64').size;
    failsOnly(run(tree({ files: { 'landing/index.html': homepage('1.1.0', { size: stale }) } })), C.sizes,
      new RegExp(`landing/index\\.html shows 157 MB for HidraNet-Browser-1\\.1\\.0-Windows-x64\\.zip; the table says ${group(win)} bytes, so ${mb(win)} MB`));
    failsOnly(run(tree({ files: { 'landing/r/index.html': reviewPage('1.1.0', { size: stale }) } })), C.sizes,
      /landing\/r\/index\.html shows 157 MB/);
    const bare = reviewPage().replace(/<span class="sz">\d+ MB<\/span>/, '');
    failsOnly(run(tree({ files: { 'landing/r/index.html': bare } })), C.sizes, /4 download links, 3 with a size beside them/);
    failsOnly(run(tree({ files: { 'landing/index.html': homepage('1.1.0', { download: (n) => n.replace('1.1.0', '1.0.0') }) } })), C.sizes,
      /saves HidraNet-Browser-1\.1\.0-macOS-arm64\.zip as HidraNet-Browser-1\.0\.0-macOS-arm64\.zip/);
  });

  check('SUMS_SIGNED false fails', () => {
    failsOnly(run(tree({ files: { 'hidra-browser/src/main/update-check.js': 'const SUMS_SIGNED = false;\n' } })), C.flag, /still says SUMS_SIGNED = false/);
  });

  check('a table without its signature, signed by another key, signed bare, or changed after signing, fails', () => {
    failsOnly(run(tree({ sigs: { 'landing/SHA256SUMS.txt.sig': null } })), C.ssig, /no landing\/SHA256SUMS\.txt\.sig/);
    failsOnly(run(tree({ sigs: { 'landing/SHA256SUMS.txt.sig': () => signBytes(browserSumsMessage(Buffer.from(table(), 'utf8')), other) } })),
      C.ssig, /does not verify/);
    // The bytes alone, without the label: not a signature of the table.
    failsOnly(run(tree({ sigs: { 'landing/SHA256SUMS.txt.sig': () => signBytes(Buffer.from(table(), 'utf8')) } })), C.ssig, /does not verify/);
    failsOnly(run(tree({ after: (root) => fs.appendFileSync(path.join(root, 'landing/SHA256SUMS.txt'), '\n') })), C.ssig, /does not verify/);
  });

  check('a table that still says it has no signature fails', () => {
    const extra = 'Until the maintainers publish the first signature there is no .sig, and\na browser that has never verified a record shows no notice.\n';
    failsOnly(run(tree({ files: { 'landing/SHA256SUMS.txt': table('1.1.0', { extra }) } })), C.prose, /still says "Until the maintainers/);
  });

  check('package.json other than the table\'s latest-version fails', () => {
    failsOnly(run(tree({ files: { 'hidra-browser/package.json': '{"version": "1.1.1"}\n' } })), C.ver,
      /package\.json says 1\.1\.1, the table's latest-version is 1\.1\.0/);
  });

  check('a table whose valid-until has passed fails', () => {
    failsOnly(run(tree({ files: { 'landing/SHA256SUMS.txt': table('1.1.0', { validUntil: '2026-10-31' }) } })), C.valid,
      /valid-until 2026-10-31 has passed/);
  });

  check('today\'s table, the unsigned 1.0.0 one, fails the table\'s checks', () => {
    const extra = 'Until the maintainers publish the first signature there is no .sig, and\n';
    const r = run(tree({
      files: { 'landing/SHA256SUMS.txt': table('1.0.0', { extra }), 'hidra-browser/src/main/update-check.js': 'const SUMS_SIGNED = false;\n' },
      sigs: { 'landing/SHA256SUMS.txt.sig': null },
    }));
    // The 1.0.0 packages are not in the folder: there is nothing of them to check.
    assert.deepStrictEqual(failing(r), [C.links, C.sizes, C.flag, C.ssig, C.prose, C.ver, C.pkgs, C.built, C.floor]);
    assert.match(r.results.find((x) => x.name === C.pkgs).detail, /HidraNet-Browser-1\.0\.0-Linux-x64\.zip not in /);
  });

  check('without --packages, the three package checks fail and nothing else', () => {
    const r = run(tree({ packagesDir: null }));
    assert.deepStrictEqual(failing(r), [C.pkgs, C.built, C.floor]);
    for (const name of [C.pkgs, C.built, C.floor]) assert.match(r.results.find((x) => x.name === name).detail, /no --packages folder given/);
  });

  check('a package missing from the folder, or other bytes than the table\'s, fails', () => {
    const r = run(tree({ packagesDir: packages({ 'macOS-x64': null }) }));
    assert.deepStrictEqual(failing(r), [C.pkgs, C.built, C.floor]);
    assert.match(r.results.find((x) => x.name === C.pkgs).detail, /HidraNet-Browser-1\.1\.0-macOS-x64\.zip not in /);
    // Built again after the table was written: the same layout, other bytes.
    const again = packages();
    fs.appendFileSync(path.join(again, zip('1.1.0', 'Linux-x64')), 'x');
    failsOnly(run(tree({ packagesDir: again })), C.pkgs,
      /HidraNet-Browser-1\.1\.0-Linux-x64\.zip has SHA-256 [0-9a-f]{64}; the table says [0-9a-f]{64}\n.*Linux-x64\.zip is [\d,]+ bytes; the table says [\d,]+/);
  });

  check('a package built before the floor and SUMS_SIGNED were raised fails, even when the tree has both', () => {
    // The tree says MIN_VERSION 0.1.2 and SUMS_SIGNED true; the packages were
    // built from a commit that did not, and that is what users would run.
    const r = run(tree({ packages: { 'Windows-x64': { min: '0.1.0' }, 'macOS-arm64': { signed: false } } }));
    failsOnly(r, C.floor, /HidraNet-Browser-1\.1\.0-macOS-arm64\.zip was built with SUMS_SIGNED false: only another browser release can change it/);
    assert.match(r.results.find((x) => x.name === C.floor).detail,
      /HidraNet-Browser-1\.1\.0-Windows-x64\.zip was built with MIN_VERSION '0\.1\.0', not '0\.1\.2'/);
    failsOnly(run(tree({ packages: { 'Linux-x64': { min: '0.1.3' } } })), C.floor, /MIN_VERSION '0\.1\.3', not '0\.1\.2'/);
    failsOnly(run(tree({ packages: { 'Linux-x64': { leave: ['src/main/update-check.js'] } } })), C.floor,
      /Linux-x64\.zip has no src\/main\/update-check\.js/);
  });

  check('a package built from another commit, a dirty tree or as another version, or a table with no commit, fails', () => {
    failsOnly(run(tree({ packages: { 'macOS-x64': { build: 'def5678' } } })), C.built,
      /macOS-x64\.zip was built from def5678; the table says abc1234/);
    failsOnly(run(tree({ packages: { 'Linux-x64': { build: 'abc1234-dirty' } } })), C.built,
      /Linux-x64\.zip was built from abc1234-dirty, a tree with uncommitted changes/);
    failsOnly(run(tree({ packages: { 'Windows-x64': { appVersion: '1.0.0' } } })), C.built, /Windows-x64\.zip's app says version 1\.0\.0, not 1\.1\.0/);
    failsOnly(run(tree({ packages: { 'Windows-x64': { leave: ['build.json'] } } })), C.built, /Windows-x64\.zip has no readable app\/build\.json/);
    failsOnly(run(tree({ files: { 'landing/SHA256SUMS.txt': table('1.1.0', { commit: null }) } })), C.built, /names no "Built from commit"/);
  });

  check('a file that cannot be read fails the checks that need it, and the run still finishes', () => {
    const r = run(tree({ files: { 'landing/vpn/release/manifest.json': null }, sigs: { 'landing/vpn/release/manifest.json.sig': null } }));
    assert.deepStrictEqual(failing(r), [C.min, C.msig, C.seq, C.exp, C.urls, C.floor]);
    assert.match(r.results.find((x) => x.name === C.min).detail, /ENOENT/);
  });

  check('the command prints each check and exits 1 when one fails, 0 when none does', () => {
    const script = path.join(__dirname, '..', 'scripts', 'launch-check.js');
    // The command uses the release key, so a fixture signed with the test key
    // fails exactly the two signature checks.
    const root = tree();
    const r = spawnSync(process.execPath, [script, '--root', root, '--packages', DEFAULT_PACKAGES], { encoding: 'utf8' });
    assert.equal(r.status, 1, r.stderr);
    for (const name of Object.values(C)) {
      const failing = name === C.msig || name === C.ssig;
      assert.ok(r.stdout.includes((failing ? '  FAIL ' : '  ok   ') + name), name + '\n' + r.stdout);
    }
    assert.match(r.stdout, /not ready: 2 of 15 checks failed/);
    // Without the packages, never ready, whatever the tree says.
    const bare = spawnSync(process.execPath, [script, '--root', root], { encoding: 'utf8' });
    assert.equal(bare.status, 1, bare.stderr);
    assert.match(bare.stdout, /  FAIL the packages are the files the table lists: no --packages folder given/);
    assert.match(bare.stdout, /not ready: 5 of 15 checks failed/);
  });

  check('the real pages carry a size beside every download link, in the markup the check reads', () => {
    // Whatever the tree's state, a change of markup must not make the size
    // check pass on nothing.
    const root = path.join(__dirname, '..', '..');
    const r = launchCheck({ root });
    assert.equal(r.results.length, Object.keys(C).length);
    const sizes = r.results.find((x) => x.name === C.sizes);
    assert.doesNotMatch(sizes.detail, /with a size beside them|links no package|saves .* as /, sizes.detail);
    const links = r.results.find((x) => x.name === C.links);
    assert.doesNotMatch(links.detail, /names no package/, links.detail);
  });

  check('the real site links only packages the real table lists', () => {
    // True on main before the launch (1.0.0 pages, 1.0.0 table) and after it
    // (1.1.0 pages, 1.1.0 table). False on a tree whose pages point at
    // packages the table does not have yet: the launch branch until its
    // table is in. Deploying such a tree sends every download to a 404.
    // (The sizes are launch-check's to compare on the day: main's 1.0.0
    // pages show sizes from before the table's packages.)
    const r = launchCheck({ root: path.join(__dirname, '..', '..') });
    const x = r.results.find((y) => y.name === C.links);
    assert.ok(x.ok, C.links + ': ' + x.detail);
  });
} finally {
  for (const root of [...roots, ...dirs]) fs.rmSync(root, { recursive: true, force: true });
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
