// What the packages are built from is pinned, and the pins are enforced.
//
// The Electron zip and the Tor files used to be whatever the server sent:
// Electron with no check at all, Tor against a checksum list from the same
// server as the bundle. scripts/lib/electron.js and scripts/lib/tor.js now
// hold the SHA-256 each must have, and the builders refuse anything else.
// This proves the refusals happen, and that the pins agree with the rest of
// the tree. It needs no network.
//
//   node hidra-browser/test/build-pins.js

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const electron = require('../scripts/lib/electron');
const tor = require('../scripts/lib/tor');

let passed = 0;
let failed = 0;
const check = (name, cond, why) => {
  if (cond) { passed++; console.log('ok    ' + name); }
  else { failed++; console.log('FAIL  ' + name + (why ? '\n      ' + why : '')); }
};
const throws = (fn, re) => { try { fn(); return false; } catch (e) { return re ? re.test(e.message) : true; } };
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-pins-'));

// ── Electron ────────────────────────────────────────────────────────────────
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
check('the pinned Electron is the one package.json installs',
      pkg.devDependencies.electron === electron.ELECTRON_VER,
      'package.json ' + pkg.devDependencies.electron + ', lib/electron.js ' + electron.ELECTRON_VER);
for (const [p, a] of [['darwin', 'arm64'], ['darwin', 'x64'], ['linux', 'x64'], ['win32', 'x64']]) {
  const h = electron.SHA256[electron.zipName(p, a)];
  check('a SHA-256 is pinned for the ' + p + '-' + a + ' zip', /^[0-9a-f]{64}$/.test(h || ''));
}
check('every pinned zip is of the pinned version',
      Object.keys(electron.SHA256).every((n) => n.indexOf('-v' + electron.ELECTRON_VER + '-') !== -1));

const fake = path.join(tmp, electron.zipName('linux', 'x64'));
fs.writeFileSync(fake, 'not the Electron zip');
check('a zip that is not Electron\'s is refused', throws(() => electron.verifyElectronZip(fake), /does not match/));
const stray = path.join(tmp, 'electron-v1.0.0-linux-x64.zip');
fs.writeFileSync(stray, 'x');
check('a zip with no pin is refused, not waved through', throws(() => electron.verifyElectronZip(stray), /no pinned SHA-256/));

const cached = path.join(ROOT, 'dist', 'electron-cache', electron.zipName('linux', 'x64'));
if (fs.existsSync(cached)) {
  check('the Electron zip in dist/electron-cache passes', !throws(() => electron.verifyElectronZip(cached)));
} else {
  console.log('skip  no Electron zip in dist/electron-cache to check against its pin');
}

// The builders take Electron only through lib/electron.js.
for (const b of ['build-mac.js', 'build-linux.js', 'build-win.js']) {
  const src = fs.readFileSync(path.join(ROOT, 'scripts', b), 'utf8');
  check(b + ' gets Electron through the verified download',
        /electronZip\(/.test(src) && !/require\('\.\/lib\/net'\)/.test(src) && !/ELECTRON_VER\s*=/.test(src));
  check(b + ' packages only a Tor that matches its pins', /verifyTorDir\(/.test(src));
}

// Every build is its package.json version: no builder carries a version of
// its own, which is how every rebuild came to call itself 1.0.0.
for (const b of ['build-mac.js', 'build-linux.js', 'build-win.js', 'pack-portable.js', 'refresh-release.js', 'update-sums.js']) {
  const src = fs.readFileSync(path.join(ROOT, 'scripts', b), 'utf8');
  check(b + ' takes its version from package.json',
        /const VERSION\s*=\s*(require\(path\.join\(ROOT, ('hidra-browser', )?'package\.json'\)\)\.version|JSON\.parse\(fs\.readFileSync\(path\.join\(ROOT, 'package\.json'\))/.test(src) &&
        !/const VERSION\s*=\s*'/.test(src));
}
// The presence signal (newtab.html) says the version of the build that
// sends it; a fixed '1.0.0' there outlived the version bump.
{
  const page = fs.readFileSync(path.join(ROOT, 'src', 'ui', 'newtab.html'), 'utf8');
  const beacon = page.slice(page.indexOf('HidraNet node beacon'));
  check('the presence signal carries the build\'s own version, not a fixed one',
        !/VER\s*=\s*'\d+\.\d+\.\d+'/.test(beacon) && /apps\.status\(\)/.test(beacon) && /s\.about\.version/.test(beacon));
}
check('package.json has a version past the 1.0.0 every earlier build was published as',
      /^\d+\.\d+\.\d+$/.test(pkg.version) && pkg.version !== '1.0.0');

// ── Tor ─────────────────────────────────────────────────────────────────────
for (const k of ['darwin-arm64', 'darwin-x64', 'linux-x64', 'win32-x64']) {
  const pins = tor.PINS[k] || {};
  check('Tor is pinned for ' + k, Object.keys(pins).length === 3 &&
        Object.values(pins).every((h) => /^[0-9a-f]{64}$/.test(h)));
}

const dir = path.join(tmp, 'tor');
fs.mkdirSync(dir);
tor.PINS['test-x'] = { tor: sha('the tor we ship'), geoip: sha('geoip'), geoip6: sha('geoip6') };
fs.writeFileSync(path.join(dir, 'tor'), 'the tor we ship');
fs.writeFileSync(path.join(dir, 'geoip'), 'geoip');
fs.writeFileSync(path.join(dir, 'geoip6'), 'geoip6');
check('a Tor folder that matches its pins passes', tor.torProblems(dir, 'test', 'x').length === 0);
fs.writeFileSync(path.join(dir, 'tor'), 'a tor someone swapped in');
check('a swapped Tor binary is refused',
      throws(() => tor.verifyTorDir(dir, 'test', 'x'), /tor does not match its pinned SHA-256/));
fs.writeFileSync(path.join(dir, 'tor'), 'the tor we ship');
fs.unlinkSync(path.join(dir, 'geoip6'));
check('a Tor folder missing a file is refused', throws(() => tor.verifyTorDir(dir, 'test', 'x'), /geoip6 is missing/));
check('a platform with no pinned Tor is refused', throws(() => tor.verifyTorDir(dir, 'linux', 'arm64'), /no pinned Tor/));

const local = tor.torDir(ROOT, 'linux', 'x64');
if (fs.existsSync(path.join(local, 'tor'))) {
  check('the Tor in build/bin/tor/linux-x64 matches its pins', tor.torProblems(local, 'linux', 'x64').length === 0,
        tor.torProblems(local, 'linux', 'x64').join('; '));
} else {
  console.log('skip  no fetched Tor in build/bin/tor/linux-x64 to check against its pins');
}

// fetch-tor.js used to hand linux-arm64 the x86_64 bundle.
const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'fetch-tor.js'), '--platform', 'linux', '--arch', 'arm64'],
                    { encoding: 'utf8', timeout: 30000 });
check('fetch-tor.js refuses linux-arm64 instead of fetching the x86_64 Tor',
      r.status !== 0 && /no Tor is pinned for linux-arm64/.test(r.stderr + r.stdout), (r.stderr || '').trim());
check('fetch-tor.js takes its version from lib/tor.js',
      /require\('\.\/lib\/tor'\)/.test(fs.readFileSync(path.join(ROOT, 'scripts', 'fetch-tor.js'), 'utf8')));

fs.rmSync(tmp, { recursive: true, force: true });
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
