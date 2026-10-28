'use strict';
/**
 * The Tor that goes into the packages, and what each of its files must hash
 * to.
 *
 * fetch-tor.js checks the bundle it downloads against the checksum list the
 * Tor Project publishes beside it. That list comes from the same server as
 * the bundle, over the same connection, so on its own it proves the download
 * is intact, not that it is genuine. The hashes below are a second check that
 * does not come from that server: the files of the Tor Expert Bundle 15.0.26
 * (tor 0.4.9.14), extracted from bundles that matched
 * sha256sums-signed-build.txt after that list's signature checked out
 * against the Tor Browser Developers key (EF6E 286D DA85 EA2A 4BA7 DE68
 * 4E2C 6E87 9329 8290). fetch-tor.js refuses a bundle whose files differ, and
 * every builder refuses to package a Tor folder that differs.
 *
 * 15.0.22, which the v1.0.0 packages carry, left dist.torproject.org; a
 * pinned version that leaves it is fetched from archive.torproject.org.
 *
 * Moving to another Tor means changing TOR_VERSION and recording new hashes
 * from a bundle whose signature was checked against the Tor Browser
 * Developers key (sha256sums-signed-build.txt and its .asc, with gpg), not
 * only its checksum.
 */
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const TOR_VERSION = '15.0.26';

const GEOIP  = '3099e91a4c8c87a1e6ab8a0b1e7407aea0314a2d8d048d654b4087b9ae103d9f';
const GEOIP6 = '10f50daba4156a5b1ae782c0db0478b4584901b1ed72cd619cddd4b9f2b03d6a';

const PINS = {
  'darwin-arm64': { 'tor': '7d5a89b6cec99aab47420040ad86dd5fd5174192e71b6c201b0b10170ba57ebb', geoip: GEOIP, geoip6: GEOIP6 },
  'darwin-x64':   { 'tor': 'e249a521aa5b0ff44a39c1dc4b5707ae8cb109d8a26c637b6acbbf6832bf2f14', geoip: GEOIP, geoip6: GEOIP6 },
  'linux-x64':    { 'tor': '39c9db0654d2ec218892bd00f75eccb5b641a7222754436c2e4a8d2f764a57d3', geoip: GEOIP, geoip6: GEOIP6 },
  'win32-x64':    { 'tor.exe': '8c38513b3c4584154158e7c584f4144849dc679a64cd679553d72dad28230c54', geoip: GEOIP, geoip6: GEOIP6 },
};

function torDir(root, platform, arch) {
  return path.join(root, 'build', 'bin', 'tor', platform + '-' + arch);
}

/**
 * Every pinned file of `dir` hashes to its pin. Returns the list of problems,
 * empty when the folder is the Tor we ship.
 */
function torProblems(dir, platform, arch) {
  const pins = PINS[platform + '-' + arch];
  if (!pins) return ['no pinned Tor for ' + platform + '-' + arch];
  const problems = [];
  for (const [file, want] of Object.entries(pins)) {
    const abs = path.join(dir, file);
    if (!fs.existsSync(abs)) { problems.push(file + ' is missing'); continue; }
    const got = crypto.createHash('sha256').update(fs.readFileSync(abs)).digest('hex');
    if (got !== want) problems.push(file + ' does not match its pinned SHA-256 (got ' + got.slice(0, 16) + '…)');
  }
  return problems;
}

/** Throws unless `dir` holds exactly the pinned Tor for this platform. */
function verifyTorDir(dir, platform, arch) {
  const problems = torProblems(dir, platform, arch);
  if (problems.length) {
    throw new Error('Tor for ' + platform + '-' + arch + ' is not the pinned Tor ' + TOR_VERSION + ':\n  ' +
                    problems.join('\n  ') + '\n  Run: node scripts/fetch-tor.js --platform ' + platform + ' --arch ' + arch);
  }
}

module.exports = { TOR_VERSION, PINS, torDir, torProblems, verifyTorDir };
