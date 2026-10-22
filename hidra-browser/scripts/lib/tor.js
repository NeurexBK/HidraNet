'use strict';
/**
 * The Tor that goes into the packages, and what each of its files must hash
 * to.
 *
 * fetch-tor.js checks the bundle it downloads against the checksum list the
 * Tor Project publishes beside it. That list comes from the same server as
 * the bundle, over the same connection, so on its own it proves the download
 * is intact, not that it is genuine. The hashes below are a second check that
 * does not come from that server: the files of the Tor Expert Bundle 15.0.22
 * (tor 0.4.9.12) as fetch-tor.js extracted them for the v1.0.0 packages.
 * fetch-tor.js refuses a bundle whose files differ, and every builder refuses
 * to package a Tor folder that differs.
 *
 * Moving to another Tor means changing TOR_VERSION and recording new hashes
 * from a bundle whose signature was checked against the Tor Browser
 * Developers key (sha256sums-signed-build.txt and its .asc, with gpg), not
 * only its checksum.
 */
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const TOR_VERSION = '15.0.22';

const GEOIP  = '25a69c1dc1d946bfdb0b1ba628db36e9668c51639963c2ee2afda7dc857f66a5';
const GEOIP6 = '0a3b61ba326550d66a4c805563be25e28f1d59e5cdfc06b091bfdd9ea2c8f998';

const PINS = {
  'darwin-arm64': { 'tor': 'baf8add2d110278bb4cb14cb091121756683d77759692084cb3fb3b09044384d', geoip: GEOIP, geoip6: GEOIP6 },
  'darwin-x64':   { 'tor': '153770d40cee72bed088c0202745c91847588afa614ef37f1c1cd76dc28af063', geoip: GEOIP, geoip6: GEOIP6 },
  'linux-x64':    { 'tor': 'ed3edb11fe56063b31915e7b3ae31fb08e40a9f4aa2fe811e988d8037650afa4', geoip: GEOIP, geoip6: GEOIP6 },
  'win32-x64':    { 'tor.exe': '60c45b01938c799862e511a9a5bab12f959a819c6264a24502edc342165f570c', geoip: GEOIP, geoip6: GEOIP6 },
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
