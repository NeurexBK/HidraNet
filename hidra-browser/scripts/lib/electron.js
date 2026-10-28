'use strict';
/**
 * The Electron runtime every package is built on, and what its download must
 * hash to.
 *
 * The builders used to take whatever GitHub served for the zip name and ship
 * it. A swapped or truncated download would have gone out as HidraNet. Now the
 * zip has to match the SHA-256 Electron publishes for it, written down here,
 * so it is checked against something that does not come from the same server
 * at build time. A cached zip is checked again on every build.
 *
 * The hashes are Electron's own SHASUMS256.txt for v44.9.3. Moving to another
 * Electron means changing the version here and in package.json (the test
 * checks they agree) and copying the new lines from that release's
 * SHASUMS256.txt.
 */
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { download } = require('./net');

const ELECTRON_VER = '44.9.3';

const SHA256 = {
  'electron-v44.9.3-darwin-arm64.zip': '4af51382278d00291dfcda265eddd9bab6e98cebb09f46aadc8438bf606de162',
  'electron-v44.9.3-darwin-x64.zip':   '451363b59bb7d2c1c9e0c4baa99106004eaabe724aa21a0c6b4c87469293531a',
  'electron-v44.9.3-linux-arm64.zip':  '8e70d53d920d84db869023280e5a1fbda82ecc58fea4443748e58309a3c80238',
  'electron-v44.9.3-linux-x64.zip':    '6e7fd2d450d442507b846ace4ae6e2bd17e1b1653e86a033b5231abfc23e6df4',
  'electron-v44.9.3-win32-x64.zip':    '41a1ffa0541cb0f2c9b9fe920dd2cef1793ad0ea2ada1a9582958880f4d1b23c',
};

function zipName(platform, arch) {
  return 'electron-v' + ELECTRON_VER + '-' + platform + '-' + arch + '.zip';
}

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

/** Throws unless `file` is the official zip it is named after. */
function verifyElectronZip(file) {
  const name = path.basename(file);
  const want = SHA256[name];
  if (!want) throw new Error('no pinned SHA-256 for ' + name + ' — add it from Electron\'s SHASUMS256.txt');
  const got = sha256File(file);
  if (got !== want) {
    throw new Error('Electron download does not match its published SHA-256: ' + name +
                    '\n  expected ' + want + '\n  got      ' + got);
  }
  return got;
}

/**
 * The official Electron zip for a platform, downloaded into cacheDir if it is
 * not there yet, and verified either way. A zip that fails is deleted, so the
 * next run downloads it again instead of failing on the same bad copy.
 */
async function electronZip(platform, arch, cacheDir) {
  fs.mkdirSync(cacheDir, { recursive: true });
  const name = zipName(platform, arch);
  const file = path.join(cacheDir, name);
  if (!fs.existsSync(file)) {
    console.log('  Downloading ' + name + ' ...');
    await download('https://github.com/electron/electron/releases/download/v' + ELECTRON_VER + '/' + name, file);
  } else {
    console.log('  Cache: ' + name);
  }
  try {
    const sum = verifyElectronZip(file);
    console.log('  SHA-256 matches Electron\'s published sum (' + sum.slice(0, 16) + '…)');
  } catch (e) {
    try { fs.unlinkSync(file); } catch (_) {}
    throw e;
  }
  return file;
}

module.exports = { ELECTRON_VER, SHA256, zipName, verifyElectronZip, electronZip };
