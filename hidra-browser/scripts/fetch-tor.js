#!/usr/bin/env node
/**
 * Fetches the official Tor Expert Bundle into build/bin/tor/.
 *
 * Tor is what actually anonymises traffic: the browser's own relay chain runs
 * entirely on the user's machine, so it encrypts but never changes the exit IP.
 * Tor's ~8000 volunteer relays do.
 *
 * The binary is downloaded rather than committed, and its SHA-256 is checked
 * against the list the Tor Project publishes next to it — a mismatch aborts.
 */
const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const { TOR_VERSION, torProblems } = require('./lib/tor');
// The Tor Project keeps only its latest releases on dist; older ones move to
// the archive, under the same names and beside the same checksum list. A
// pinned version that leaves dist is fetched from there, and is still held to
// the same checksum and the same pins.
const DIST = `https://dist.torproject.org/torbrowser/${TOR_VERSION}`;
const ARCHIVE = `https://archive.torproject.org/tor-package-archive/torbrowser/${TOR_VERSION}`;

const ROOT = path.join(__dirname, '..');

// Kept per platform/arch: packaging a Linux ZIP on Windows must not bundle
// tor.exe, which would silently ship a package with no working anonymity.
function outDirFor(platform, arch) {
  return path.join(ROOT, 'build', 'bin', 'tor', `${platform}-${arch}`);
}

function bundleName(platform, arch) {
  if (platform === 'win32') return `tor-expert-bundle-windows-x86_64-${TOR_VERSION}.tar.gz`;
  if (platform === 'linux') {
    // Only x86_64 is fetched and pinned. Asked for arm64, this used to fetch
    // the x86_64 bundle anyway, and the package would have shipped a Tor
    // that cannot run on the machine it is for.
    if (arch !== 'x64') throw new Error(`no Tor is pinned for linux-${arch}`);
    return `tor-expert-bundle-linux-x86_64-${TOR_VERSION}.tar.gz`;
  }
  if (platform === 'darwin') {
    return arch === 'arm64'
      ? `tor-expert-bundle-macos-aarch64-${TOR_VERSION}.tar.gz`
      : `tor-expert-bundle-macos-x86_64-${TOR_VERSION}.tar.gz`;
  }
  throw new Error(`no Tor bundle for ${platform}/${arch}`);
}

function get(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'HidraNet-build' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return resolve(get(res.headers.location));
      }
      if (res.statusCode !== 200) {
        res.resume();
        const err = new Error(`HTTP ${res.statusCode} at ${url}`);
        err.status = res.statusCode;
        return reject(err);
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    }).on('error', reject);
  });
}

function argValue(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

async function main() {
  const platform = argValue('--platform', process.platform);
  const arch = argValue('--arch', platform === 'darwin' ? 'arm64' : 'x64');
  const file = bundleName(platform, arch);

  const OUT_DIR = outDirFor(platform, arch);
  const STAMP = path.join(OUT_DIR, '.version');
  const rel = path.relative(ROOT, OUT_DIR).replace(/\\/g, '/');

  if (fs.existsSync(STAMP) && fs.readFileSync(STAMP, 'utf8').trim() === TOR_VERSION) {
    const problems = torProblems(OUT_DIR, platform, arch);
    if (!problems.length) {
      console.log(`[ok] Tor ${TOR_VERSION} already present in ${rel}, every file matches its pin`);
      return;
    }
    console.log(`[..] the Tor in ${rel} does not match its pins (${problems[0]}); fetching it again`);
  }

  console.log(`[..] downloading ${file}`);
  // The list and the bundle always come from the same host.
  const from = (base) => Promise.all([get(`${base}/sha256sums-unsigned-build.txt`), get(`${base}/${file}`)]);
  let sums;
  let tarball;
  try {
    [sums, tarball] = await from(DIST);
  } catch (e) {
    if (e.status !== 404) throw e;
    console.log(`[..] Tor ${TOR_VERSION} is no longer on dist.torproject.org; fetching it from archive.torproject.org`);
    [sums, tarball] = await from(ARCHIVE);
  }

  const line = sums.toString('utf8').split('\n').find((l) => l.includes(file));
  if (!line) throw new Error(`${file} is not in the official checksum list`);
  const expected = line.trim().split(/\s+/)[0];
  const actual = crypto.createHash('sha256').update(tarball).digest('hex');

  if (expected !== actual) {
    throw new Error(`checksum does not match for ${file}\n  expected: ${expected}\n  got:      ${actual}`);
  }
  console.log(`[ok] SHA-256 matches (${actual.slice(0, 16)}…)`);

  fs.rmSync(OUT_DIR, { recursive: true, force: true });
  fs.mkdirSync(OUT_DIR, { recursive: true });

  const stage = path.join(OUT_DIR, '_stage');
  fs.mkdirSync(stage, { recursive: true });
  fs.writeFileSync(path.join(stage, file), tarball);

  // Extract with the archive named relatively and cwd set to its folder: GNU
  // tar (the one Git for Windows puts on PATH) reads a leading "C:" as a remote
  // host and fails on absolute Windows paths.
  execFileSync('tar', ['-xzf', file], { cwd: stage, stdio: 'inherit' });
  fs.unlinkSync(path.join(stage, file));

  // A client needs the daemon plus the GeoIP tables it uses to pick circuits.
  const exeName = platform === 'win32' ? 'tor.exe' : 'tor';
  const wanted = [
    [path.join(stage, 'tor', exeName), exeName],
    [path.join(stage, 'data', 'geoip'), 'geoip'],
    [path.join(stage, 'data', 'geoip6'), 'geoip6'],
  ];

  for (const [src, dest] of wanted) {
    if (!fs.existsSync(src)) throw new Error(`the bundle did not contain ${dest}`);
    fs.copyFileSync(src, path.join(OUT_DIR, dest));
    if (dest === exeName) fs.chmodSync(path.join(OUT_DIR, dest), 0o755);
  }

  fs.rmSync(stage, { recursive: true, force: true });

  // The checksum above came from the same server as the bundle. The pins in
  // lib/tor.js did not: a bundle that passes the first and fails these is
  // not the Tor we ship.
  const problems = torProblems(OUT_DIR, platform, arch);
  if (problems.length) {
    fs.rmSync(OUT_DIR, { recursive: true, force: true });
    throw new Error(`the bundle's files do not match the pinned Tor ${TOR_VERSION}:\n  ${problems.join('\n  ')}`);
  }
  console.log(`[ok] every file matches its pin in scripts/lib/tor.js`);
  fs.writeFileSync(STAMP, TOR_VERSION, 'utf8');

  const mb = (fs.statSync(path.join(OUT_DIR, exeName)).size / 1024 / 1024).toFixed(1);
  console.log(`[ok] Tor ${TOR_VERSION} ready in ${rel} (${exeName}: ${mb} MB)`);
}

main().catch((err) => {
  console.error(`[!!] could not fetch Tor: ${err.message}`);
  console.error('     The browser still builds, but with no network anonymity.');
  process.exit(1);
});
