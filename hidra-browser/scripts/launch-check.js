#!/usr/bin/env node
/**
 * HidraNet — is this tree, and are these packages, ready to go out as the
 * browser release?
 *
 * The browser compiles in two values that only a new browser release can
 * change: MIN_VERSION (src/main/vpn-installer.js, the oldest HidraVPN it
 * installs) and SUMS_SIGNED (src/main/update-check.js, whether it requires
 * the table's signature). The packages carry src/ as plain files, so they
 * have whatever those lines said in the commit they were built from, not what
 * the tree says on the day the site starts linking them. Launch day therefore
 * goes in this order, and nothing else works:
 *
 *   1. The HidraVPN manifest of the new release is signed and on the site.
 *   2. On main, in one commit made on the PC with the release key: the table
 *      as it is today signed (SHA256SUMS.txt.sig), SUMS_SIGNED = true and
 *      MIN_VERSION = that release. verify-sums.js wants the flip in the same
 *      commit as the .sig.
 *   3. The four packages are built from that commit, from a clean checkout.
 *   4. The launch branch, rebased onto that commit, gets the new table
 *      (update-sums.js with the folder and the commit), its signature and
 *      the site's links. This script is then run with --packages on that
 *      folder, and only then is the branch merged and the release published.
 *
 * Every check reads the tree and the packages as they are; nothing is
 * fetched, built or signed. Each one prints ok or FAIL with the reason, and
 * the exit status is 1 if any failed.
 *
 *   - MIN_VERSION in src/main/vpn-installer.js is the HidraVPN release the
 *     site serves (landing/vpn/release/manifest.json), and that manifest is
 *     signed by the release key, has a sequence of at least 1 and an expiry
 *     still ahead. A browser whose floor is above the published release has
 *     nothing it can install; one whose floor is below it still accepts the
 *     older, vulnerable releases.
 *   - the manifest has Linux and Windows, and every file's address is
 *     exactly that file on the GitHub release hidravpn-v<its version>
 *     (make-release-manifest.sh writes <base>/<platform>/<file>, which a
 *     GitHub release does not have). With the floor at that version there is
 *     no older release to fall back on: a wrong address fails every install.
 *   - every browser download named on the homepage, the review page (/r/) and
 *     the installation guide is a file landing/SHA256SUMS.txt lists, on the
 *     tag of its own version; the two pages link every package of the
 *     table's latest version, and the size they show is the table's.
 *   - SUMS_SIGNED in src/main/update-check.js is true, SHA256SUMS.txt.sig
 *     exists and is the release key's signature of the table, and the table
 *     no longer says it has none.
 *   - package.json's version is the table's latest-version, and the table's
 *     valid-until is still ahead.
 *   - the packages (--packages <folder>): each package of the table's latest
 *     version is in the folder with the table's SHA-256 and size; its
 *     build.json names the table's "Built from commit", not -dirty, and its
 *     app is that version; and the copy of vpn-installer.js and
 *     update-check.js inside it says MIN_VERSION is the published HidraVPN
 *     and SUMS_SIGNED is true. Without --packages these fail: the tree alone
 *     says nothing about what was compiled into the files people download.
 *
 * Usage:
 *   node scripts/launch-check.js --packages <folder with the four zips> [--root <repository>]
 */
'use strict';

const fs = require('fs');
const path = require('path');
const releaseVerify = require('../src/main/release-verify');
const { parseRecord } = require('../src/main/update-check');
const { parseManifest } = require('../src/main/vpn-installer');
const { readZip } = require('./lib/zip');
const { platformOf, layoutOf } = require('./lib/package-runtime');
const { inflateRawSync } = require('zlib');
const crypto = require('crypto');

const DEFAULT_ROOT = path.join(__dirname, '..', '..');
const DAY = 24 * 60 * 60 * 1000;

// The pages and the guide that send people to a package.
const PAGES = [path.join('landing', 'index.html'), path.join('landing', 'r', 'index.html')];
const GUIDE = path.join('docs', 'technical', '07-installation-guide.md');
const RELEASES = 'https://github.com/NeurexBK/HidraNet/releases/download/';
const LINK_RE = /https:\/\/github\.com\/NeurexBK\/HidraNet\/releases\/download\/([^/"'\s<>]+)\/([^"'\s<>]+)/g;
const PACKAGE_RE = /^HidraNet-Browser-(\d+\.\d+\.\d+)-([A-Za-z0-9]+-[A-Za-z0-9]+)\.zip$/;
const NAME_RE = /HidraNet-Browser-[0-9A-Za-z.-]+?\.zip/g;
// The HidraVPN platforms a manifest must have: the browser runs on both, and
// a missing one leaves every user of it with nothing to install.
const VPN_PLATFORMS = ['linux-x64', 'win32-x64'];
// The size each page shows beside a link, in decimal megabytes.
const SHOWN = {
  [path.join('landing', 'index.html')]:
    /<div class="meta">v(\d+\.\d+\.\d+) · [^<]*?· (\d+) MB<\/div>\s*<a class="b" href="([^"]+)" download="([^"]+)"/g,
  [path.join('landing', 'r', 'index.html')]:
    /<a href="([^"]+)">(?:(?!<\/a>)[\s\S])*?<span class="sz">(\d+) MB<\/span><\/a>/g,
};

function readText(root, rel) {
  return fs.readFileSync(path.join(root, rel), 'utf8');
}

// `const NAME = <value>;` in a source file, read as text: the check is of
// the tree being merged, not of the copy this script happens to load.
function constant(root, rel, name) {
  return constantIn(readText(root, rel), rel, name);
}
function constantIn(text, rel, name) {
  const m = text.match(new RegExp('^const ' + name + " = ('[^']*'|true|false);", 'm'));
  if (!m) throw new Error('no `const ' + name + '` in ' + rel);
  return m[1].startsWith("'") ? m[1].slice(1, -1) : m[1] === 'true';
}

// The file of a package at `rel` inside its app folder, as text, or null.
function appFile(entries, layout, rel) {
  const e = entries.find((x) => x.filename.replace(/\\/g, '/').replace(/^\.\//, '') === layout.res + 'app/' + rel);
  if (!e) return null;
  return (e.method === 8 ? inflateRawSync(e.rawData) : e.rawData).toString('utf8');
}

// The files the table lists, by name, and its size rows, by label.
function readTable(text) {
  const files = new Map();
  for (const m of text.matchAll(/^([0-9a-f]{64})  (\S+)$/gm)) files.set(m[2], m[1]);
  const sizes = new Map();
  for (const m of text.matchAll(/^  (\S+ \S+)\s+([\d,]+) bytes\s+\([\d.]+ MiB\)$/gm)) {
    sizes.set(m[1], Number(m[2].replace(/,/g, '')));
  }
  return { files, sizes };
}

const megabytes = (bytes) => Math.round(bytes / 1e6);
const labelOf = (name) => (name.match(PACKAGE_RE) || [])[2].replace('-', ' ');

/**
 * Runs every check on the repository at `root`. Returns
 * { ok, results: [{ name, ok, detail }] }. `packages` is the folder with
 * the zips the table lists (null: the package checks fail). `publicKey` is the release key
 * (the one the browser embeds unless a test gives its own), `now` the time
 * the expiries are measured against.
 */
function launchCheck({ root = DEFAULT_ROOT, packages = null, publicKey = releaseVerify.RELEASE_PUBLIC_KEY, now = Date.now() } = {}) {
  const results = [];
  const check = (name, fn) => {
    try {
      const detail = fn();
      results.push({ name, ok: true, detail: detail || '' });
    } catch (e) {
      results.push({ name, ok: false, detail: (e && e.message) || String(e) });
    }
  };
  const settle = (fn) => { try { return { value: fn() }; } catch (e) { return { error: e }; } };
  const need = (r) => { if (r.error) throw r.error; return r.value; };

  // HidraVPN: the release the site serves, and the browser's floor.
  const manifestFile = path.join('landing', 'vpn', 'release', 'manifest.json');
  const manifestText = settle(() => readText(root, manifestFile));
  const manifest = settle(() => parseManifest(need(manifestText)));
  const minVersion = settle(() => constant(root, path.join('hidra-browser', 'src', 'main', 'vpn-installer.js'), 'MIN_VERSION'));

  check('MIN_VERSION is the HidraVPN release the site serves', () => {
    const min = need(minVersion);
    const m = need(manifest);
    if (min !== m.version) {
      throw new Error('vpn-installer.js says MIN_VERSION ' + min + ', ' + manifestFile + ' is HidraVPN ' + m.version);
    }
    return 'both ' + min;
  });
  check('the HidraVPN manifest is signed by the release key', () => {
    const text = need(manifestText);
    const sigFile = manifestFile + '.sig';
    if (!fs.existsSync(path.join(root, sigFile))) throw new Error('no ' + sigFile);
    if (!releaseVerify.verifyBytes(Buffer.from(text, 'utf8'), readText(root, sigFile), publicKey)) {
      throw new Error(sigFile + ' is not the release key\'s signature of manifest.json');
    }
    return sigFile;
  });
  check('the HidraVPN manifest has a sequence of at least 1', () => {
    const m = need(manifest);
    if (!(m.sequence >= 1)) {
      throw new Error('its sequence is ' + m.sequence + (JSON.parse(need(manifestText)).sequence === undefined ? ' (it has none)' : '') +
                      ': a browser that has accepted nothing yet would still take an older release in its place');
    }
    return 'sequence ' + m.sequence;
  });
  check('the HidraVPN manifest has not expired', () => {
    const m = need(manifest);
    if (m.expiresAt === null) throw new Error('it has no expires: an old one served in its place would never stop being believed');
    if (m.expiresAt <= now) throw new Error('it expired on ' + m.expires + ': no browser will install from it');
    return 'expires ' + m.expires + ', in ' + Math.floor((m.expiresAt - now) / DAY) + ' days';
  });
  check('the HidraVPN manifest\'s downloads are its own release\'s assets, for Linux and Windows', () => {
    const m = need(manifest);
    const base = RELEASES + 'hidravpn-v' + m.version + '/';
    const problems = [];
    for (const key of VPN_PLATFORMS) if (!m.platforms[key]) problems.push('it has no ' + key + ': nobody on it could install or update');
    for (const [key, p] of Object.entries(m.platforms)) {
      for (const f of p.files) {
        if (f.url !== base + f.name) problems.push(key + '/' + f.name + ' is at ' + f.url + ', not ' + base + f.name);
      }
    }
    if (problems.length) throw new Error(problems.join('\n       '));
    return VPN_PLATFORMS.join(' and ') + ', every file on ' + base;
  });

  // The table, its record and its signature.
  const sumsFile = path.join('landing', 'SHA256SUMS.txt');
  const sums = settle(() => fs.readFileSync(path.join(root, sumsFile)));
  const table = settle(() => readTable(need(sums).toString('utf8')));
  const record = settle(() => parseRecord(need(sums).toString('utf8')));
  const version = settle(() => JSON.parse(readText(root, path.join('hidra-browser', 'package.json'))).version);

  // The downloads the pages and the guide name.
  const named = (rel) => {
    const text = readText(root, rel);
    if (rel === GUIDE) return [...new Set(text.match(NAME_RE) || [])].map((file) => ({ file }));
    return [...text.matchAll(LINK_RE)].map((m) => ({ tag: m[1], file: m[2] }));
  };
  check('every download on the site and in the guide is a file the table lists', () => {
    const { files } = need(table);
    const latest = need(record).latest;
    const wanted = [...files.keys()].filter((f) => (f.match(PACKAGE_RE) || [])[1] === latest);
    const problems = [];
    let count = 0;
    for (const rel of [...PAGES, GUIDE]) {
      const links = named(rel);
      if (!links.length) problems.push(rel + ' names no package');
      for (const { tag, file } of links) {
        count++;
        const m = file.match(PACKAGE_RE);
        if (!files.has(file)) problems.push(rel + ' names ' + file + ', which ' + sumsFile + ' does not list');
        else if (tag !== undefined && m && tag !== 'v' + m[1]) problems.push(rel + ' links ' + file + ' on the tag ' + tag + ', not v' + m[1]);
      }
      if (PAGES.includes(rel)) {
        const linked = new Set(links.map((l) => l.file));
        for (const f of wanted) if (!linked.has(f)) problems.push(rel + ' does not link ' + f);
      }
    }
    if (problems.length) throw new Error(problems.join('\n       '));
    return count + ' named, all in the table';
  });
  check('the size each page shows is the table\'s', () => {
    const { files, sizes } = need(table);
    const problems = [];
    for (const rel of PAGES) {
      const text = readText(root, rel);
      const all = [...text.matchAll(LINK_RE)].length;
      const shown = [...text.matchAll(SHOWN[rel])].map((m) => rel === PAGES[0]
        ? { version: m[1], mb: Number(m[2]), href: m[3], download: m[4] }
        : { href: m[1], mb: Number(m[2]) });
      if (!all) problems.push(rel + ' links no package');
      else if (shown.length !== all) problems.push(rel + ': ' + all + ' download links, ' + shown.length + ' with a size beside them');
      for (const s of shown) {
        const file = s.href.startsWith(RELEASES) ? s.href.split('/').pop() : s.href;
        const m = file.match(PACKAGE_RE);
        if (!m || !files.has(file)) {
          problems.push(rel + ' shows ' + s.mb + ' MB for ' + file + ', which the table does not list: there is no size to compare');
          continue;
        }
        if (s.download !== undefined && s.download !== file) problems.push(rel + ' saves ' + file + ' as ' + s.download);
        if (s.version !== undefined && s.version !== m[1]) problems.push(rel + ' labels ' + file + ' v' + s.version);
        const bytes = sizes.get(labelOf(file));
        if (bytes === undefined) problems.push(sumsFile + ' has no size row for ' + labelOf(file));
        else if (s.mb !== megabytes(bytes)) {
          problems.push(rel + ' shows ' + s.mb + ' MB for ' + file + '; the table says ' + bytes.toLocaleString('en-US') +
                        ' bytes, so ' + megabytes(bytes) + ' MB');
        }
      }
    }
    if (problems.length) throw new Error(problems.join('\n       '));
    return PAGES.length + ' pages, every size as the table says';
  });

  check('SUMS_SIGNED is true', () => {
    const signed = constant(root, path.join('hidra-browser', 'src', 'main', 'update-check.js'), 'SUMS_SIGNED');
    if (signed !== true) throw new Error('update-check.js still says SUMS_SIGNED = false');
    return 'true';
  });
  check('SHA256SUMS.txt.sig is the release key\'s signature of the table', () => {
    const sigFile = sumsFile + '.sig';
    if (!fs.existsSync(path.join(root, sigFile))) throw new Error('no ' + sigFile + ': sign the table offline (scripts/sign-sums.ps1)');
    if (!releaseVerify.verifyBrowserSums(need(sums), readText(root, sigFile), publicKey)) {
      throw new Error(sigFile + ' does not verify: the table changed after it was signed, or another key signed it');
    }
    return sigFile;
  });
  check('the table no longer says it has no signature', () => {
    const text = need(sums).toString('utf8').replace(/\s+/g, ' ');
    if (text.includes('Until the maintainers publish the first signature there is no .sig')) {
      throw new Error(sumsFile + ' still says "Until the maintainers publish the first signature there is no .sig": edit it, then sign');
    }
    return '';
  });
  check('package.json\'s version is the table\'s latest-version', () => {
    const v = need(version);
    const r = need(record);
    if (v !== r.latest) throw new Error('hidra-browser/package.json says ' + v + ', the table\'s latest-version is ' + r.latest);
    return v + ' (minimum-safe-version ' + r.minimum + ')';
  });
  check('the table\'s record has not expired', () => {
    const r = need(record);
    if (r.expires <= now) throw new Error('valid-until ' + r.validUntil + ' has passed: browsers would not believe it');
    return 'valid until ' + r.validUntil + ', ' + Math.floor((r.expires - now) / DAY) + ' days';
  });

  // The packages themselves: what the browser was compiled with is what
  // their copy of src/ says, whatever the tree says today.
  const pkgs = settle(() => {
    if (!packages) throw new Error('no --packages folder given: the tree alone says nothing about what the four zips carry');
    const { files } = need(table);
    const latest = need(record).latest;
    const names = [...files.keys()].filter((f) => (f.match(PACKAGE_RE) || [])[1] === latest);
    if (!names.length) throw new Error(sumsFile + ' lists no package of ' + latest);
    return names.map((name) => {
      const file = path.join(packages, name);
      if (!fs.existsSync(file)) return { name, error: 'not in ' + packages };
      const bytes = fs.readFileSync(file);
      try {
        const { platform } = platformOf(name);
        const entries = readZip(bytes);
        const layout = layoutOf(entries, platform);
        return { name, bytes, read: (rel) => appFile(entries, layout, rel) };
      } catch (e) {
        return { name, bytes, error: 'cannot be read: ' + e.message };
      }
    });
  });
  const eachPackage = (fn, ok) => {
    const problems = [];
    for (const p of need(pkgs)) {
      if (p.error) problems.push(p.name + ' ' + p.error);
      else problems.push(...fn(p));
    }
    if (problems.length) throw new Error(problems.join('\n       '));
    return ok(need(pkgs).length);
  };

  check('the packages are the files the table lists', () => {
    const { files, sizes } = need(table);
    return eachPackage((p) => {
      const out = [];
      const sha = crypto.createHash('sha256').update(p.bytes).digest('hex');
      if (sha !== files.get(p.name)) out.push(p.name + ' has SHA-256 ' + sha + '; the table says ' + files.get(p.name));
      const bytes = sizes.get(labelOf(p.name));
      if (bytes !== p.bytes.length) {
        out.push(p.name + ' is ' + p.bytes.length.toLocaleString('en-US') + ' bytes; the table says ' +
                 (bytes === undefined ? 'nothing' : bytes.toLocaleString('en-US')));
      }
      return out;
    }, (n) => n + ' packages, each as the table says');
  });
  check('every package was built from the table\'s commit, from a clean tree, as its version', () => {
    const text = need(sums).toString('utf8');
    const line = /Built from commit ([0-9a-f]{7,40})\./.exec(text);
    if (!line) throw new Error(sumsFile + ' names no "Built from commit": update-sums.js <folder> <commit> writes it');
    const commit = line[1].slice(0, 7);
    const latest = need(record).latest;
    return eachPackage((p) => {
      const out = [];
      let stamp = null;
      try { stamp = JSON.parse(p.read('build.json')); } catch (e) { /* below */ }
      const build = stamp && typeof stamp.build === 'string' ? stamp.build : null;
      if (build === null) out.push(p.name + ' has no readable app/build.json');
      else if (/-dirty$/.test(build)) out.push(p.name + ' was built from ' + build + ', a tree with uncommitted changes');
      else if (build.slice(0, 7) !== commit) out.push(p.name + ' was built from ' + build + '; the table says ' + commit);
      let pkg = null;
      try { pkg = JSON.parse(p.read('package.json')); } catch (e) { /* below */ }
      if (!pkg || pkg.version !== latest) out.push(p.name + '\'s app says version ' + (pkg ? pkg.version : 'nothing') + ', not ' + latest);
      return out;
    }, (n) => n + ' packages, from ' + commit);
  });
  check('every package refuses HidraVPN older than the published release and wants the table signed', () => {
    const want = need(manifest).version;
    return eachPackage((p) => {
      const out = [];
      for (const [rel, name, ok, says] of [
        ['src/main/vpn-installer.js', 'MIN_VERSION', (v) => v === want, (v) => "MIN_VERSION '" + v + "', not '" + want + "'"],
        ['src/main/update-check.js', 'SUMS_SIGNED', (v) => v === true, (v) => 'SUMS_SIGNED ' + v],
      ]) {
        const text = p.read(rel);
        if (text === null) { out.push(p.name + ' has no ' + rel); continue; }
        try {
          const v = constantIn(text, rel, name);
          if (!ok(v)) out.push(p.name + ' was built with ' + says(v) + ': only another browser release can change it');
        } catch (e) {
          out.push(p.name + ': ' + e.message);
        }
      }
      return out;
    }, (n) => n + " packages with MIN_VERSION '" + want + "' and SUMS_SIGNED true");
  });

  return { ok: results.every((r) => r.ok), results };
}

module.exports = { launchCheck };

if (require.main === module) {
  const args = process.argv.slice(2);
  const value = (flag) => { const at = args.indexOf(flag); return at >= 0 ? path.resolve(args[at + 1] || '.') : null; };
  const root = value('--root') || DEFAULT_ROOT;
  const { ok, results } = launchCheck({ root, packages: value('--packages') });
  for (const r of results) {
    console.log((r.ok ? '  ok   ' : '  FAIL ') + r.name + (r.detail ? ': ' + r.detail : ''));
  }
  const failed = results.filter((r) => !r.ok).length;
  console.log(ok ? '\nready: every check passed' : '\nnot ready: ' + failed + ' of ' + results.length + ' checks failed');
  process.exit(ok ? 0 : 1);
}
