#!/usr/bin/env node
/**
 * HidraNet — is this tree ready to go out as the browser release?
 *
 * Run on launch day, on the branch that raises the browser's floor for
 * HidraVPN and points the site at the new packages, after the maintainer has
 * added what only the offline release key can make and before that branch is
 * merged. Every check reads the tree as it is; nothing is fetched, built or
 * signed. Each one prints ok or FAIL with the reason, and the exit status is
 * 1 if any failed.
 *
 *   - MIN_VERSION in src/main/vpn-installer.js is the HidraVPN release the
 *     site serves (landing/vpn/release/manifest.json), and that manifest is
 *     signed by the release key, has a sequence of at least 1 and an expiry
 *     still ahead. A browser whose floor is above the published release has
 *     nothing it can install; one whose floor is below it still accepts the
 *     older, vulnerable releases.
 *   - every browser download named on the homepage, the review page (/r/) and
 *     the installation guide is a file landing/SHA256SUMS.txt lists, on the
 *     tag of its own version; the two pages link every package of the
 *     table's latest version, and the size they show is the table's.
 *   - SUMS_SIGNED in src/main/update-check.js is true, SHA256SUMS.txt.sig
 *     exists and is the release key's signature of the table, and the table
 *     no longer says it has none.
 *   - package.json's version is the table's latest-version, and the table's
 *     valid-until is still ahead.
 *
 * Usage:
 *   node scripts/launch-check.js [--root <repository>]
 */
'use strict';

const fs = require('fs');
const path = require('path');
const releaseVerify = require('../src/main/release-verify');
const { parseRecord } = require('../src/main/update-check');
const { parseManifest } = require('../src/main/vpn-installer');

const DEFAULT_ROOT = path.join(__dirname, '..', '..');
const DAY = 24 * 60 * 60 * 1000;

// The pages and the guide that send people to a package.
const PAGES = [path.join('landing', 'index.html'), path.join('landing', 'r', 'index.html')];
const GUIDE = path.join('docs', 'technical', '07-installation-guide.md');
const RELEASES = 'https://github.com/NeurexBK/HidraNet/releases/download/';
const LINK_RE = /https:\/\/github\.com\/NeurexBK\/HidraNet\/releases\/download\/([^/"'\s<>]+)\/([^"'\s<>]+)/g;
const PACKAGE_RE = /^HidraNet-Browser-(\d+\.\d+\.\d+)-([A-Za-z0-9]+-[A-Za-z0-9]+)\.zip$/;
const NAME_RE = /HidraNet-Browser-[0-9A-Za-z.-]+?\.zip/g;
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
  const m = readText(root, rel).match(new RegExp('^const ' + name + " = ('[^']*'|true|false);", 'm'));
  if (!m) throw new Error('no `const ' + name + '` in ' + rel);
  return m[1].startsWith("'") ? m[1].slice(1, -1) : m[1] === 'true';
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
 * { ok, results: [{ name, ok, detail }] }. `publicKey` is the release key
 * (the one the browser embeds unless a test gives its own), `now` the time
 * the expiries are measured against.
 */
function launchCheck({ root = DEFAULT_ROOT, publicKey = releaseVerify.RELEASE_PUBLIC_KEY, now = Date.now() } = {}) {
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

  return { ok: results.every((r) => r.ok), results };
}

module.exports = { launchCheck };

if (require.main === module) {
  const args = process.argv.slice(2);
  const at = args.indexOf('--root');
  const root = at >= 0 ? path.resolve(args[at + 1] || '.') : DEFAULT_ROOT;
  const { ok, results } = launchCheck({ root });
  for (const r of results) {
    console.log((r.ok ? '  ok   ' : '  FAIL ') + r.name + (r.detail ? ': ' + r.detail : ''));
  }
  const failed = results.filter((r) => !r.ok).length;
  console.log(ok ? '\nready: every check passed' : '\nnot ready: ' + failed + ' of ' + results.length + ' checks failed');
  process.exit(ok ? 0 : 1);
}
