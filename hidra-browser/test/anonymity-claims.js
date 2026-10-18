// Every claim the anonymity panel makes has to be one the browser keeps.
//
// The panel is a row of green badges, and a green badge is a promise. Six of
// them were hardcoded in the HTML, so they read the same whether the browser
// was routed through the network or sitting there disconnected — "DNS Leak
// Protection: Active" included, which is the one that was false exactly when
// a user most needed it to be true.
//
// This test is a lint over the page and the main process rather than a
// running check, because what it guards against is the same hardcoded badge
// coming back: someone adds a row, writes "Active" in the markup, and nothing
// anywhere disagrees.

const fs = require('fs');
const path = require('path');

const UI = path.join(__dirname, '..', 'src', 'ui');
const MAIN = path.join(__dirname, '..', 'src', 'main');

const newtab = fs.readFileSync(path.join(UI, 'newtab.html'), 'utf8');
const tabManager = fs.readFileSync(path.join(MAIN, 'tab-manager.js'), 'utf8');

let failed = 0;
const ok = (name) => console.log('ok    ' + name);
const bad = (name, why) => {
  console.log('FAIL  ' + name + '\n      ' + why);
  failed++;
};

// ── The claims that must be backed by code that always runs ──────────────
//
// These describe what every tab gets, connected or not, so a fixed badge is
// honest — as long as the code is really there.

const UNCONDITIONAL = [
  {
    claim: 'Fingerprint Protection',
    evidence: /_injectFingerprint\s*\(/,
    where: 'tab-manager.js',
    source: tabManager,
  },
  {
    claim: 'WebRTC Leak Protection',
    evidence: /setWebRTCIPHandlingPolicy\(\s*['"]disable_non_proxied_udp['"]\s*\)/,
    where: 'tab-manager.js',
    source: tabManager,
  },
  {
    claim: 'Tab Isolation',
    evidence: /session\.fromPartition\(/,
    where: 'tab-manager.js',
    source: tabManager,
  },
  {
    claim: 'Referrer Stripping',
    evidence: /[Rr]eferer/,
    where: 'tab-manager.js',
    source: tabManager,
  },
  {
    claim: 'Client Hints',
    evidence: /Sec-CH-UA/,
    where: 'tab-manager.js',
    source: tabManager,
  },
];

for (const { claim, evidence, where, source } of UNCONDITIONAL) {
  if (!newtab.includes(claim)) {
    bad(claim, 'the panel no longer makes this claim — drop it from this test');
    continue;
  }
  if (evidence.test(source)) ok(claim + ': backed by ' + where);
  else bad(claim, 'the panel claims it, but nothing in ' + where + ' does it');
}

// ── The claim that depends on being connected ────────────────────────────

const dnsRow = newtab.match(
  /DNS Leak Protection[\s\S]{0,400}?<\/div>\s*<\/div>/
);
if (!dnsRow) {
  bad('DNS Leak Protection', 'could not find the row in newtab.html');
} else if (/setting-badge"[^>]*>\s*(Active|Enforced|Blocked|Stripped)\s*</.test(dnsRow[0])) {
  bad(
    'DNS Leak Protection',
    'the badge is hardcoded. Names only reach an exit relay while traffic is ' +
      'routed through the engine; disconnected, this machine resolves them ' +
      'itself, and the badge would be claiming otherwise.'
  );
} else if (!/id="dns-badge"/.test(dnsRow[0])) {
  bad('DNS Leak Protection', 'the badge has no id, so nothing can update it');
} else if (!/dns-badge[\s\S]*?Not routed/.test(newtab)) {
  bad(
    'DNS Leak Protection',
    'the badge is driven from script, but nothing ever sets the disconnected state'
  );
} else {
  ok('DNS Leak Protection: driven from the live connection state');
}

// ── No relay address reaches the panel ───────────────────────────────────

if (/octets\[0\]\s*\+\s*['"]\.['"]\s*\+\s*octets\[1\]/.test(newtab)) {
  bad(
    'relay display',
    'a relay is shown as a masked address. A /16 plus the port leaves very ' +
      'few candidates for a guard, and the guard is the one address that ' +
      'identifies this user.'
  );
} else if (!/relayFingerprint\s*\(/.test(newtab)) {
  bad('relay display', 'nothing turns a relay address into a fingerprint');
} else if (!/crypto\.getRandomValues\([\s\S]{0,40}fingerprintKey|fingerprintKey\s*=\s*crypto\.getRandomValues/.test(newtab)) {
  bad(
    'relay display',
    'the fingerprint is unkeyed. An IPv4 address is 32 bits, so an unkeyed ' +
      'hash of one is recovered by trying all of them.'
  );
} else {
  ok('relay display: keyed per-session fingerprints, no addresses');
}

// ── Sites are not linked by a shared exit ───────────────────────────────
//
// Chromium sends no SOCKS credentials, so Tor cannot tell one tab from
// another; without stream isolation every site visited in the same ten
// minutes left through one exit.
const torManager = fs.readFileSync(path.join(MAIN, 'tor-manager.js'), 'utf8');
if (/'--SocksPort',\s*`\$\{this\.socksPort\} IsolateDestAddr`/.test(torManager)) ok('each destination gets its own Tor circuit');
else bad('each destination gets its own Tor circuit', 'tor-manager.js no longer starts Tor with IsolateDestAddr on its SocksPort');

// ── Only this machine goes around Tor ───────────────────────────────────
const lock = fs.readFileSync(path.join(MAIN, 'network-lock.js'), 'utf8');
const proxy = fs.readFileSync(path.join(MAIN, 'proxy-manager.js'), 'utf8');
if (/LOOPBACK_ONLY = 'localhost,\*\.localhost,127\.0\.0\.1,\[::1\]'/.test(proxy)) ok('only this machine goes around the proxy');
else bad('only this machine goes around the proxy', 'proxy-manager.js bypasses the proxy for more than loopback');
if (/endsWith\('\.localhost'\)/.test(lock)) ok('the apps\' own hosts count as this machine for the lock');
else bad('the apps\' own hosts count as this machine for the lock', 'network-lock.js would block the apps');

if (failed) {
  console.log('\n' + failed + ' claim(s) the browser does not keep');
  process.exit(1);
}
console.log('\nevery badge on the panel is backed by something real');
