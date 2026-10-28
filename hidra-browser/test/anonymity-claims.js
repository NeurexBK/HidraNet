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

// ── DNS: no name reaches this machine's resolver ─────────────────────────
//
// The badge used to follow the connection: "Active" while routed, "Not
// routed" otherwise, because disconnected Chromium resolved names itself. It
// did so connected, too, for a page's dns-prefetch hints, which no proxy and
// no request filter sees. Now Chromium resolves nothing but this machine's own
// names in any state, so the badge is fixed, and it is true only while the
// switch that does it is there and maps every other name to nothing.

const main = fs.readFileSync(path.join(MAIN, 'main.js'), 'utf8');
const lockSrc = fs.readFileSync(path.join(MAIN, 'network-lock.js'), 'utf8');
const rules = (lockSrc.match(/const HOST_RESOLVER_RULES = '([^']*)'/) || [])[1];
const dnsRow = newtab.match(/DNS Leak Protection[\s\S]{0,400}?<\/div>\s*<\/div>/);
if (!dnsRow) {
  bad('DNS Leak Protection', 'could not find the row in newtab.html');
} else if (!/appendSwitch\('host-resolver-rules', HOST_RESOLVER_RULES\)/.test(main)) {
  bad('DNS Leak Protection', 'main.js no longer gives Chromium the host-resolver-rules switch, so a page\'s dns-prefetch hint reaches the system resolver');
} else if (!rules || !/^MAP \* ~NOTFOUND(, EXCLUDE [^,]+)*$/.test(rules)) {
  bad('DNS Leak Protection', 'HOST_RESOLVER_RULES does not map every name to NOTFOUND: ' + rules);
} else if (rules.split(', ').slice(1).some((r) => !['EXCLUDE localhost', 'EXCLUDE *.localhost', 'EXCLUDE 127.0.0.1', 'EXCLUDE ::1'].includes(r))) {
  bad('DNS Leak Protection', 'HOST_RESOLVER_RULES lets Chromium resolve a name that is not this machine: ' + rules);
} else {
  ok('DNS Leak Protection: Chromium resolves only this machine\'s names, in every state');
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

// ── "Nothing left this computer" ────────────────────────────────────────
//
// The page a blocked tab shows says so. It holds only if no session is ever
// left on a route of its own while the lock is shut: Disconnect and a Tor
// crash used to set every session to 'direct', and tabs started out on
// whatever answered on port 9050. Every session now gets Tor's route from the
// lock the moment it is made, and nothing else sets one.
const mainDir = fs.readdirSync(MAIN).filter((f) => f.endsWith('.js'))
  .map((f) => [f, fs.readFileSync(path.join(MAIN, f), 'utf8')]);
const direct = mainDir.filter(([, src]) => /mode:\s*['"]direct['"]|direct:\/\//.test(src)).map(([f]) => f);
const setters = mainDir.filter(([f, src]) => f !== 'network-lock.js' && /\.setProxy\(/.test(src)
  && src.replace(/probe\.setProxy\(\{ proxyRules, proxyBypassRules: LOOPBACK_ONLY \}\)/, '').includes('.setProxy(')).map(([f]) => f);
if (!tabManager.includes('Nothing left this computer')) bad('the block page', 'it no longer makes this claim — drop it from this test');
else if (direct.length) bad('the block page', 'a session can be set to direct in ' + direct.join(', '));
else if (setters.length) bad('the block page', 'something besides the network lock gives a browsing session its route: ' + setters.join(', '));
else if (!/protect\(electronSession\) \{[\s\S]*?setProxy\(this\.proxyConfig\(\)\)/.test(lock)) bad('the block page', 'the lock no longer routes the sessions it protects');
else if (/9050|_probeSocks|configure\(/.test(proxy.replace(/^\s*\/\/.*$/gm, ''))) bad('the block page', 'proxy-manager.js still looks for a SOCKS proxy on 9050');
else ok('the block page: no session is ever routed anywhere but Tor');

// It also holds only while the lock is shut whenever Tor is not running. A
// connect awaits its checks before opening, and a Disconnect or a Tor crash
// during them used to be undone by the release that followed. And Disconnect
// stopped Tor before closing, leaving Tor's port free behind an open lock.
const connectBody = (main.match(/async function connectTorOnce\(\) \{[\s\S]*?\n\}/) || [''])[0];
const disconnectBody = (main.match(/'proxy:disconnect'[\s\S]*?\n {2}\}\);/) || [''])[0];
if (!/const generation = networkLock\.generation;\s*(\/\/.*\s*)*const started = await torManager\.start/.test(connectBody)) {
  bad('the block page', 'connectTorOnce no longer takes the lock\'s generation before it awaits anything');
} else if ((connectBody.match(/networkLock\.release\(/g) || []).length !== 1
  || !/getStatus\(\)\.state !== 'ready' \|\| !networkLock\.release\(generation\)/.test(connectBody)) {
  bad('the block page', 'connectTorOnce can open the lock without checking that Tor is still up and nothing closed it since');
} else if (!/networkLock\.engage\('disconnected by the user'\);\s*await torManager\.stop\(\);/.test(disconnectBody)) {
  bad('the block page', 'Disconnect stops Tor before it closes the lock');
} else {
  ok('the block page: a late connect cannot reopen the lock, and Disconnect closes it first');
}

if (failed) {
  console.log('\n' + failed + ' claim(s) the browser does not keep');
  process.exit(1);
}
console.log('\nevery badge on the panel is backed by something real');
