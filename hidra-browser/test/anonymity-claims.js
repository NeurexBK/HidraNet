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

// ── What carries the traffic ─────────────────────────────────────────────
//
// Connecting means Tor (main.js, proxy:connect). The HidraNet engine has a
// post-quantum Noise handshake and a DHT, but carries none of the browsing,
// and the apps meet on public MQTT brokers. The panel and the homepage named
// the engine's primitives as if they protected the browser: a cipher name on
// every hop, "encrypted" past the exit, ML-KEM in the footer.

const mainJs = fs.readFileSync(path.join(MAIN, 'main.js'), 'utf8');
const ENGINE_TERMS = /ML-KEM|Kyber|[Qq]uantum|\bNoise\b|BLAKE3|ChaCha20|AES-\d+|Kademlia|\bDHT\b/;
const text = (html) => html.replace(/<!--[\s\S]*?-->/g, ' ').replace(/<[^>]+>/g, ' ').replace(/&[a-z]+;/g, ' ').replace(/\s+/g, ' ').trim();
const markup = (html) => html.replace(/<!--[\s\S]*?-->/g, (c) => ' '.repeat(c.length));

const routedByTor = /ipcMain\.handle\('proxy:connect'[\s\S]{0,200}?connectTor\(/.test(mainJs);
if (!routedByTor) {
  bad('what carries the traffic', 'main.js no longer connects through Tor: say what does, here and on the panel');
} else {
  const page = markup(newtab);
  const hit = page.match(ENGINE_TERMS);
  if (hit) {
    bad(
      'the panel names what really carries the traffic',
      `newtab.html says "${hit[0]}", a primitive of the HidraNet engine, which carries none of the browsing (connecting means Tor)`
    );
  } else {
    ok('the panel names no engine primitive the browsing does not use');
  }

  const hops = [...page.matchAll(/<span class="line-encrypted[^"]*">([^<]*)<\/span>/g)].map((m) => m[1].trim());
  if (hops.length !== 4) {
    bad('circuit labels', `expected four links (you, guard, middle, exit, site), found ${hops.length}`);
  } else if (!hops.slice(0, 3).every((h) => /^Tor\b/.test(h))) {
    bad('circuit labels', 'the hops to the exit are not labelled as Tor: ' + hops.slice(0, 3).join(' / '));
  } else if (!/if the site uses HTTPS/i.test(hops[3])) {
    bad(
      'circuit labels',
      `the link past the exit says "${hops[3]}". There is no HTTPS-only mode, so a plain-HTTP site leaves the exit in clear text`
    );
  } else {
    ok('circuit labels: Tor to the exit, TLS past it only if the site uses HTTPS');
  }

  const dest = page.match(/<div class="circuit-node destination">[\s\S]*?<span class="node-ip">([^<]*)<\/span>/);
  if (!dest) bad('the site the circuit ends at', 'could not find the destination node');
  else if (/encrypt|secure|protected/i.test(dest[1])) bad('the site the circuit ends at', `labelled "${dest[1]}", which depends on the site`);
  else ok('the site the circuit ends at is not labelled encrypted');

  const foot = page.match(/<footer class="footer">([\s\S]*?)<\/footer>/);
  if (!foot) bad('panel footer', 'could not find the footer');
  else if (!/\bTor\b/.test(text(foot[1])) || !/MQTT brokers/.test(text(foot[1]))) {
    bad('panel footer', 'the footer does not say that browsing goes through Tor and the apps through public MQTT brokers');
  } else ok('panel footer: browsing through Tor, apps through public brokers');
}

// The homepage: an engine primitive may be named only on a card that says
// it is the engine's and that the engine does not carry the traffic yet. A
// stat, a chip or the page description cannot carry that qualification, so
// there it is not allowed at all.
const home = markup(fs.readFileSync(path.join(__dirname, '..', '..', 'landing', 'index.html'), 'utf8'))
  .replace(/<(style|script)\b[\s\S]*?<\/\1>/g, (c) => ' '.repeat(c.length));
const cards = [...home.matchAll(/<article\b[\s\S]*?<\/article>/g)].map((m) => ({ from: m.index, to: m.index + m[0].length, html: m[0], text: text(m[0]) }));
const unqualified = [];
for (const m of home.matchAll(new RegExp(ENGINE_TERMS.source, 'g'))) {
  const card = cards.find((c) => m.index >= c.from && m.index < c.to);
  const where = card ? card.text.slice(0, 80) : home.slice(Math.max(0, m.index - 60), m.index + 40).replace(/\s+/g, ' ');
  if (!card || !/HidraNet engine/.test(card.text) || !/does not carry|not yet carr/i.test(card.text)) {
    unqualified.push(`"${m[0]}" in: ${where}`);
  }
}
if (unqualified.length) {
  bad('homepage engine claims', 'named as if they protected the browser:\n      ' + unqualified.join('\n      '));
} else {
  ok('homepage: engine primitives only where it says the engine does not carry the traffic yet');
}

const browserCard = cards.find((c) => /<h3>HidraBrowser<\/h3>/.test(c.html));
if (!browserCard) bad('homepage HidraBrowser card', 'could not find the HidraBrowser product card');
else if (!/\bTor\b/.test(browserCard.text)) bad('homepage HidraBrowser card', 'the card does not say the browser goes through Tor');
else ok('homepage HidraBrowser card: says it is Tor');

// Tor isolates by destination host (IsolateDestAddr), not by the site in the
// address bar: a tracker or a CDN embedded in many sites is reached over one
// circuit for all of them. "A circuit per site" reads as Tor Browser's
// first-party isolation, which would take per-site SOCKS credentials.
const perSite = /circuits?\b[^.<]{0,30}?\b(?:per|for each|for every|each) (?:site|website)\b/i;
if (!/IsolateSOCKSAuth/.test(torManager)) {
  const claims = [['landing/index.html', text(home)], ['newtab.html', text(markup(newtab))]]
    .map(([where, t]) => [where, t.match(perSite)])
    .filter(([, m]) => m)
    .map(([where, m]) => `"${m[0]}" in ${where}`);
  if (claims.length) bad('circuit isolation claims', 'circuits are per destination host, not per site: ' + claims.join(', '));
  else ok('circuit isolation claims: per destination, as Tor is started');
}

if (/MQTT_BROKERS/.test(fs.readFileSync(path.join(UI, 'hidrachat.html'), 'utf8')) && !/public MQTT brokers/.test(text(home))) {
  bad('homepage apps', 'the apps meet on public MQTT brokers and the homepage never says so');
} else {
  ok('homepage apps: says they meet on public MQTT brokers');
}

if (failed) {
  console.log('\n' + failed + ' claim(s) the browser does not keep');
  process.exit(1);
}
console.log('\nevery badge on the panel is backed by something real');
