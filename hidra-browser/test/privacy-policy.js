// The privacy policy has to name every place the software and the site send
// data, and say what HidraNet's own machines see.
//
// Version 1.0 described the browser, the apps and the website and left out
// HidraVPN entirely: the nodes and the pass issuer the maintainers run, the
// resolvers the exits ask, the leak test. It also said, without exception,
// that HidraNet never collects an IP address together with browsing, which a
// one-hop node sees by design. And the site's review page connected every
// visitor's browser, without Tor, to two public MQTT brokers the website
// section never mentioned, though the site's own CSP allows exactly them.
//
// Like anonymity-claims.js this is a lint, not a proof: it reads where the
// data really goes from the code (the CSP, the review page's broker list,
// the node's default resolvers, the leak test's URL, the signed node list)
// and fails when the policy does not name it.

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..');
const LANDING = path.join(ROOT, 'landing');
const read = (...p) => fs.readFileSync(path.join(...p), 'utf8');

const policyHtml = read(LANDING, 'privacy', 'index.html');
const text = (html) => html.replace(/<!--[\s\S]*?-->/g, ' ').replace(/<[^>]+>/g, ' ').replace(/&[a-z]+;/g, ' ').replace(/\s+/g, ' ').trim();
const policy = text(policyHtml);

let failed = 0;
const ok = (name) => console.log('ok    ' + name);
const bad = (name, why) => {
  console.log('FAIL  ' + name + '\n      ' + why);
  failed++;
};
const missing = (hay, needles) => needles.filter((n) => !hay.toLowerCase().includes(n.toLowerCase()));

// A part of the policy: from the element with this id to the next heading of
// the same level or higher.
function part(id) {
  const m = policyHtml.match(new RegExp(`<(h[23]|section)\\b[^>]*\\bid="${id}"[^>]*>`));
  if (!m) return null;
  const rest = policyHtml.slice(m.index + m[0].length);
  const stop = m[1] === 'section' ? rest.search(/<\/section>/) : rest.search(/<h[23]\b/);
  return text(stop < 0 ? rest : rest.slice(0, stop));
}

// The name a host goes by: broker.emqx.io → emqx, cloudflare-dns.com →
// cloudflare, api.ipify.org → ipify.
function label(host) {
  const parts = host.split('.');
  return parts[parts.length - 2].split('-')[0];
}

const website = part('website');
const vpn = part('vpn');
const third = part('third');
const principle = part('principle');

// ── The site's connect-src: every host it lets a page talk to ───────────
{
  const csps = [];
  for (const f of ['_headers', 'vercel.json']) {
    if (!fs.existsSync(path.join(LANDING, f))) continue;
    for (const m of read(LANDING, f).matchAll(/connect-src ([^;"]*)/g)) csps.push([f, m[1]]);
  }
  if (!csps.length) {
    bad('connect-src', 'neither landing/_headers nor landing/vercel.json has a connect-src');
  } else if (!website) {
    bad('connect-src', 'the policy has no website section (id="website")');
  } else {
    for (const [f, src] of csps) {
      const hosts = src.trim().split(/\s+/).filter((s) => !s.startsWith("'"))
        .map((s) => s.replace(/^[a-z]+:\/\//, '').replace(/[:/].*$/, ''));
      const unnamed = missing(website, hosts);
      if (unnamed.length) bad(`connect-src in ${f}`, `the website section does not name ${unnamed.join(', ')}`);
      else ok(`connect-src in ${f}: every host is named in the website section (${hosts.join(', ') || 'none'})`);
    }
  }
}

// ── The review page: its brokers, and what it tells the person ──────────
{
  const page = read(LANDING, 'r', 'index.html');
  const list = page.match(/var BROKERS = \[([^\]]*)\]/);
  const hosts = list ? [...list[1].matchAll(/wss?:\/\/([^:/'"]+)/g)].map((m) => m[1]) : [];
  if (!hosts.length) {
    bad('review page brokers', 'could not read BROKERS from landing/r/index.html');
  } else {
    const inPolicy = website ? missing(website, hosts) : hosts;
    if (inPolicy.length) bad('review page brokers', `the website section does not name ${inPolicy.join(', ')}`);
    else if (!/without Tor/.test(website) || !/IP address/.test(website)) {
      bad('review page brokers', 'the website section does not say the page connects without Tor and shows the IP address');
    } else ok('review page brokers: named in the website section, with "without Tor"');

    const tableNames = third ? missing(third, hosts.map(label)) : hosts;
    if (tableNames.length) bad('review page brokers', `the processors table does not list ${tableNames.join(', ')}`);
    else ok('review page brokers: in the processors table');

    const notice = page.match(/<[^>]*\bid="review-notice"[^>]*>([\s\S]*?)<\/p>/);
    const send = page.indexOf('id="send"');
    if (!notice) {
      bad('review notice', 'the review form has no notice (id="review-notice")');
    } else if (notice.index > send) {
      bad('review notice', 'the notice comes after the "Post review" button, so it is read after posting');
    } else {
      const n = text(notice[1]);
      const unnamed = missing(n, hosts);
      if (unnamed.length) bad('review notice', `it does not name ${unnamed.join(', ')}`);
      else if (!/public/.test(n) || !/name/.test(n) || !/place/.test(n) || !/kept/.test(n) || !/without Tor/.test(n)) {
        bad('review notice', 'it must say the name and place are public and kept by the brokers, and that the page connects without Tor');
      } else ok('review notice: before the button, names the brokers, says public, kept and without Tor');
    }
  }
}

// ── HidraVPN ─────────────────────────────────────────────────────────────
if (!vpn) {
  bad('HidraVPN section', 'the policy has no HidraVPN section (id="vpn")');
} else {
  ok('HidraVPN section: present');

  // Who runs the nodes and the issuer: the signed list says.
  const list = JSON.parse(read(LANDING, 'vpn', 'nodes.json'));
  const operators = [...new Set((list.nodes || []).map((n) => n.operator))];
  if (operators.includes('HidraNet') && !/run by the HidraNet maintainers/.test(vpn)) {
    bad('HidraVPN operators', 'the signed list names HidraNet as an operator, and the section does not say the maintainers run the nodes');
  } else ok('HidraVPN operators: ' + operators.join(', '));

  const issuerHost = list.pass_issuer && new URL(list.pass_issuer.url).host;
  if (issuerHost && !vpn.includes(issuerHost)) bad('HidraVPN issuer', `the section does not name the issuer, ${issuerHost}`);
  else ok('HidraVPN issuer: ' + (issuerHost || 'none on the list'));

  // What each party sees.
  const parties = [
    [/one-hop mode/, /IP address and your traffic/],
    [/entry/, /Your IP address/],
    [/exit/, /entry's address, not yours/],
    [/issuer/, /account token/],
  ];
  const gaps = parties.filter(([who, what]) => !who.test(vpn) || !what.test(vpn)).map(([who]) => who.source);
  if (gaps.length) bad('HidraVPN parties', 'the section does not say what these see: ' + gaps.join(', '));
  else ok('HidraVPN parties: the one-hop node, the entry, the exit and the issuer');

  // What the issuer keeps, and when it sees the person's own address.
  const issuer = [/hash of its token/, /orders file/, /exact amount/, /Solana's public ledger/, /not connected shows the issuer your own IP address/];
  const gone = issuer.filter((r) => !r.test(vpn)).map((r) => r.source);
  if (gone.length) bad('HidraVPN issuer records', 'the section does not say: ' + gone.join(', '));
  else ok('HidraVPN issuer records: accounts, orders, the ledger, and fetching outside the tunnel');

  // When the issuer forgets an order: only as often as it prunes. While
  // prune runs only inside the handlers for a new order and a claim (open,
  // and hold and before_claim for a claim), and in the maintainers' own
  // order commands (take_lapsed for a credit by hand, and main, which only
  // reads), a stated deadline is not a bound, and the policy must say so.
  const issuerSrc = read(ROOT, 'hidravpn', 'crates', 'hidravpn-issuer', 'src', 'main.rs');
  const testsAt = issuerSrc.search(/\nmod tests\b/);
  const live = testsAt < 0 ? issuerSrc : issuerSrc.slice(0, testsAt);
  const pruners = [...new Set([...live.matchAll(/\.prune\(/g)].map((m) => {
    const fns = [...live.slice(0, m.index).matchAll(/\bfn (\w+)/g)];
    return fns.length ? fns[fns.length - 1][1] : '?';
  }))];
  const onDemand = pruners.length > 0 && pruners.every((f) => ['open', 'hold', 'before_claim', 'take_lapsed', 'main'].includes(f));
  if (!pruners.length) bad('HidraVPN order retention', 'could not find where the issuer prunes its orders');
  else if (onDemand && (/orders? (?:are|is) deleted after/i.test(vpn) || !/next time anyone opens or claims an order/.test(vpn))) {
    bad('HidraVPN order retention', `the issuer prunes orders only in ${pruners.join(' and ')}; the section must say old orders go when the next order is opened or claimed`);
  } else ok('HidraVPN order retention: as the issuer prunes (' + pruners.join(', ') + ')');

  // What the issuer keeps of an order that lapses unpaid: a file of its
  // own beside the orders, with the amount and the times the ledger can be
  // matched against, kept for its days whatever the orders file says.
  const ordersDefault = issuerSrc.match(/default_value = "[^"]*\/([^"/]+)\.json"\s*\)\]\s*orders: PathBuf/);
  const lapsedExt = live.match(/fn lapsed_path\(orders: &Path\) -> PathBuf \{\s*orders\.with_extension\("([^"]+)"\)/);
  const lapsedKept = live.match(/const LAPSED_KEPT: i64 = (\d+) \* 86_400;/);
  if (!ordersDefault || !lapsedExt || !lapsedKept) {
    bad('HidraVPN lapsed orders', 'could not read the orders file, lapsed_path or LAPSED_KEPT from hidravpn-issuer/src/main.rs');
  } else {
    const file = `${ordersDefault[1]}.${lapsedExt[1]}`;
    const days = `${lapsedKept[1]} days`;
    if (!vpn.includes(file) || !vpn.includes(days) || !/three files/.test(vpn) || /two files/.test(vpn)) {
      bad('HidraVPN lapsed orders', `the issuer keeps the record of an order that lapses unpaid in a third file, ${file}, for ${days}; the section must say three files, name it and say how long`);
    } else ok(`HidraVPN lapsed orders: ${file}, kept ${days}`);
  }

  // How long an order stays open: less when no claim has reached it.
  const paymentSrc = read(ROOT, 'hidravpn', 'crates', 'hidravpn-core', 'src', 'payment.rs');
  const unclaimed = paymentSrc.match(/pub const UNCLAIMED_LIFETIME: i64 = (\d+) \* 3600;/);
  const life = paymentSrc.match(/pub const ORDER_LIFETIME: i64 = (\d+) \* 3600;/);
  if (!unclaimed || !life) {
    bad('HidraVPN order life', 'could not read UNCLAIMED_LIFETIME or ORDER_LIFETIME from hidravpn-core/src/payment.rs');
  } else if (!vpn.includes(`${unclaimed[1]} hours after it was made`) || !vpn.includes(`a claim has reached after ${life[1]} hours`)) {
    bad('HidraVPN order life', `an order no claim has reached lapses ${unclaimed[1]} hours after it was made, one a claim has reached after ${life[1]} hours, and the section does not say so`);
  } else ok(`HidraVPN order life: ${unclaimed[1]} hours unclaimed, ${life[1]} once claimed`);

  // Account names: random only for one a purchase made.
  if (/fn add\(&mut self, name: &str/.test(issuerSrc) && !/chosen by the maintainers/.test(vpn)) {
    bad('HidraVPN account names', 'the maintainers name the accounts they make by hand (account add --name); the section must say so');
  } else ok('HidraVPN account names: random for purchases, chosen for accounts handed out');

  // Keys and journals the nodes keep.
  const nodeCfg = read(ROOT, 'hidravpn', 'crates', 'hidravpn-node', 'src', 'config.rs');
  const idle = nodeCfg.match(/fn default_idle_days\(\) -> u32 \{\s*(\d+)/);
  if (!idle) bad('HidraVPN open leases', 'could not read default_idle_days from hidravpn-node/src/config.rs');
  else if (!vpn.includes(`${idle[1]} days without a handshake`)) {
    bad('HidraVPN open leases', `a key joined by hand is kept until ${idle[1]} days without a handshake, and the section does not say so`);
  } else ok(`HidraVPN open leases: ${idle[1]} days`);
  if (/last pass's key/.test(read(ROOT, 'hidravpn', 'docs', 'anonymity.md')) && !/last pass's key/.test(vpn)) {
    bad('HidraVPN one-hop key', "with no pass left one hop reconnects with the last pass's key, and the section says every key is made for the connection");
  } else ok("HidraVPN one-hop key: the last pass's key when none is left");
  const nodeMain = read(ROOT, 'hidravpn', 'crates', 'hidravpn-node', 'src', 'main.rs');
  if (/info!\("admitted a client/.test(nodeMain) && !/journals do record/.test(vpn)) {
    bad('HidraVPN journals', 'the nodes and the issuer note admissions, expiries, issuances and orders in their journals, and the section does not say so');
  } else ok('HidraVPN journals: admissions and orders are noted, without addresses');

  // Every context where HidraNet itself processes data gives a legal basis.
  if (!/Legal basis:/.test(vpn)) bad('HidraVPN legal basis', 'the section gives no legal basis, as sections 4.4 to 4.8 do');
  else ok('HidraVPN legal basis: given');

  // Where the exits' DNS goes: the node's own defaults.
  const config = read(ROOT, 'hidravpn', 'crates', 'hidravpn-node', 'src', 'config.rs');
  const dns = config.match(/fn default_dns\(\)[\s\S]*?\{([\s\S]*?)\n {4}\}/);
  const resolvers = dns ? [...dns[1].matchAll(/"https:\/\/([^/"]+)/g)].map((m) => m[1]) : [];
  if (!resolvers.length) {
    bad('HidraVPN DNS', 'could not read NodeConfig::default_dns from hidravpn-node/src/config.rs');
  } else {
    const unnamed = missing(vpn, resolvers);
    const notListed = third ? missing(third, resolvers.map(label)) : resolvers;
    if (unnamed.length) bad('HidraVPN DNS', `the section does not name ${unnamed.join(', ')}`);
    else if (notListed.length) bad('HidraVPN DNS', `the processors table does not list ${notListed.join(', ')}`);
    else ok('HidraVPN DNS: ' + resolvers.join(', '));
  }

  // The leak test's service.
  const leak = read(ROOT, 'hidra-browser', 'src', 'main', 'vpn-leaktest.js');
  const leakHosts = [...leak.matchAll(/const IPV[46]_URL = 'https:\/\/([^/?']+)/g)].map((m) => m[1]);
  if (!leakHosts.length) bad('HidraVPN leak test', 'could not read the leak test URLs from vpn-leaktest.js');
  else {
    const unnamed = missing(vpn, leakHosts);
    const notListed = third ? missing(third, [...new Set(leakHosts.map(label))]) : leakHosts;
    if (unnamed.length) bad('HidraVPN leak test', `the section does not name ${unnamed.join(', ')}`);
    else if (notListed.length) bad('HidraVPN leak test', `the processors table does not list ${notListed.join(', ')}`);
    else ok('HidraVPN leak test: ' + leakHosts.join(', '));
  }
}

// ── The principle, for VPN users too ─────────────────────────────────────
if (!principle) {
  bad('the principle', 'the policy has no principle section (id="principle")');
} else if (/IP address/.test(principle) && !/one-hop/.test(principle)) {
  bad(
    'the principle',
    'section 2 makes a promise about the IP address with no exception for HidraVPN, whose one-hop node sees the address and the traffic together'
  );
} else if (/never collects/.test(principle)) {
  bad('the principle', 'section 2 says "never collects", but HidraVPN nodes process the traffic they carry; say what is never stored or logged');
} else {
  ok('the principle: never stored or logged, with the one-hop exception');
}

if (failed) {
  console.log('\n' + failed + ' place(s) the policy does not name');
  process.exit(1);
}
console.log('\nthe policy names everywhere the data goes');
