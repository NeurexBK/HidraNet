// The hourly node check (node-monitor.mjs), against nodes, a site, an issuer
// and a GitHub of its own on loopback.
//
// What it guards: that the check accepts a list exactly when a client would;
// that a node that is down, or answers with another key, is reported once,
// said again when what is wrong changes, and closed when it is back; that only
// a failure seen in every round is an alert and only a pass in the latest one
// closes; that a list or manifest whose signature does not hold, a site
// serving other bytes than main, an issuer that does not sign under the key
// clients ask with or sells nothing, and a list or pass key about to run out
// are each reported; that when nothing answers no issue is touched, and that
// an issue whose check could not run stays open; that only the workflow's
// own issues count; that nothing a node says reaches an issue as markup, and
// no node address reaches anything written; and that --preview refuses a
// list unfit to publish.
//
//   node hidravpn/scripts/test-node-monitor.mjs

import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as mon from './node-monitor.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..');

let failed = 0;
let passed = 0;
const ok = (n) => { passed++; console.log('ok    ' + n); };
const bad = (n, why) => { failed++; console.log('FAIL  ' + n + '\n      ' + why); };
const expect = (name, cond, why) => (cond ? ok(name) : bad(name, why));

// ── Keys ─────────────────────────────────────────────────────────────────
function ed25519() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const x = publicKey.export({ format: 'jwk' }).x;
  return { pub: Buffer.from(x, 'base64url').toString('base64'), sign: (data) => sign(null, data, privateKey).toString('base64') };
}
const LISTK = ed25519();
const RELK = ed25519();
const OTHER = ed25519();
const wgKey = (c) => Buffer.alloc(32, c).toString('base64');
// Pass keys as the issuer makes them: RSA-PSS 2048, named by a hash.
function passKey() {
  const { publicKey } = generateKeyPairSync('rsa-pss', { modulusLength: 2048, hashAlgorithm: 'sha384', mgf1HashAlgorithm: 'sha384', saltLength: 48 });
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const id = createHash('sha256').update('HidraVPN pass key id v1\0').update(spki).digest('hex').slice(0, 16);
  return { id, key: spki.toString('base64') };
}
const PK1 = passKey();
const PK2 = passKey();

const NOW = new Date('2026-10-28T12:00:00Z');
const day = (n) => new Date(NOW.getTime() + n * 86400000).toISOString().replace('.000Z', 'Z');

// ── Servers ──────────────────────────────────────────────────────────────
// Nodes listen on 127.0.0.2, everything else on 127.0.0.1: the address
// nothing written may name is the nodes'.
const servers = [];
function serve(handler, host = '127.0.0.1') {
  return new Promise((resolve) => {
    const s = createServer(handler);
    s.listen(0, host, () => { servers.push(s); resolve(s); });
  });
}
const port = (s) => s.address().port;
const json = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(typeof body === 'string' ? body : JSON.stringify(body)); };

// A node: answers its record, or what its mode says. `failOn(hit)` makes a
// given request answer 503: a node that fails on some tries only.
async function fakeNode(name, key, extra = {}) {
  const node = { name, key, mode: 'ok', hits: 0, failOn: () => false, ...extra };
  const handler = (req, res) => {
    node.hits++;
    if (node.failOn(node.hits)) return json(res, 503, { error: 'busy' });
    switch (node.mode) {
      case 'ok': return json(res, 200, { node_name: name, node_public_key: node.answers ?? node.key, role: 'exit' });
      case 'other-key': return json(res, 200, { node_name: name, node_public_key: wgKey(9) });
      case 'evil': return json(res, 200, { node_public_key: '@everyone [click](https://evil.example) <img src=x>' });
      case 'garbage': return res.end('<html>hello</html>');
      case 'hang': return; // never answers
      case 'drop': return req.socket.destroy();
      default: return json(res, 500, {});
    }
  };
  node.start = async () => { node.server = await serve(handler, '127.0.0.2'); };
  node.stop = () => new Promise((ok) => { node.server.close(ok); node.server.closeAllConnections?.(); });
  node.reset = () => { node.mode = 'ok'; node.hits = 0; node.failOn = () => false; delete node.answers; };
  await node.start();
  return node;
}

const site = { files: new Map(), mode: 'ok' };
const siteServer = await serve((req, res) => {
  if (site.mode === 'down') return json(res, 503, {});
  if (site.mode === 'drop') return req.socket.destroy();
  const body = site.files.get(req.url);
  if (!body) return json(res, 404, {});
  res.writeHead(200, { 'content-type': 'application/octet-stream' });
  res.end(body);
});

const issuer = { keys: [], packs: [], mode: 'ok' };
const issuerReset = () => Object.assign(issuer, { keys: [{ id: PK1.id, not_after: day(60) }, { id: PK2.id, not_after: day(90) }], packs: [{ passes: 10, price_raw: 1 }], mode: 'ok' });
issuerReset();
const issuerServer = await serve((req, res) => {
  if (issuer.mode === 'down') return json(res, 503, {});
  if (issuer.mode === 'drop') return req.socket.destroy();
  if (req.url === '/keys') return json(res, 200, { keys: issuer.keys });
  if (req.url === '/packs') return json(res, 200, { packs: issuer.packs, decimals: 6, mint: 'm', wallet: 'w' });
  return json(res, 404, {});
});
const ISSUER_URL = `http://127.0.0.1:${port(issuerServer)}`;

// alpha has no admission_port in the list, as every real node: it is asked
// on the default port, which the test points at it.
const alpha = await fakeNode('alpha-1', wgKey(1), { listPort: false });
const beta = await fakeNode('beta-1', wgKey(2));

function listFor(nodes, { sequence = 5, expires = day(28), keys = [{ ...PK1, not_after: day(28) }], issuerUrl = ISSUER_URL, noIssuer = false } = {}) {
  return Buffer.from(JSON.stringify({
    version: 1, generated: day(0), sequence, expires,
    nodes: nodes.map((n) => ({
      node_name: n.name, node_public_key: n.key, endpoint: n.endpoint ?? '127.0.0.2:51820',
      ...(n.listPort === false ? {} : { admission_port: n.listedPort ?? port(n.server) }),
      ...(n.operator === null ? {} : { operator: n.operator ?? 'HidraNet' }),
      role: 'exit', admission: 'pass', country: 'FI', features: ['sessions'],
      ...(n.extra ?? {}),
    })),
    ...(noIssuer ? {} : { pass_issuer: { url: issuerUrl, keys } }),
  }, null, 2));
}
const manifestFor = (version = '0.1.0') => Buffer.from(JSON.stringify({ product: 'hidravpn', version, platforms: {} }));

let landing;
const scratch = mkdtempSync(join(tmpdir(), 'node-monitor-'));
// Writes the list and manifest to "main" (the landing dir) and, unless told
// otherwise, the same bytes to the site.
function publish(list, manifest = manifestFor(), { sig = LISTK.sign(list), msig = RELK.sign(manifest), siteToo = true } = {}) {
  if (landing) rmSync(landing, { recursive: true, force: true });
  landing = mkdtempSync(join(scratch, 'landing-'));
  mkdirSync(join(landing, 'vpn', 'release'), { recursive: true });
  writeFileSync(join(landing, 'vpn', 'nodes.json'), list);
  writeFileSync(join(landing, 'vpn', 'nodes.json.sig'), sig + '\n');
  writeFileSync(join(landing, 'vpn', 'release', 'manifest.json'), manifest);
  writeFileSync(join(landing, 'vpn', 'release', 'manifest.json.sig'), msig + '\n');
  if (siteToo) {
    site.files = new Map([
      ['/vpn/nodes.json', list], ['/vpn/nodes.json.sig', Buffer.from(sig + '\n')],
      ['/vpn/release/manifest.json', manifest], ['/vpn/release/manifest.json.sig', Buffer.from(msig + '\n')],
    ]);
  }
}

const logs = [];
const sleeps = [];
let onSleep = null;
const cfg = (extra = {}) => ({
  ...mon.defaults(),
  listUrl: `http://127.0.0.1:${port(siteServer)}/vpn/nodes.json`,
  manifestUrl: `http://127.0.0.1:${port(siteServer)}/vpn/release/manifest.json`,
  listKey: LISTK.pub,
  releaseKey: RELK.pub,
  defaultAdmissionPort: port(alpha.server),
  landingDir: landing,
  allowHttp: true,
  retryDelayMs: 0,
  timeoutMs: 1500,
  now: () => NOW,
  sleep: async (ms) => { sleeps.push(ms); if (onSleep) onSleep(sleeps.length); },
  log: (l) => logs.push(l),
  ...extra,
});
const check = (extra) => mon.check(cfg({ landingDir: landing, ...extra }));

// A GitHub with issues, in memory, as the check sees it through `github()`.
const gh = { issues: [], comments: [], calls: 0 };
const ghServer = await serve(async (req, res) => {
  gh.calls++;
  let body = '';
  for await (const c of req) body += c;
  const data = body ? JSON.parse(body) : null;
  if (req.headers.authorization !== 'Bearer t0ken') return json(res, 401, {});
  const u = new URL(req.url, 'http://x');
  let m;
  if (req.method === 'GET' && u.pathname === '/repos/o/r/issues') {
    const page = Number(u.searchParams.get('page') || 1);
    const per = Number(u.searchParams.get('per_page') || 30);
    const open = gh.issues.filter((i) => i.state === 'open');
    return json(res, 200, open.slice((page - 1) * per, page * per));
  }
  if (req.method === 'POST' && u.pathname === '/repos/o/r/issues') {
    const issue = { number: gh.issues.length + 1, title: data.title, body: data.body, state: 'open', user: { login: 'github-actions[bot]' } };
    gh.issues.push(issue);
    return json(res, 201, issue);
  }
  if (req.method === 'POST' && (m = /^\/repos\/o\/r\/issues\/(\d+)\/comments$/.exec(u.pathname))) {
    gh.comments.push({ number: Number(m[1]), body: data.body });
    return json(res, 201, {});
  }
  if (req.method === 'PATCH' && (m = /^\/repos\/o\/r\/issues\/(\d+)$/.exec(u.pathname))) {
    const issue = gh.issues.find((i) => i.number === Number(m[1]));
    Object.assign(issue, data);
    return json(res, 200, issue);
  }
  return json(res, 404, {});
});
const GHAPI = `http://127.0.0.1:${port(ghServer)}`;
const ghEnv = { GITHUB_TOKEN: 't0ken', GITHUB_REPOSITORY: 'o/r', GITHUB_API_URL: GHAPI };
const client = mon.github({ token: 't0ken', repo: 'o/r', api: GHAPI });
const at = '2026-10-28T12:00:00Z';
const reconcile = (result) => mon.reconcile(result, client, { at, runUrl: 'https://github.com/o/r/actions/runs/1', mention: ['DefiMind7'], log: (l) => logs.push(l) });
const MARK = (b) => (/<!-- node-monitor:([^ ]+) -->/.exec(b ?? '') || [])[1];
const mine = () => gh.issues.filter((i) => i.user.login === 'github-actions[bot]');
const openIssue = (key) => mine().find((i) => i.state === 'open' && MARK(i.body) === key);
const openKeys = () => mine().filter((i) => i.state === 'open').map((i) => MARK(i.body)).sort();
const summaries = [];

// ── The check is the client's ─────────────────────────────────────────────
const releaseRs = readFileSync(join(REPO, 'hidravpn', 'crates', 'hidravpn-core', 'src', 'release.rs'), 'utf8');
const admissionRs = readFileSync(join(REPO, 'hidravpn', 'crates', 'hidravpn-core', 'src', 'admission.rs'), 'utf8');
const mainJs = readFileSync(join(REPO, 'hidra-browser', 'src', 'main', 'main.js'), 'utf8');
expect('the list key is the one the client embeds', releaseRs.includes(`LIST_PUBLIC_KEY_B64: &str = "${mon.LIST_PUBLIC_KEY_B64}"`), 'LIST_PUBLIC_KEY_B64 differs from release.rs');
expect('the release key is the one the client embeds', releaseRs.includes(`RELEASE_PUBLIC_KEY_B64: &str = "${mon.RELEASE_PUBLIC_KEY_B64}"`), 'RELEASE_PUBLIC_KEY_B64 differs from release.rs');
expect('the default admission port is the node\'s', admissionRs.includes(`DEFAULT_ADMISSION_PORT: u16 = ${mon.DEFAULT_ADMISSION_PORT};`), 'DEFAULT_ADMISSION_PORT differs from admission.rs');
expect('the list and manifest addresses are the browser\'s', mainJs.includes(`VPN_LIST_URL = '${mon.LIST_URL}'`) && mainJs.includes(`VPN_RELEASE_URL = '${mon.MANIFEST_URL}'`), 'LIST_URL or MANIFEST_URL differs from main.js');
const real = readFileSync(join(REPO, 'landing', 'vpn', 'nodes.json'));
const realSig = readFileSync(join(REPO, 'landing', 'vpn', 'nodes.json.sig'), 'utf8');
const realRead = mon.readList(real, realSig, mon.LIST_PUBLIC_KEY_B64);
expect('the published list verifies, and passes every check a client makes', realRead.list !== undefined, realRead.error);
const realKey = realRead.list && mon.newestCurrent(realRead.list.pass_issuer.keys, Math.floor(NOW.getTime() / 1000));
expect('the published pass key is one a client would ask with', realKey && realKey.key.id === realRead.list.pass_issuer.keys[0].id, JSON.stringify(realKey));
const d = mon.defaults();
expect('three tries, two minutes apart, https only, by default', d.attempts === 3 && d.retryDelayMs === 120000 && d.allowHttp === false && d.timeoutMs === 10000, JSON.stringify(d));

// ── Signatures, strictly ──────────────────────────────────────────────────
const data = Buffer.from('hello');
const s = LISTK.sign(data);
expect('a good signature verifies', mon.signatureMatches(LISTK.pub, data, s + '\n'), 'refused');
expect('another key\'s signature does not', !mon.signatureMatches(LISTK.pub, data, OTHER.sign(data)), 'accepted');
expect('a changed file does not', !mon.signatureMatches(LISTK.pub, Buffer.from('hellO'), s), 'accepted');
expect('a signature with a stray character does not, as in the client', !mon.signatureMatches(LISTK.pub, data, s.slice(0, 10) + '!' + s.slice(10)), 'lenient base64 accepted it');
const lastc = s[85];
const sibling = 'AQgw'.includes(lastc) ? String.fromCharCode(lastc.charCodeAt(0) + 1) : lastc;
expect('a signature with stray low bits does not, as in the client', sibling === lastc || !mon.signatureMatches(LISTK.pub, data, s.slice(0, 85) + sibling + '=='), 'non-canonical base64 accepted');

// ── Dates, as the client reads them ───────────────────────────────────────
expect('a date in Z form', mon.parseTime('2026-10-13T12:34:56Z') === 1791894896, String(mon.parseTime('2026-10-13T12:34:56Z')));
expect('the same date in +00:00 form, with a fraction, and spaces', mon.parseTime(' 2026-10-13T12:34:56.250+00:00 ') === 1791894896, String(mon.parseTime(' 2026-10-13T12:34:56.250+00:00 ')));
for (const bad of ['2026-10-13', 'soon', '2026-13-01T00:00:00Z', '2026-10-13T24:00:00Z', '2026-10-13T12:34:56+01:00', '2026-10-13T1:00:00Z', '2026-10-13T12:34:56.Z', null, 7])
  expect(`${JSON.stringify(bad)} is not a date`, mon.parseTime(bad) === null, String(mon.parseTime(bad)));

// ── Endpoints ─────────────────────────────────────────────────────────────
expect('ip:port parses', mon.parseEndpoint('203.0.113.10:51820')?.port === 51820, 'did not parse');
expect('[v6]:port parses as IPv6', mon.parseEndpoint('[2001:db8::1]:51820')?.family === 6, 'did not parse');
for (const e of ['host.example:51820', '203.0.113.10:70000', '999.1.1.1:5', '203.0.113.10', '2001:db8::1:51820'])
  expect(`${e} is not an endpoint`, mon.parseEndpoint(e) === null, 'parsed');

// ── A list a client refuses ───────────────────────────────────────────────
const base = () => JSON.parse(listFor([alpha, beta]).toString());
const refusal = (edit) => { const l = base(); edit(l); return mon.clientRefusal(l); };
expect('a good list is accepted', mon.clientRefusal(base()) === null, mon.clientRefusal(base()));
const refusals = [
  ['version 2', (l) => { l.version = 2; }, 'version 1'],
  ['an expiry that is not a date', (l) => { l.expires = 'soon'; }, 'expiry'],
  ['nodes that are not a list', (l) => { l.nodes = {}; }, 'nodes'],
  ['no nodes and nothing removed', (l) => { l.nodes = []; }, 'names no nodes'],
  ['a null node', (l) => { l.nodes.push(null); }, 'not a record'],
  ['a name with a space', (l) => { l.nodes[0].node_name = 'alpha one'; }, 'name'],
  ['a name that is a number', (l) => { l.nodes[0].node_name = 12345; }, 'no name'],
  ['an operator over 64 characters', (l) => { l.nodes[0].operator = 'O'.repeat(65); l.nodes[0].endpoint = '203.0.113.77:51820'; }, 'operator of alpha-1'],
  ['a contact over 128 characters', (l) => { l.nodes[1].contact = 'c'.repeat(129); }, 'contact of beta-1'],
  ['a key that is not one', (l) => { l.nodes[0].node_public_key = 'abc'; }, 'key of alpha-1'],
  ['an IPv6 endpoint', (l) => { l.nodes[0].endpoint = '[2001:db8::7]:51820'; }, 'IPv6'],
  ['an endpoint that is a name', (l) => { l.nodes[0].endpoint = 'node.example:51820'; }, 'endpoint of alpha-1'],
  ['an admission port that is text', (l) => { l.nodes[1].admission_port = '51822'; }, 'admission port'],
  ['a role that is none of the three', (l) => { l.nodes[0].role = 'middle'; }, 'role'],
  ['an admission that is none of the three', (l) => { l.nodes[0].admission = 'paid'; }, 'admission of'],
  ['a country of three letters', (l) => { l.nodes[0].country = 'FIN'; }, 'country'],
  ['a feature in capitals', (l) => { l.nodes[0].features = ['Sessions']; }, 'features'],
  ['a removed key that is not one', (l) => { l.removed = ['nope']; }, 'removed'],
  ['a pass key whose id is not its own', (l) => { l.pass_issuer.keys[0].id = '0000000000000000'; }, 'its own id'],
  ['a pass key that is not RSA', (l) => { l.pass_issuer.keys[0].key = wgKey(5); }, 'RSA'],
  ['an issuer on plain HTTP on the internet', (l) => { l.pass_issuer.url = 'http://passes.example.org'; }, 'plain HTTP'],
  ['an issuer with no key', (l) => { l.pass_issuer.keys = []; }, 'no key'],
];
for (const [what, edit, says] of refusals) {
  const why = refusal(edit);
  expect(`refused, as by the client: ${what}`, why?.includes(says), String(why));
}
expect('a refusal never names an address', !refusal((l) => { l.nodes[0].operator = 'O'.repeat(65); l.nodes[0].endpoint = '203.0.113.77:51820'; }).includes('203.0.113'), 'it does');
expect('accepted, as by the client: only removed keys', refusal((l) => { l.nodes = []; l.removed = [wgKey(8)]; }) === null, 'refused');
expect('accepted, as by the client: an issuer on plain HTTP on a private network', refusal((l) => { l.pass_issuer.url = 'http://10.1.2.3:8080'; }) === null, 'refused');
expect('accepted, as by the client: an expiry in +00:00 form', refusal((l) => { l.expires = '2027-01-26T00:00:00+00:00'; }) === null, 'refused');

// ── All well ─────────────────────────────────────────────────────────────
publish(listFor([alpha, beta]));
let r = await check();
expect('all well: nothing to report', r.confirmed.size === 0, `reported ${[...r.confirmed.keys()]}: ${JSON.stringify([...r.confirmed.values()])}`);
expect('all well: one round, no wait', r.rounds === 1 && sleeps.length === 0, `${r.rounds} rounds`);
expect('all well: every check passed', ['list', 'manifest', 'site', 'expiry', 'issuer', 'issuer-sales', 'node:alpha-1', 'node:beta-1'].every((k) => r.passed.has(k)), `passed: ${[...r.passed.keys()]}`);
expect('a node with no admission port in the list is asked on the default one', alpha.hits === 1, `${alpha.hits} hits on alpha`);
await reconcile(r);
expect('all well: no issue', gh.issues.length === 0, `${gh.issues.length} issues`);

// ── A node goes down, stays down, comes back ──────────────────────────────
// A stranger's issue carrying the marker is not the workflow's.
gh.issues.push({ number: 1, title: 'beta-1?', body: 'is it down? <!-- node-monitor:node:beta-1 -->', state: 'open', user: { login: 'someone' } });
await beta.stop();
sleeps.length = 0;
r = await check({ retryDelayMs: 120000 });
expect('a node that refuses is reported', r.confirmed.get('node:beta-1')?.detail.includes('refuses the connection'), JSON.stringify([...r.confirmed]));
expect('after three tries, two minutes apart', r.rounds === 3 && sleeps.join() === '120000,120000', `${r.rounds} rounds, sleeps ${sleeps}`);
expect('the other node is not', !r.confirmed.has('node:alpha-1'), 'alpha reported');
await reconcile(r);
expect('one issue opens, despite a stranger\'s with the marker', openKeys().join() === 'node:beta-1', openKeys().join());
const down = openIssue('node:beta-1');
expect('its title names the node', down?.title === '[node monitor] beta-1 is not answering', down?.title);
expect('it mentions who should hear', down?.body.includes('cc @DefiMind7'), down?.body);
expect('it links the run', down?.body.includes('https://github.com/o/r/actions/runs/1'), down?.body);
expect('it says it was seen on three tries', down?.body.includes('on 3 tries'), down?.body);
expect('it does not say someone else runs our node', !down?.body.includes('not by us'), down?.body);
await reconcile(await check());
expect('the next hour opens no second issue', mine().length === 1, `${mine().length} issues`);
// Back on another port, as the list then says: the same node, restarted.
await beta.start();
publish(listFor([alpha, beta]));
r = await check();
expect('back up: passes', r.passed.has('node:beta-1') && !r.confirmed.has('node:beta-1'), JSON.stringify([...r.confirmed]));
await reconcile(r);
expect('back up: the issue closes', down.state === 'closed' && down.state_reason === 'completed', JSON.stringify(down));
expect('with a comment saying so', gh.comments.at(-1)?.body.includes('beta-1 answers with its key'), JSON.stringify(gh.comments));
expect('the stranger\'s issue is left alone', gh.issues[0].state === 'open' && !gh.comments.some((c) => c.number === 1), JSON.stringify(gh.issues[0]));

// ── Only failures seen every time; only the latest pass closes ────────────
beta.reset();
beta.failOn = (hit) => hit === 1;
r = await check();
expect('a node that fails once then answers is not reported', !r.confirmed.has('node:beta-1') && r.passed.has('node:beta-1'), JSON.stringify([...r.confirmed]));
expect('it took a second round', r.rounds === 2, `${r.rounds} rounds`);
beta.reset();
// beta down for real, with an issue open.
beta.mode = 'off';
await reconcile(await check());
expect('a node answering 500 is reported', openIssue('node:beta-1')?.title === '[node monitor] beta-1 is not answering', openKeys().join());
// Then: alpha fails the first try only, beta answers the first and fails
// the next two. Neither was seen failing every time; beta failed last.
beta.reset();
alpha.hits = 0; beta.hits = 0;
alpha.failOn = (hit) => hit === 1;
beta.failOn = (hit) => hit >= 2;
const commentsBefore = gh.comments.length;
r = await check();
expect('three rounds when something keeps failing', r.rounds === 3, `${r.rounds} rounds`);
expect('a failure not seen in every round is no alert', !r.confirmed.has('node:alpha-1') && !r.confirmed.has('node:beta-1'), [...r.confirmed.keys()].join());
expect('a node that failed the latest round does not count as passed', !r.passed.has('node:beta-1') && r.passed.has('node:alpha-1'), [...r.passed.keys()].join());
await reconcile(r);
expect('so its issue stays open, with nothing said', openIssue('node:beta-1') && gh.comments.length === commentsBefore, `${gh.comments.length - commentsBefore} comments`);
alpha.reset(); beta.reset();

// ── What is wrong changes: said once, in the same issue ───────────────────
beta.mode = 'other-key';
r = await check();
expect('another key: both keys are shown', r.confirmed.get('node:beta-1')?.detail.includes(wgKey(2)) && r.confirmed.get('node:beta-1')?.detail.includes(wgKey(9)), r.confirmed.get('node:beta-1')?.detail);
await reconcile(r);
const changed = openIssue('node:beta-1');
expect('the open issue takes the new title', changed?.title === '[node monitor] beta-1 answers with a different key', changed?.title);
expect('and says what changed, in a comment that e-mails', gh.comments.at(-1)?.number === changed?.number && gh.comments.at(-1).body.startsWith('**Now:** beta-1 answers with a different key'), JSON.stringify(gh.comments.at(-1)));
const n1 = gh.comments.length;
await reconcile(await check());
expect('and only once', gh.comments.length === n1 && mine().filter((i) => MARK(i.body) === 'node:beta-1' && i.state === 'open').length === 1, `${gh.comments.length - n1} more comments`);

// ── Other ways a node fails ───────────────────────────────────────────────
for (const [mode, what] of [['garbage', 'not with a node record'], ['hang', 'timed out'], ['drop', 'drops the connection']]) {
  beta.mode = mode;
  r = await check({ timeoutMs: 400 });
  const p = r.confirmed.get('node:beta-1');
  expect(`a node that ${{ garbage: 'answers something else', hang: 'never answers', drop: 'drops the connection' }[mode]} is reported`, p && (p.title + p.detail).includes(what), JSON.stringify(p));
  await reconcile(r);
}
beta.mode = 'evil';
r = await check();
await reconcile(r);
const evil = openIssue('node:beta-1');
expect('what a node says never reaches an issue', evil && !/everyone|evil\.example|<img/.test(JSON.stringify([evil, gh.comments])), JSON.stringify(gh.comments.at(-1)));
beta.reset();
await reconcile(await check());
expect('a node back with its key closes its issue', !openIssue('node:beta-1'), openKeys().join());

// ── An operator's node: the issue says whom to write to ───────────────────
const gamma = await fakeNode('gamma-1', wgKey(3), { operator: 'Some Operator', mode: 'off' });
const sigma = await fakeNode('sigma-1', wgKey(6), { operator: 'Сергей', mode: 'off' });
publish(listFor([alpha, beta, gamma, sigma]));
let code = await mon.main([], { ...ghEnv, NODE_MONITOR_MENTION: 'DefiMind7 other-login', GITHUB_SERVER_URL: 'https://github.com', GITHUB_RUN_ID: '42' }, cfg({ landingDir: landing }));
const g = openIssue('node:gamma-1');
expect('an operator\'s node: the issue names them and says to write', g?.body.includes('run by `Some Operator`, not by us') && g?.body.includes('Write to them'), g?.body);
expect('an operator whose name does not print is still someone else', openIssue('node:sigma-1')?.body.includes('an operator whose name cannot be shown here'), openIssue('node:sigma-1')?.body);
expect('the command mentions every login it is given', g?.body.includes('cc @DefiMind7 @other-login'), g?.body);
expect('and links its own run', g?.body.includes('https://github.com/o/r/actions/runs/42'), g?.body);
expect('and exits 0 with problems reported', code === 0, `exit ${code}`);

// ── A node taken out of the list: its issue closes ────────────────────────
publish(listFor([alpha, beta]));
await reconcile(await check());
expect('a node no longer listed has its issue closed', g.state === 'closed' && gh.comments.some((c) => c.number === g.number && c.body.includes('no longer in the list')), JSON.stringify(g));

// ── The list on the site ──────────────────────────────────────────────────
const good = listFor([alpha, beta]);
publish(good);
const tampered = Buffer.from(good.toString().replace('"sequence": 5', '"sequence": 6'));
site.files.set('/vpn/nodes.json', tampered);
r = await check();
expect('a list whose signature does not hold is reported', r.confirmed.get('list')?.detail.includes('signature does not match'), JSON.stringify(r.confirmed.get('list')));
expect('and the nodes are still checked, from main\'s copy', r.rows.length === 2 && r.passed.has('node:alpha-1'), JSON.stringify(r.rows));
expect('and the site is reported as serving other bytes', r.confirmed.has('site'), [...r.confirmed.keys()].join());

const older = listFor([alpha, beta], { sequence: 4 });
site.files.set('/vpn/nodes.json', older);
site.files.set('/vpn/nodes.json.sig', Buffer.from(LISTK.sign(older)));
r = await check();
expect('a site a merge never reached: reported with both sequences', r.confirmed.get('site')?.detail.includes('hidranet.org has sequence 4, main has 5'), r.confirmed.get('site')?.detail);
expect('while its own list is fine', r.passed.has('list') && !r.confirmed.has('list'), [...r.confirmed.keys()].join());
const baseDir = mkdtempSync(join(scratch, 'base-'));
cpSync(landing, baseDir, { recursive: true });
publish(good);
writeFileSync(join(baseDir, 'vpn', 'nodes.json'), older);
writeFileSync(join(baseDir, 'vpn', 'nodes.json.sig'), LISTK.sign(older));
logs.push('--- landing');
code = await mon.main(['--dry-run', '--landing', baseDir], {}, cfg({ landingDir: landing }));
expect('--landing compares the site with that copy instead', code === 0 && logs.slice(logs.lastIndexOf('--- landing')).some((l) => l.includes('hidranet.org has sequence 5, main has 4')), logs.slice(-6).join(' | '));

const refused = JSON.parse(good.toString());
refused.nodes[0].operator = 'O'.repeat(65);
refused.nodes[0].endpoint = '127.0.0.2:51820';
const refusedBytes = Buffer.from(JSON.stringify(refused));
publish(refusedBytes);
r = await check();
expect('a signed list every client refuses is reported, with the reason', r.confirmed.get('list')?.detail.includes('clients refuse it: the operator of alpha-1'), JSON.stringify(r.confirmed.get('list')));
expect('and with main\'s copy refused too, no node is checked', r.rows.length === 0, JSON.stringify(r.rows));

publish(good);
site.files.set('/vpn/release/manifest.json.sig', Buffer.from(OTHER.sign(manifestFor())));
r = await check();
expect('a manifest not signed with the release key is reported', r.confirmed.get('manifest')?.detail.includes('release key'), JSON.stringify(r.confirmed.get('manifest')));
publish(good);
site.files.delete('/vpn/nodes.json.sig');
r = await check();
expect('a missing .sig is reported', r.confirmed.get('list')?.detail.includes('.sig answers HTTP 404'), JSON.stringify(r.confirmed.get('list')));

// ── An issue whose check could not run stays open ─────────────────────────
publish(good);
beta.mode = 'off';
await reconcile(await check());
publish(listFor([alpha, beta], { expires: day(10), keys: [{ ...PK1, not_after: day(10) }] }));
issuer.keys = [{ id: PK1.id, not_after: day(10) }];
await reconcile(await check());
expect('set up: a node issue and a reminder are open', openKeys().join() === 'expiry,node:beta-1', openKeys().join());
const unusable = listFor([alpha, beta]);
publish(unusable, manifestFor(), { sig: OTHER.sign(unusable) });
const n2 = gh.comments.length;
r = await check();
await reconcile(r);
expect('with no usable list anywhere: the list issue opens', openKeys().includes('list'), openKeys().join());
expect('and the node and reminder issues stay, with nothing said', openKeys().includes('node:beta-1') && openKeys().includes('expiry') && gh.comments.length === n2, `${openKeys()} / ${gh.comments.length - n2} comments`);
beta.reset();
issuerReset();
publish(good);
await reconcile(await check());
expect('a good list again closes all three', !openKeys().some((k) => ['list', 'node:beta-1', 'expiry'].includes(k)), openKeys().join());

// ── Dates ─────────────────────────────────────────────────────────────────
issuer.keys = [{ id: PK1.id, not_after: day(10) }];
publish(listFor([alpha, beta], { expires: day(10), keys: [{ ...PK1, not_after: day(10) }] }));
r = await check();
let exp = r.confirmed.get('expiry');
expect('ten days before the list runs out: reported', exp?.title === `Renew before ${day(10).slice(0, 10)}: the node list or the pass key runs out`, JSON.stringify(exp));
expect('it names both, with the days left', exp?.detail.includes('in 10 days') && exp?.detail.includes(`pass key clients ask with (${PK1.id})`), exp?.detail);
expect('a date is not retried', r.rounds === 1, `${r.rounds} rounds`);
issuer.keys = [{ id: PK1.id, not_after: day(5) }];
publish(listFor([alpha, beta], { expires: day(60), keys: [{ ...PK1, not_after: day(5) }] }));
r = await check();
exp = r.confirmed.get('expiry');
expect('a pass key running out alone: its date is the title\'s', exp?.title === `Renew before ${day(5).slice(0, 10)}: the node list or the pass key runs out` && !exp.detail.includes('node list expires'), JSON.stringify(exp));
issuerReset();
publish(listFor([alpha, beta], { expires: day(60), keys: [{ ...PK1, not_after: day(5) }, { ...PK2, not_after: day(90) }] }));
r = await check();
expect('during a rotation, an old key running out is no reminder', !r.confirmed.has('expiry') && r.passed.has('issuer'), JSON.stringify([...r.confirmed]));
publish(listFor([alpha, beta], { expires: day(60), keys: [{ ...PK1, not_after: day(-1) }] }));
r = await check();
expect('an expired pass key with a good list says it expired', r.confirmed.get('expiry')?.title === 'The node list or the pass key has expired' && r.confirmed.get('expiry').detail.includes('every pass key the list names has expired'), JSON.stringify(r.confirmed.get('expiry')));
publish(listFor([alpha, beta], { expires: '2027-01-26T00:00:00+00:00', keys: [{ ...PK1, not_after: day(60) }] }));
r = await check();
expect('an expiry in +00:00 form is a date, as for the client', !r.confirmed.has('list') && !r.confirmed.has('expiry'), JSON.stringify([...r.confirmed]));
// A reminder that becomes an expiry: said again, in the same issue.
publish(listFor([alpha, beta], { expires: day(10), keys: [{ ...PK1, not_after: day(60) }] }));
await reconcile(await check());
const reminder = openIssue('expiry');
publish(listFor([alpha, beta], { expires: day(-1), keys: [{ ...PK1, not_after: day(60) }] }));
r = await check();
expect('an expired list says so', r.confirmed.get('expiry')?.title === 'The node list or the pass key has expired', r.confirmed.get('expiry')?.title);
await reconcile(r);
expect('the reminder issue becomes the expiry, with a comment that e-mails', reminder?.title === '[node monitor] The node list or the pass key has expired' && gh.comments.at(-1)?.number === reminder.number && gh.comments.at(-1).body.includes('has expired'), JSON.stringify([reminder?.title, gh.comments.at(-1)]));
publish(listFor([alpha, beta], { expires: day(60), keys: [{ ...PK1, not_after: day(60) }] }));
await reconcile(await check());
expect('a renewed list closes it', !openKeys().includes('expiry') && reminder.state === 'closed', openKeys().join());

// ── The pass issuer ───────────────────────────────────────────────────────
const twoKeys = { expires: day(60), keys: [{ ...PK1, not_after: day(60) }, { ...PK2, not_after: day(90) }] };
publish(listFor([alpha, beta], twoKeys));
issuer.keys = [{ id: PK1.id, not_after: day(60) }];
r = await check();
expect('an issuer without the newest key the list names is reported: clients ask under that one', r.confirmed.get('issuer')?.title === 'The pass issuer does not sign under the key clients ask with' && r.confirmed.get('issuer').detail.includes(PK2.id), JSON.stringify(r.confirmed.get('issuer')));
issuer.keys = [{ id: PK1.id, not_after: day(60) }, { id: PK2.id.toUpperCase(), not_after: day(-1) }];
r = await check();
expect('an issuer holding that key as expired is reported too', r.confirmed.has('issuer'), JSON.stringify([...r.confirmed]));
issuerReset();
r = await check();
expect('an issuer with the newest key is fine', r.passed.has('issuer'), JSON.stringify(r.confirmed.get('issuer')));
issuer.packs = [];
r = await check();
expect('an issuer selling nothing is reported', r.confirmed.get('issuer-sales')?.detail.includes('nothing for sale'), JSON.stringify(r.confirmed.get('issuer-sales')));
issuerReset();
issuer.mode = 'down';
r = await check();
expect('an issuer that is down is reported', r.confirmed.get('issuer')?.detail.includes('answers HTTP 503'), JSON.stringify(r.confirmed.get('issuer')));
expect('by name, never by address', !r.confirmed.get('issuer')?.detail.includes('127.0.0.1') && r.confirmed.get('issuer')?.detail.startsWith('the pass issuer/keys'), r.confirmed.get('issuer')?.detail);
await reconcile(r);
issuerReset();
publish(listFor([alpha, beta], { noIssuer: true }));
r = await check();
expect('a list with nodes that take passes and no issuer is reported', r.confirmed.get('issuer')?.title === 'The list names no pass issuer', JSON.stringify([...r.confirmed]));
const noPass = (n) => ({ ...n, server: n.server, name: n.name, key: n.key, listPort: n.listPort, extra: { admission: 'open' } });
publish(listFor([noPass(alpha), noPass(beta)], { noIssuer: true }));
r = await check();
expect('a list with no issuer and no node taking passes passes both', r.passed.has('issuer') && r.passed.has('issuer-sales'), JSON.stringify([...r.confirmed]));
await reconcile(r);
expect('so an old issuer issue closes', !openKeys().includes('issuer'), openKeys().join());

// ── When nothing answers ──────────────────────────────────────────────────
publish(listFor([alpha, beta]));
alpha.mode = 'drop'; beta.mode = 'drop'; site.mode = 'drop'; issuer.mode = 'drop';
const before = JSON.stringify(gh.issues);
const callsBlind = gh.calls;
code = await mon.main([], ghEnv, cfg({ landingDir: landing }));
expect('nothing answers: the run fails', code === 1, `exit ${code}`);
expect('and no issue is touched', JSON.stringify(gh.issues) === before && gh.calls === callsBlind, `${gh.calls - callsBlind} GitHub calls`);
// The site and the issuer unreachable, the nodes answering: not blind.
alpha.reset(); beta.reset();
r = await check();
expect('with the site and the issuer unreachable but the nodes up, the run is not blind', !r.blind && r.confirmed.has('list') && r.confirmed.has('issuer') && r.passed.has('node:alpha-1'), `blind ${r.blind}, ${[...r.confirmed.keys()]}`);
code = await mon.main([], ghEnv, cfg({ landingDir: landing }));
expect('and the outage is reported', code === 0 && openKeys().includes('list') && openKeys().includes('issuer'), `exit ${code}, ${openKeys()}`);
// A first round that reaches nothing, then the network back but beta down.
alpha.mode = 'drop'; beta.mode = 'drop';
onSleep = () => { site.mode = 'ok'; issuer.mode = 'ok'; alpha.mode = 'ok'; };
r = await check();
onSleep = null;
expect('a runner that reaches nothing for one round is not a blind run', !r.blind && r.confirmed.has('node:beta-1') && !r.confirmed.has('node:alpha-1'), `blind ${r.blind}, ${[...r.confirmed.keys()]}`);
alpha.reset(); beta.reset(); site.mode = 'ok'; issuerReset();
await reconcile(await check());

// ── The command: dry run, summary, options ────────────────────────────────
const summaryFile = join(scratch, 'summary.md');
writeFileSync(summaryFile, '');
beta.mode = 'hang';
const callsBefore = gh.calls;
code = await mon.main(['--dry-run'], { ...ghEnv, GITHUB_STEP_SUMMARY: summaryFile }, cfg({ landingDir: landing, timeoutMs: 400 }));
expect('dry run: exit 0', code === 0, `exit ${code}`);
expect('dry run: GitHub is not called', gh.calls === callsBefore, `${gh.calls - callsBefore} calls`);
const summ = readFileSync(summaryFile, 'utf8');
summaries.push(summ);
expect('the run summary lists the nodes by name, failing ones too', summ.includes('| alpha-1 |') && summ.includes('| beta-1 | exit, FI | does not answer (timed out)'), summ);
beta.reset();
expect('unknown options are refused', (await mon.main(['--fix'], {}, cfg())) === 2, 'accepted');
expect('--landing without a directory is refused', (await mon.main(['--landing'], {}, cfg())) === 2, 'accepted');
expect('without a token it does not pretend', (await mon.main([], {}, cfg({ landingDir: landing }))) === 2, 'ran');

// ── Preview: is the list in this checkout fit to publish? ─────────────────
const preview = (extra) => mon.main(['--preview'], {}, cfg({ landingDir: landing, ...extra }));
const published = listFor([alpha, beta]);
publish(published);
expect('preview: the published list itself is fit', (await preview()) === 0, 'unfit');
const delta = await fakeNode('delta-1', wgKey(4), { mode: 'off' });
const withDelta = listFor([alpha, beta, delta], { sequence: 6 });
publish(withDelta, manifestFor(), { siteToo: false });
expect('preview: a new node that does not answer makes the list unfit', (await preview()) === 1, 'fit');
delta.mode = 'ok';
expect('preview: once it answers, the list is fit', (await preview()) === 0, 'unfit');
alpha.mode = 'off';
expect('preview: a node already published being down is not the change\'s fault', (await preview()) === 0, 'unfit');
alpha.reset();
beta.answers = wgKey(2);
publish(listFor([alpha, { ...beta, key: wgKey(7) }], { sequence: 6 }), manifestFor(), { siteToo: false });
expect('preview: a node whose key the change replaces, still answering the old one, is unfit', (await preview()) === 1, 'fit');
beta.reset();
publish(listFor([alpha, { ...beta, listedPort: port(delta.server) + 1 }], { sequence: 6 }), manifestFor(), { siteToo: false });
expect('preview: a node moved to an address where nothing answers is unfit', (await preview()) === 1, 'fit');
publish(listFor([alpha, beta], { sequence: 4 }), manifestFor(), { siteToo: false });
expect('preview: a lower sequence than the published list is unfit', (await preview()) === 1, 'fit');
publish(listFor([alpha, beta, delta], { sequence: 5 }), manifestFor(), { siteToo: false });
expect('preview: a changed list with the published sequence is unfit', (await preview()) === 1, 'fit');
publish(listFor([alpha, beta], { sequence: 6, expires: day(-1) }), manifestFor(), { siteToo: false });
expect('preview: an expired list is unfit', (await preview()) === 1, 'fit');
publish(listFor([alpha, beta], { sequence: 6, expires: day(10), keys: [{ ...PK1, not_after: day(10) }] }), manifestFor(), { siteToo: false });
issuer.keys = [{ id: PK1.id, not_after: day(10) }];
expect('preview: a list two weeks from running out is still fit', (await preview()) === 0, 'unfit');
issuerReset();
publish(listFor([alpha, beta], { sequence: 6, noIssuer: true }), manifestFor(), { siteToo: false });
expect('preview: a list with nodes that take passes and no issuer is unfit', (await preview()) === 1, 'fit');
const refusedPreview = JSON.parse(listFor([alpha, beta], { sequence: 6 }).toString());
refusedPreview.nodes[1].contact = 'c'.repeat(129);
publish(Buffer.from(JSON.stringify(refusedPreview)), manifestFor(), { siteToo: false });
expect('preview: a list clients refuse is unfit', (await preview()) === 1, 'fit');
publish(withDelta, manifestFor(), { sig: OTHER.sign(withDelta), siteToo: false });
expect('preview: a list signed with another key is unfit', (await preview()) === 1, 'fit');
publish(withDelta, manifestFor(), { msig: OTHER.sign(manifestFor()), siteToo: false });
expect('preview: a manifest signed with another key is unfit', (await preview()) === 1, 'fit');

// ── No node address anywhere ──────────────────────────────────────────────
const written = JSON.stringify({ issues: gh.issues, comments: gh.comments, logs, summaries });
expect('no node address in any issue, comment, line printed or summary', !written.includes('127.0.0.2'), written.match(/.{0,60}127\.0\.0\.2.{0,20}/)?.[0]);
expect('the check printed failing rows for this to mean something', logs.some((l) => l.startsWith('FAIL beta-1')) && logs.some((l) => l.startsWith('FAIL list')), 'no failing rows were printed');

for (const s of servers) { s.closeAllConnections?.(); s.close(); }
rmSync(scratch, { recursive: true, force: true });
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
