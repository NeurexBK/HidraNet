// The apps server holds every loopback address of its port, or the apps are
// off for the run; and it vouches for each response it sends.
//
// apps-server-electron.js proves this on real tabs. This runs the same
// AppsServer on real sockets, on a free port of its own, to reach the cases a
// browser does not produce on demand: an address held by another program
// before start, one freed during the retries, a bind that fails for another
// reason, and every way a response can carry the token or not. The ::1 cases
// need an IPv6 loopback; on a host without one they say so and are skipped,
// and the decision for that host is checked on its own.
//
//   node hidra-browser/test/apps-server.js

'use strict';

const fs = require('fs');
const http = require('http');
const net = require('net');
const path = require('path');
const { AppsServer, TOKEN_HEADER, isAppsAddress, judgeBinds } = require('../src/main/apps-server');
const { APPS, appOrigin } = require('../src/main/app-origins');

let passed = 0;
let failed = 0;
let skipped = 0;
const check = (name, cond, why) => {
  if (cond) { passed++; console.log('ok    ' + name); }
  else { failed++; console.log('FAIL  ' + name + (why ? '\n      ' + why : '')); }
};
const skip = (name, why) => { skipped++; console.log(`skip  ${name} (${why})`); };

const listen = (server, port, host) => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(port, host, () => { server.removeListener('error', reject); resolve(server); });
});
const close = (server) => new Promise((r) => server.close(r));

// Whether this host has ::1 at all.
async function hasIpv6Loopback() {
  try { await close(await listen(net.createServer(), 0, '::1')); return true; } catch { return false; }
}

// A port free on every loopback address this host has.
async function freePort(v6) {
  for (;;) {
    const s = await listen(net.createServer(), 0, '127.0.0.1');
    const { port } = s.address();
    await close(s);
    if (!v6) return port;
    try { await close(await listen(net.createServer(), port, '::1')); return port; } catch { /* taken there: another */ }
  }
}

// A GET to one address with an app's Host, as Chromium sends it.
function get(host, port, path = '/') {
  return new Promise((resolve) => {
    const req = http.get({ host, port, path, headers: { Host: `mail.localhost:${port}` }, agent: false }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', (e) => resolve({ error: e.code }));
  });
}

// Something else on the port: answers anything, and notes that it was asked.
function squatter() {
  const seen = [];
  const server = http.createServer((req, res) => { seen.push(req.url); res.end('not the apps'); });
  return { server, seen };
}

// The onHeadersReceived details Chromium hands over for a response.
const response = (url, headers) => ({ url, responseHeaders: headers });

// What the handler answers in these tests: one path writes its headers with
// writeHead, the other sets none of its own.
function handler(req, res) {
  if (req.url === '/plain') { res.end('plain'); return; }
  res.writeHead(200, { 'Content-Type': 'text/plain', 'X-From': 'handler' });
  res.end('app');
}

(async () => {
  const v6 = await hasIpv6Loopback();
  console.log(v6 ? '      this host has an IPv6 loopback' : '      this host has no IPv6 loopback: the ::1 cases are skipped');

  // ── Which addresses are the apps' ──
  for (const name of Object.keys(APPS)) {
    check(`${appOrigin(name)} is an apps address`, isAppsAddress(appOrigin(name) + '/?x=1'));
  }
  check('so are the old shared addresses on 127.0.0.1 and localhost',
    isAppsAddress('http://127.0.0.1:8090/mail') && isAppsAddress('http://localhost:8090/'));
  for (const other of ['https://mail.localhost:8090/', 'http://mail.localhost:8091/', 'http://evil.localhost:8090/',
    'http://mail.localhost.example.com:8090/', 'https://example.com/', 'http://127.0.0.1:8084/', 'file:///tmp/x.html',
    'data:text/html,x', 'not a url']) {
    check(`${other} is not`, !isAppsAddress(other));
  }

  // ── What a round of binds comes to ──
  const err = (code) => Object.assign(new Error(code), { code });
  const judged = (o) => JSON.stringify(judgeBinds(o));
  check('both held: up', judged({ '127.0.0.1': null, '::1': null }) === '{"busy":[],"failed":[]}');
  check('no IPv6 on this host (EAFNOSUPPORT on ::1): up on 127.0.0.1 alone',
    judged({ '127.0.0.1': null, '::1': err('EAFNOSUPPORT') }) === '{"busy":[],"failed":[]}');
  check('no ::1 on this host (EADDRNOTAVAIL on ::1): up on 127.0.0.1 alone',
    judged({ '127.0.0.1': null, '::1': err('EADDRNOTAVAIL') }) === '{"busy":[],"failed":[]}');
  check('::1 held by another program: busy, never up',
    judged({ '127.0.0.1': null, '::1': err('EADDRINUSE') }) === '{"busy":["::1"],"failed":[]}');
  check('127.0.0.1 held by another program: busy',
    judged({ '127.0.0.1': err('EADDRINUSE'), '::1': null }) === '{"busy":["127.0.0.1"],"failed":[]}');
  check('127.0.0.1 missing is not a host without it: a failure',
    judged({ '127.0.0.1': err('EADDRNOTAVAIL'), '::1': null }) === '{"busy":[],"failed":["127.0.0.1"]}');
  check('any other bind error on ::1 is a failure',
    judged({ '127.0.0.1': null, '::1': err('EACCES') }) === '{"busy":[],"failed":["::1"]}');

  // ── Before it has started ──
  {
    const apps = new AppsServer();
    check('a server not yet started holds nothing', !apps.holds && apps.state === 'starting');
    check('and refuses every apps address', Object.keys(APPS).every((n) => apps.refuses(appOrigin(n) + '/')) && apps.refuses('http://127.0.0.1:8090/mail'));
    check('but nothing else', !apps.refuses('https://example.com/') && !apps.refuses('http://127.0.0.1:9051/'));
    const vetted = apps.vetResponse(response(appOrigin('mail') + '/', { [TOKEN_HEADER]: [apps.token] }));
    check('a response from an app is dropped even with the right token', vetted.cancel === true, JSON.stringify(vetted));
    check('and one from anywhere else passes as it came', JSON.stringify(apps.vetResponse(response('https://example.com/', { a: ['b'] }))) === '{}');
    check('the token is 32 random bytes, new for each server', /^[0-9a-f]{64}$/.test(apps.token) && apps.token !== new AppsServer().token);
  }

  // ── Started on a free port ──
  {
    const port = await freePort(v6);
    const apps = new AppsServer({ port, retryMs: 50 });
    const up = await apps.start(handler);
    check('on a free port the server comes up', up && apps.holds && apps.state === 'listening' && apps.error === null, `${apps.state} ${apps.error}`);
    check(v6 ? 'on 127.0.0.1 and on ::1' : 'on 127.0.0.1 (this host has no ::1)',
      apps.addresses().join() === (v6 ? '127.0.0.1,::1' : '127.0.0.1'), apps.addresses().join());
    check('and refuses no apps address now', !apps.refuses(appOrigin('mail') + '/'));

    const four = await get('127.0.0.1', port);
    check('a response on 127.0.0.1 carries the token, with the handler\'s own headers',
      four.headers && four.headers[TOKEN_HEADER] === apps.token && four.headers['x-from'] === 'handler' && four.body === 'app',
      JSON.stringify(four));
    const plain = await get('127.0.0.1', port, '/plain');
    check('so does one whose handler sets no headers', plain.headers && plain.headers[TOKEN_HEADER] === apps.token, JSON.stringify(plain));
    if (v6) {
      const six = await get('::1', port);
      check('the same handler answers on ::1, with the token', six.body === 'app' && six.headers[TOKEN_HEADER] === apps.token, JSON.stringify(six));
    } else skip('the same handler answers on ::1', 'no IPv6 loopback');

    // What the tabs' sessions do with each response.
    const url = appOrigin('mail') + '/';
    const ok = apps.vetResponse(response(url, { 'Content-Type': ['text/html'], 'X-Hidra-Apps-Token': [apps.token] }));
    check('the right token, once: the response goes through', !ok.cancel && ok.responseHeaders, JSON.stringify(ok));
    check('with the token taken off and every other header kept',
      ok.responseHeaders && JSON.stringify(ok.responseHeaders) === '{"Content-Type":["text/html"]}', JSON.stringify(ok));
    for (const [what, headers] of [
      ['no token', { 'Content-Type': ['text/html'] }],
      ['a wrong token', { [TOKEN_HEADER]: [new AppsServer().token] }],
      ['an empty token', { [TOKEN_HEADER]: [''] }],
      ['the token twice', { [TOKEN_HEADER]: [apps.token, apps.token] }],
      ['the token under two spellings', { [TOKEN_HEADER]: [apps.token], 'X-HIDRA-APPS-TOKEN': [apps.token] }],
      ['the token with something else', { [TOKEN_HEADER]: [apps.token + ', x'] }],
      ['no headers at all', undefined],
    ]) {
      check(`${what}: dropped`, apps.vetResponse(response(url, headers)).cancel === true);
    }
    check('the old shared address is held to the same token',
      apps.vetResponse(response('http://127.0.0.1:8090/mail', {})).cancel === true
      && !apps.vetResponse(response('http://127.0.0.1:8090/mail', { [TOKEN_HEADER]: [apps.token] })).cancel);
    check('a response from a website is not looked at', JSON.stringify(apps.vetResponse(response('https://example.com/', {}))) === '{}');

    await apps.close();
    const after = await get('127.0.0.1', port);
    check('once closed, nothing answers and the apps are off', after.error === 'ECONNREFUSED' && !apps.holds && apps.refuses(url),
      JSON.stringify(after));
  }

  // ── 127.0.0.1 held by another program before start ──
  {
    const port = await freePort(v6);
    const sq = squatter();
    await listen(sq.server, port, '127.0.0.1');
    const apps = new AppsServer({ port, retries: 2, retryMs: 50 });
    const t0 = Date.now();
    const up = await apps.start(handler);
    check('with 127.0.0.1 taken, the server gives up after its retries', !up && apps.state === 'off' && Date.now() - t0 >= 100,
      `${apps.state} after ${Date.now() - t0} ms`);
    check('and says so plainly', /another program holds port \d+ on 127\.0\.0\.1, so the apps are off until HidraNet is restarted/.test(apps.error), apps.error);
    check('the apps\' addresses are refused for the rest of the run', !apps.holds && apps.refuses(appOrigin('forum') + '/'));
    if (v6) {
      const six = await get('::1', port);
      check('and nothing of it is left listening on ::1', six.error === 'ECONNREFUSED', JSON.stringify(six));
    } else skip('nothing of it is left listening on ::1', 'no IPv6 loopback');
    await close(sq.server);
    check('freeing the port later does not bring the apps back in this run', !apps.holds && apps.state === 'off');
  }

  // ── ::1 held by another program before start ──
  if (v6) {
    const port = await freePort(v6);
    const sq = squatter();
    await listen(sq.server, port, '::1');
    const apps = new AppsServer({ port, retries: 1, retryMs: 50 });
    const up = await apps.start(handler);
    check('with ::1 taken, the apps are off too, though 127.0.0.1 was free', !up && apps.state === 'off' && /on ::1/.test(apps.error), apps.error);
    const four = await get('127.0.0.1', port);
    check('and nothing of it is left listening on 127.0.0.1', four.error === 'ECONNREFUSED', JSON.stringify(four));
    await close(sq.server);
  } else skip('with ::1 taken, the apps are off', 'no IPv6 loopback');

  // ── A copy of the browser that is shutting down lets go during the retries ──
  {
    const port = await freePort(v6);
    const sq = squatter();
    await listen(sq.server, port, '127.0.0.1');
    const apps = new AppsServer({ port, retries: 10, retryMs: 50 });
    const starting = apps.start(handler);
    await new Promise((r) => setTimeout(r, 20));
    check('while it waits, it holds nothing and says it is retrying', !apps.holds && apps.state === 'starting' && /busy, retrying/.test(apps.error), apps.error);
    await new Promise((r) => setTimeout(r, 100));
    await close(sq.server);
    check('once the port is free it comes up', (await starting) && apps.holds, `${apps.state} ${apps.error}`);
    const four = await get('127.0.0.1', port);
    check('and it is the one answering', four.headers && four.headers[TOKEN_HEADER] === apps.token && sq.seen.length === 0, JSON.stringify(four));
    await apps.close();
  }

  // ── A bind that fails for any other reason ──
  {
    // 192.0.2.1 is a documentation address no host has: EADDRNOTAVAIL, which
    // only ::1 may answer and still leave the apps up.
    const apps = new AppsServer({ port: await freePort(false), hosts: ['192.0.2.1'], retries: 5, retryMs: 1000 });
    const t0 = Date.now();
    const up = await apps.start(handler);
    check('a bind that fails for another reason turns the apps off at once, without retrying',
      !up && apps.state === 'off' && Date.now() - t0 < 1000 && /could not open port \d+ on 192\.0\.2\.1/.test(apps.error), `${apps.error} after ${Date.now() - t0} ms`);
  }

  // ── main.js wires it in ──
  // apps-server-electron.js puts the same parts together itself, so it would
  // stay green if main.js stopped doing this.
  const main = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'main.js'), 'utf8');
  check('main.js hands the network lock\'s filter the apps server\'s refusals',
    main.includes('new NetworkLock(proxyRulesFor(SOCKS_PORT), { refuse: (url) => appsServer.refuses(url) })'));
  check('it hands the tabs the apps server', main.includes('new TabManager(mainWindow, networkLock, appsServer)'));
  check('its vault handlers ask the apps server',
    (main.match(/vaultCompartmentOf\(event, apps\)/g) || []).length === 2 && main.includes('apps = appsServer) {'));
  check('and it listens for the apps only through the apps server',
    main.includes('appsServer.start(handle)') && !/\.listen\(/.test(main));

  console.log(`\n${passed} passed, ${failed} failed${skipped ? `, ${skipped} skipped (no IPv6 loopback)` : ''}`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
