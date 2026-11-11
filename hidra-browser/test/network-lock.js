// The network lock routes every session it protects, and opens only when
// each one is on Tor's route.
//
// tor-route-electron.js proves this on real Chromium sessions. This runs the
// same NetworkLock against stand-in sessions, to reach the cases a real
// session does not produce on demand: a setProxy that fails, a session that
// reports another route, and one that will not take Tor's at all.
//
// It also loads main.js against a stand-in Electron and checks that it gives
// Chromium HOST_RESOLVER_RULES before the app is ready: a switch appended
// later does nothing. dns-prefetch-electron.js applies the switch itself, so
// it would stay green if main.js stopped.
//
//   node hidra-browser/test/network-lock.js

'use strict';

const { NetworkLock, HOST_RESOLVER_RULES, connectionMode } = require('../src/main/network-lock');
const { mainSwitches } = require('./lib/main-switches');

let passed = 0;
let failed = 0;
const check = (name, cond, why) => {
  if (cond) { passed++; console.log('ok    ' + name); }
  else { failed++; console.log('FAIL  ' + name + (why ? '\n      ' + why : '')); }
};

const RULES = 'socks5://127.0.0.1:9052';

// A session that keeps what it is told, unless told to misbehave.
function fakeSession({ failFirst = 0, stuck = null } = {}) {
  const s = {
    route: 'DIRECT',
    writes: [],
    closed: 0,
    filters: 0,
    webRequest: { onBeforeRequest(fn) { s.filters++; s.filter = fn; } },
    async setProxy(config) {
      s.writes.push(config);
      if (failFirst > 0) { failFirst--; throw new Error('setProxy failed'); }
      s.route = stuck || (config.proxyRules ? 'SOCKS5 ' + config.proxyRules.replace('socks5://', '') : 'DIRECT');
    },
    async resolveProxy() { return s.route; },
    async closeAllConnections() { s.closed++; },
  };
  return s;
}

(async () => {
  // Only Tor's port on loopback is a route the lock will give.
  for (const bad of [undefined, null, '', 'direct://', 'socks5://10.0.0.1:9052', 'socks5://127.0.0.1:9052,direct://', 'http://127.0.0.1:9052']) {
    let threw = false;
    try { new NetworkLock(bad); } catch (e) { threw = true; }
    check(`the lock refuses ${JSON.stringify(bad)} as its route`, threw);
  }

  const lock = new NetworkLock(RULES);
  check('the lock starts shut', lock.engaged);

  // Protecting a session routes it at once, and only once.
  const a = fakeSession();
  const routing = lock.protect(a);
  check('protect() starts routing the session before anything awaits', a.writes.length === 1 && a.writes[0].proxyRules === RULES, JSON.stringify(a.writes));
  await routing;
  check('and the session ends on Tor\'s route', a.route === 'SOCKS5 127.0.0.1:9052', a.route);
  check('protecting it again adds no second filter or route', lock.protect(a) === routing && a.filters === 1 && a.writes.length === 1);
  check('routed() hands out the same routing', lock.routed(a) === routing);
  check('the route goes around Tor for this machine only', a.writes[0].proxyBypassRules === 'localhost,*.localhost,127.0.0.1,[::1]', a.writes[0].proxyBypassRules);

  // A session whose first setProxy failed is routed again before opening.
  const b = fakeSession({ failFirst: 1 });
  lock.protect(b);
  check('a session whose first route failed is found and routed again', (await lock.unrouted()).length === 0 && b.route === 'SOCKS5 127.0.0.1:9052', JSON.stringify(b));

  // A session that reports another route keeps the lock shut.
  const c = fakeSession({ stuck: 'DIRECT' });
  lock.protect(c);
  const wrong = await lock.unrouted();
  check('a session that will not take Tor\'s route is reported, so the lock stays shut', wrong.length === 1 && wrong[0] === c, String(wrong.length));
  lock.forget(c);
  check('a forgotten session is no longer checked', (await lock.unrouted()).length === 0);

  // Closing: no route changes, connections are dropped.
  check('the lock opens for the connect that took its generation', lock.release(lock.generation) && !lock.engaged);
  const before = a.writes.length + b.writes.length;
  lock.engage('Tor exited unexpectedly');
  check('engaging changes no session\'s route', a.writes.length + b.writes.length === before && a.route === 'SOCKS5 127.0.0.1:9052');
  check('engaging drops every protected session\'s open connections', a.closed === 1 && b.closed === 1, `${a.closed} ${b.closed}`);
  check('and nothing was ever set direct', [...a.writes, ...b.writes].every((w) => w.proxyRules === RULES && !w.mode), JSON.stringify([...a.writes, ...b.writes]));

  // A connect takes the generation, then awaits its checks. Tor dying or a
  // Disconnect during them engages the lock, and the late release is refused.
  {
    const late = new NetworkLock(RULES);
    let slow;
    const d = fakeSession();
    d.resolveProxy = () => new Promise((r) => { slow = () => r(d.route); });
    late.protect(d);
    const generation = late.generation;
    const checking = late.unrouted();
    await new Promise((r) => setImmediate(r));
    late.engage('Tor exited unexpectedly');
    slow();
    check('the checks still pass on their own', (await checking).length === 0);
    check('a release from before engage() is refused', late.release(generation) === false);
    check('so the lock stays shut, with the reason that shut it', late.engaged && late.getStatus().reason === 'Tor exited unexpectedly', JSON.stringify(late.getStatus()));
    check('a release with no generation is refused too', late.release() === false && late.engaged);
    check('the current generation still opens it', late.release(late.generation) && !late.engaged);
  }

  // The apps server's refusals go through the same filter, the one
  // onBeforeRequest listener a session has, whatever the lock's state.
  {
    const refused = new Set(['http://mail.localhost:8090/']);
    const gated = new NetworkLock(RULES, { refuse: (url) => refused.has(url) });
    const e = fakeSession();
    gated.protect(e);
    const decide = (url) => new Promise((r) => e.filter({ url }, r));
    check('with the lock shut, a refused apps address is cancelled', (await decide('http://mail.localhost:8090/')).cancel === true);
    check('and another local address still goes through', !(await decide('http://chat.localhost:8090/')).cancel);
    gated.release(gated.generation);
    check('with the lock open, the refused address is still cancelled', (await decide('http://mail.localhost:8090/')).cancel === true);
    check('and a website goes through', !(await decide('https://example.com/')).cancel);
    check('a refusal is not counted as a request the lock blocked', gated.getStatus().blocked === 0, JSON.stringify(gated.getStatus()));
    const plain = new NetworkLock(RULES);
    const f = fakeSession();
    plain.protect(f);
    plain.release(plain.generation);
    check('a lock given no refusals cancels nothing on its own once open',
      !(await new Promise((r) => f.filter({ url: 'http://mail.localhost:8090/' }, r))).cancel);
  }

  // What the toolbar and the new tab page are told.
  check('Tor at 100% behind a shut lock is not shown as anonymous', connectionMode('ready', true, false) === 'disconnected');
  check('Tor at 100% while the connect still checks the routes is connecting', connectionMode('ready', true, true) === 'connecting');
  check('Tor at 100% with the lock open is anonymous', connectionMode('ready', false, false) === 'tor');
  check('Tor bootstrapping is connecting, not off', connectionMode('starting', true, false) === 'connecting');
  check('Tor stopped or failed is disconnected', connectionMode('stopped', true, false) === 'disconnected' && connectionMode('failed', true, false) === 'disconnected');

  // What Chromium may resolve by itself.
  check('Chromium resolves nothing but this machine\'s names', HOST_RESOLVER_RULES === 'MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE *.localhost, EXCLUDE 127.0.0.1, EXCLUDE ::1', HOST_RESOLVER_RULES);

  // main.js gives Chromium its switches before the app is ready: one appended
  // later does nothing (see lib/main-switches.js).
  let switches = null;
  let loadError = '';
  try {
    switches = mainSwitches();
  } catch (e) {
    loadError = String(e.stderr || e.message).slice(0, 400);
  }
  const rules = (switches || []).filter((a) => a[0] === 'host-resolver-rules');
  check('main.js gives Chromium these rules before the app is ready', rules.length === 1 && rules[0][1] === HOST_RESOLVER_RULES, loadError || JSON.stringify(switches));

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
