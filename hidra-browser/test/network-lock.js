// The network lock routes every session it protects, and opens only when
// each one is on Tor's route.
//
// tor-route-electron.js proves this on real Chromium sessions. This runs the
// same NetworkLock against stand-in sessions, to reach the cases a real
// session does not produce on demand: a setProxy that fails, a session that
// reports another route, and one that will not take Tor's at all.
//
//   node hidra-browser/test/network-lock.js

'use strict';

const { NetworkLock, HOST_RESOLVER_RULES } = require('../src/main/network-lock');

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
    webRequest: { onBeforeRequest() { s.filters++; } },
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
  lock.release();
  const before = a.writes.length + b.writes.length;
  lock.engage('Tor exited unexpectedly');
  check('engaging changes no session\'s route', a.writes.length + b.writes.length === before && a.route === 'SOCKS5 127.0.0.1:9052');
  check('engaging drops every protected session\'s open connections', a.closed === 1 && b.closed === 1, `${a.closed} ${b.closed}`);
  check('and nothing was ever set direct', [...a.writes, ...b.writes].every((w) => w.proxyRules === RULES && !w.mode), JSON.stringify([...a.writes, ...b.writes]));

  // What Chromium may resolve by itself.
  check('Chromium resolves nothing but this machine\'s names', HOST_RESOLVER_RULES === 'MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE *.localhost, EXCLUDE 127.0.0.1, EXCLUDE ::1', HOST_RESOLVER_RULES);

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
