// No tab is ever routed anywhere but Tor: not while Tor bootstraps, not once
// it is up, not after Disconnect or a crash.
//
// Tabs used to start out on whatever answered as SOCKS5 on loopback port
// 9050, or on 'direct' when nothing did, and were switched to Tor's rules when
// Tor reached 100%. That switch walked the tabs it knew about; a tab still
// being built at that moment was not one of them, and kept its first route
// after the kill switch opened. The shared apps partition could even be
// switched to Tor and then back by a write still in flight. Disconnect and a
// Tor crash set every session to 'direct' and left the request filter as the
// only thing between open pages and this machine's own address.
//
// This builds real tabs with the real TabManager and NetworkLock under
// Electron, against a stand-in for Tor's SOCKS port that notes the hostnames
// it is asked for, and goes through a bootstrap with tabs being opened while
// the connect runs, a crash, and a request the filter does not stop. Every
// proxy setting any session is given is recorded, and every session is asked
// what Chromium would use for a remote address.
//
//   cd hidra-browser && xvfb-run -a npx electron test/tor-route-electron.js

const { app, BrowserWindow, ipcMain, session } = require('electron');
const net = require('net');
const { TabManager } = require('../src/main/tab-manager');
const { NetworkLock } = require('../src/main/network-lock');
const { proxyRulesFor } = require('../src/main/tor-manager');

const failures = [];
const check = (name, ok, detail) => {
  if (ok) console.log('ok    ' + name);
  else {
    console.log('FAIL  ' + name + (detail ? '\n      ' + detail : ''));
    failures.push(name);
  }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const guard = setTimeout(() => { console.log('FAIL  timed out'); process.exit(1); }, 90000);

// Every setProxy any session gets, from anywhere (installed once the app is
// ready, before any session is made).
const writes = [];
function recordRoutes() {
  const Session = Object.getPrototypeOf(session.defaultSession);
  const setProxy = Session.setProxy;
  Session.setProxy = function (config) {
    writes.push(JSON.stringify(config));
    return setProxy.call(this, config);
  };
}

// Every connection this process opens on its own, by port: the old code
// probed 9050 and 9051 from here.
const dialled = [];
const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  const a = args[0];
  dialled.push(typeof a === 'object' && a !== null ? Number(a.port) : Number(a));
  return connect.apply(this, args);
};

// A stand-in for Tor's SOCKS port: answers the greeting, notes the hostname
// of each CONNECT, and refuses it.
function fakeTor(port) {
  const asked = [];
  const server = net.createServer((s) => {
    s.on('error', () => {});
    s.once('data', () => {
      s.write(Buffer.from([5, 0]));
      s.once('data', (d) => {
        if (d[3] === 3) asked.push(d.slice(5, 5 + d[4]).toString());
        s.end(Buffer.from([5, 1, 0, 1, 0, 0, 0, 0, 0, 0]));
      });
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port || 0, '127.0.0.1', () => resolve({ server, asked, port: server.address().port }));
  });
}

// Something on 9050 that answers like SOCKS5, as anything on the machine
// could. It must never be asked anything.
async function squatter() {
  const seen = [];
  const server = net.createServer((s) => { seen.push(Date.now()); s.on('error', () => {}); s.once('data', () => s.write(Buffer.from([5, 0]))); });
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(9050, '127.0.0.1', resolve); });
    return { server, seen };
  } catch (e) {
    return null;
  }
}

async function load(contents, url) {
  try {
    await contents.loadURL(url);
    return 'loaded';
  } catch (e) {
    return e.code || String(e.errno || e);
  }
}

app.on('window-all-closed', () => {});

// The tabs load the new tab page, which asks the main process for its
// status; nothing here is that main process.
for (const ch of ['proxy:status', 'prefs:get', 'vpn:status', 'apps:status', 'vault:status']) ipcMain.handle(ch, () => null);

app.whenReady().then(async () => {
  recordRoutes();
  const tor = await fakeTor();
  const sq = await squatter();
  const rules = proxyRulesFor(tor.port);
  const expected = `SOCKS5 127.0.0.1:${tor.port}`;
  const lock = new NetworkLock(rules);
  await lock.protect(session.defaultSession);

  const win = new BrowserWindow({ show: false, width: 900, height: 700 });
  await win.loadURL('data:text/html,<title>bar</title>');
  const tabs = new TabManager(win, lock);

  // What Chromium says every session the browser owns would use, now.
  const routes = async () => {
    const all = [session.defaultSession, ...tabs.getAllSessions(), ...lock._sessions.keys()];
    const out = [];
    for (const s of new Set(all)) out.push(await s.resolveProxy('https://example.com/'));
    return out;
  };
  const offRoute = (list) => list.filter((r) => r !== expected);
  const badWrites = () => writes.filter((w) => w !== JSON.stringify(lock.proxyConfig()));

  // ── Tor is bootstrapping: tabs are opened, one of them an app ──
  const first = await tabs.createTab('hidra://newtab');
  check('a tab opened while Tor bootstraps is on Tor\'s route from the start',
    offRoute(await routes()).length === 0, JSON.stringify(await routes()));

  // ── Tor reaches 100% while more tabs are being built ──
  // What connectTorOnce does now: check every session, then open. Tabs and
  // an app tab are started in the same tick, so they are mid-build while the
  // check runs.
  const opening = [
    tabs.createTab('hidra://newtab'),
    tabs.createTab('http://mail.localhost:8090/'),
    tabs.createTab('https://example.com/'),
  ];
  const generation = lock.generation;
  const unrouted = await lock.unrouted();
  const opened = lock.release(generation);
  opening.push(tabs.createTab('hidra://newtab'));
  await Promise.all(opening);
  await sleep(300);
  check('the lock found no session off Tor\'s route before opening', unrouted.length === 0 && opened, String(unrouted.length));
  check('every session, the apps\' one included, is on Tor\'s route after the lock opens',
    offRoute(await routes()).length === 0, JSON.stringify(await routes()));
  check('the apps\' shared partition ends on Tor', tabs.appsSession
    && (await tabs.appsSession.resolveProxy('wss://broker.example/mqtt')) === expected);

  // A page in a tab reaches the network through Tor only, by name.
  const name = `t${Date.now()}.example`;
  const tab = tabs.tabs.get(first);
  await load(tab.view.webContents, `http://${name}/`);
  check('a page load goes to Tor\'s port with the hostname, for Tor to resolve', tor.asked.includes(name), JSON.stringify(tor.asked));

  // ── Tor dies ──
  tor.server.close();
  await new Promise((r) => tor.server.once('close', r));
  lock.engage('Tor exited unexpectedly');
  const late = await tabs.createTab('hidra://newtab');
  await sleep(200);
  check('after Tor dies every session keeps Tor\'s route, none is set direct',
    offRoute(await routes()).length === 0, JSON.stringify(await routes()));
  check('a tab opened after Tor died is on Tor\'s route too',
    (await tabs.tabs.get(late).session.resolveProxy('https://example.com/')) === expected);

  // The filter is the second layer. A request it never sees still has
  // nowhere to go: open the lock for this one load, as if a socket had gone
  // round the filter, and the load fails at Tor's closed port.
  lock.release(lock.generation);
  const escaped = await load(tab.view.webContents, `http://e${Date.now()}.example/`);
  lock.engage('Tor exited unexpectedly');
  check('with Tor gone, a request the filter misses fails at the proxy instead of leaving direct',
    escaped === 'ERR_PROXY_CONNECTION_FAILED', escaped);

  // ── The user presses Disconnect, closes a tab, opens another ──
  lock.engage('disconnected by the user');
  tabs.closeTab(late);
  await tabs.createTab('https://example.org/');
  await sleep(200);
  check('after Disconnect every session is still on Tor\'s route',
    offRoute(await routes()).length === 0, JSON.stringify(await routes()));

  check('no session was ever given any route but Tor\'s, \'direct\' included',
    writes.length > 0 && badWrites().length === 0, JSON.stringify(badWrites().slice(0, 5)));
  check('nothing in this process dialled 9050 or 9051', !dialled.includes(9050) && !dialled.includes(9051), JSON.stringify(dialled));
  if (sq) check('a SOCKS5 listener on 9050 was never contacted', sq.seen.length === 0, `${sq.seen.length} connection(s)`);
  else console.log('skip  port 9050 is taken on this machine; the listener check did not run');

  clearTimeout(guard);
  console.log(`\n${failures.length ? failures.length + ' failed' : 'every tab stays on Tor\'s route'}`);
  process.exit(failures.length ? 1 : 0);
}).catch((e) => { console.error(e); process.exit(1); });
