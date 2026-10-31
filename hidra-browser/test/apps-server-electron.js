// The apps open only from this browser's own apps server, and only then is
// the vault handed out.
//
// A page on an app's origin, http://<app>.localhost:8090, is handed that
// app's compartment of the vault. This builds real tabs with the real
// TabManager, NetworkLock, tab preload, AppsServer and VaultStore under
// Electron, with the vault handlers as main.js registers them
// (vaultCompartmentOf) and the resolver rules main.js gives Chromium, and
// checks that:
//   - a service worker that something else once registered on HidraMail's
//     origin, in the apps' partition kept on disk, is gone before the app
//     loads, and the page it would serve is never handed the vault; while
//     the apps server is still starting the app's tab says so, shows the
//     app's address, and a reload once it is up opens the app; and the app's
//     own page cannot register a service worker;
//   - with 127.0.0.1:8090 held by another server before the apps server
//     starts, the apps are off: opening one sends that server nothing, the
//     tab and the new tab page say the apps are off and why, and a page that
//     server puts on an app's origin outside the tabs is refused the vault;
//   - the browser's own server works end to end: the app loads on its
//     origin, reads and writes its compartment, and never sees the token;
//   - a response on an app's origin without the token, or with a wrong one,
//     is dropped before anything in it runs, and nothing is handed out;
//   - where this host has an IPv6 loopback, a server on [::1]:8090 beside an
//     apps server that listens on 127.0.0.1 alone is the one Chromium
//     reaches, and its response is dropped the same way. Without one, that
//     part is skipped and says so.
//
// It needs port 8090 free on this machine.
//
//   cd hidra-browser && xvfb-run -a ./node_modules/.bin/electron --no-sandbox test/apps-server-electron.js

const { app, BrowserWindow, ipcMain, session, safeStorage } = require('electron');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');
const { TabManager, vaultCompartmentOf, APPS_PARTITION, UI_ROOT_URL } = require('../src/main/tab-manager');
const { NetworkLock, HOST_RESOLVER_RULES } = require('../src/main/network-lock');
const { proxyRulesFor } = require('../src/main/tor-manager');
const { VaultStore } = require('../src/main/vault');
const { AppsServer, TOKEN_HEADER } = require('../src/main/apps-server');
const { APPS_PORT, appOrigin } = require('../src/main/app-origins');

// As main.js does, before the app is ready.
app.commandLine.appendSwitch('host-resolver-rules', HOST_RESOLVER_RULES);
// A profile of its own, so that the apps' partition starts empty.
app.setPath('userData', fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-apps-server-ud-')));
// The vault's directory, removed however the run ends.
const VAULT_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-apps-server-e-'));
const finish = (code) => {
  fs.rmSync(VAULT_DIR, { recursive: true, force: true });
  app.exit(code);
};
// A test machine has no keyring (see vault-electron.js). TEST ONLY.
if (process.platform === 'linux' && typeof safeStorage.setUsePlainTextEncryption === 'function') {
  safeStorage.setUsePlainTextEncryption(true);
}

const failures = [];
const check = (name, ok, detail) => {
  if (ok) console.log('ok    ' + name);
  else {
    console.log('FAIL  ' + name + (detail ? '\n      ' + detail : ''));
    failures.push(name);
  }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, ms = 15000) => {
  for (const t0 = Date.now(); Date.now() - t0 < ms; await sleep(100)) {
    const v = await fn();
    if (v) return v;
  }
  return null;
};
const guard = setTimeout(() => { console.log('FAIL  timed out'); finish(1); }, 150000);

const MAIL = appOrigin('mail') + '/';
const SECRET = JSON.stringify({ ids: [{ addr: 'test@hidra', privJwk: { d: 'TEST-ONLY-NOT-A-KEY' } }] });

// ── The vault, and its handlers as main.js registers them ──
let vault = null;
let apps = null;          // the apps server of the part running
let handedOut = 0;        // compartments the vault opened for a page
ipcMain.handle('vault:get', (event) => {
  const ns = vaultCompartmentOf(event, apps);
  handedOut++;
  return vault.get(ns);
});
ipcMain.handle('vault:set', async (event, value) => {
  const ns = vaultCompartmentOf(event, apps);
  handedOut++;
  await vault.set(ns, value);
  return true;
});
// What the new tab page asks for. apps:status is built from the apps server
// the way main.js builds it; nothing else here is that main process.
ipcMain.handle('apps:status', () => ({
  chat: apps.holds, sevennine: false, hidrareview: apps.holds, error: apps.holds ? null : apps.error,
  appsOff: apps.state === 'off', about: { version: '1.1.0', build: 'test', date: null }, update: null,
}));
ipcMain.handle('proxy:status', () => ({ connected: false, mode: 'disconnected', lock: { engaged: true } }));
ipcMain.handle('prefs:get', () => ({ theme: 'teal', searchLang: 'all', autoConnect: true }));
ipcMain.handle('vault:status', () => ({ encrypted: false, backend: 'test' }));
ipcMain.handle('vpn:status', () => ({ state: 'not-installed', installable: false }));

// ── Servers ──
const listen = (server, port, host) => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(port, host, () => { server.removeListener('error', reject); resolve(server); });
});
const close = (server) => new Promise((r) => {
  server.close(() => r());
  if (server.closeAllConnections) server.closeAllConnections();
});

async function hasIpv6Loopback() {
  try { await close(await listen(net.createServer(), 0, '::1')); return true; } catch { return false; }
}

// Notes every request a server is sent: method, host, path, body, and the
// address it came in on.
function recorder() {
  const seen = [];
  const note = (req, then) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      seen.push({ method: req.method, host: req.headers.host, url: req.url, body: body.slice(0, 200), on: req.socket.localAddress });
      then();
    });
  };
  return { seen, note };
}

// What a server that is not the browser's serves on an app's origin: a page
// that asks for the vault and posts back to itself what it got.
const TAKER = `<!doctype html><meta charset="utf-8"><title>taker</title><script>
  (window.hidra && window.hidra.vault ? window.hidra.vault.get() : Promise.reject(new Error('no bridge')))
    .then(function (v) { return fetch('/took', { method: 'POST', body: String(v) }); },
          function (e) { return fetch('/refused', { method: 'POST', body: String(e && e.message || e) }); });
</script>`;

// A service worker that answers every page of its origin with TAKER, and a
// page that registers it the way a page can past the fingerprint engine's
// shim, which replaces only navigator.serviceWorker.register.
const WORKER = `self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', (e) => {
  if (e.request.mode === 'navigate') e.respondWith(new Response(${JSON.stringify(TAKER)}, { headers: { 'Content-Type': 'text/html' } }));
});`;
const REGISTER = `ServiceWorkerContainer.prototype.register.call(navigator.serviceWorker, '/sw.js')
  .then(() => navigator.serviceWorker.ready).then(() => 'registered', (e) => 'refused: ' + e.message)`;

function taker() {
  const rec = recorder();
  rec.server = http.createServer((req, res) => rec.note(req, () => {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(TAKER);
  }));
  return rec;
}

// The browser's own apps server's handler in this test: the app's page, the
// old shared address's redirect to it, and two paths whose responses lose
// the token on the way out, standing in for an answer from somewhere else.
const own = recorder();
function ownHandler(req, res) {
  own.note(req, () => {
    if (req.headers.host === `127.0.0.1:${APPS_PORT}`) {
      res.writeHead(302, { Location: MAIL, 'Cache-Control': 'no-store' });
      res.end();
      return;
    }
    if (req.url === '/sw.js') {
      res.writeHead(200, { 'Content-Type': 'text/javascript' });
      res.end(WORKER);
      return;
    }
    if (req.url === '/no-token') res.removeHeader(TOKEN_HEADER);
    if (req.url === '/wrong-token') res.setHeader(TOKEN_HEADER, 'f'.repeat(64));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(req.url === '/' ? '<!doctype html><meta charset="utf-8"><title>own app</title><p>own' : TAKER);
  });
}

// A stand-in for Tor's SOCKS port that refuses everything.
async function fakeTor() {
  const server = net.createServer((s) => { s.on('error', () => {}); s.destroy(); });
  await listen(server, 0, '127.0.0.1');
  return server;
}

// The parts main.js puts together, around one apps server.
async function browserWith(appsServer, torPort) {
  const lock = new NetworkLock(proxyRulesFor(torPort), { refuse: (url) => appsServer.refuses(url) });
  const win = new BrowserWindow({ show: false, width: 900, height: 700 });
  await win.loadURL('data:text/html,<title>bar</title>');
  const tabs = new TabManager(win, lock, appsServer);
  const contents = (id) => tabs.tabs.get(id).view.webContents;
  const done = () => {
    for (const t of tabs.tabs.values()) { t.closed = true; try { t.view.webContents.close(); } catch (e) { /* gone */ } }
    win.destroy();
  };
  return { tabs, contents, done };
}

// The page a refused app's address leaves in the tab.
async function refusedPage(contents) {
  const wc = await until(() => { const c = contents(); return !c.isLoading() && c.getURL().startsWith('data:') && c; });
  return wc ? wc.executeJavaScript('document.body.innerText') : '(the tab never showed a page of its own)';
}

app.on('window-all-closed', () => {});

app.whenReady().then(async () => {
  vault = new VaultStore(VAULT_DIR, safeStorage);
  await vault.set('mail', SECRET);
  const v6 = await hasIpv6Loopback();
  console.log(v6 ? '      this host has an IPv6 loopback' : '      this host has no IPv6 loopback: the ::1 part is skipped');

  // The apps' own port has to be free, on every loopback address.
  for (const host of v6 ? ['127.0.0.1', '::1'] : ['127.0.0.1']) {
    try { await close(await listen(net.createServer(), APPS_PORT, host)); } catch (e) {
      check(`port ${APPS_PORT} is free on ${host} for this test`, false, `${e.code}: close what holds it (a running HidraNet, say)`);
      finish(1);
      return;
    }
  }
  const tor = await fakeTor();
  const torPort = tor.address().port;

  // A website, for a request a page makes to an app's address.
  const site = http.createServer((_req, res) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<!doctype html><title>site</title>'); });
  await listen(site, 0, '127.0.0.1');
  const SITE = `http://127.0.0.1:${site.address().port}/`;

  // ── A service worker left on HidraMail's origin by an earlier run ──
  {
    // Whatever answered there then, outside this browser's tabs: a page on
    // the origin registers the worker, and the worker answers the origin from
    // then on.
    const planter = recorder();
    planter.server = http.createServer((req, res) => planter.note(req, () => {
      res.writeHead(200, { 'Content-Type': req.url === '/sw.js' ? 'text/javascript' : 'text/html; charset=utf-8' });
      res.end(req.url === '/sw.js' ? WORKER : '<!doctype html><title>planter</title>');
    }));
    await listen(planter.server, APPS_PORT, '127.0.0.1');
    const partition = session.fromPartition(APPS_PARTITION, { cache: false });
    const earlier = new BrowserWindow({ show: false, webPreferences: { session: partition } });
    await earlier.loadURL(MAIL);
    const registered = await earlier.webContents.executeJavaScript(REGISTER);
    await earlier.loadURL(MAIL).catch(() => {});
    const answered = await until(() => planter.seen.some((r) => r.url === '/refused'));
    check('a service worker on HidraMail\'s origin, in the apps\' partition, answers it before the browser starts',
      registered === 'registered' && answered && earlier.webContents.getTitle() === 'taker', `${registered} / ${earlier.webContents.getTitle()}`);
    earlier.destroy();
    await close(planter.server);

    // The browser starts; its apps server is not up yet. Clearing the
    // partition is made slow here, so that an app let load before it was
    // done would be answered by the worker.
    const clear = partition.clearStorageData.bind(partition);
    partition.clearStorageData = (options) => sleep(1500).then(() => clear(options));
    apps = new AppsServer();
    const b = await browserWith(apps, torPort);
    const mail = await b.tabs.createTab('hidra://mail');
    delete partition.clearStorageData;
    const shown = await refusedPage(() => b.contents(mail));
    check('while the apps server is starting, HidraMail\'s tab says the apps are not up yet',
      /not up yet/.test(shown) && /still starting/.test(shown), shown);
    check('and its address is still HidraMail\'s', b.tabs.tabs.get(mail).url === 'hidra://mail', b.tabs.tabs.get(mail).url);

    // Up, and the tab is reloaded as the page says.
    await apps.start(ownHandler);
    b.tabs.reload(mail);
    const wc = await until(() => { const c = b.contents(mail); return !c.isLoading() && c.getURL() === MAIL && c; });
    const title = wc ? await wc.executeJavaScript('document.title') : null;
    await sleep(500);
    check('a reload once it is up opens HidraMail from the browser\'s own server, not from the worker',
      title === 'own app' && own.seen.some((r) => r.url === '/'), `${title} at ${b.contents(mail).getURL()}`);
    check('and the vault handed nothing to the worker\'s page', handedOut === 0 && !own.seen.some((r) => r.url === '/took' || r.url === '/refused'),
      `handed out: ${handedOut} / ${JSON.stringify(own.seen)}`);

    // The app's own page, past the shim, cannot leave a worker either: its
    // script is refused before it is asked for.
    const again = wc ? await wc.executeJavaScript(REGISTER) : null;
    check('a page on an app\'s origin cannot register a service worker',
      /^refused/.test(String(again)) && !own.seen.some((r) => r.url === '/sw.js'), `${again} / ${JSON.stringify(own.seen.map((r) => r.url))}`);
    b.done();
    await apps.close();
    own.seen.length = 0;
  }

  // ── 127.0.0.1:8090 held by another server before the apps server starts ──
  {
    const sq = taker();
    await listen(sq.server, APPS_PORT, '127.0.0.1');
    apps = new AppsServer({ retries: 1, retryMs: 200 });
    const up = await apps.start(ownHandler);
    check('with 127.0.0.1:8090 held before start, the apps server does not come up', !up && !apps.holds && apps.state === 'off', apps.state);
    check('and says the apps are off, and why',
      /another program holds port 8090 on 127\.0\.0\.1, so the apps are off until HidraNet is restarted/.test(apps.error), apps.error);

    const b = await browserWith(apps, torPort);
    const mail = await b.tabs.createTab('hidra://mail');
    const shown = await refusedPage(() => b.contents(mail));
    check('opening HidraMail shows that the apps are off, with the reason',
      /apps are off/.test(shown) && /another program holds port 8090/.test(shown), shown);
    check('and the server on 127.0.0.1:8090 is sent nothing', sq.seen.length === 0, JSON.stringify(sq.seen));

    // A navigation the page makes itself, not through the address bar.
    await b.contents(mail).executeJavaScript(`location.href = ${JSON.stringify(appOrigin('chat') + '/')}`).catch(() => {});
    await sleep(1500);
    const again = await refusedPage(() => b.contents(mail));
    check('a page that sends the tab to another app gets the same page, and that server nothing',
      /apps are off/.test(again) && sq.seen.length === 0, `${again} / ${JSON.stringify(sq.seen)}`);

    // A website asking for an app's address, with words in it.
    const web = await b.tabs.createTab(SITE);
    await until(() => !b.contents(web).isLoading() && b.contents(web).getURL() === SITE);
    const fetched = await b.contents(web).executeJavaScript(
      `fetch(${JSON.stringify(appOrigin('search') + '/?q=private-words')}, { mode: 'no-cors' }).then(() => 'sent', () => 'refused')`);
    check('a request a website makes to an app\'s address is refused before it is sent',
      fetched === 'refused' && sq.seen.length === 0, `${fetched} / ${JSON.stringify(sq.seen)}`);

    // The new tab page.
    const newtab = new BrowserWindow({
      show: false,
      webPreferences: {
        preload: path.join(__dirname, '..', 'src', 'renderer', 'tab-preload.js'),
        contextIsolation: true, nodeIntegration: false, sandbox: true,
        additionalArguments: [`--hidra-ui-root=${UI_ROOT_URL}`, '--hidra-app-origins='],
      },
    });
    await newtab.loadURL(pathToFileURL(path.join(__dirname, '..', 'src', 'ui', 'newtab.html')).href);
    const BADGES = `JSON.stringify(['chat-badge', 'mail-badge', 'forum-badge'].map((id) => {
      const b = document.getElementById(id); return b ? [b.textContent, b.title] : null; }))`;
    const badges = await until(async () => {
      const got = JSON.parse(await newtab.webContents.executeJavaScript(BADGES));
      return got.every((b) => b && b[0] !== 'Checking…' && b[0] !== 'Ready' && b[0] !== 'Online') && got;
    });
    check('the new tab page marks chat, mail and the forum off, and says why',
      badges && badges.every(([text, why]) => text === 'Off' && /another program holds port 8090/.test(why)), JSON.stringify(badges));
    newtab.destroy();

    // A page that server serves on HidraMail's origin, loaded outside the
    // tabs (no filter, no check of the response), with the bridge the
    // preload offers the apps: the vault still refuses it.
    const outsideSession = session.fromPartition('outside-the-tabs');
    await outsideSession.setProxy({ mode: 'direct' });
    const outside = new BrowserWindow({
      show: false,
      webPreferences: {
        preload: path.join(__dirname, '..', 'src', 'renderer', 'tab-preload.js'),
        contextIsolation: true, nodeIntegration: false, sandbox: true, session: outsideSession,
        additionalArguments: [`--hidra-ui-root=${UI_ROOT_URL}`, `--hidra-app-origins=${appOrigin('mail')}`],
      },
    });
    await outside.loadURL(MAIL).catch(() => {});
    const answer = await until(() => sq.seen.find((r) => r.url === '/took' || r.url === '/refused'));
    check('a page that server serves on HidraMail\'s origin is refused the vault, with the reason',
      answer && answer.url === '/refused' && /refused: another program holds port 8090/.test(answer.body) && handedOut === 0,
      JSON.stringify(answer) + ` handed out: ${handedOut}`);
    outside.destroy();

    b.done();
    await close(sq.server);
  }

  // ── The browser's own server ──
  apps = new AppsServer();
  const up = await apps.start(ownHandler);
  check(`with port 8090 free, the apps server comes up on ${v6 ? '127.0.0.1 and ::1' : '127.0.0.1'}`,
    up && apps.holds && apps.addresses().join() === (v6 ? '127.0.0.1,::1' : '127.0.0.1'), `${apps.state} ${apps.error} ${apps.addresses()}`);
  {
    const b = await browserWith(apps, torPort);
    const mail = await b.tabs.createTab('hidra://mail');
    const wc = await until(() => { const c = b.contents(mail); return !c.isLoading() && c.getURL() === MAIL && c; });
    const title = wc ? await wc.executeJavaScript('document.title') : null;
    check('HidraMail loads on its origin from the browser\'s own server', title === 'own app', `${title} at ${b.contents(mail).getURL()}`);
    const first = own.seen.find((r) => r.url === '/');
    if (v6) check('Chromium reached it on ::1', first && first.on === '::1', JSON.stringify(first));
    const got = wc ? await wc.executeJavaScript('window.hidra.vault.get()').catch((e) => 'error: ' + e.message) : null;
    check('and the app reads its compartment of the vault', got === SECRET && handedOut === 1, `${String(got).slice(0, 120)} handed out: ${handedOut}`);
    const wrote = wc ? await wc.executeJavaScript(`window.hidra.vault.set(${JSON.stringify(SECRET + ' ')})`).catch((e) => 'error: ' + e.message) : null;
    check('and writes it', wrote === true && vault.get('mail') === SECRET + ' ', String(wrote));
    const token = wc ? await wc.executeJavaScript(`fetch('/').then((r) => r.headers.get(${JSON.stringify(TOKEN_HEADER)}))`) : 'no page';
    check('the page never sees the token', token === null, String(token));

    // ── Responses on the app's origin that do not carry this run's token ──
    const before = handedOut;
    const ran = () => own.seen.filter((r) => r.url === '/took' || r.url === '/refused');
    const sub = wc ? await wc.executeJavaScript(`fetch('/no-token').then(() => 'loaded', () => 'dropped')`) : null;
    check('from the app\'s own page, a request whose response lacks the token fails', sub === 'dropped', String(sub));
    for (const forged of ['/no-token', '/wrong-token']) {
      b.tabs.navigate(mail, appOrigin('mail') + forged);
      const shown = await refusedPage(() => b.contents(mail));
      check(`a page on HidraMail's origin with ${forged === '/no-token' ? 'no token' : 'a wrong token'} is dropped, and the tab says the app did not open`,
        /did not open/.test(shown) && /did not come from this browser's apps server/.test(shown), shown);
      check('nothing in it ran, and the vault handed out nothing', ran().length === 0 && handedOut === before,
        `${JSON.stringify(ran())} handed out: ${handedOut - before}`);
    }

    // The old shared address: its redirect is the browser's own answer too,
    // and still sends the tab on to the app once the token is taken off.
    b.tabs.navigate(mail, `http://127.0.0.1:${APPS_PORT}/mail`);
    await sleep(500);
    const back = await until(() => { const c = b.contents(mail); return !c.isLoading() && c.getURL() === MAIL && c; });
    check('the old shared address still sends the tab to the app\'s own origin',
      back && (await back.executeJavaScript('document.title')) === 'own app', b.contents(mail).getURL());
    b.done();
  }
  await apps.close();

  // ── A server on [::1]:8090 beside an apps server on 127.0.0.1 alone ──
  if (v6) {
    const sq = taker();
    await listen(sq.server, APPS_PORT, '::1');
    apps = new AppsServer({ hosts: ['127.0.0.1'] });
    await apps.start(ownHandler);
    const seenBefore = own.seen.length;
    const before = handedOut;
    const b = await browserWith(apps, torPort);
    const mail = await b.tabs.createTab('hidra://mail');
    const shown = await refusedPage(() => b.contents(mail));
    check('Chromium reaches the server on [::1]:8090 first', sq.seen.some((r) => r.url === '/' && r.host === 'mail.localhost:8090'),
      JSON.stringify(sq.seen) + ` / own server asked ${own.seen.length - seenBefore} time(s)`);
    check('its response is dropped, and the tab says the app did not open', /did not open/.test(shown), shown);
    check('nothing in it ran, and the vault handed out nothing',
      !sq.seen.some((r) => r.url === '/took' || r.url === '/refused') && handedOut === before, JSON.stringify(sq.seen));
    b.done();
    await apps.close();
    await close(sq.server);
  } else {
    console.log('skip  a server on [::1]:8090 beside an apps server on 127.0.0.1 alone (no IPv6 loopback)');
  }

  await close(site);
  await close(tor);
  clearTimeout(guard);
  console.log(failures.length ? `\n${failures.length} failed` : '\nthe apps open only from this browser\'s own server');
  finish(failures.length ? 1 : 0);
}).catch((e) => { console.error(e); finish(1); });
