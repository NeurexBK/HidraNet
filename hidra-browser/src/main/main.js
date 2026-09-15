const { app, BrowserWindow, session, ipcMain, protocol, net } = require('electron');
const path = require('path');
const http = require('http');
const fs = require('fs');
const { TabManager } = require('./tab-manager');
const { ProxyManager } = require('./proxy-manager');
const { TorManager } = require('./tor-manager');
const { FingerprintEngine } = require('../fingerprint/engine');

const PROXY_ADDR = '127.0.0.1';
const PROXY_PORT = 9050;
const CHAT_PORT = 8090;
const SEVENNINE_PORT = 8084;

// The apps server is reachable by any page the user visits, so it only answers
// requests that carry our own Host and Origin. The Host check is what stops DNS
// rebinding, where a site points its own hostname at 127.0.0.1.
const ALLOWED_HOSTS = new Set([`127.0.0.1:${CHAT_PORT}`, `localhost:${CHAT_PORT}`]);
const ALLOWED_ORIGINS = new Set([`http://127.0.0.1:${CHAT_PORT}`, `http://localhost:${CHAT_PORT}`]);

function isTrustedRequest(req) {
  const host = String(req.headers.host || '').toLowerCase();
  if (!ALLOWED_HOSTS.has(host)) return false;

  // Our own pages are same-origin, so they either omit Origin or send ours.
  // Anything else is a page the user merely visited.
  const origin = req.headers.origin;
  if (origin && !ALLOWED_ORIGINS.has(origin)) return false;

  return true;
}

function pingLocalPort(port, urlPath, timeoutMs) {
  return new Promise((resolve) => {
    const req = http.get(
      { hostname: '127.0.0.1', port, path: urlPath || '/', timeout: timeoutMs || 2000 },
      (res) => {
        res.resume();
        resolve(res.statusCode >= 200 && res.statusCode < 500);
      }
    );
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
  });
}

let mainWindow = null;
let tabManager = null;
let proxyManager = null;
let torManager = null;
let chatServer = null;
// Whether the apps server actually got its port. A silent failure here
// costs chat, mail, forum and search with no sign in the interface.
let appsServer = { listening: false, error: null };

// Applies (or clears) the network proxy on every session the browser owns —
// the default one plus each tab's isolated partition. New tabs pick the same
// rules up through TabManager.setProxyRules.
async function applyProxyEverywhere(proxyRules) {
  const config = proxyRules
    ? { proxyRules, proxyBypassRules: '<local>' }
    : { mode: 'direct' };

  if (tabManager) tabManager.setProxyRules(proxyRules);

  await session.defaultSession.setProxy(config);
  if (tabManager) {
    for (const s of tabManager.getAllSessions()) {
      await s.setProxy(config);
    }
  }
}

// Shared by the Conectar button and the automatic connect at startup, so both
// paths route traffic and verify the exit the same way.
async function connectTor() {
  const started = await torManager.start(app.getPath('userData'));
  if (!started.ok) {
    return { ok: false, msg: started.error || 'não foi possível iniciar o Tor' };
  }

  const rules = torManager.getStatus().proxyRules;
  await applyProxyEverywhere(rules);

  const exit = await detectExitIp(rules);
  torManager.exitIp = exit && exit.ip ? exit.ip : null;

  if (exit && exit.isTor && exit.ip) {
    return { ok: true, msg: `Anônimo — saindo por ${exit.ip}`, exitIp: exit.ip, isTor: true };
  }

  // Tor bootstrapped but the check could not confirm it. Stay connected and say
  // so plainly rather than claiming an anonymity we did not verify.
  return {
    ok: true,
    msg: exit && exit.ip
      ? `Conectado, mas a verificação não confirmou o Tor (saída ${exit.ip})`
      : 'Conectado ao Tor — não consegui confirmar o IP de saída',
    exitIp: exit ? exit.ip : null,
    isTor: false,
  };
}

// Asks the Tor Project's own checker what it sees, so "anonymous" is something
// the browser confirms rather than asserts.
function detectExitIp(proxyRules) {
  return new Promise((resolve) => {
    const probe = session.fromPartition('exit-ip-' + Date.now());
    probe.setProxy({ proxyRules, proxyBypassRules: '<local>' }).then(() => {
      const request = net.request({ url: 'https://check.torproject.org/api/ip', session: probe });
      let body = '';
      const timer = setTimeout(() => {
        try { request.abort(); } catch (e) {}
        resolve(null);
      }, 25000);

      request.on('response', (res) => {
        res.on('data', (c) => { body += c; });
        res.on('end', () => {
          clearTimeout(timer);
          try {
            const parsed = JSON.parse(body);
            resolve({ ip: parsed.IP || null, isTor: parsed.IsTor === true });
          } catch (e) {
            resolve(null);
          }
        });
      });
      request.on('error', () => { clearTimeout(timer); resolve(null); });
      request.end();
    }).catch(() => resolve(null));
  });
}

// ─── User Preferences ─────────────────────────────────────────────────────────

// autoConnect defaults on: a privacy browser that is only anonymous when the
// user remembers to press a button is not a privacy browser.
let userPrefs = { theme: 'teal', searchLang: 'all', autoConnect: true };

function loadPrefs() {
  try {
    const p = path.join(app.getPath('userData'), 'hidranet-prefs.json');
    if (fs.existsSync(p)) userPrefs = { ...userPrefs, ...JSON.parse(fs.readFileSync(p, 'utf8')) };
  } catch(e) {}
}

function savePrefs() {
  try {
    const p = path.join(app.getPath('userData'), 'hidranet-prefs.json');
    fs.writeFileSync(p, JSON.stringify(userPrefs), 'utf8');
  } catch(e) {}
}

// ─── HidraSearch proxy helpers ────────────────────────────────────────────────

// Searches go out through Electron's net, not Node's https. Node's http stack
// knows nothing about Electron sessions, so every query used to leave with the
// user's real IP even while connected — and a search history is the most
// revealing thing this browser handles. net.request rides the default session,
// which applyProxyEverywhere points at Tor.
function netRequest(options) {
  return new Promise((resolve, reject) => {
    let request;
    try {
      request = net.request({
        url: options.url,
        method: options.method || 'GET',
        session: session.defaultSession,
        useSessionCookies: false,
      });
    } catch (e) {
      return reject(e);
    }

    for (const [key, value] of Object.entries(options.headers || {})) {
      try { request.setHeader(key, String(value)); } catch (e) {}
    }

    let settled = false;
    const done = (fn, arg) => { if (!settled) { settled = true; clearTimeout(timer); fn(arg); } };

    const timer = setTimeout(() => {
      try { request.abort(); } catch (e) {}
      done(reject, new Error('timeout'));
    }, options.timeoutMs || 8000);

    request.on('response', (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => done(resolve, {
        ok: res.statusCode >= 200 && res.statusCode < 300,
        status: res.statusCode,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    request.on('error', (err) => done(reject, err));

    if (options.body) request.write(options.body);
    request.end();
  });
}

function httpsGet(url, timeoutMs) {
  return netRequest({
    url,
    method: 'GET',
    headers: {
      'User-Agent': 'Mozilla/5.0 (compatible; HidraSearch/1.0)',
      'Accept': 'application/json, text/html, */*',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    timeoutMs: timeoutMs || 7000,
  });
}

function httpsPost(url, body, headers, timeoutMs) {
  return netRequest({
    url,
    method: 'POST',
    headers: Object.assign({
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,*/*',
      'Accept-Language': 'en-US,en;q=0.9',
      'Content-Type': 'application/x-www-form-urlencoded',
    }, headers || {}),
    body: Buffer.from(body, 'utf8'),
    timeoutMs: timeoutMs || 8000,
  });
}

// Results are scraped out of HTML, so titles and snippets arrive with entities
// still encoded — they were reaching the UI as "Shaping Europe&#x27;s future".
function decodeEntities(text) {
  return text
    .replace(/&#x([0-9a-fA-F]+);/g, (m, hex) => {
      try { return String.fromCodePoint(parseInt(hex, 16)); } catch (e) { return m; }
    })
    .replace(/&#(\d+);/g, (m, dec) => {
      try { return String.fromCodePoint(parseInt(dec, 10)); } catch (e) { return m; }
    })
    .replace(/&nbsp;/g, ' ')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

function parseDDGHtml(html) {
  const results = [];
  const seen = new Set();
  let pos = 0;

  while (results.length < 10) {
    // Each result starts with <h2 class="result__title">
    const h2 = html.indexOf('<h2 class="result__title">', pos);
    if (h2 === -1) break;
    const aOpen = html.indexOf('<a ', h2);
    const aClose = html.indexOf('</a>', aOpen);
    if (aOpen === -1 || aClose === -1) { pos = h2 + 1; continue; }

    const aTag = html.slice(aOpen, aClose + 4);
    const hrefM = aTag.match(/href="([^"]+)"/);
    if (!hrefM) { pos = aClose; continue; }

    let url = hrefM[1];
    const uddgM = url.match(/[?&]uddg=([^&]+)/);
    if (uddgM) { try { url = decodeURIComponent(uddgM[1]); } catch(e) {} }

    if (!url.startsWith('http') || seen.has(url)) { pos = aClose; continue; }
    seen.add(url);

    const title = decodeEntities(aTag.replace(/<[^>]+>/g, '')).replace(/\s+/g, ' ').trim();
    if (!title) { pos = aClose; continue; }

    let snippet = '';
    const region = html.slice(aClose, aClose + 2500);
    const snipM = region.match(/class="result__snippet"[^>]*>([\s\S]*?)<\/(a|div)>/);
    if (snipM) {
      snippet = decodeEntities(snipM[1].replace(/<[^>]+>/g, ' '))
        .replace(/\s+/g, ' ').trim();
    }

    results.push({ title, url, snippet, engine: 'duckduckgo' });
    pos = aClose;
  }
  return results;
}

// Public SearXNG instances disable the JSON API by default, so these answer
// with HTML, 429 or nothing at all. They stay as a fallback in case one ever
// enables it, but they are no longer the first thing every search waits on.
const SEARX_INSTANCES = [
  'https://searx.be',
  'https://search.mdosch.de',
  'https://priv.au',
];

// The language picker offers Google-Translate style codes; DuckDuckGo filters by
// region instead. Only languages DDG actually has a region for can be honoured —
// the rest fall through to worldwide results.
const DDG_REGIONS = {
  'pt-BR': 'br-pt', 'pt-PT': 'pt-pt', 'en-US': 'us-en', 'en-GB': 'uk-en',
  es: 'es-es', fr: 'fr-fr', de: 'de-de', it: 'it-it', ja: 'jp-jp',
  'zh-CN': 'cn-zh', 'zh-TW': 'tw-tzh', ru: 'ru-ru', ar: 'xa-ar',
  nl: 'nl-nl', pl: 'pl-pl', tr: 'tr-tr', sv: 'se-sv', da: 'dk-da',
  fi: 'fi-fi', no: 'no-no', cs: 'cz-cs', sk: 'sk-sk', hu: 'hu-hu',
  ro: 'ro-ro', bg: 'bg-bg', hr: 'hr-hr', sl: 'sl-sl', et: 'ee-et',
  lv: 'lv-lv', lt: 'lt-lt', el: 'gr-el', he: 'il-he', ko: 'kr-kr',
  th: 'th-th', vi: 'vn-vi', id: 'id-id', ms: 'my-ms', tl: 'ph-tl',
  uk: 'ua-uk', ca: 'ct-ca',
};

// httpsPost defaults to a hardcoded pt-BR Accept-Language, which contradicted
// whichever region the user actually asked for.
function acceptLanguageFor(lang) {
  if (!lang || lang === 'all') return 'en-US,en;q=0.9';
  const base = lang.split('-')[0];
  return lang === base ? `${lang},en;q=0.8` : `${lang},${base};q=0.9,en;q=0.8`;
}

const DDG_URL = 'https://html.duckduckgo.com/html/';
const DDG_PER_PAGE = 10;

async function searchDuckDuckGo(query, pageNo, lang) {
  const kl = DDG_REGIONS[lang] || 'wt-wt';
  const headers = { 'Accept-Language': acceptLanguageFor(lang) };

  const firstBody = new URLSearchParams({
    q: query, kl, kp: '-1', ks: 'n', kaf: '1',
  }).toString();

  const first = await httpsPost(DDG_URL, firstBody, headers, 9000);
  if (!first.ok) throw new Error('DDG HTTP ' + first.status);
  if (pageNo <= 1) return parseDDGHtml(first.body);

  // Later pages need the offset in "s" plus the vqd token minted alongside the
  // query. The old code sent "b", which DuckDuckGo ignores — page 2 and page 3
  // came back as page 1.
  const vqdMatch = first.body.match(/name="vqd"[^>]*value="([^"]+)"/)
    || first.body.match(/value="([^"]+)"[^>]*name="vqd"/);
  if (!vqdMatch) return parseDDGHtml(first.body);

  const offset = (pageNo - 1) * DDG_PER_PAGE;
  const nextBody = new URLSearchParams({
    q: query,
    s: String(offset),
    nextParams: '',
    v: 'l',
    o: 'json',
    dc: String(offset + 1),
    api: 'd.js',
    vqd: vqdMatch[1],
    kl,
    kp: '-1',
  }).toString();

  const next = await httpsPost(DDG_URL, nextBody, headers, 9000);
  if (!next.ok) throw new Error('DDG HTTP ' + next.status);
  return parseDDGHtml(next.body);
}

async function searchSearxng(query, pageNo, lang) {
  const enc = encodeURIComponent(query);
  for (const base of SEARX_INSTANCES) {
    try {
      const url = `${base}/search?q=${enc}&format=json&pageno=${pageNo}&language=${lang}&safesearch=0&engines=general`;
      const res = await httpsGet(url, 4000);
      if (!res.ok) continue;
      const data = JSON.parse(res.body);
      if (data.results && data.results.length > 0) {
        return data.results.slice(0, 10).map(r => ({
          title: r.title || '',
          url: r.url || '',
          snippet: r.content || '',
          engine: (r.engine || r.engines && r.engines[0] || 'searxng'),
        }));
      }
    } catch (e) {
      console.log('[search] SearXNG ' + base + ' failed:', e.message);
    }
  }
  return [];
}

async function performSearch(query, page, searchLang) {
  const pageNo = Math.max(1, page);
  const lang = (searchLang && searchLang !== 'all') ? searchLang : 'all';

  try {
    const results = await searchDuckDuckGo(query, pageNo, lang);
    if (results.length > 0) return results;
  } catch (e) {
    console.log('[search] DuckDuckGo failed:', e.message);
  }

  const fallback = await searchSearxng(query, pageNo, lang);
  if (fallback.length > 0) return fallback;

  throw new Error('Nenhum mecanismo de busca respondeu');
}

// ─── End HidraSearch helpers ──────────────────────────────────────────────────

// Serve HidraChat from the trusted browser process (localhost = secure context
// for Web Crypto). The chat is fully client-side (MQTT relay + E2E in browser),
// so it does NOT depend on the hidra-node engine — works even if Smart App
// Control blocks the engine.
function startChatServer(attempt) {
  attempt = attempt || 0;
  const load = (f) => {
    try { return fs.readFileSync(path.join(__dirname, '..', 'ui', f), 'utf8'); }
    catch (e) { console.error('[srv] failed to load', f, e.message); return '<h1>' + f + ' não encontrado</h1>'; }
  };
  const pages = { chat: load('hidrachat.html'), publish: load('sitepub.html'), site: load('siteload.html'), mail: load('hidramail.html'), forum: load('forum.html'), donate: load('donate.html'), search: load('hidrasearch.html') };
  chatServer = http.createServer(async (req, res) => {
    if (!isTrustedRequest(req)) {
      res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('forbidden');
      return;
    }

    const fullUrl = req.url || '/';
    const qi = fullUrl.indexOf('?');
    const p = qi >= 0 ? fullUrl.slice(0, qi) : fullUrl;
    const qs = qi >= 0 ? fullUrl.slice(qi + 1) : '';

    // Prefs GET
    if (p === '/prefs' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify(userPrefs));
      return;
    }

    // Prefs POST
    if (p === '/prefs' && req.method === 'POST') {
      let body = '';
      req.on('data', c => { body += c; });
      req.on('end', () => {
        try {
          const update = JSON.parse(body);
          if (update.theme) userPrefs.theme = update.theme;
          if (update.searchLang !== undefined) userPrefs.searchLang = update.searchLang;
          if (update.autoConnect !== undefined) userPrefs.autoConnect = !!update.autoConnect;
          savePrefs();
        } catch(e) {}
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      });
      return;
    }

    // Async search API — must return before html fallback
    if (p === '/search/api') {
      const params = new URLSearchParams(qs);
      const q = (params.get('q') || '').trim();
      const page = Math.max(1, parseInt(params.get('p') || '1', 10));
      const lang = params.get('lang') || userPrefs.searchLang || 'all';
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      if (!q) { res.end(JSON.stringify({ results: [], total: 0 })); return; }
      const t0 = Date.now();
      try {
        const results = await performSearch(q, page, lang);
        res.end(JSON.stringify({ results, total: results.length, query: q, elapsed_ms: Date.now() - t0 }));
      } catch (err) {
        console.error('[search] error:', err.message);
        res.end(JSON.stringify({ results: [], error: err.message, query: q }));
      }
      return;
    }

    let html = pages.chat;
    if (p.indexOf('/mail') === 0) html = pages.mail;
    else if (p.indexOf('/forum') === 0) html = pages.forum;
    else if (p.indexOf('/donate') === 0) html = pages.donate;
    else if (p === '/sites' || p.indexOf('/publish') === 0) html = pages.publish;
    else if (p.indexOf('/site') === 0) html = pages.site;
    else if (p.indexOf('/search') === 0) html = pages.search;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    res.end(html);
  });
  chatServer.on('error', (e) => {
    console.error('[srv] server error:', e.message);

    // Another copy of the browser that is still shutting down holds the port
    // for a few seconds. Retry before giving up, and record why if we do —
    // otherwise the apps just read "Offline" forever with no explanation.
    if (e.code === 'EADDRINUSE' && attempt < 5) {
      appsServer = { listening: false, error: 'porta ' + CHAT_PORT + ' ocupada, a tentar de novo' };
      setTimeout(() => startChatServer(attempt + 1), 2000);
      return;
    }

    appsServer = {
      listening: false,
      error: e.code === 'EADDRINUSE'
        ? 'a porta ' + CHAT_PORT + ' está ocupada por outro programa — feche a outra janela da HidraNet e reinicie'
        : 'falha ao abrir a porta ' + CHAT_PORT + ': ' + e.message,
    };
  });

  chatServer.listen(CHAT_PORT, '127.0.0.1', () => {
    appsServer = { listening: true, error: null };
    console.log('[srv] HidraNet apps at http://127.0.0.1:' + CHAT_PORT + ' (chat, /publish, /site)');
  });
}

app.commandLine.appendSwitch('disable-features', 'WebRTC');
app.commandLine.appendSwitch('disable-webrtc');
app.commandLine.appendSwitch('disable-reading-from-canvas');
app.commandLine.appendSwitch('disable-gl-extensions');
app.commandLine.appendSwitch('disable-accelerated-2d-canvas');

protocol.registerSchemesAsPrivileged([{
  scheme: 'hidra',
  privileges: { standard: true, secure: true, supportFetchAPI: true }
}]);

app.whenReady().then(async () => {
  loadPrefs();
  startChatServer();
  proxyManager = new ProxyManager(PROXY_ADDR, PROXY_PORT);
  torManager = new TorManager();

  const proxyReady = await proxyManager.configure(session.defaultSession);
  if (proxyReady) {
    console.log('SOCKS5 proxy detected — connected');
  } else {
    console.log('Waiting for user to click Conectar');
  }

  mainWindow = createMainWindow();
  tabManager = new TabManager(mainWindow, proxyManager);

  setupIPC(tabManager, proxyManager);

  mainWindow.once('ready-to-show', async () => {
    mainWindow.show();
    await tabManager.createTab('hidra://newtab');

    // Start anonymising immediately instead of waiting for the user to press
    // Conectar. The new tab page watches proxy:status and shows the bootstrap
    // climbing, so this is visible rather than silent.
    if (userPrefs.autoConnect !== false) {
      connectTor()
        .then((r) => console.log('[tor] auto-connect:', r.ok ? r.msg : 'falhou — ' + r.msg))
        .catch((e) => console.error('[tor] auto-connect erro:', e.message));
    }
  });
});

app.on('window-all-closed', () => {
  if (proxyManager) {
    proxyManager.shutdownFull();
  }
  if (torManager) {
    torManager.stop();
  }
  app.quit();
});

function createMainWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    title: 'HidraNet Browser',
    backgroundColor: '#0a0a0f',
    frame: false,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, '..', 'renderer', 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  win.loadFile(path.join(__dirname, '..', 'ui', 'browser.html'));
  return win;
}

function setupIPC(tabs, proxy) {
  ipcMain.handle('tab:create', async (_event, url) => {
    return await tabs.createTab(url || 'hidra://newtab');
  });

  ipcMain.handle('tab:close', (_event, tabId) => {
    tabs.closeTab(tabId);
  });

  ipcMain.handle('tab:navigate', (_event, tabId, url) => {
    tabs.navigate(tabId, url);
  });

  ipcMain.handle('tab:go-back', (_event, tabId) => {
    tabs.goBack(tabId);
  });

  ipcMain.handle('tab:go-forward', (_event, tabId) => {
    tabs.goForward(tabId);
  });

  ipcMain.handle('tab:reload', (_event, tabId) => {
    tabs.reload(tabId);
  });

  ipcMain.handle('tab:activate', (_event, tabId) => {
    tabs.activateTab(tabId);
  });

  ipcMain.handle('tab:list', () => {
    return tabs.listTabs();
  });

  ipcMain.handle('proxy:status', () => {
    const base = proxy.getStatus();
    const tor = torManager.getStatus();
    const connected = tor.state === 'ready';

    return {
      ...base,
      connected,
      mode: connected ? 'tor' : (tor.state === 'starting' ? 'connecting' : 'disconnected'),
      tor,
    };
  });

  // SevenNine is the engine's .hidra site builder, not a browser-served app, so
  // it only runs when the user actually opens it.
  ipcMain.handle('sevennine:start', async () => {
    const result = await proxy.startSevenNine();
    return result.ok
      ? { ok: true, url: `http://127.0.0.1:${SEVENNINE_PORT}/` }
      : { ok: false, msg: result.error };
  });

  ipcMain.handle('sevennine:stop', async () => proxy.stopSevenNine());

  ipcMain.handle('tor:new-identity', async () => {
    const previous = torManager.exitIp;
    const result = await torManager.newIdentity();
    if (!result.ok) return { ok: false, msg: result.error };

    // NEWNYM only steers *new* streams; sockets already open keep their old
    // circuit, so without dropping them the exit IP would appear unchanged.
    try {
      await session.defaultSession.closeAllConnections();
      if (tabManager) {
        for (const s of tabManager.getAllSessions()) await s.closeAllConnections();
      }
    } catch (e) {}

    const rules = torManager.getStatus().proxyRules;

    // Tor rate-limits NEWNYM ("delaying by N seconds"), so asking straight away
    // can still answer with the old exit and make a working switch look broken.
    // Give it a few tries before concluding anything.
    let exit = null;
    for (let attempt = 0; attempt < 5; attempt++) {
      exit = await detectExitIp(rules);
      if (exit && exit.ip && exit.ip !== previous) break;
      await new Promise((r) => setTimeout(r, 3000));
    }

    torManager.exitIp = exit && exit.ip ? exit.ip : null;

    if (!exit || !exit.ip) {
      return { ok: false, msg: 'não consegui confirmar o novo IP de saída' };
    }

    return {
      ok: true,
      exitIp: exit.ip,
      isTor: exit.isTor === true,
      // Tor can legitimately hand back the same exit; say so instead of
      // implying a change that did not happen.
      changed: exit.ip !== previous,
      msg: exit.ip === previous
        ? `O Tor devolveu o mesmo nó de saída (${exit.ip}) — tente de novo em alguns segundos`
        : `Novo IP de saída: ${exit.ip}`,
    };
  });

  // Connecting means Tor, not the HidraNet engine. The engine's circuit runs
  // over relays that config.toml points at 127.0.0.1, so it never changes the
  // exit IP; Tor's volunteer network is what actually anonymises the traffic.
  ipcMain.handle('proxy:connect', () => connectTor());

  ipcMain.handle('proxy:disconnect', async () => {
    await torManager.stop();
    await applyProxyEverywhere(null);
    await proxy.shutdown(null);
    return { ok: true, msg: 'desconectado' };
  });

  // The new tab page lives on file://, so it cannot probe the apps ports with
  // fetch — the responses are cross-origin and get blocked, which made every
  // app show as "Offline" even while running. Probe from the main process.
  ipcMain.handle('apps:status', async () => {
    const [chat, sevennine] = await Promise.all([
      pingLocalPort(CHAT_PORT, '/'),
      pingLocalPort(SEVENNINE_PORT, '/'),
    ]);
    // appsServer.error explains a chat/mail/forum outage the ping alone cannot:
    // the port was taken, usually by a second copy of the browser.
    return { chat, sevennine, error: chat ? null : appsServer.error };
  });

  ipcMain.handle('prefs:get', () => ({ ...userPrefs }));

  ipcMain.handle('prefs:save', (_event, update) => {
    if (update && typeof update === 'object') {
      if (update.theme) userPrefs.theme = update.theme;
      if (update.searchLang !== undefined) userPrefs.searchLang = update.searchLang;
      if (update.autoConnect !== undefined) userPrefs.autoConnect = !!update.autoConnect;
      savePrefs();
    }
    return { ok: true };
  });

  ipcMain.handle('window:minimize', () => {
    if (mainWindow) mainWindow.minimize();
  });

  ipcMain.handle('window:maximize', () => {
    if (mainWindow) {
      if (mainWindow.isMaximized()) {
        mainWindow.unmaximize();
      } else {
        mainWindow.maximize();
      }
    }
  });

  ipcMain.handle('window:close', () => {
    if (mainWindow) mainWindow.close();
  });
}
