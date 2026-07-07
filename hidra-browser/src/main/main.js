const { app, BrowserWindow, session, ipcMain, protocol } = require('electron');
const path = require('path');
const http = require('http');
const https = require('https');
const fs = require('fs');
const { TabManager } = require('./tab-manager');
const { ProxyManager } = require('./proxy-manager');
const { FingerprintEngine } = require('../fingerprint/engine');

const PROXY_ADDR = '127.0.0.1';
const PROXY_PORT = 9050;
const CHAT_PORT = 8090;

let mainWindow = null;
let tabManager = null;
let proxyManager = null;
let chatServer = null;

// ─── User Preferences ─────────────────────────────────────────────────────────

let userPrefs = { theme: 'teal', searchLang: 'all' };

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

function httpsGet(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(url); } catch(e) { return reject(e); }
    const req = https.request({
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; HidraSearch/1.0)',
        'Accept': 'application/json, text/html, */*',
        'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
      },
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.setTimeout(timeoutMs || 7000, () => { req.destroy(new Error('timeout')); });
    req.end();
  });
}

function httpsPost(url, body, headers, timeoutMs) {
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(url); } catch(e) { return reject(e); }
    const buf = Buffer.from(body, 'utf8');
    const req = https.request({
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: Object.assign({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,*/*',
        'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': buf.length,
        'Cookie': '',
      }, headers || {}),
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.setTimeout(timeoutMs || 8000, () => { req.destroy(new Error('timeout')); });
    req.write(buf);
    req.end();
  });
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

    const title = aTag.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
    if (!title) { pos = aClose; continue; }

    let snippet = '';
    const region = html.slice(aClose, aClose + 2500);
    const snipM = region.match(/class="result__snippet"[^>]*>([\s\S]*?)<\/(a|div)>/);
    if (snipM) {
      snippet = snipM[1].replace(/<[^>]+>/g, ' ')
        .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"').replace(/\s+/g, ' ').trim();
    }

    results.push({ title, url, snippet, engine: 'duckduckgo' });
    pos = aClose;
  }
  return results;
}

const SEARX_INSTANCES = [
  'https://searx.be',
  'https://search.mdosch.de',
  'https://searxng.world',
  'https://priv.au',
];

async function performSearch(query, page, searchLang) {
  const enc = encodeURIComponent(query);
  const pageNo = Math.max(1, page);
  const lang = (searchLang && searchLang !== 'all') ? searchLang : 'all';

  // 1. Try SearXNG public instances (JSON API)
  for (const base of SEARX_INSTANCES) {
    try {
      const url = `${base}/search?q=${enc}&format=json&pageno=${pageNo}&language=${lang}&safesearch=0&engines=general`;
      const res = await httpsGet(url, 6000);
      if (res.ok) {
        const data = JSON.parse(res.body);
        if (data.results && data.results.length > 0) {
          return data.results.slice(0, 10).map(r => ({
            title: r.title || '',
            url: r.url || '',
            snippet: r.content || '',
            engine: (r.engine || r.engines && r.engines[0] || 'searxng'),
          }));
        }
      }
    } catch(e) {
      console.log('[search] SearXNG ' + base + ' failed:', e.message);
    }
  }

  // 2. Fallback: DuckDuckGo HTML scraping
  console.log('[search] Falling back to DuckDuckGo HTML...');
  const body = new URLSearchParams({
    q: query,
    b: pageNo > 1 ? String((pageNo - 1) * 30) : '',
    kl: 'wt-wt',
    kp: '-1',
    ks: 'n',
    kaf: '1',
  }).toString();

  const ddgRes = await httpsPost('https://html.duckduckgo.com/html/', body, {}, 9000);
  if (!ddgRes.ok) throw new Error('DDG HTTP ' + ddgRes.status);
  const parsed = parseDDGHtml(ddgRes.body);
  if (parsed.length === 0) throw new Error('No results from DuckDuckGo');
  return parsed;
}

// ─── End HidraSearch helpers ──────────────────────────────────────────────────

// Serve HidraChat from the trusted browser process (localhost = secure context
// for Web Crypto). The chat is fully client-side (MQTT relay + E2E in browser),
// so it does NOT depend on the hidra-node engine — works even if Smart App
// Control blocks the engine.
function startChatServer() {
  const load = (f) => {
    try { return fs.readFileSync(path.join(__dirname, '..', 'ui', f), 'utf8'); }
    catch (e) { console.error('[srv] failed to load', f, e.message); return '<h1>' + f + ' não encontrado</h1>'; }
  };
  const pages = { chat: load('hidrachat.html'), publish: load('sitepub.html'), site: load('siteload.html'), mail: load('hidramail.html'), forum: load('forum.html'), donate: load('donate.html'), search: load('hidrasearch.html') };
  chatServer = http.createServer(async (req, res) => {
    const fullUrl = req.url || '/';
    const qi = fullUrl.indexOf('?');
    const p = qi >= 0 ? fullUrl.slice(0, qi) : fullUrl;
    const qs = qi >= 0 ? fullUrl.slice(qi + 1) : '';

    // Prefs GET
    if (p === '/prefs' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Access-Control-Allow-Origin': '*' });
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
          savePrefs();
        } catch(e) {}
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
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
  chatServer.on('error', (e) => console.error('[srv] server error:', e.message));
  chatServer.listen(CHAT_PORT, '127.0.0.1', () => {
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
  });
});

app.on('window-all-closed', () => {
  if (proxyManager) {
    proxyManager.shutdownFull();
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
    return proxy.getStatus();
  });

  ipcMain.handle('proxy:set-hops', (_event, hops) => {
    return proxy.setHopCount(hops);
  });

  ipcMain.handle('proxy:connect', async () => {
    if (proxy.isRunning()) {
      await proxy.configure(session.defaultSession);
      for (const s of tabs.getAllSessions()) {
        await proxy.configure(s);
      }
      return { ok: true, msg: 'already running' };
    }
    const ok = await proxy.startHidraNode();
    if (ok) {
      await proxy.configure(session.defaultSession);
      for (const s of tabs.getAllSessions()) {
        await proxy.configure(s);
      }
      return { ok: true, msg: 'connected' };
    }
    return { ok: false, msg: 'failed to start hidra-node' };
  });

  ipcMain.handle('proxy:disconnect', async () => {
    await proxy.shutdown(session.defaultSession);
    for (const s of tabs.getAllSessions()) {
      await s.setProxy({ mode: 'direct' });
    }
    return { ok: true, msg: 'disconnected' };
  });

  ipcMain.handle('prefs:get', () => ({ ...userPrefs }));

  ipcMain.handle('prefs:save', (_event, update) => {
    if (update && typeof update === 'object') {
      if (update.theme) userPrefs.theme = update.theme;
      if (update.searchLang !== undefined) userPrefs.searchLang = update.searchLang;
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
