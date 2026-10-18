const { app, BrowserWindow, session, ipcMain, protocol, net, safeStorage, nativeImage, shell } = require('electron');
const path = require('path');
const http = require('http');
const fs = require('fs');
const { TabManager, vaultNamespaceOf, appNamespace, UI_ROOT_URL } = require('./tab-manager');
const appOrigins = require('./app-origins');
const { applyAppIcon, windowIcon } = require('./app-icon');
const { senderPage, requirePage } = require('./ipc-guard');
const { VaultStore } = require('./vault');
const { ProxyManager, LOOPBACK_ONLY } = require('./proxy-manager');
const { TorManager } = require('./tor-manager');
const { NetworkLock } = require('./network-lock');
const { FingerprintEngine } = require('../fingerprint/engine');

const PROXY_ADDR = '127.0.0.1';
const PROXY_PORT = 9050;
const CHAT_PORT = 8090;
const SEVENNINE_PORT = 8084;

// The apps server is reachable by any page the user visits, so it only answers
// requests that carry one of our own Hosts, and an Origin that is the same
// app's. The Host check is what stops DNS rebinding, where a site points its
// own hostname at 127.0.0.1; the Origin check is what keeps one app from
// talking to another's routes now that each has an origin of its own.
function isTrustedRequest(req) {
  const host = String(req.headers.host || '').toLowerCase();
  const app = appOrigins.appOfHost(host);
  if (!app) return appOrigins.LEGACY_HOSTS.has(host) && !req.headers.origin;
  const origin = req.headers.origin;
  if (origin && origin !== appOrigins.appOrigin(app)) return false;
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
// Closed until Tor confirms it is carrying the traffic. See network-lock.js.
let networkLock = new NetworkLock();
// Whether the apps server actually got its port. A silent failure here
// costs chat, mail, forum and search with no sign in the interface.
let appsServer = { listening: false, error: null };

// Where the apps keep what identifies you, under the system keychain. See
// vault.js. Created once the app is ready, because safeStorage is not before.
let vault = null;

// Applies (or clears) the network proxy on every session the browser owns —
// the default one plus each tab's isolated partition. New tabs pick the same
// rules up through TabManager.setProxyRules.
async function applyProxyEverywhere(proxyRules) {
  const config = proxyRules
    ? { proxyRules, proxyBypassRules: LOOPBACK_ONLY }
    : { mode: 'direct' };

  if (tabManager) tabManager.setProxyRules(proxyRules);

  networkLock.protect(session.defaultSession);
  await session.defaultSession.setProxy(config);
  if (tabManager) {
    for (const s of tabManager.getAllSessions()) {
      await s.setProxy(config);
    }
  }
}

// Shared by the Connect button and the automatic connect at startup, so both
// paths route traffic and verify the exit the same way. Connect pressed while
// the automatic connect is still bootstrapping joins it rather than running a
// second one beside it (see TorManager.start).
let connecting = null;
function connectTor() {
  if (!connecting) connecting = connectTorOnce().finally(() => { connecting = null; });
  return connecting;
}

async function connectTorOnce() {
  const started = await torManager.start(app.getPath('userData'));
  if (!started.ok) {
    // Stays closed: a Tor that did not start must not let traffic out.
    networkLock.engage('Tor did not start — ' + (started.error || 'reason unknown'));
    return { ok: false, msg: started.error || 'could not start Tor' };
  }

  const rules = torManager.getStatus().proxyRules;
  await applyProxyEverywhere(rules);

  // Tor reached 100% and the rules are applied to every session: the
  // traffic physically goes through its SOCKS port. This is the moment to open —
  // not the IP check, which depends on an external site being up. If that check
  // fails we tell the user, but we do not leave them without a network.
  networkLock.release();

  const exit = await detectExitIp(rules);
  torManager.exitIp = exit && exit.ip ? exit.ip : null;

  if (exit && exit.isTor && exit.ip) {
    return { ok: true, msg: `Anonymous — exiting via ${exit.ip}`, exitIp: exit.ip, isTor: true };
  }

  // Tor bootstrapped but the check could not confirm it. Stay connected and say
  // so plainly rather than claiming an anonymity we did not verify.
  return {
    ok: true,
    msg: exit && exit.ip
      ? `Connected, but the check could not confirm Tor (exit ${exit.ip})`
      : 'Connected to Tor — could not confirm the exit IP',
    exitIp: exit ? exit.ip : null,
    isTor: false,
  };
}

// Asks the Tor Project's own checker what it sees, so "anonymous" is something
// the browser confirms rather than asserts.
function detectExitIp(proxyRules) {
  return new Promise((resolve) => {
    // One fixed partition, reused. It used to be 'exit-ip-' + Date.now(),
    // which created a new session per check — five per new identity — and
    // Electron never frees them. It bypasses the lock: it has to go out via
    // Tor precisely so it can confirm that Tor is working.
    const probe = session.fromPartition('hidra-exit-check');
    probe.closeAllConnections().catch(() => {});
    probe.setProxy({ proxyRules, proxyBypassRules: LOOPBACK_ONLY }).then(() => {
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
      // The same string as httpsPost: a name of our own would tell the
      // search engine which of the people behind a Tor exit use HidraNet.
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
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
      const url = `${base}/search?q=${enc}&format=json&pageno=${pageNo}&language=${encodeURIComponent(lang)}&safesearch=0&engines=general`;
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


// A result comes from a search engine, or from whoever runs a public SearXNG
// instance, and its link is shown for the user to click. Only a web address
// goes through: a javascript: or data: link in a result would run in the
// search page, which shares its origin with every one of the apps.
function webResultsOnly(results) {
  return results.filter((r) => {
    try {
      const u = new URL(String(r && r.url));
      return u.protocol === 'https:' || u.protocol === 'http:';
    } catch (e) {
      return false;
    }
  }).map((r) => ({
    title: String(r.title || ''),
    url: new URL(String(r.url)).href,
    snippet: String(r.snippet || ''),
    engine: String(r.engine || ''),
  }));
}

async function performSearch(query, page, searchLang) {
  return webResultsOnly(await searchAnyEngine(query, page, searchLang));
}

async function searchAnyEngine(query, page, searchLang) {
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

  throw new Error('No search engine responded');
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
    catch (e) { console.error('[srv] failed to load', f, e.message); return '<h1>' + f + ' not found</h1>'; }
  };
  // By app name (app-origins.js): each is served on its own origin.
  const pages = { chat: load('hidrachat.html'), publish: load('sitepub.html'), site: load('siteload.html'), mail: load('hidramail.html'), forum: load('forum.html'), donate: load('donate.html'), search: load('hidrasearch.html'), reviews: load('hidrareview.html') };
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

    // An address from when the apps shared one origin: sent on to the app's
    // own. Bookmarks, old links and the cards on cached new tab pages keep
    // working.
    const app = appOrigins.appOfHost(req.headers.host);
    if (!app) {
      const target = appOrigins.legacyTarget(req.headers.host, fullUrl);
      if (target && req.method === 'GET') {
        res.writeHead(302, { Location: target, 'Cache-Control': 'no-store' });
      } else {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      }
      res.end();
      return;
    }

    // The search page's preferences, for the search page.
    if (p === '/prefs' && req.method === 'GET' && app === 'search') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify(userPrefs));
      return;
    }

    // There is no POST /prefs. Preferences change through the browser's own
    // window (the prefs IPC below), never over HTTP: every app and every
    // .hidra site shown in the site viewer shares this origin, and a route
    // here let any of them switch off connecting to Tor at startup.

    // Third-party libraries, served from the application bundle.
    //
    // These pages used to load mqtt from unpkg.com, with no integrity
    // check and on a version range (@5) that serves whatever is
    // newest. They are the same pages that generate keys and encrypt mail:
    // anyone controlling that response read everything in plaintext. Now the
    // file comes from disk, at the version that was reviewed.
    //
    // The shim the apps load to reach their vault compartment, and the room
    // cryptography the chat page loads. Fixed names, like the vendor files
    // below: nothing concatenates the request path.
    const SHARED = { '/hidra-store.js': 'hidra-store.js', '/hidrachat-crypto.js': 'hidrachat-crypto.js', '/hidra-site.js': 'hidra-site.js' };
    if (Object.prototype.hasOwnProperty.call(SHARED, p)) {
      try {
        const body = fs.readFileSync(path.join(__dirname, '..', 'ui', SHARED[p]));
        res.writeHead(200, {
          'Content-Type': 'application/javascript; charset=utf-8',
          'Cache-Control': 'no-cache',
        });
        res.end(body);
      } catch (e) {
        console.error('[srv]', SHARED[p], e.message);
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('could not read ' + SHARED[p]);
      }
      return;
    }

    // The HidraNet logo and the tab icon, for every app. A fixed list again.
    const IMAGES = {
      '/img/favicon.png': 'favicon.png',
      '/img/hidranet-logo.png': 'hidranet-logo.png',
      '/img/hidranet-icon.png': 'hidranet-icon.png',
    };
    if (Object.prototype.hasOwnProperty.call(IMAGES, p)) {
      try {
        const body = fs.readFileSync(path.join(__dirname, '..', 'ui', 'img', IMAGES[p]));
        res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=86400' });
        res.end(body);
      } catch (e) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('not found');
      }
      return;
    }

    // The list is fixed on purpose — nothing concatenates the request path, so
    // directory traversal is not possible.
    if (p.indexOf('/vendor/') === 0) {
      const VENDOR = {
        '/vendor/mqtt.min.js': 'mqtt.min.js',
        '/vendor/qrcode.js': 'qrcode.js',
      };
      const name = VENDOR[p];
      if (!name) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('not found');
        return;
      }
      try {
        const body = fs.readFileSync(path.join(__dirname, '..', 'ui', 'vendor', name));
        res.writeHead(200, {
          'Content-Type': 'application/javascript; charset=utf-8',
          'Cache-Control': 'public, max-age=31536000, immutable',
        });
        res.end(body);
      } catch (e) {
        console.error('[srv] vendor', name, e.message);
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('could not read ' + name);
      }
      return;
    }

    // Async search API — must return before html fallback
    if (p === '/search/api' && app === 'search') {
      const params = new URLSearchParams(qs);
      const q = (params.get('q') || '').trim();
      const page = Math.max(1, parseInt(params.get('p') || '1', 10));
      const lang = params.get('lang') || userPrefs.searchLang || 'all';
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      if (!q) { res.end(JSON.stringify({ results: [], total: 0 })); return; }
      // net.request may bypass webRequest filters depending on the Electron
      // version. A search query is the most revealing thing this browser
      // handles, so it is checked explicitly here rather than trusting the
      // filter.
      if (networkLock.engaged) {
        res.end(JSON.stringify({
          results: [],
          error: 'Search is blocked until Tor is ready ('
            + networkLock.reason + ').',
          query: q,
        }));
        return;
      }
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

    // Each app's page, on its own origin, at its root and nowhere else.
    const html = (p === '/' || p === '/index.html') ? pages[app] : null;
    if (!html) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('not found');
      return;
    }
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache',
      // Each page carries its own CSP in a <meta>, but frame-ancestors is
      // ignored there — a meta policy cannot stop the page being framed,
      // because by the time it parses the framing has happened. It has to
      // come down as a header, so it does, here.
      'Content-Security-Policy': "frame-ancestors 'none'",
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    });
    res.end(html);
  });
  chatServer.on('error', (e) => {
    console.error('[srv] server error:', e.message);

    // Another copy of the browser that is still shutting down holds the port
    // for a few seconds. Retry before giving up, and record why if we do —
    // otherwise the apps just read "Offline" forever with no explanation.
    if (e.code === 'EADDRINUSE' && attempt < 5) {
      appsServer = { listening: false, error: 'port ' + CHAT_PORT + ' busy, retrying' };
      setTimeout(() => startChatServer(attempt + 1), 2000);
      return;
    }

    appsServer = {
      listening: false,
      error: e.code === 'EADDRINUSE'
        ? 'port ' + CHAT_PORT + ' is held by another program — close the other HidraNet window and restart'
        : 'could not open port ' + CHAT_PORT + ': ' + e.message,
    };
  });

  chatServer.listen(CHAT_PORT, '127.0.0.1', () => {
    appsServer = { listening: true, error: null };
    console.log('[srv] HidraNet apps at http://127.0.0.1:' + CHAT_PORT + ' (chat, /publish, /site)');
  });
}

// 'disable-features=WebRTC' and '--disable-webrtc' correspond to nothing in
// Chromium: 'WebRTC' is not a base::Feature and the switch does not exist. They
// gave the impression of protection without giving any. What closes the ICE
// candidate leak is setWebRTCIPHandlingPolicy('disable_non_proxied_udp'),
// applied per tab in tab-manager.js, plus the shim in fingerprint/engine.js.
//
// This one does exist, and hides local IPs behind mDNS names.
app.commandLine.appendSwitch('enable-features', 'WebRtcHideLocalIpsWithMdns');
app.commandLine.appendSwitch('disable-reading-from-canvas');
app.commandLine.appendSwitch('disable-gl-extensions');
app.commandLine.appendSwitch('disable-accelerated-2d-canvas');

protocol.registerSchemesAsPrivileged([{
  scheme: 'hidra',
  privileges: { standard: true, secure: true, supportFetchAPI: true }
}]);

// One browser at a time. Two copies share the same profile, the same apps
// port and the same Tor port and data directory, and fight over all three:
// the second one's Tor could not start, its apps read "Offline", and each
// copy's panel said the other's connection was down. Opening HidraNet again
// now brings the window that is already open to the front.
const firstInstance = app.requestSingleInstanceLock();
if (!firstInstance) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (!mainWindow) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
  });
}

app.whenReady().then(async () => {
  if (!firstInstance) return;
  applyAppIcon({ app, nativeImage, shell });
  loadPrefs();
  vault = new VaultStore(path.join(app.getPath('userData'), 'vault'), safeStorage);
  startChatServer();
  proxyManager = new ProxyManager(PROXY_ADDR, PROXY_PORT);
  torManager = new TorManager();

  // Before any request can leave.
  networkLock.protect(session.defaultSession);

  // A Tor that dies mid-session used to leave the proxy falling back to
  // direct, and browsing carried on with no warning. Now it closes again.
  torManager.onUnexpectedExit = (reason) => {
    networkLock.engage('Tor exited unexpectedly' + (reason ? ' — ' + reason : ''));
    applyProxyEverywhere(null).catch(() => {});
  };

  const proxyReady = await proxyManager.configure(session.defaultSession);
  if (proxyReady) {
    console.log('SOCKS5 proxy detected — connected');
  } else {
    console.log('Waiting for user to click Connect');
  }

  mainWindow = createMainWindow();
  tabManager = new TabManager(mainWindow, proxyManager, networkLock);

  setupIPC(tabManager, proxyManager);

  mainWindow.once('ready-to-show', async () => {
    mainWindow.show();
    await tabManager.createTab('hidra://newtab');

    // Start anonymising immediately instead of waiting for the user to press
    // Connect. The new tab page watches proxy:status and shows the bootstrap
    // climbing, so this is visible rather than silent.
    if (userPrefs.autoConnect !== false) {
      connectTor()
        .then((r) => console.log('[tor] auto-connect:', r.ok ? r.msg : 'failed — ' + r.msg))
        .catch((e) => console.error('[tor] auto-connect error:', e.message));
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
    icon: windowIcon(nativeImage),
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

function setupIPC(tabs, proxy, chromeContents = () => (mainWindow ? mainWindow.webContents : null)) {
  // Every handler names the pages that call it, and refuses everything else
  // before it does anything (see ipc-guard.js). The browser's own bar is
  // browser.html in the main window; the other pages are tabs.
  const fromPages = (event, pages, what) => requirePage(event, UI_ROOT_URL, pages, what);
  const fromChrome = (event, what) => {
    const contents = chromeContents();
    if (!contents || event.sender !== contents || senderPage(event, UI_ROOT_URL) !== 'browser.html') {
      throw new Error(`refused: ${what} is for the browser's own bar`);
    }
  };
  // Either the bar or one of the named pages.
  const fromChromeOr = (event, pages, what) => {
    const contents = chromeContents();
    if (contents && event.sender === contents && senderPage(event, UI_ROOT_URL) === 'browser.html') return;
    fromPages(event, pages, what);
  };

  // The vault. Which compartment a page may open is decided here, from the
  // URL of the frame that asked — never from anything the page sent. The
  // preload only offers the bridge; this is what refuses.
  const refused = () => new Error('refused: only HidraNet apps have a vault compartment');

  ipcMain.handle('vault:get', (event) => {
    const ns = vaultNamespaceOf(event);
    if (!ns) throw refused();
    return vault.get(ns);
  });

  ipcMain.handle('vault:set', async (event, value) => {
    const ns = vaultNamespaceOf(event);
    if (!ns) throw refused();
    await vault.set(ns, value);
    return true;
  });

  // Whether the keychain is protecting the data is not a secret, but it is
  // still only for our own pages: the apps, and the new tab page's panel.
  ipcMain.handle('vault:status', (event) => {
    // Narrowed from "any page under src/ui" to the one that shows it.
    const url = event.senderFrame ? event.senderFrame.url : '';
    if (!appNamespace(url) && senderPage(event, UI_ROOT_URL) !== 'newtab.html') throw refused();
    return vault.status();
  });

  ipcMain.handle('tab:create', async (event, url) => {
    fromChrome(event, 'tab:create');
    return await tabs.createTab(url || 'hidra://newtab');
  });

  ipcMain.handle('tab:close', (event, tabId) => {
    fromChrome(event, 'tab:close');
    tabs.closeTab(tabId);
  });

  ipcMain.handle('tab:navigate', (event, tabId, url) => {
    fromChrome(event, 'tab:navigate');
    tabs.navigate(tabId, url);
  });

  ipcMain.handle('tab:go-back', (event, tabId) => {
    fromChrome(event, 'tab:go-back');
    tabs.goBack(tabId);
  });

  ipcMain.handle('tab:go-forward', (event, tabId) => {
    fromChrome(event, 'tab:go-forward');
    tabs.goForward(tabId);
  });

  ipcMain.handle('tab:reload', (event, tabId) => {
    fromChrome(event, 'tab:reload');
    tabs.reload(tabId);
  });

  ipcMain.handle('tab:activate', (event, tabId) => {
    fromChrome(event, 'tab:activate');
    tabs.activateTab(tabId);
  });

  ipcMain.handle('tab:list', (event) => {
    fromChrome(event, 'tab:list');
    return tabs.listTabs();
  });

  ipcMain.handle('proxy:status', (event) => {
    fromChromeOr(event, ['newtab.html'], 'proxy:status');
    const base = proxy.getStatus();
    const tor = torManager.getStatus();
    const connected = tor.state === 'ready';

    return {
      ...base,
      connected,
      mode: connected ? 'tor' : (tor.state === 'starting' ? 'connecting' : 'disconnected'),
      tor,
      lock: networkLock.getStatus(),
    };
  });

  // SevenNine is the engine's .hidra site builder, not a browser-served app, so
  // it only runs when the user actually opens it.
  ipcMain.handle('sevennine:start', async (event) => {
    fromPages(event, ['newtab.html'], 'sevennine:start');
    const result = await proxy.startSevenNine();
    return result.ok
      ? { ok: true, url: `http://127.0.0.1:${SEVENNINE_PORT}/` }
      : { ok: false, msg: result.error };
  });

  ipcMain.handle('sevennine:stop', async (event) => {
    fromPages(event, ['newtab.html'], 'sevennine:stop');
    return proxy.stopSevenNine();
  });

  ipcMain.handle('tor:new-identity', async (event) => {
    fromChromeOr(event, ['newtab.html'], 'tor:new-identity');
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
      return { ok: false, msg: 'could not confirm the new exit IP' };
    }

    return {
      ok: true,
      exitIp: exit.ip,
      isTor: exit.isTor === true,
      // Tor can legitimately hand back the same exit; say so instead of
      // implying a change that did not happen.
      changed: exit.ip !== previous,
      msg: exit.ip === previous
        ? `Tor returned the same exit node (${exit.ip}) — try again in a few seconds`
        : `New exit IP: ${exit.ip}`,
    };
  });

  // Connecting means Tor, not the HidraNet engine. The engine's circuit runs
  // over relays that config.toml points at 127.0.0.1, so it never changes the
  // exit IP; Tor's volunteer network is what actually anonymises the traffic.
  ipcMain.handle('proxy:connect', (event) => {
    fromPages(event, ['newtab.html'], 'proxy:connect');
    return connectTor();
  });

  ipcMain.handle('proxy:disconnect', async (event) => {
    fromPages(event, ['newtab.html'], 'proxy:disconnect');
    await torManager.stop();
    networkLock.engage('disconnected by the user');
    await applyProxyEverywhere(null);
    await proxy.shutdown(null);
    return { ok: true, msg: 'disconnected' };
  });

  // The new tab page lives on file://, so it cannot probe the apps ports with
  // fetch — the responses are cross-origin and get blocked, which made every
  // app show as "Offline" even while running. Probe from the main process.
  ipcMain.handle('apps:status', async (event) => {
    fromPages(event, ['newtab.html'], 'apps:status');
    const [chat, sevennine] = await Promise.all([
      pingLocalPort(CHAT_PORT, '/'),
      pingLocalPort(SEVENNINE_PORT, '/'),
    ]);
    // appsServer.error explains a chat/mail/forum outage the ping alone cannot:
    // the port was taken, usually by a second copy of the browser.
    return { chat, sevennine, hidrareview: chat, error: chat ? null : appsServer.error };
  });

  ipcMain.handle('prefs:get', (event) => {
    fromPages(event, ['newtab.html'], 'prefs:get');
    return { ...userPrefs };
  });

  ipcMain.handle('prefs:save', (event, update) => {
    fromPages(event, ['newtab.html'], 'prefs:save');
    if (update && typeof update === 'object') {
      if (update.theme) userPrefs.theme = update.theme;
      if (update.searchLang !== undefined) userPrefs.searchLang = update.searchLang;
      if (update.autoConnect !== undefined) userPrefs.autoConnect = !!update.autoConnect;
      savePrefs();
    }
    return { ok: true };
  });

  ipcMain.handle('window:minimize', (event) => {
    fromChrome(event, 'window:minimize');
    if (mainWindow) mainWindow.minimize();
  });

  ipcMain.handle('window:maximize', (event) => {
    fromChrome(event, 'window:maximize');
    if (mainWindow) {
      if (mainWindow.isMaximized()) {
        mainWindow.unmaximize();
      } else {
        mainWindow.maximize();
      }
    }
  });

  ipcMain.handle('window:close', (event) => {
    fromChrome(event, 'window:close');
    if (mainWindow) mainWindow.close();
  });
}

// For test/ipc-senders.js, which loads this file with a stand-in for Electron
// and calls every handler with forged senders. Electron itself ignores it.
module.exports = { setupIPC };
