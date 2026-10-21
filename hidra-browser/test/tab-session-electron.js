// The tab surface still has to hold on whatever Electron the browser ships.
//
// Every other Electron test here uses a plain BrowserWindow, so none of them
// touch what a real tab is built on: a BrowserView carrying a hardened,
// partitioned session. That is exactly the surface an Electron/Chromium bump
// is most likely to break quietly — BrowserView could be removed, a session
// API could change signature, or a new Chromium could start sending a client
// hint the strip list does not name. This test exercises that path on a LIVE
// request and fails loudly if any of it regresses.
//
// It mirrors the controls tab-manager.js applies to each tab's session
// (setUserAgent + Sec-CH-UA / X-Client-Data stripping + cross-site Referer
// drop + the permission allowlist) and proves, against a local echo server,
// that the client hints really leave and the spoofed User-Agent is the one
// that goes out. Keep it in lockstep with tab-manager.js: if the strip list or
// the spoofed UA major changes there, change it here.
//
//   cd hidra-browser && xvfb-run -a npx electron test/tab-session-electron.js
//
// Exits non-zero if any case comes out wrong.

const { app, BrowserWindow, BrowserView, session, protocol } = require('electron');
const http = require('http');

const failures = [];
const check = (name, ok, detail) => {
  if (ok) {
    console.log('ok    ' + name);
  } else {
    console.log('FAIL  ' + name + (detail ? '\n      ' + detail : ''));
    failures.push(name);
  }
};

// The current engine is Chromium 152 (Electron 44); the spoofed UA must claim
// the same major, so keep this equal to the Chrome major in
// src/fingerprint/engine.js.
const SPOOF_UA =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36';

// The same client hints tab-manager.js drops.
const DROP = [
  'X-Client-Data',
  'Sec-CH-UA', 'Sec-CH-UA-Platform', 'Sec-CH-UA-Mobile',
  'Sec-CH-UA-Full-Version', 'Sec-CH-UA-Full-Version-List',
  'Sec-CH-UA-Arch', 'Sec-CH-UA-Bitness', 'Sec-CH-UA-Model',
  'Sec-CH-UA-Platform-Version', 'Sec-CH-UA-WoW64',
];

// hidra:// registers as a privileged scheme before ready, as main.js does;
// a bump that changed this call would break the app's own pages.
try {
  protocol.registerSchemesAsPrivileged([
    { scheme: 'hidra', privileges: { standard: true, secure: true, supportFetchAPI: true } },
  ]);
  check('protocol.registerSchemesAsPrivileged(hidra://) does not throw', true);
} catch (e) {
  check('protocol.registerSchemesAsPrivileged(hidra://) does not throw', false, String(e));
}

// A hard stop so a hung load fails the job instead of hanging CI.
const guard = setTimeout(() => {
  console.log('FAIL  timed out');
  process.exit(1);
}, 45000);

async function main() {
  let seen = null;
  const server = http.createServer((req, res) => {
    if (req.url === '/page') seen = req.headers;
    res.setHeader('Content-Type', 'text/html');
    res.end('<!doctype html><meta charset="utf-8"><title>t</title>ok');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const url = `http://127.0.0.1:${port}/page`;

  check('BrowserView is a constructor', typeof BrowserView === 'function');

  const win = new BrowserWindow({ show: false, width: 800, height: 600 });

  // The per-tab session, hardened the way tab-manager.js hardens it.
  const ses = session.fromPartition('persist:tab-session-test', { cache: false });
  ses.setUserAgent(SPOOF_UA, 'en-US,en');
  ses.webRequest.onBeforeSendHeaders((details, cb) => {
    const headers = { ...details.requestHeaders };
    const drop = (name) => {
      const t = name.toLowerCase();
      for (const k of Object.keys(headers)) if (k.toLowerCase() === t) delete headers[k];
    };
    DROP.forEach(drop);
    const refKey = Object.keys(headers).find((k) => k.toLowerCase() === 'referer');
    if (refKey) {
      let same = false;
      try {
        same = new URL(headers[refKey]).origin === new URL(details.url).origin;
      } catch (e) {
        same = false;
      }
      if (!same) delete headers[refKey];
    }
    cb({ requestHeaders: headers });
  });
  const ALLOWED = new Set(['fullscreen', 'clipboard-sanitized-write']);
  let handlersOk = true;
  try {
    ses.setPermissionRequestHandler((_wc, p, cb) => cb(ALLOWED.has(p)));
    ses.setPermissionCheckHandler((_wc, p) => ALLOWED.has(p));
    ses.setDevicePermissionHandler(() => false);
    await ses.setProxy({ proxyRules: 'direct://' });
  } catch (e) {
    handlersOk = false;
    check('session permission/proxy handlers wire up', false, String(e));
  }
  if (handlersOk) check('session permission/proxy handlers wire up', true);

  // A real tab: a BrowserView on the hardened session, sized like tab-manager.
  let view;
  try {
    view = new BrowserView({
      webPreferences: { session: ses, contextIsolation: true, nodeIntegration: false, sandbox: true },
    });
    win.addBrowserView(view);
    view.setBounds({ x: 0, y: 0, width: 800, height: 600 });
    view.setAutoResize({ width: true, height: true });
    check('BrowserView attaches to the window and sizes', true);
  } catch (e) {
    check('BrowserView attaches to the window and sizes', false, String(e));
    clearTimeout(guard);
    process.exit(1);
  }

  // Load through the hardened session with a cross-site referrer set.
  await view.webContents.loadURL(url, { httpReferrer: 'https://tracker.example/other' });

  check('the view fetched the page (server saw the request)', seen !== null);
  if (seen) {
    const lower = Object.fromEntries(Object.entries(seen).map(([k, v]) => [k.toLowerCase(), v]));
    check('Sec-CH-UA stripped on a live request', !('sec-ch-ua' in lower), 'headers: ' + Object.keys(lower).join(','));
    check('Sec-CH-UA-Platform stripped', !('sec-ch-ua-platform' in lower));
    check('X-Client-Data stripped', !('x-client-data' in lower));
    check('the spoofed User-Agent is what goes out', lower['user-agent'] === SPOOF_UA, 'got: ' + lower['user-agent']);
    check('cross-site Referer dropped', !('referer' in lower), 'got: ' + lower['referer']);
  }

  win.removeBrowserView(view);
  server.close();
  clearTimeout(guard);
  app.quit();
  process.exit(failures.length ? 1 : 0);
}

app.whenReady().then(() =>
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  })
);
