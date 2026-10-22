// A tab's fingerprint holds everywhere a page can look, from its first line.
//
// The fingerprint used to be injected on dom-ready into the main frame only.
// A script in the page's <head>, navigator.userAgentData, a fresh iframe and a
// worker all read the real values (see src/main/fingerprint-guard.js). This
// builds a tab the way tab-manager.js does — per-tab session, the tab
// preload, guardFingerprint before the first load — and reads every one of
// those places, plus a frame on another site, against the profile.
//
// The profile is a Windows one whatever this machine is, with values unlike
// the machine's, so a real value showing through cannot pass for the profile.
//
//   cd hidra-browser && xvfb-run -a npx electron test/fingerprint-electron.js

const { app, BrowserWindow, BrowserView, session } = require('electron');
const http = require('http');
const os = require('os');
const path = require('path');
const { FingerprintEngine } = require('../src/fingerprint/engine');
const { guardFingerprint } = require('../src/main/fingerprint-guard');

const failures = [];
const check = (name, ok, detail) => {
  if (ok) console.log('ok    ' + name);
  else {
    console.log('FAIL  ' + name + (detail ? '\n      ' + detail : ''));
    failures.push(name);
  }
};

const guard = setTimeout(() => { console.log('FAIL  timed out'); process.exit(1); }, 60000);

const FRAME = `<!doctype html><script>parent.postMessage({
  platform: navigator.platform, cores: navigator.hardwareConcurrency,
  tz: Intl.DateTimeFormat().resolvedOptions().timeZone, screen: screen.width + 'x' + screen.height,
  uad: navigator.userAgentData && navigator.userAgentData.platform }, '*')</script>`;

const PAGE = `<!doctype html><meta charset="utf-8"><script>
window.__early = { platform: navigator.platform, cores: navigator.hardwareConcurrency,
  uad: navigator.userAgentData && navigator.userAgentData.platform,
  tz: Intl.DateTimeFormat().resolvedOptions().timeZone, screen: screen.width + 'x' + screen.height };
</script><body><iframe id=f src="about:blank"></iframe><script>
window.__worker = new Promise((res) => {
  const src = 'postMessage({platform: navigator.platform, cores: navigator.hardwareConcurrency, tz: Intl.DateTimeFormat().resolvedOptions().timeZone, uad: navigator.userAgentData && navigator.userAgentData.platform})';
  const w = new Worker(URL.createObjectURL(new Blob([src], { type: 'text/javascript' })));
  w.onmessage = (e) => res(e.data);
  setTimeout(() => res(null), 4000);
});
window.__other = new Promise((res) => {
  addEventListener('message', (e) => res(e.data));
  const f = document.createElement('iframe');
  f.src = 'http://localhost:' + location.port + '/frame';
  document.body.appendChild(f);
  setTimeout(() => res(null), 4000);
});
</script>`;

app.whenReady().then(async () => {
  const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.end(req.url === '/frame' ? FRAME : PAGE);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}/`;

  // A Windows profile, with a core count this machine does not have.
  const real = os.cpus().length;
  const fp = Object.assign(FingerprintEngine.generate(), {
    platform: 'Win32',
    uaPlatform: 'Windows',
    platformVersion: '10.0.0',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36',
    hardwareConcurrency: [4, 8, 12, 16].find((n) => n !== real),
    timezone: 'Asia/Tokyo',
    screen: { width: 1536, height: 864, colorDepth: 24, pixelRatio: 1 },
  });
  const want = { platform: 'Win32', cores: fp.hardwareConcurrency, tz: 'Asia/Tokyo', screen: '1536x864', uad: 'Windows' };

  const ses = session.fromPartition('fingerprint-test', { cache: false });
  ses.setUserAgent(fp.userAgent, fp.languages.join(','));
  const win = new BrowserWindow({ show: false, width: 1000, height: 700 });
  const view = new BrowserView({
    webPreferences: {
      session: ses, contextIsolation: true, nodeIntegration: false, sandbox: true,
      preload: path.join(__dirname, '..', 'src', 'renderer', 'tab-preload.js'),
    },
  });
  win.setBrowserView(view);
  view.setBounds({ x: 0, y: 0, width: 1000, height: 700 });

  check('the DevTools protocol attaches to a tab', await guardFingerprint(view.webContents, fp));
  await view.webContents.loadURL(url);
  await new Promise((r) => setTimeout(r, 500));

  const seen = await view.webContents.executeJavaScript(`(async () => ({
    early: window.__early,
    late: { platform: navigator.platform, cores: navigator.hardwareConcurrency,
            uad: navigator.userAgentData.platform, tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
            screen: screen.width + 'x' + screen.height,
            high: await navigator.userAgentData.getHighEntropyValues(['platform', 'platformVersion']) },
    iframe: (() => { const w = document.getElementById('f').contentWindow; return {
      platform: w.navigator.platform, cores: w.navigator.hardwareConcurrency,
      tz: w.Intl.DateTimeFormat().resolvedOptions().timeZone, screen: w.screen.width + 'x' + w.screen.height,
      uad: w.navigator.userAgentData.platform }; })(),
    worker: await window.__worker,
    other: await window.__other,
    sharedWorker: typeof window.SharedWorker,
    serviceWorker: await navigator.serviceWorker.register('/sw.js').then(() => 'registered', (e) => e.name),
  }))()`);

  const same = (where, got, keys) => {
    const off = keys.filter((k) => !got || got[k] !== want[k]);
    check(where + ' sees the profile (' + keys.join(', ') + ')', off.length === 0,
      off.map((k) => k + ': ' + JSON.stringify(got && got[k]) + ' instead of ' + JSON.stringify(want[k])).join('; '));
  };
  const all = ['platform', 'cores', 'tz', 'screen', 'uad'];
  same('a script in the <head>, before anything else', seen.early, all);
  same('the page once loaded', seen.late, all);
  check('userAgentData high-entropy values match', seen.late.high.platform === 'Windows' && seen.late.high.platformVersion === '10.0.0',
    JSON.stringify(seen.late.high));
  same('a fresh iframe', seen.iframe, all);
  same('a frame on another site', seen.other, all);
  same('a dedicated worker', seen.worker, ['platform', 'cores', 'tz', 'uad']);
  check('shared workers are switched off', seen.sharedWorker === 'undefined', seen.sharedWorker);
  check('service workers cannot be registered', seen.serviceWorker === 'SecurityError', seen.serviceWorker);
  check('the blank page the tab starts on is not in its history',
    !view.webContents.navigationHistory.canGoBack(), 'Back would show a blank page');

  // The profile a tab really gets is always this machine's own system.
  const own = FingerprintEngine.generate();
  const expected = { win32: 'Win32', darwin: 'MacIntel' }[process.platform] || 'Linux x86_64';
  check('a generated profile is of the system it runs on (' + expected + ')', own.platform === expected, own.platform);

  clearTimeout(guard);
  server.close();
  console.log(failures.length ? `\n${failures.length} failed` : '\nall cases correct');
  app.exit(failures.length ? 1 : 0);
}).catch((e) => { console.log('FAIL  ' + (e && e.stack)); app.exit(1); });
