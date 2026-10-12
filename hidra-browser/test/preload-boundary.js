// Does the privileged `window.hidra` API reach only our own shipped pages, and
// do the apps get only their vault?
//
// The check in tab-preload.js used to be `url.startsWith('file://')`, which is
// every file on the disk: any .html the user downloaded and opened got
// proxy.disconnect() — which turns Tor off — along with tor.newIdentity(),
// prefs.save() and sevennine.start(). This is the regression test for that.
//
// The apps (mail, chat, forum, the publisher) are served on a loopback origin
// and hold an identity, so they get a bridge too — one thing, a compartment
// in the vault, and none of the above. A website gets nothing, and so does a
// page on the apps' origin that is not one of them.
//
//   cd hidra-browser && xvfb-run -a npx electron test/preload-boundary.js
//
// Exits non-zero if any case comes out wrong.

const { app, BrowserWindow } = require('electron');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');

const ROOT = path.join(__dirname, '..');
const UI_ROOT_URL = pathToFileURL(path.join(ROOT, 'src', 'ui') + path.sep).href;

// What a page can see of window.hidra: its top-level keys, and the vault's.
const SHAPE = `JSON.stringify(window.hidra
  ? { keys: Object.keys(window.hidra).sort(),
      vault: window.hidra.vault ? Object.keys(window.hidra.vault).sort() : null }
  : null)`;

async function shapeAt(url, appsOrigin) {
  const win = new BrowserWindow({
    show: false,
    webPreferences: {
      preload: path.join(ROOT, 'src', 'renderer', 'tab-preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      additionalArguments: [`--hidra-ui-root=${UI_ROOT_URL}`, `--hidra-apps-origin=${appsOrigin}`],
    },
  });
  try {
    await win.loadURL(url);
    return JSON.parse(await win.webContents.executeJavaScript(SHAPE));
  } catch {
    // A page that will not even load cannot hold the API.
    return null;
  } finally {
    if (!win.isDestroyed()) win.destroy();
  }
}

// A stand-in for the apps server, and a second server standing in for any
// other site: same page, different origin.
function serve() {
  return new Promise((resolve) => {
    const s = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<!doctype html><p>page');
    });
    s.listen(0, '127.0.0.1', () => resolve(s));
  });
}

// Electron quits when the last window closes, which would end the run midway.
app.on('window-all-closed', () => {});

app.whenReady().then(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-preload-'));
  const downloaded = path.join(tmp, 'downloaded.html');
  fs.writeFileSync(downloaded, '<!doctype html><p>a file the user downloaded');

  const apps = await serve();
  const other = await serve();
  const APPS = `http://127.0.0.1:${apps.address().port}`;
  const OTHER = `http://127.0.0.1:${other.address().port}`;

  const FULL = ['apps', 'prefs', 'proxy', 'sevennine', 'tor', 'vault'];
  const full = (s) => s && s.keys.join() === FULL.join() && s.vault.join() === 'status';
  const vaultOnly = (s) => s && s.keys.join() === 'vault' && s.vault.join() === 'get,set,status';
  const none = (s) => s === null;

  const cases = [
    ['our own newtab.html', pathToFileURL(path.join(ROOT, 'src', 'ui', 'newtab.html')).href, full, 'the full API'],
    ['a downloaded file', pathToFileURL(downloaded).href, none, 'nothing'],
    ['..' + ' out of the ui directory', `${UI_ROOT_URL}../../${path.basename(downloaded)}`, none, 'nothing'],
    ['a remote page', 'data:text/html,<p>x', none, 'nothing'],
    ['HidraMail on the apps origin', `${APPS}/mail`, vaultOnly, 'the vault only'],
    ['HidraChat on the apps origin', `${APPS}/`, vaultOnly, 'the vault only'],
    ['the forum on the apps origin', `${APPS}/forum?x=1`, vaultOnly, 'the vault only'],
    ['the publisher on the apps origin', `${APPS}/sites`, vaultOnly, 'the vault only'],
    ['search on the apps origin', `${APPS}/search?q=x`, none, 'nothing'],
    ['the site viewer on the apps origin', `${APPS}/site?addr=x`, none, 'nothing'],
    ['a website at /mail', `${OTHER}/mail`, none, 'nothing'],
  ];

  let failures = 0;
  for (const [label, url, want, wantLabel] of cases) {
    const got = await shapeAt(url, APPS);
    const ok = want(got);
    if (!ok) failures++;
    console.log(`${ok ? 'ok  ' : 'FAIL'}  ${label}: gets ${wantLabel}` + (ok ? '' : `\n        got ${JSON.stringify(got)}`));
  }

  apps.close();
  other.close();
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(failures ? `\n${failures} case(s) wrong` : '\nall cases correct');
  app.exit(failures ? 1 : 0);
});
