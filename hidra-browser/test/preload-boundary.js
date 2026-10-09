// Does the privileged `window.hidra` API reach only our own shipped pages?
//
// The check in tab-preload.js used to be `url.startsWith('file://')`, which is
// every file on the disk: any .html the user downloaded and opened got
// proxy.disconnect() — which turns Tor off — along with tor.newIdentity(),
// prefs.save() and sevennine.start(). This is the regression test for that.
//
//   cd hidra-browser && xvfb-run -a npx electron test/preload-boundary.js
//
// Exits non-zero if any case comes out wrong.

const { app, BrowserWindow } = require('electron');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');

const ROOT = path.join(__dirname, '..');
const UI_ROOT_URL = pathToFileURL(path.join(ROOT, 'src', 'ui') + path.sep).href;

async function hasApi(url) {
  const win = new BrowserWindow({
    show: false,
    webPreferences: {
      preload: path.join(ROOT, 'src', 'renderer', 'tab-preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      additionalArguments: [`--hidra-ui-root=${UI_ROOT_URL}`],
    },
  });
  try {
    await win.loadURL(url);
    return await win.webContents.executeJavaScript('typeof window.hidra !== "undefined"');
  } catch {
    // A page that will not even load cannot hold the API.
    return false;
  } finally {
    if (!win.isDestroyed()) win.destroy();
  }
}

// Electron quits when the last window closes, which would end the run midway.
app.on('window-all-closed', () => {});

app.whenReady().then(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-preload-'));
  const downloaded = path.join(tmp, 'downloaded.html');
  fs.writeFileSync(downloaded, '<!doctype html><p>a file the user downloaded');

  const cases = [
    ['our own newtab.html', pathToFileURL(path.join(ROOT, 'src', 'ui', 'newtab.html')).href, true],
    ['a downloaded file', pathToFileURL(downloaded).href, false],
    ['..' + ' out of the ui directory', `${UI_ROOT_URL}../../${path.basename(downloaded)}`, false],
    ['a remote page', 'data:text/html,<p>x', false],
  ];

  let failures = 0;
  for (const [label, url, expected] of cases) {
    const actual = await hasApi(url);
    const ok = actual === expected;
    if (!ok) failures++;
    console.log(
      `${ok ? 'ok  ' : 'FAIL'}  ${label}: ${actual ? 'has' : 'does not have'} the API` +
        (ok ? '' : ` (expected ${expected ? 'to have' : 'not to have'} it)`)
    );
  }

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(failures ? `\n${failures} case(s) wrong` : '\nall cases correct');
  app.exit(failures ? 1 : 0);
});
