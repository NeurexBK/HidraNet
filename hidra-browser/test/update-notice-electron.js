// The new tab page shows the update notice the main process hands it, and
// nothing else.
//
// main.js runs src/main/update-check.js once Tor is carrying the traffic and
// puts its notice in the apps:status reply; newtab.html shows it above the
// search box. This loads the real page with the real tab preload, answers its
// IPC with stand-ins (the notice coming from a real UpdateCheck fed a record
// signed by a test key), and reads what the page shows: below the minimum
// safe version a security warning, a newer build an update notice, an
// expired record or no signature nothing at all, and nothing for a notice
// that is not made of versions.
//
//   cd hidra-browser && xvfb-run -a ./node_modules/.bin/electron --no-sandbox test/update-notice-electron.js
//
// Exits non-zero if any case comes out wrong.

const { app, BrowserWindow, ipcMain } = require('electron');
const crypto = require('crypto');
const path = require('path');
const { pathToFileURL } = require('url');
const rv = require('../src/main/release-verify');
const { UpdateCheck, SUMS_URL } = require('../src/main/update-check');

const ROOT = path.join(__dirname, '..');
const UI_ROOT_URL = pathToFileURL(path.join(ROOT, 'src', 'ui') + path.sep).href;
const NEWTAB = pathToFileURL(path.join(ROOT, 'src', 'ui', 'newtab.html')).href;

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const pub = publicKey.export({ format: 'der', type: 'spki' }).slice(-32).toString('base64');
function signedTable({ latest, minimum, validUntil }) {
  const table = Buffer.from([
    'HidraNet Browser ' + latest + ' — SHA-256 checksums', '',
    '  latest-version:        ' + latest,
    '  minimum-safe-version:  ' + minimum,
    '  valid-until:           ' + validUntil, '',
    'b'.repeat(64) + '  HidraNet-Browser-' + latest + '-Linux-x64.zip', '',
  ].join('\n'));
  return { table, sig: crypto.sign(null, rv.browserSumsMessage(table), privateKey).toString('base64') };
}
// The notice a real check would hand the page, for this record and version.
async function noticeFor(current, record) {
  const files = {};
  if (record) {
    const { table, sig } = signedTable(record);
    files[SUMS_URL] = table;
    files[SUMS_URL + '.sig'] = sig;
  }
  const fetchBytes = async (url) => {
    if (!(url in files)) throw Object.assign(new Error(url + ': 404'), { status: 404 });
    return Buffer.from(files[url]);
  };
  const check = new UpdateCheck({ fetchBytes, currentVersion: current, publicKey: pub });
  await check.run();
  return check.notice();
}

let update = null;
const stub = (channel, value) => ipcMain.handle(channel, () => (typeof value === 'function' ? value() : value));
stub('apps:status', () => ({ chat: true, sevennine: false, hidrareview: true, error: null,
  about: { version: '1.1.0', build: 'test', date: null }, update }));
stub('proxy:status', { connected: true, mode: 'tor', lock: { engaged: false } });
stub('prefs:get', { theme: 'teal', searchLang: 'all', autoConnect: true });
stub('vault:status', { available: true });
stub('vpn:status', { state: 'not-installed', installable: true });

const failures = [];
const expect = (name, ok, detail) => {
  console.log((ok ? 'ok    ' : 'FAIL  ') + name + (ok || !detail ? '' : '\n      ' + detail));
  if (!ok) failures.push(name);
};

const SHOWN = `JSON.stringify((() => {
  const box = document.getElementById('update-notice');
  return { hidden: box.hidden, unsafe: box.classList.contains('unsafe'), text: box.textContent.replace(/\\s+/g, ' ').trim(),
           html: box.innerHTML.indexOf('<script') !== -1 || box.querySelector('img,a,script') !== null };
})())`;

async function pageWith(notice) {
  update = notice;
  const win = new BrowserWindow({
    show: false,
    webPreferences: {
      preload: path.join(ROOT, 'src', 'renderer', 'tab-preload.js'),
      contextIsolation: true, nodeIntegration: false, sandbox: true,
      additionalArguments: [`--hidra-ui-root=${UI_ROOT_URL}`, '--hidra-app-origins='],
    },
  });
  try {
    await win.loadURL(NEWTAB);
    // detectApps() shows the notice, then writes the version into the
    // footer: once the footer has it, the notice is decided.
    for (let i = 0; i < 100; i++) {
      const footer = await win.webContents.executeJavaScript("document.getElementById('app-version').textContent");
      if (/1\.1\.0/.test(footer)) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    const shown = JSON.parse(await win.webContents.executeJavaScript(SHOWN));
    return shown;
  } finally {
    if (!win.isDestroyed()) win.destroy();
  }
}

app.on('window-all-closed', () => {});
// A page that never answers is a failure, not a hang.
setTimeout(() => { console.log('FAIL  the page did not answer within 60 seconds'); app.exit(1); }, 60000).unref();

app.whenReady().then(async () => {
  const unsafe = await pageWith(await noticeFor('1.1.0', { latest: '1.3.0', minimum: '1.2.0', validUntil: '2099-01-01' }));
  expect('below the minimum safe version: a security warning, with the versions', !unsafe.hidden && unsafe.unsafe &&
         /known security problems/.test(unsafe.text) && /1\.1\.0/.test(unsafe.text) && /1\.2\.0/.test(unsafe.text) &&
         /Download 1\.3\.0 from hidranet\.org/.test(unsafe.text), JSON.stringify(unsafe));

  const newer = await pageWith(await noticeFor('1.1.0', { latest: '1.2.0', minimum: '1.0.0', validUntil: '2099-01-01' }));
  expect('a newer build: an update notice, not a warning', !newer.hidden && !newer.unsafe &&
         /HidraNet Browser 1\.2\.0 is available/.test(newer.text) && /This is 1\.1\.0/.test(newer.text), JSON.stringify(newer));

  const current = await pageWith(await noticeFor('1.2.0', { latest: '1.2.0', minimum: '1.0.0', validUntil: '2099-01-01' }));
  expect('the latest build: nothing shown', current.hidden, JSON.stringify(current));

  const expired = await pageWith(await noticeFor('1.1.0', { latest: '1.3.0', minimum: '1.2.0', validUntil: '2020-01-01' }));
  expect('an expired record, even one that says unsafe: nothing shown', expired.hidden, JSON.stringify(expired));

  const unsigned = await pageWith(await noticeFor('1.1.0', null));
  expect('no signature yet: nothing shown, no error', unsigned.hidden && unsigned.text === '', JSON.stringify(unsigned));

  const odd = await pageWith({ current: '1.1.0', latest: '<img src=x onerror=alert(1)>', minimum: '1.0.0', unsafe: false });
  expect('a notice that is not made of versions: nothing shown', odd.hidden && !odd.html, JSON.stringify(odd));

  console.log(failures.length ? `\n${failures.length} case(s) wrong` : '\nall cases correct');
  app.exit(failures.length ? 1 : 0);
}).catch((e) => {
  console.log('FAIL  ' + ((e && e.message) || e));
  app.exit(1);
});
