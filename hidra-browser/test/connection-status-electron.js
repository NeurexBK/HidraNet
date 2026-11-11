// The toolbar and the new tab page show the connection state the main
// process works out (connectionMode in network-lock.js), and nothing else.
//
// A page that reads only "connected", or keeps its own idea of a mode, says
// "Tor: off" for the whole bootstrap. This loads the real toolbar with the
// real preload, and the real new tab page with the tab preload, answers
// proxy:status with each state the main process can send, and reads what
// each page shows. The new tab page's MQTT library is swapped for a stand-in,
// so nothing here reaches a broker.
//
//   cd hidra-browser && xvfb-run -a ./node_modules/.bin/electron --no-sandbox test/connection-status-electron.js
//
// Exits non-zero if any case comes out wrong.

const { app, BrowserWindow, ipcMain } = require('electron');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');
const { connectionMode } = require('../src/main/network-lock');

const ROOT = path.join(__dirname, '..');
const STUB = `window.mqtt = { connect: function () {
  var c = { connected: false, on: function () { return c; }, subscribe: function () {}, unsubscribe: function () {},
    publish: function () {}, end: function () {} };
  return c; } };`;

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-status-'));
fs.cpSync(path.join(ROOT, 'src', 'ui'), dir, { recursive: true });
fs.writeFileSync(path.join(dir, 'vendor', 'mqtt.min.js'), STUB);
const UI_ROOT_URL = pathToFileURL(dir + path.sep).href;

const tor = (state, pct, extra) => Object.assign({ state, bootstrapPercent: pct, exitIp: null, lastError: null, readyAt: null }, extra);
// Built the way main.js builds its proxy:status answer.
const answer = (t, engaged, connecting) => {
  const mode = connectionMode(t.state, engaged, connecting);
  return { proxy: '127.0.0.1:9052', connected: mode === 'tor', mode, tor: t, lock: { engaged } };
};
const STATES = {
  connecting: answer(tor('starting', 40), true, true),
  anonymous: answer(tor('ready', 100, { readyAt: Date.now() }), false, false),
  blocked: answer(tor('ready', 100), true, false),
  off: answer(tor('stopped', 0), true, false),
};
let status = STATES.off;
ipcMain.handle('proxy:status', () => status);
const stub = (channel, value) => ipcMain.handle(channel, () => value);
stub('apps:status', { chat: true, sevennine: false, hidrareview: true, error: null,
  about: { version: '1.1.0', build: 'test', date: null }, update: null });
stub('prefs:get', { theme: 'teal', searchLang: 'all', autoConnect: false });
stub('vault:status', { available: true });
stub('vpn:status', { state: 'not-installed', installable: true });

const failures = [];
const expect = (name, ok, detail) => {
  console.log((ok ? 'ok    ' : 'FAIL  ') + name + (ok || !detail ? '' : '\n      ' + detail));
  if (!ok) failures.push(name);
};

function windowWith(preload, extraArgs) {
  return new BrowserWindow({
    show: false,
    webPreferences: { preload, contextIsolation: true, nodeIntegration: false, sandbox: true, additionalArguments: extraArgs || [] },
  });
}

app.on('window-all-closed', () => {});
setTimeout(() => { console.log('FAIL  the pages did not answer within 60 seconds'); app.exit(1); }, 60000).unref();

app.whenReady().then(async () => {
  const bar = windowWith(path.join(ROOT, 'src', 'renderer', 'preload.js'));
  await bar.loadFile(path.join(dir, 'browser.html'));
  const toolbar = async (s) => {
    status = s;
    return bar.webContents.executeJavaScript(`refreshProxyStatus().then(() => ({
      label: document.getElementById('proxy-label').textContent,
      panel: document.getElementById('panel-status').textContent }))`);
  };

  const page = windowWith(path.join(ROOT, 'src', 'renderer', 'tab-preload.js'),
    [`--hidra-ui-root=${UI_ROOT_URL}`, '--hidra-app-origins=']);
  await page.loadURL(pathToFileURL(path.join(dir, 'newtab.html')).href);
  const newtab = async (s) => {
    status = s;
    return page.webContents.executeJavaScript(`poll().then(() => document.getElementById('status-text').textContent)`);
  };

  let t = await toolbar(STATES.connecting);
  expect('toolbar: Tor bootstrapping reads connecting, not off', t.label === 'Tor: connecting' && /Connecting to Tor — 40%/.test(t.panel), JSON.stringify(t));
  t = await toolbar(STATES.anonymous);
  expect('toolbar: Tor up and the lock open reads anonymous', t.label === 'Tor: Anonymous', JSON.stringify(t));
  t = await toolbar(STATES.blocked);
  expect('toolbar: Tor up behind a shut lock is not anonymous', t.label === 'Tor: off' && t.panel === 'Disconnected', JSON.stringify(t));
  t = await toolbar(STATES.off);
  expect('toolbar: Tor stopped reads off', t.label === 'Tor: off', JSON.stringify(t));

  let n = await newtab(STATES.connecting);
  expect('new tab: Tor bootstrapping reads connecting', /^Connecting to Tor — 40%/.test(n), n);
  n = await newtab(STATES.anonymous);
  expect('new tab: Tor up and the lock open reads anonymous', /traffic is anonymous/.test(n), n);
  n = await newtab(STATES.blocked);
  expect('new tab: Tor up behind a shut lock is not anonymous', /^Disconnected/.test(n), n);

  bar.destroy();
  page.destroy();
  fs.rmSync(dir, { recursive: true, force: true });
  console.log(failures.length ? `\n${failures.length} case(s) wrong` : '\nall cases correct');
  app.exit(failures.length ? 1 : 0);
}).catch((e) => { console.error(e); app.exit(2); });
