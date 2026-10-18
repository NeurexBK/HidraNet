// Every handler in main.js refuses a caller it was not written for, and
// still answers the pages that use it.
//
// This loads the real main.js with a stand-in for Electron (nothing starts:
// app.whenReady never resolves), lets the real setupIPC register its
// handlers, and calls them with forged senders: a website, a subframe, a
// file elsewhere on the disk, and each of our own pages that has no business
// with that handler. A refusal must come before the handler does anything,
// so every forged call here is also checked to have touched nothing.
//
//   node hidra-browser/test/ipc-senders.js

'use strict';

const Module = require('module');
const path = require('path');
const { pathToFileURL } = require('url');

const ROOT = path.join(__dirname, '..');
const UI = pathToFileURL(path.join(ROOT, 'src', 'ui') + path.sep).href;

// ── A stand-in for Electron ──────────────────────────────────────────────
// Anything main.js reaches for at load time answers and does nothing; the
// handlers are kept for the test.
const handlers = new Map();
const inert = new Proxy(function inert() {}, {
  get: (_t, k) => (k === 'then' ? undefined : k === Symbol.toPrimitive ? () => '' : inert),
  apply: () => inert,
  construct: () => inert,
});
const electron = new Proxy({
  ipcMain: { handle: (ch, fn) => handlers.set(ch, fn), on() {}, removeHandler() {} },
  app: new Proxy({ whenReady: () => new Promise(() => {}), getPath: () => '/nonexistent' }, {
    get: (t, k) => (k in t ? t[k] : inert),
  }),
}, { get: (t, k) => (k in t ? t[k] : inert) });

// What a handler that got past its check would reach. Every call is noted,
// so a forged call that slipped through shows up even if it returned.
const touched = [];
const spy = (name) => new Proxy(function () {}, {
  get: (_t, k) => (k === 'then' ? undefined : (...a) => { touched.push(`${name}.${String(k)}`); return undefined; }),
});
const load = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'electron') return electron;
  return load.call(this, request, parent, isMain);
};

const { setupIPC } = require('../src/main/main.js');
// The browser's own bar: browser.html in the main window's contents.
const chrome = { mainFrame: { url: null } };
setupIPC(spy('tabs'), spy('proxy'), () => chrome);

// ── Senders ──────────────────────────────────────────────────────────────
function from(url, { subframe = false, sender } = {}) {
  const mainFrame = { url };
  const frame = subframe ? { url } : mainFrame;
  return { sender: sender || { mainFrame }, senderFrame: frame };
}
const page = (name, opts) => from(UI + name, opts);
chrome.mainFrame.url = UI + 'browser.html';
const BAR = { sender: chrome, senderFrame: chrome.mainFrame };
const app = (name) => `http://${name}.localhost:8090/`;

const OUTSIDERS = {
  'a website': from('https://example.com/newtab.html'),
  'a website on loopback': from('http://127.0.0.1:9/'),
  'a file elsewhere on the disk': from('file:///tmp/newtab.html'),
  'a file whose name only starts like ours': from(UI + 'newtab.html.evil.html'),
  'a page in a folder under ours': from(UI + 'vendor/newtab.html'),
  'a hidra:// address': from('hidra://newtab'),
  'a data: URL': from('data:text/html,<p>hi'),
  'no frame at all': { sender: { mainFrame: null }, senderFrame: null },
};
// Our own pages, each as the main frame of a tab.
const OURS = ['newtab.html', 'hidrachat.html', 'hidramail.html', 'forum.html',
  'hidrareview.html', 'hidrasearch.html', 'donate.html', 'siteload.html', 'sitepub.html', 'browser.html'];
// The apps, served on their loopback origin.
const APPS = { 'HidraMail on its origin': from(app('mail')), 'HidraChat on its origin': from(app('chat')) };

// Who calls what, from preload.js, tab-preload.js and the pages under src/ui.
// "bar" is browser.html in the main window. Nothing else may ask.
const BAR_ONLY = ['bar'];
const WHO = {
  'tab:create': BAR_ONLY, 'tab:close': BAR_ONLY, 'tab:navigate': BAR_ONLY, 'tab:go-back': BAR_ONLY,
  'tab:go-forward': BAR_ONLY, 'tab:reload': BAR_ONLY, 'tab:activate': BAR_ONLY, 'tab:list': BAR_ONLY,
  'window:minimize': BAR_ONLY, 'window:maximize': BAR_ONLY, 'window:close': BAR_ONLY,
  'proxy:status': ['bar', 'newtab.html'],
  'tor:new-identity': ['bar', 'newtab.html'],
  'proxy:connect': ['newtab.html'], 'proxy:disconnect': ['newtab.html'],
  'prefs:get': ['newtab.html'], 'prefs:save': ['newtab.html'],
  'apps:status': ['newtab.html'],
  'sevennine:start': ['newtab.html'], 'sevennine:stop': ['newtab.html'],
  'vault:get': ['apps'], 'vault:set': ['apps'], 'vault:status': ['apps', 'newtab.html'],
};

// Everyone who is not on a handler's list.
function strangersTo(allowed) {
  const out = { ...OUTSIDERS };
  for (const name of OURS) {
    if (!allowed.includes(name)) out[`our ${name}`] = page(name);
    out[`our ${name} in a subframe`] = page(name, { subframe: true });
  }
  if (!allowed.includes('bar')) out['the browser bar'] = BAR;
  // browser.html loaded in a tab is not the bar.
  out['browser.html in a tab, not the main window'] = page('browser.html');
  if (!allowed.includes('apps')) Object.assign(out, APPS);
  return out;
}
function friendsOf(allowed) {
  const out = {};
  for (const who of allowed) {
    if (who === 'bar') out['the browser bar'] = BAR;
    else if (who === 'apps') Object.assign(out, APPS);
    else { out[`our ${who}`] = page(who); out[`our ${who} with a #fragment`] = page(who + '#x'); }
  }
  return out;
}

let passed = 0;
let failed = 0;
const check = (name, cond, why) => {
  if (cond) { passed++; console.log('ok    ' + name); }
  else { failed++; console.log('FAIL  ' + name + (why ? '\n      ' + why : '')); }
};

async function outcome(channel, event, ...args) {
  touched.length = 0;
  try {
    await handlers.get(channel)(event, ...args);
    return { refused: false, touched: touched.slice() };
  } catch (e) {
    return { refused: /^refused:/.test(e.message), error: e.message, touched: touched.slice() };
  }
}

// Asks every forged sender; each must be refused and touch nothing.
async function refusesAll(channel, senders, args = []) {
  const wrong = [];
  for (const [who, event] of Object.entries(senders)) {
    const r = await outcome(channel, event, ...args);
    if (!r.refused) wrong.push(`${who}: ${r.error || 'answered'}`);
    else if (r.touched.length) wrong.push(`${who}: refused only after touching ${r.touched.join(', ')}`);
  }
  return wrong;
}

(async () => {
  const registered = [...handlers.keys()].sort();
  check('every handler main.js registers is in the table of callers, and no other',
    registered.join() === Object.keys(WHO).sort().join(),
    `registered but not in the table: ${registered.filter((c) => !WHO[c]).join(', ') || 'none'}; ` +
    `in the table but not registered: ${Object.keys(WHO).filter((c) => !handlers.has(c)).join(', ') || 'none'}`);
  check('the count matches what the review counted (23)', registered.length === 23, `${registered.length}`);
  // HidraVPN is not released: its half of the browser is parked in
  // hidravpn/browser/, and nothing here may drive a VPN service.
  check('the browser has no VPN handler', registered.every((c) => !c.startsWith('vpn:')),
    registered.filter((c) => c.startsWith('vpn:')).join(', '));

  const ARGS = { 'tab:navigate': [1, 'https://example.com/'],
    'prefs:save': [{ theme: 'dark' }], 'vault:set': ['x'], 'tab:create': ['https://example.com/'] };

  for (const ch of registered) {
    const allowed = WHO[ch];
    const wrong = await refusesAll(ch, strangersTo(allowed), ARGS[ch] || []);
    check(`${ch} refuses everyone but ${allowed.join(', ')}`, wrong.length === 0, wrong.join('\n      '));
    const turnedAway = [];
    for (const [who, event] of Object.entries(friendsOf(allowed))) {
      const r = await outcome(ch, event, ...(ARGS[ch] || []));
      if (r.refused) turnedAway.push(`${who}: ${r.error}`);
    }
    check(`${ch} still answers ${allowed.join(', ')}`, turnedAway.length === 0, turnedAway.join('\n      '));
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
