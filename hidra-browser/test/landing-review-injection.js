// hidranet.org/r/<slug> must not run a stranger's script.
//
// The landing site's review page — where an NFC card on a café table sends a
// phone — reads listings, photos, reviews and replies from the same public
// relay as HidraReview, and had the same holes: photos straight into
// <img src="...">, an esc() that left quotes alone, ids used as object keys.
// There it is worse, because the page is on the project's own domain, beside
// its download links.
//
// The page is copied to a scratch directory with its MQTT library swapped for
// a stand-in that delivers what this test hands it and nothing else; then it
// is loaded in Chromium, fed hostile records, and inspected.
//
//   cd hidra-browser && xvfb-run -a npx electron test/landing-review-injection.js

const { app, BrowserWindow } = require('electron');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');

const SRC = path.join(__dirname, '..', '..', 'landing', 'r');
const PWN = 'window.__pwned=(window.__pwned||0)+1';
const GOOD_PIC = 'data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=';
const T = `<img src=x onerror="${PWN}">"'><b>x</b>`;

// The stand-in: connects at once, records subscriptions, and lets the test
// deliver messages by calling window.__deliver(topic, string).
const STUB = `window.mqtt = { connect: function () {
  var h = {}; var c = {
    on: function (ev, fn) { h[ev] = fn; if (ev === 'connect') setTimeout(fn, 0); return c; },
    subscribe: function (t) { (window.__subs = window.__subs || []).push(t); },
    unsubscribe: function () {}, publish: function () {}, end: function () {},
  };
  window.__deliver = function (t, s) { h.message && h.message(t, { toString: function () { return s; } }); };
  return c; } };`;

let passed = 0;
let failed = 0;
const check = (name, cond, why) => {
  if (cond) { passed++; console.log('ok    ' + name); }
  else { failed++; console.log('FAIL  ' + name + (why ? '\n      ' + why : '')); }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function stage() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-landing-r-'));
  fs.cpSync(SRC, dir, { recursive: true });
  fs.mkdirSync(path.join(dir, 'vendor'), { recursive: true });
  // Whatever name the page loads its library under, it gets the stand-in.
  const html = fs.readFileSync(path.join(dir, 'index.html'), 'utf8');
  const srcs = [...html.matchAll(/<script src="([^"]+)"/g)].map((m) => m[1]).filter((s) => /mqtt/i.test(s));
  for (const s of srcs) fs.writeFileSync(path.join(dir, s.replace(/^\//, '').replace(/^r\//, '')), STUB);
  return dir;
}

app.setPath('userData', fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-landing-ud-')));
app.on('window-all-closed', () => {});

async function open(dir, query) {
  const win = new BrowserWindow({ show: false, width: 420, height: 900,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true } });
  await win.loadURL(pathToFileURL(path.join(dir, 'index.html')).href + query);
  const run = (js) => win.webContents.executeJavaScript(js);
  for (let i = 0; i < 50 && !(await run('typeof window.__deliver === "function"')); i++) await sleep(100);
  return { win, run };
}

app.whenReady().then(async () => {
  const dir = stage();

  // ── A listing's own page ──
  {
    const { win, run } = await open(dir, '?b=cafe');
    check('the stand-in relay is in use', await run('typeof window.__deliver === "function"'));
    await run(`(() => {
      const d = (t, v) => window.__deliver(t, typeof v === 'string' ? v : JSON.stringify(v));
      const T = ${JSON.stringify(T)};
      d('hreview/b/cafe', { name: 'Cafe ' + T, cat: T, desc: T, city: T, addr: T, phone: T, hours: T, about: T, menu: T,
        site: 'javascript:' + ${JSON.stringify(PWN)} });
      d('hreview/p/cafe/bad1', 'x" onerror="${PWN}');
      d('hreview/p/cafe/bad2', 'data:image/png;base64,AAAA" onerror="${PWN}');
      d('hreview/p/cafe/bad3', 'javascript:${PWN}');
      d('hreview/p/cafe/good', ${JSON.stringify(GOOD_PIC)});
      d('hreview/p/cafe/__proto__', ${JSON.stringify(GOOD_PIC)});
      d('hreview/r/cafe/r1', { stars: '5"><b>', text: T, name: T, loc: T, at: 'x' });
      d('hreview/r/cafe/' + 'a"><img src=x onerror="${PWN}">', { stars: 5, text: 'x' });
      d('hreview/reply/cafe/r1', { text: T });
      d('hreview/r/cafe/r2', { stars: 4, text: ['x'], name: { a: 1 } });
    })(); 1`);
    await sleep(3200); // the page waits 2.5 s for retained messages before drawing "missing"
    const seen = await run(`({
      pwned: window.__pwned || 0,
      handlers: document.querySelectorAll('[onerror], [onmouseover], [onload]').length,
      bx: [...document.querySelectorAll('b')].filter((b) => b.textContent === 'x' || b.textContent === '').length,
      imgs: [...document.querySelectorAll('img')].map((i) => i.getAttribute('src')),
      name: (document.querySelector('#hero h1') || {}).textContent || '',
      js: [...document.querySelectorAll('a[href]')].filter((a) => /^\\s*javascript:/i.test(a.getAttribute('href'))).length,
      proto: ({}).text === undefined,
    })`);
    check('no script from a listing ran on the review page', seen.pwned === 0, `window.__pwned = ${seen.pwned}`);
    check('no handler or element was injected', seen.handlers === 0 && seen.bx === 0, JSON.stringify(seen));
    const bad = seen.imgs.filter((s) => !/^data:image\/(jpeg|png|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(s));
    check('only real image data reaches an <img>', bad.length === 0, bad.join(' | '));
    check('a real photo is still shown', seen.imgs.includes(GOOD_PIC));
    check('the listing is shown with its name', /^Cafe /.test(seen.name), seen.name);
    check('no javascript: link', seen.js === 0);
    check('Object.prototype is untouched', seen.proto);
    win.destroy();
  }

  // ── The directory, and a slug that is a relay wildcard ──
  {
    const { win, run } = await open(dir, '');
    await run(`(() => {
      const d = (t, v) => window.__deliver(t, JSON.stringify(v));
      d('hreview/b/' + 'x"><img src=x onerror="${PWN}">', { name: 'bad slug' });
      d('hreview/b/good', { name: ${JSON.stringify(T)}, city: ${JSON.stringify(T)} });
      d('hreview/b/types', { name: 42, city: {}, cat: [] });
    })(); 1`);
    await sleep(3200);
    const seen = await run(`({ pwned: window.__pwned || 0,
      hrefs: [...document.querySelectorAll('#dir-list a')].map((a) => a.getAttribute('href')) })`);
    check('the directory runs nothing either', seen.pwned === 0, `window.__pwned = ${seen.pwned}`);
    check('a listing under a slug that is not plain is not listed',
      seen.hrefs.every((h) => /^\/r\/[a-z0-9-]+$/.test(h)) && seen.hrefs.includes('/r/good'), seen.hrefs.join(' | '));
    win.destroy();
  }
  {
    const { win, run } = await open(dir, '?b=%23');
    await sleep(300);
    const subs = await run('window.__subs || []');
    check('a slug of "#" does not subscribe to the whole relay', !subs.some((t) => /[#+]$/.test(t) && /^hreview\/b\//.test(t) && t !== 'hreview/b/+'),
      subs.join(' | '));
    win.destroy();
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  app.exit(failed ? 1 : 0);
}).catch((e) => { console.error(e); app.exit(2); });
