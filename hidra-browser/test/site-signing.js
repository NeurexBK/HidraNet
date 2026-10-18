// A .hidra site can be read by anyone with its address, and changed only by
// its owner.
//
// A site's relay topic and encryption key used to come from its address
// alone, so every visitor could publish a replacement under it. Now the
// address is made of the site's signing key and the viewer checks the
// signature before it shows anything. This publishes a site through the real
// Sites page, opens it in the real viewer, and then tries what a visitor
// turned attacker would: an unsigned replacement, one signed by their own
// key, and an older signed copy replayed over a newer one. An address from
// before signing still opens, with a warning.
//
// Each page is copied to a scratch directory with its MQTT library swapped
// for a stand-in that records what is published and delivers what the test
// hands it.
//
//   cd hidra-browser && xvfb-run -a npx electron test/site-signing.js

const { app, BrowserWindow } = require('electron');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');

const UI = path.join(__dirname, '..', 'src', 'ui');
const STUB = `window.mqtt = { connect: function () {
  var h = {}; var c = { connected: true,
    on: function (ev, fn) { h[ev] = fn; if (ev === 'connect') setTimeout(fn, 0); return c; },
    subscribe: function (t) { (window.__subs = window.__subs || []).push(t); },
    unsubscribe: function () {}, end: function () {},
    publish: function (t, v, o, cb) { (window.__pub = window.__pub || []).push([t, String(v)]); if (typeof cb === 'function') cb(); },
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-sites-'));
  fs.cpSync(UI, dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'vendor', 'mqtt.min.js'), STUB);
  return dir;
}

app.setPath('userData', fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-sites-ud-')));
app.on('window-all-closed', () => {});

async function open(dir, page) {
  const win = new BrowserWindow({ show: false, width: 1100, height: 800,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true } });
  await win.loadURL(pathToFileURL(path.join(dir, page.split('?')[0])).href + (page.includes('?') ? '?' + page.split('?')[1] : ''));
  const run = (js) => win.webContents.executeJavaScript(js);
  for (let i = 0; i < 50 && !(await run('typeof window.__deliver === "function"')); i++) await sleep(100);
  return { win, run };
}

// What the viewer shows for `addr` when the relay hands it `wire`.
async function view(dir, addr, wire, topic) {
  const { win, run } = await open(dir, 'siteload.html?addr=' + encodeURIComponent(addr));
  await sleep(200);
  await run(`window.__deliver(${JSON.stringify(topic)}, ${JSON.stringify(wire)}); 1`);
  await sleep(700);
  const seen = await run(`({
    shown: !document.getElementById('frame').classList.contains('hidden'),
    html: document.getElementById('frame').srcdoc || '',
    error: !document.getElementById('error').classList.contains('hidden'),
    why: (document.getElementById('err-msg') || {}).textContent || '',
    legacy: !document.getElementById('legacy').classList.contains('hidden'),
    subs: window.__subs || [],
  })`);
  win.destroy();
  return seen;
}

// Run inside a page that has hidra-site.js and the viewer's crypto loaded.
const ATTACK = (addr, kind) => `(async () => {
  const addr = ${JSON.stringify(addr)};
  const key = await deriveKey(addr), top = await siteTopic(addr);
  let plain;
  if (${JSON.stringify(kind)} === 'unsigned') plain = JSON.stringify({ 'index.html': '<h1>EVIL</h1>' });
  else if (${JSON.stringify(kind)} === 'other-key') {
    const mine = await hidraSite.newSite();
    plain = await hidraSite.sealFiles(Object.assign({}, mine, { addr: addr }), { 'index.html': '<h1>EVIL</h1>' });
  }
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const c = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plain)));
  const o = new Uint8Array(12 + c.length); o.set(iv); o.set(c, 12);
  let s = ''; for (let i = 0; i < o.length; i++) s += String.fromCharCode(o[i]);
  return { topic: top, wire: btoa(s) };
})()`;

app.whenReady().then(async () => {
  const dir = stage();

  // ── Publish through the Sites page ──
  const pub = await open(dir, 'sitepub.html');
  await sleep(300);
  await pub.run(`document.getElementById('site-name').value = 'My site';
    document.getElementById('site-html').value = '<h1>The real site</h1>';
    document.getElementById('btn-pub').click(); 1`);
  for (let i = 0; i < 50 && !(await pub.run("!document.getElementById('result').classList.contains('hidden')")); i++) await sleep(100);
  const published = await pub.run(`({ addr: document.getElementById('r-addr').textContent, pubs: window.__pub || [],
    stored: localStorage.getItem('hidra_pub_sites') })`);
  const addr = published.addr;
  const sent = published.pubs.find((p) => /^hsite\//.test(p[0]));
  check('the Sites page published a site', !!sent && /\.hidra$/.test(addr), JSON.stringify(published).slice(0, 200));
  check('a new site gets a 32-character address, made of its key', /^[a-z2-7]{32}\.hidra$/.test(addr), addr);
  const stored = JSON.parse(published.stored || '[]');
  check('the site key is kept with the site, so its owner can change it',
    stored.length === 1 && stored[0].privJwk && stored[0].pk && stored[0].wire, JSON.stringify(stored).slice(0, 120));
  // Attacks are built in the publisher's window, which has the same crypto.
  const evilUnsigned = await pub.run(ATTACK(addr, 'unsigned'));
  const evilOtherKey = await pub.run(ATTACK(addr, 'other-key'));
  pub.win.destroy();

  // ── The real copy opens ──
  const real = await view(dir, addr, sent[1], sent[0]);
  check('the viewer subscribes to the site\'s topic', real.subs.includes(sent[0]), JSON.stringify(real.subs));
  check('the real site is shown', real.shown && /The real site/.test(real.html), JSON.stringify(real));
  check('a signed site carries no warning', !real.legacy);

  // ── What a visitor turned attacker can publish under the same address ──
  const u = await view(dir, addr, evilUnsigned.wire, evilUnsigned.topic);
  check('an unsigned replacement is refused', !u.shown && u.error && !/EVIL/.test(u.html), JSON.stringify(u));
  const k = await view(dir, addr, evilOtherKey.wire, evilOtherKey.topic);
  check('a replacement signed by another key is refused', !k.shown && k.error && !/EVIL/.test(k.html), JSON.stringify(k));

  // ── An older signed copy replayed over a newer one ──
  {
    const p2 = await open(dir, 'sitepub.html');
    const copies = await p2.run(`(async () => {
      const mine = JSON.parse(localStorage.getItem('hidra_pub_sites'))[0];
      const site = { addr: mine.addr, pk: mine.pk, privJwk: mine.privJwk };
      const wrap = async (plain) => {
        const key = await deriveKey(site.addr), top = await siteTopic(site.addr);
        return { topic: top, wire: await E(key, plain) };
      };
      return { old: await wrap(await hidraSite.sealFiles(site, { 'index.html': 'old' }, Date.now() - 86400000)),
               cur: await wrap(await hidraSite.sealFiles(site, { 'index.html': 'current' }, Date.now())) };
    })()`);
    p2.win.destroy();
    const cur = await view(dir, addr, copies.cur.wire, copies.cur.topic);
    check('a newer signed copy from the owner is shown', cur.shown && /current/.test(cur.html), JSON.stringify(cur));
    const old = await view(dir, addr, copies.old.wire, copies.old.topic);
    check('an older signed copy, replayed after a newer one was seen, is refused', !old.shown && old.error, JSON.stringify(old));
  }

  // ── A site from before signing ──
  {
    const legacyAddr = 'abcdefghijklmnopqrstuvwxyz.hidra';
    const p3 = await open(dir, 'sitepub.html');
    const legacy = await p3.run(`(async () => {
      const key = await deriveKey(${JSON.stringify(legacyAddr)}), top = await siteTopic(${JSON.stringify(legacyAddr)});
      return { topic: top, wire: await E(key, JSON.stringify({ 'index.html': '<h1>old site</h1>' })) };
    })()`);
    p3.win.destroy();
    const l = await view(dir, legacyAddr, legacy.wire, legacy.topic);
    check('a site from before signing still opens', l.shown && /old site/.test(l.html), JSON.stringify(l));
    check('and says plainly that anyone can change it', l.legacy);
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  app.exit(failed ? 1 : 0);
}).catch((e) => { console.error(e); app.exit(2); });
