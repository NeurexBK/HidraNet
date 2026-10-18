// A HidraReview listing belongs to whoever registered it.
//
// A listing, its photos and its "reply from the business" sat on a public
// relay where anyone can publish under any topic, and the owner panel only
// compared a hash that was itself inside the listing. So anyone could
// overwrite a listing with their own, wipe it, add photos to it, or answer
// reviews as the business. Now all three are signed by a key made from the
// owner key, and a page keeps the first key it saw for each listing.
//
// This registers a listing through the real form, opens it in other windows
// (each with storage of its own, as other people's browsers would be), and
// then tries each of those attacks. It also checks that a listing from before
// signing still shows, and that its owner signs it by opening the panel once.
//
//   cd hidra-browser && xvfb-run -a npx electron test/review-signing.js

const { app, BrowserWindow } = require('electron');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');

const UI = path.join(__dirname, '..', 'src', 'ui');
const STUB = `window.mqtt = { connect: function () {
  var h = {}; var c = { connected: true,
    on: function (ev, fn) { h[ev] = fn; if (ev === 'connect') setTimeout(fn, 0); return c; },
    subscribe: function () {}, unsubscribe: function () {}, end: function () {},
    publish: function (t, v, o, cb) { (window.__pub = window.__pub || []).push([t, String(v)]); if (typeof cb === 'function') cb(); },
  };
  window.__deliver = function (t, s) { h.message && h.message(t, { toString: function () { return s; } }); };
  return c; } };`;
const PIC = 'data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=';

let passed = 0;
let failed = 0;
const check = (name, cond, why) => {
  if (cond) { passed++; console.log('ok    ' + name); }
  else { failed++; console.log('FAIL  ' + name + (why ? '\n      ' + why : '')); }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-review-sign-'));
fs.cpSync(UI, dir, { recursive: true });
fs.writeFileSync(path.join(dir, 'vendor', 'mqtt.min.js'), STUB);

app.setPath('userData', fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-review-sign-ud-')));
app.on('window-all-closed', () => {});

let n = 0;
// A browser of its own: its own storage, so its own memory of owners.
async function browser() {
  const win = new BrowserWindow({ show: false, width: 1280, height: 1000,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true, partition: 'viewer-' + (++n) } });
  await win.loadURL(pathToFileURL(path.join(dir, 'hidrareview.html')).href);
  const run = (js) => win.webContents.executeJavaScript(js);
  for (let i = 0; i < 50 && !(await run('typeof window.__deliver === "function" && typeof hidraRoom === "object"')); i++) await sleep(100);
  return { win, run };
}
const deliverAll = (run, msgs) => run(`(async () => { for (const [t, v] of ${JSON.stringify(msgs)}) window.__deliver(t, v);
  await inbox; await new Promise((r) => setTimeout(r, 200)); })()`);
const look = (run, slug) => run(`(() => {
  openBiz(${JSON.stringify(slug)});
  const b = state.biz[${JSON.stringify(slug)}];
  return { name: b ? b.name : null, signed: !!(b && b.signed),
    photos: photosOf(${JSON.stringify(slug)}).length,
    replies: Object.values(state.replies).filter((r) => r._slug === ${JSON.stringify(slug)}).map((r) => [r.text, !!r.verified]),
    caution: document.getElementById('b-caution').textContent,
    page: document.getElementById('r-list').textContent };
})()`);

app.whenReady().then(async () => {
  // ── The owner registers, through the form ──
  const owner = await browser();
  await owner.run(`state.draft = [${JSON.stringify(PIC)}]; setKind('place');
    document.getElementById('n-name').value = 'Café Real';
    document.getElementById('n-city').value = 'Lisboa';
    document.getElementById('n-mail').value = 'abcdefghijklmnop@hidra';
    document.getElementById('n-save').click(); 1`);
  for (let i = 0; i < 300 && !(await owner.run("document.getElementById('okey').className.indexOf('on') >= 0")); i++) await sleep(100);
  const reg = await owner.run(`({ key: document.getElementById('okey-val').textContent, slug: state.ownerSlug, pub: window.__pub || [] })`);
  const slug = reg.slug;
  const listing = reg.pub.find((p) => p[0] === 'hreview/b/' + slug);
  const photo = reg.pub.find((p) => p[0].indexOf('hreview/p/' + slug + '/') === 0);
  check('the form registered a listing and showed the owner key', !!listing && reg.key.length >= 16, JSON.stringify(reg).slice(0, 200));
  check('the listing is signed by a key made from the owner key', listing && /"opk":"B/.test(listing[1]) && /"sig":/.test(listing[1]));
  check('its photo is signed too', photo && /"sig":/.test(photo[1]));

  // The owner answers a review, from the panel.
  const review = ['hreview/r/' + slug + '/aaaaaaaaaaaaaaaa', JSON.stringify({ stars: 5, text: 'great', name: 'Ana', at: 1 })];
  // The relay hands a subscriber back what it published; the stand-in does not.
  await deliverAll(owner.run, reg.pub.filter((p) => /^hreview\//.test(p[0])).concat([review]));
  await owner.run(`openOwner(${JSON.stringify(slug)}); 1`);
  await sleep(300);
  await owner.run(`document.getElementById('rep-aaaaaaaaaaaaaaaa').value = 'Thank you!';
    document.querySelector('[data-rep="aaaaaaaaaaaaaaaa"]').click(); 1`);
  await sleep(800);
  const ownerReply = (await owner.run('window.__pub')).find((p) => p[0] === 'hreview/reply/' + slug + '/aaaaaaaaaaaaaaaa');
  check('the owner reply is signed', ownerReply && /"sig":/.test(ownerReply[1]), JSON.stringify(ownerReply));
  owner.win.destroy();

  // ── A visitor sees it, photos first as the owner published them ──
  const real = [photo, listing, review, ownerReply];
  const v1 = await browser();
  await deliverAll(v1.run, real);
  let seen = await look(v1.run, slug);
  check('a visitor sees the signed listing', seen.name === 'Café Real' && seen.signed, JSON.stringify(seen));
  check('with its photo, though it arrived before the listing', seen.photos === 1, JSON.stringify(seen));
  check('and the owner reply, as from the business', seen.replies.some((r) => r[0] === 'Thank you!' && r[1])
    && /Reply from the business/.test(seen.page), JSON.stringify(seen));

  // ── A stranger tries to take it over ──
  const evil = await v1.run(`(async () => {
    const slug = ${JSON.stringify(slug)};
    const me = await hidraRoom.deriveIdentity('hreview-owner', slug + ':' + 'the attacker key 1234567890');
    const rec = cleanBiz(${JSON.stringify(JSON.parse(listing[1]))});
    rec.name = 'Café Real (now mine)';
    const signed = await signedListing(slug, Object.assign({}, rec), me);
    const unsignedRec = Object.assign({}, rec); delete unsignedRec.opk; delete unsignedRec.sig;
    const fakeReply = { text: 'We are closed forever', at: 5 };
    fakeReply.sig = await hidraRoom.signFields(me, replyFields(slug, 'aaaaaaaaaaaaaaaa', fakeReply));
    return {
      otherKey: ['hreview/b/' + slug, JSON.stringify(signed)],
      unsigned: ['hreview/b/' + slug, JSON.stringify(unsignedRec)],
      wipe: ['hreview/b/' + slug, ''],
      replyUnsigned: ['hreview/reply/' + slug + '/aaaaaaaaaaaaaaaa', JSON.stringify({ text: 'We are closed', at: 9 })],
      replyOtherKey: ['hreview/reply/' + slug + '/aaaaaaaaaaaaaaaa', JSON.stringify(fakeReply)],
      photoUnsigned: ['hreview/p/' + slug + '/badbadbadbad', ${JSON.stringify(PIC)}],
    };
  })()`);
  await deliverAll(v1.run, [evil.otherKey, evil.unsigned, evil.wipe, evil.replyUnsigned, evil.replyOtherKey, evil.photoUnsigned]);
  seen = await look(v1.run, slug);
  check('a listing signed by another key does not replace it', seen.name === 'Café Real', JSON.stringify(seen));
  check('an unsigned listing or an empty payload does not remove it either', seen.name === 'Café Real' && seen.signed);
  check('and the page says someone tried', /tried to replace or remove/.test(seen.caution), seen.caution);
  check('a reply nobody but the owner signed is not shown as the business\'s',
    !seen.replies.some((r) => /closed/.test(r[0])) && !/closed/.test(seen.page), JSON.stringify(seen.replies));
  check('a stranger\'s photo is not added to the listing', seen.photos === 1, JSON.stringify(seen));
  v1.win.destroy();

  // ── A listing from before signing ──
  {
    const legacySecret = 'legacy-owner-key-123456';
    const v2 = await browser();
    const legacy = await v2.run(`(async () => ({ hash: await ownerHashOf(${JSON.stringify(legacySecret)}) }))()`);
    const old = ['hreview/b/old-bar', JSON.stringify({ name: 'Old Bar', kind: 'place', city: 'Porto', mail: 'abcdefghijklmnop@hidra', ownerHash: legacy.hash, at: 1 })];
    const oldReply = ['hreview/reply/old-bar/bbbbbbbbbbbbbbbb', JSON.stringify({ text: 'old reply', at: 2 })];
    await deliverAll(v2.run, [old, ['hreview/r/old-bar/bbbbbbbbbbbbbbbb', JSON.stringify({ stars: 4, text: 'ok', name: 'Bo', at: 1 })], oldReply]);
    seen = await look(v2.run, 'old-bar');
    check('a listing from before signing still shows', seen.name === 'Old Bar' && !seen.signed, JSON.stringify(seen));
    check('its reply is shown, marked unverified', /unverified/.test(seen.page) && !/Reply from the business/.test(seen.page), seen.page);
    // Its owner opens the panel with the old key: the listing gets signed.
    await v2.run(`window.__pub = []; openOwner('old-bar'); document.getElementById('o-slug').value = 'old-bar';
      document.getElementById('o-key').value = ${JSON.stringify(legacySecret)}; document.getElementById('o-enter').click(); 1`);
    for (let i = 0; i < 300 && !(await v2.run("(window.__pub || []).some((p) => p[0] === 'hreview/b/old-bar')")); i++) await sleep(100);
    const up = await v2.run('window.__pub');
    const upListing = up.find((p) => p[0] === 'hreview/b/old-bar');
    const upReply = up.find((p) => p[0] === 'hreview/reply/old-bar/bbbbbbbbbbbbbbbb');
    check('opening the panel with the old key signs the listing', upListing && /"opk":/.test(upListing[1]) && /"sig":/.test(upListing[1]));
    check('and its reply', upReply && /"sig":/.test(upReply[1]));
    v2.win.destroy();
    const v3 = await browser();
    await deliverAll(v3.run, [upListing, upReply]);
    seen = await look(v3.run, 'old-bar');
    check('after which a visitor sees it signed, the reply as the business\'s', seen.signed && seen.replies.some((r) => r[1]), JSON.stringify(seen));
    v3.win.destroy();
  }

  // ── hidranet.org/r/<slug>, the page an NFC card opens, follows the same rules ──
  {
    const ldir = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-landing-sign-'));
    fs.cpSync(path.join(__dirname, '..', '..', 'landing', 'r'), ldir, { recursive: true });
    fs.mkdirSync(path.join(ldir, 'vendor'), { recursive: true });
    fs.writeFileSync(path.join(ldir, 'vendor', 'mqtt.min.js'), STUB);
    const win = new BrowserWindow({ show: false, width: 420, height: 900,
      webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true, partition: 'landing' } });
    await win.loadURL(pathToFileURL(path.join(ldir, 'index.html')).href + '?b=' + slug);
    const run = (js) => win.webContents.executeJavaScript(js);
    for (let i = 0; i < 50 && !(await run('typeof window.__deliver === "function"')); i++) await sleep(100);
    const feed = async (msgs) => { await run(`(async () => { for (const [t, v] of ${JSON.stringify(msgs)}) window.__deliver(t, v);
      await queue; })()`); await sleep(3000); };
    await feed(real.concat([evil.otherKey, evil.unsigned, evil.wipe, evil.replyUnsigned, evil.replyOtherKey, evil.photoUnsigned]));
    const page = await run(`({ name: (document.querySelector('#hero h1') || {}).textContent || '',
      hero: document.getElementById('hero').textContent, list: document.getElementById('list').textContent,
      photos: document.querySelectorAll('#hero img, #gal img').length })`);
    check('the public page shows the owner\'s listing, not the attacker\'s', page.name === 'Café Real', JSON.stringify(page));
    check('it says someone tried to replace it', /tried to replace or remove/.test(page.hero), page.hero);
    check('the owner reply is shown as the business\'s, the forged ones are not',
      /Reply from the business/.test(page.list) && /Thank you!/.test(page.list) && !/closed/.test(page.list), page.list);
    check('a stranger\'s photo is not added there either', page.photos === 1, JSON.stringify(page));
    win.destroy();
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  app.exit(failed ? 1 : 0);
}).catch((e) => { console.error(e); app.exit(2); });
