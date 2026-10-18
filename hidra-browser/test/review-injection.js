// A stranger's listing must stay data, every field of it.
//
// HidraReview reads every listing, photo, review and reply from a public
// relay, where anyone can publish under any topic. Photos went into
// <img src="..."> as they arrived, with no check that they were images, and
// the listing's slug — taken from the relay topic — went into data-slug="...".
// esc() left quotes alone, so either one closed its attribute and ran a
// stranger's script on the directory's front page, without a click.
//
// This loads the real page in Chromium, feeds it hostile records through the
// handler the relay calls, renders the directory, opens every listing and the
// owner's panel, and checks that nothing ran, nothing was injected, and that
// a real photo and a real listing still show.
//
//   cd hidra-browser && xvfb-run -a npx electron test/review-injection.js

const { app, BrowserWindow } = require('electron');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');

const PAGE = pathToFileURL(path.join(__dirname, '..', 'src', 'ui', 'hidrareview.html')).href;

const PWN = 'window.__pwned=(window.__pwned||0)+1';
const BAD_PICS = [
  `x" onerror="${PWN}`,
  `data:image/png;base64,AAAA" onerror="${PWN}`,
  `javascript:${PWN}`,
  `https://tracker.example/pixel.png`,
  `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`,
  `data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+`,
];
// One white pixel: the control, a photo the page itself would have made.
const GOOD_PIC = 'data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=';
const BAD_SLUGS = [
  `a"><img src=x onerror="${PWN}">`,
  `b" onmouseover="${PWN}`,
  `__proto__`,
];
const HOSTILE_TEXT = `<img src=x onerror="${PWN}">"'><b>x</b>`;

let passed = 0;
let failed = 0;
const check = (name, cond, why) => {
  if (cond) { passed++; console.log('ok    ' + name); }
  else { failed++; console.log('FAIL  ' + name + (why ? '\n      ' + why : '')); }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

app.setPath('userData', fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-review-inj-')));
app.on('window-all-closed', () => {});

app.whenReady().then(async () => {
  const win = new BrowserWindow({
    show: false, width: 1280, height: 1000,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  await win.loadURL(PAGE);
  const run = (js) => win.webContents.executeJavaScript(js);
  for (let i = 0; i < 50 && !(await run("typeof onMessage === 'function' && !!window.state")); i++) await sleep(100);

  const errors = [];
  win.webContents.on('console-message', (_e, level, msg) => { if (level >= 3) errors.push(msg); });

  await run(`(() => {
    const deliver = (topic, v) => onMessage(topic, { toString: () => typeof v === 'string' ? v : JSON.stringify(v) });
    const T = ${JSON.stringify(HOSTILE_TEXT)};
    const rec = (name) => ({ name: name, kind: 'place', cat: T, desc: T, city: T, addr: T, phone: T,
      site: 'javascript:' + ${JSON.stringify(PWN)}, hours: T, about: T, menu: T + '\\n' + T, mail: T, at: 1 });
    // An ordinary listing, carrying hostile photos next to a real one.
    deliver('hreview/b/cafe', rec('Cafe ' + T));
    ${JSON.stringify(BAD_PICS)}.forEach((p, i) => deliver('hreview/p/cafe/bad' + i, p));
    deliver('hreview/p/cafe/good', ${JSON.stringify(GOOD_PIC)});
    // A listing whose only photo is hostile, so it becomes the cover.
    deliver('hreview/b/cover', rec('Cover'));
    deliver('hreview/p/cover/x', ${JSON.stringify(BAD_PICS[0])});
    // Hostile slugs, in the listing, photo, review and reply topics.
    ${JSON.stringify(BAD_SLUGS)}.forEach((s, i) => {
      deliver('hreview/b/' + s, rec('slug ' + i));
      deliver('hreview/p/' + s + '/p' + i, ${JSON.stringify(GOOD_PIC)});
      deliver('hreview/r/' + s + '/r' + i, { stars: 5, text: T, name: T, loc: T, at: 1 });
    });
    // Reviews with hostile ids and fields of the wrong type.
    deliver('hreview/r/cafe/' + ${JSON.stringify(BAD_SLUGS[0])}, { stars: 5, text: T, name: T, loc: T, at: 1 });
    deliver('hreview/r/cafe/ok1', { stars: '5"><b>', text: T, name: T, loc: T, at: 'later' });
    deliver('hreview/r/cafe/ok2', { stars: 4, text: ['x'], name: { a: 1 }, loc: 7, at: 2 });
    deliver('hreview/reply/cafe/ok1', { text: T, at: 3 });
    deliver('hreview/reply/cafe/ok2', { text: { a: 1 } });
    // A listing whose every field is the wrong type.
    deliver('hreview/b/wrongtypes', { name: 42, kind: ['site'], hidra: {}, phone: 9, menu: ['a'], cat: 1, site: 5, sats: '1" onerror="x' });
  })(); 1`);
  await sleep(400);

  // Render the directory, open every listing, open the owner's panel.
  await run(`(async () => {
    render();
    await new Promise((r) => setTimeout(r, 100));
    for (const slug of Object.keys(state.biz)) { openBiz(slug); await new Promise((r) => setTimeout(r, 30)); back(); }
    openBiz('cafe');
    document.querySelectorAll('[onmouseover]').forEach((e) => e.dispatchEvent(new MouseEvent('mouseover')));
    back();
    state.ownerSlug = 'cafe'; state.ownerSecret = 'x'; openOwner('cafe');
    await new Promise((r) => setTimeout(r, 100));
    closeOwner();
  })()`);
  await sleep(800);

  const seen = await run(`(() => {
    render();
    openBiz('cafe');
    const imgs = [...document.querySelectorAll('img')].map((i) => i.getAttribute('src')).filter(Boolean);
    return {
      pwned: window.__pwned || 0,
      bTags: [...document.querySelectorAll('b')].filter((b) => b.textContent === 'x' || b.textContent === '')
        .map((b) => b.outerHTML).concat([...document.querySelectorAll('[onerror], [onmouseover], [onload]')].map((e) => e.outerHTML.slice(0, 80))),
      imgs: imgs,
      slugs: Object.keys(state.biz),
      picSlugs: Object.keys(state.pics),
      revSlugs: Object.values(state.revs).map((r) => r._slug),
      revIds: Object.keys(state.revs),
      cafeShown: !!document.querySelector('#view-biz h3') && /Cafe/.test(document.querySelector('#view-biz h3').textContent),
      links: [...document.querySelectorAll('a[href]')].map((a) => a.getAttribute('href')),
    };
  })()`);

  check('no script from a listing ran', seen.pwned === 0, `window.__pwned = ${seen.pwned}`);
  check('no handler was injected through a listing',
    !seen.bTags.length, seen.bTags.join(' | '));
  const badImg = seen.imgs.filter((s) => !/^data:image\/(jpeg|png|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(s));
  check('only real image data reaches an <img>', badImg.length === 0, badImg.join(' | '));
  check('a real photo is still shown', seen.imgs.includes(GOOD_PIC), `${seen.imgs.length} images`);
  check('the listing still opens and shows its name', seen.cafeShown);
  const plain = (s) => /^[a-z0-9][a-z0-9-]{0,63}$/.test(s);
  const badSlugs = seen.slugs.concat(seen.picSlugs, seen.revSlugs).filter((s) => !plain(s));
  check('a record under a topic that is not a plain slug is not kept', badSlugs.length === 0, JSON.stringify(badSlugs));
  const badIds = seen.revIds.filter((s) => !/^[A-Za-z0-9-]{1,64}$/.test(s));
  check('a review under an id that is not plain is not kept', badIds.length === 0, JSON.stringify(badIds));
  check('no javascript: link', !seen.links.some((h) => /^\s*javascript:/i.test(h)), seen.links.join(' | '));
  check('a listing of the wrong types does not break the page', errors.filter((e) => /TypeError/.test(e)).length === 0,
    errors.join('\n      '));
  check('Object.prototype is untouched', await run(`({}).name === undefined && ({}).kind === undefined`));

  win.destroy();
  console.log(`\n${passed} passed, ${failed} failed`);
  app.exit(failed ? 1 : 0);
}).catch((e) => { console.error(e); app.exit(2); });
