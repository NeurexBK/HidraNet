// A stranger's mail must stay text, every field of it.
//
// HidraMail pasted the message id (`mid`) of incoming mail into the page as
// HTML — data-mid="..." on the list item and onclick="trash('...')" on the
// buttons — and the sender chooses the id. A message whose id closed the
// attribute ran its script in the Mail app the moment it arrived, with the
// recipient's keys one call away. Verification does not stop it: anyone can
// sign mail with their own key, so the sender being proven is not the sender
// being friendly.
//
// This loads the real page in Chromium, makes a stranger's identity with the
// page's own key code, and sends hostile mail signed and encrypted exactly as
// a real sender would, through the same receive path the relay uses. Then it
// opens each message and presses its buttons, and checks that nothing ran,
// nothing was injected, and Delete and Spam still act on the right message.
//
//   cd hidra-browser && xvfb-run -a npx electron test/mail-injection.js

const { app, BrowserWindow } = require('electron');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');

const PAGE = pathToFileURL(path.join(__dirname, '..', 'src', 'ui', 'hidramail.html')).href;

const PWN = 'window.__pwned=(window.__pwned||0)+1';
const HOSTILE_IDS = [
  `x"><img src=x onerror="${PWN}">`,
  `x');${PWN};('`,
  `x\\');${PWN};//`,
  `x" onmouseover="${PWN}`,
  `x' onmouseover='${PWN}`,
  `</div><img src=x onerror=${PWN}>`,
];
const HOSTILE_TEXT = `<img src=x onerror="${PWN}">"'><b>x</b>`;

let passed = 0;
let failed = 0;
const check = (name, cond, why) => {
  if (cond) { passed++; console.log('ok    ' + name); }
  else { failed++; console.log('FAIL  ' + name + (why ? '\n      ' + why : '')); }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// A profile of its own, so mail from an earlier run is not already there.
app.setPath('userData', fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-mail-inj-')));
app.on('window-all-closed', () => {});

app.whenReady().then(async () => {
  const win = new BrowserWindow({
    show: false,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  await win.loadURL(PAGE);
  const run = (js) => win.webContents.executeJavaScript(js);
  for (let i = 0; i < 100 && !(await run('!!(window.state && state.ids && state.ids.length)')); i++) await sleep(100);
  check('the page made an identity', await run('state.ids.length > 0'));

  // The stranger: a real identity, real signatures, real encryption.
  const delivered = await run(`(async () => {
    const me = activeId();
    const base = state.box.inbox.length;
    const eve = await genId();
    const topic = (await inboxTopic(me.addr)) + '/x';
    const ids = ${JSON.stringify(HOSTILE_IDS)};
    const send = async (mid, extra) => {
      const m = Object.assign({ v: MAIL_VERSION, mid: mid, from: eve.addr, to: me.addr,
        subject: ${JSON.stringify(HOSTILE_TEXT)}, body: ${JSON.stringify(HOSTILE_TEXT)}, date: Date.now(),
        sp: eve.pubRaw, ss: eve.sigPubRaw }, extra || {});
      m.sig = await signMail(eve, m);
      const ct = await encryptTo(b64d(me.pubRaw), JSON.stringify(m));
      await onMessage(topic + Math.random(), { toString: () => ct });
    };
    for (const id of ids) await send(id);
    // Fields that are not strings must not break the page either.
    await send(['array', 'id']);
    await send(42);
    await send('ok-1');
    await send('ok-2');
    return { base, now: state.box.inbox.length };
  })()`);
  const SENT = HOSTILE_IDS.length + 4;
  check('every signed message arrived', delivered.now - delivered.base === SENT, JSON.stringify(delivered));
  await sleep(300);

  // Open every message and hover everything, as a reader would.
  await run(`(async () => {
    const items = [...document.querySelectorAll('#list .mail-item')];
    for (const it of items) {
      it.click();
      document.querySelectorAll('[onmouseover]').forEach((e) => e.dispatchEvent(new MouseEvent('mouseover')));
      await new Promise((r) => setTimeout(r, 30));
    }
  })()`);
  await sleep(500);

  const seen = await run(`({
    pwned: window.__pwned || 0,
    injected: document.querySelectorAll('#list img, #list b, #view img, #view b, [onmouseover]').length,
    items: document.querySelectorAll('#list .mail-item').length,
    inlineHandlers: [...document.querySelectorAll('#list [onclick], #view [onclick]')].map((e) => e.getAttribute('onclick')),
  })`);
  check('no script from a stranger\'s mail ran', seen.pwned === 0, `window.__pwned = ${seen.pwned}`);
  check('no element was injected through a mail field', seen.injected === 0, `${seen.injected} injected`);
  check('every message has its own row', seen.items === delivered.now, `${seen.items} rows`);
  check('the buttons carry no script built from mail data',
    seen.inlineHandlers.every((h) => !/trash\(|spam\(/.test(h)), seen.inlineHandlers.join(' | '));

  // Delete and Spam must act on the message that is open, and only on it.
  const acted = await run(`(async () => {
    const out = {};
    for (const want of ['ok-1', 'ok-2']) {
      const m = state.box.inbox.find((x) => x.mid === want);
      if (!m) { out[want] = 'missing'; continue; }
      openMail(m.mid);
      const btn = want === 'ok-1'
        ? [...document.querySelectorAll('#view button')].find((b) => /Delete/.test(b.textContent))
        : [...document.querySelectorAll('#view button')].find((b) => /Spam/.test(b.textContent));
      if (!btn) { out[want] = 'no button'; continue; }
      const before = state.box.inbox.length;
      btn.click();
      out[want] = { gone: !state.box.inbox.some((x) => x.mid === want), removed: before - state.box.inbox.length,
        trash: state.box.trash.some((x) => x.mid === want), spam: state.box.spam.some((x) => x.mid === want) };
    }
    // And on a hostile one: the button must still delete it, not run it.
    const h = state.box.inbox.find((x) => x.subject && x.mid !== 'ok-1' && x.mid !== 'ok-2');
    if (h) {
      openMail(h.mid);
      const del = [...document.querySelectorAll('#view button')].find((b) => /Delete/.test(b.textContent));
      const before = state.box.inbox.length;
      del.click();
      out.hostile = { removed: before - state.box.inbox.length };
    }
    out.pwned = window.__pwned || 0;
    return out;
  })()`);
  check('Delete moves the open message to the trash, and only it',
    acted['ok-1'] && acted['ok-1'].gone && acted['ok-1'].trash && acted['ok-1'].removed === 1, JSON.stringify(acted['ok-1']));
  check('Spam moves the open message to spam, and only it',
    acted['ok-2'] && acted['ok-2'].gone && acted['ok-2'].spam && acted['ok-2'].removed === 1, JSON.stringify(acted['ok-2']));
  check('Delete on a hostile message deletes it', acted.hostile && acted.hostile.removed === 1, JSON.stringify(acted.hostile));
  check('pressing the buttons ran nothing', acted.pwned === 0, `window.__pwned = ${acted.pwned}`);

  // Ids that are not ours to trust are replaced, so they never reach storage
  // or a selector as they were sent.
  const stored = await run(`state.box.inbox.concat(state.box.trash, state.box.spam).map((m) => m.mid)`);
  const bad = stored.filter((mid) => typeof mid !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(mid));
  check('every stored message id is a plain token', bad.length === 0, JSON.stringify(bad));

  win.destroy();
  console.log(`\n${passed} passed, ${failed} failed`);
  app.exit(failed ? 1 : 0);
}).catch((e) => { console.error(e); app.exit(2); });
