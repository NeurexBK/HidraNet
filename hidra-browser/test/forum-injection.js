// A stranger's post must stay text, every field of it.
//
// The forum runs on a public relay: anyone can publish a topic or a reply,
// and choose its body, its id and the MQTT topic it sits under. Signing says
// who wrote a post, not that it is harmless, so this sends hostile posts both
// ways a page accepts them — signed by a real account, and unsigned as posts
// from before accounts were — and checks that nothing runs:
//
//   - markdown: esc() once left quotes alone, so ![x](https://a"onerror="...)
//     closed the src attribute of the image it made;
//   - the post id and the relay topic, once pasted into onclick="report('...')".
//
// It reads every topic, presses every button, and checks that ordinary
// markdown still renders and that Report and Delete act on their own post.
//
//   cd hidra-browser && xvfb-run -a npx electron test/forum-injection.js

const { app, BrowserWindow } = require('electron');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');

const PAGE = pathToFileURL(path.join(__dirname, '..', 'src', 'ui', 'forum.html')).href;

const PWN = 'window.__pwned=(window.__pwned||0)+1';
const BODIES = [
  `![x](https://a.example/x.png"onerror="${PWN})`,
  `![x"onerror="${PWN}](https://a.example/x.png)`,
  `[click](https://a.example/"onmouseover="${PWN})`,
  `https://a.example/"onmouseover="${PWN}`,
  `<img src=x onerror="${PWN}">`,
  `\`<img src=x onerror=${PWN}>\``,
  `**<svg onload=${PWN}>**`,
];
const BAD_IDS = [
  `t1"><img src=x onerror="${PWN}">`,
  `tabcdefghij');${PWN};('`,
  `tabcdefghij" onmouseover="${PWN}`,
  '__proto__',
];

let passed = 0;
let failed = 0;
const check = (name, cond, why) => {
  if (cond) { passed++; console.log('ok    ' + name); }
  else { failed++; console.log('FAIL  ' + name + (why ? '\n      ' + why : '')); }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

app.setPath('userData', fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-forum-inj-')));
app.on('window-all-closed', () => {});

app.whenReady().then(async () => {
  const win = new BrowserWindow({
    show: false,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  await win.loadURL(PAGE);
  const run = (js) => win.webContents.executeJavaScript(js);
  // Until the page has its relays: replaced before then, they would be
  // replaced again by the page's own.
  for (let i = 0; i < 50 && !(await run("typeof onMessage === 'function' && !!window.state && !!window.relays")); i++) await sleep(100);

  // Relays that publish nowhere, and a reader with a real account.
  await run(`window.__sent = [];
    relays.stop();
    window.relays = { anyUp() { return true; }, isUp() { return true; }, subscribe() {}, unsubscribe() {}, stop() {},
      publish(t, v) { window.__sent.push([t, v]); return Promise.resolve(1); },
      publishTo(i, t, v) { window.__sent.push([t, v]); return Promise.resolve(1); } };
    state.ready = true; 1`);
  const signedIn = await run(`signIn('reader_1', 'correct horse battery staple 1729')`);
  check('the reader can sign in', signedIn === true);

  await run(`(async () => {
    const id = (p) => rid(p);
    const eve = await hidraRoom.deriveIdentity('eve_1', 'another long password for eve');
    window.__ids = { mine: id('t'), good: id('t'), legacy: id('t'), typed: id('t') };
    const deliver = (topic, obj) => onMessage(topic, typeof obj === 'string' ? obj : JSON.stringify(obj));
    const signedTopic = async (who, tid, f) => {
      const o = Object.assign({ id: tid, cat: 'Privacy', title: 't', body: 'b', nick: 'eve', ts: Date.now() }, f);
      o.pk = who.pub;
      o.sig = await hidraRoom.signFields(who, ['t', tid, o.cat, o.title, o.body, o.nick, o.ts]);
      await deliver('hforum/t/' + tid, o);
    };
    const signedReply = async (who, tid, rid_, body) => {
      const o = { id: rid_, topicId: tid, body, nick: 'eve', ts: Date.now(), pk: who.pub };
      o.sig = await hidraRoom.signFields(who, ['r', rid_, tid, body, 'eve', o.ts]);
      await deliver('hforum/r/' + tid + '/' + rid_, o);
    };
    const BODIES = ${JSON.stringify(BODIES)};
    for (const b of BODIES) {
      const tid = id('t');
      await signedTopic(eve, tid, { body: b, title: b });
      await signedReply(eve, tid, id('r'), b);
      // The same, unsigned, as a post from before accounts.
      const lid = id('t');
      await deliver('hforum/t/' + lid, { id: lid, cat: 'Privacy', title: b, body: b, nick: b, tag: 'x', ts: Date.now() });
    }
    // Ids that are not ids, under the topic and inside the payload.
    for (const bad of ${JSON.stringify(BAD_IDS)}) {
      await deliver('hforum/t/' + bad, { id: bad, cat: 'Privacy', title: 'bad', body: 'b', nick: 'eve', ts: 1 });
      const ok = id('t');
      await deliver('hforum/t/' + ok, { id: bad, cat: 'Privacy', title: 'claims another id', body: 'b', nick: 'eve', ts: 1 });
    }
    // Fields of the wrong type: must not stop the forum rendering.
    await deliver('hforum/t/' + __ids.typed, { id: __ids.typed, cat: { a: 1 }, title: 42, body: ['b'], nick: null, tag: {}, ts: 'soon' });
    // The control, and one of the reader's own.
    await signedTopic(eve, __ids.good, { title: 'good', body: '**bold** *it* \`code\` [link](https://example.com/a) https://example.org/b' });
    await signedTopic(state.me, __ids.mine, { title: 'mine', nick: state.me.nick });
  })(); 1`);
  await sleep(500);

  // Read every topic as a moderator would see it, hover and press everything.
  await run(`(async () => {
    state.mod = true;
    for (const id of Object.keys(state.topics)) {
      if (id === __ids.mine || id === __ids.good) continue;
      openTopic(id);
      document.querySelectorAll('[onmouseover]').forEach((e) => e.dispatchEvent(new MouseEvent('mouseover')));
      document.querySelectorAll('#view .p-foot a').forEach((a) => { try { a.click(); } catch (e) {} });
      await new Promise((r) => setTimeout(r, 20));
    }
    state.mod = false;
  })()`);
  await sleep(600);

  const seen = await run(`({
    pwned: window.__pwned || 0,
    topics: Object.keys(state.topics).length,
    injected: document.querySelectorAll('#list img, #view img, [onmouseover], [onerror], [onload]').length,
    inline: [...document.querySelectorAll('#list [onclick], #view [onclick]')].map((e) => e.getAttribute('onclick')),
    ids: Object.keys(state.topics).concat(Object.keys(state.replies)),
    bound: Object.entries(state.topics).filter(([k, t]) => t.id !== k).length,
  })`);
  check('the hostile posts were accepted and shown, so the checks below mean something',
    seen.topics >= 2 * BODIES.length, `${seen.topics} topics kept`);
  check('no script from a post ran', seen.pwned === 0, `window.__pwned = ${seen.pwned}`);
  check('no element or handler was injected through a post', seen.injected === 0, `${seen.injected} injected`);
  check('no button carries script built from post data', seen.inline.length === 0, seen.inline.join(' | '));
  const badIds = seen.ids.filter((x) => !/^[tr][a-z2-7]{10}$/.test(x));
  check('a post whose relay topic is not a plain id is not kept', badIds.length === 0, JSON.stringify(badIds));
  check('a post is known by the topic it sits under, not by the id it claims', seen.bound === 0);
  check('Object.prototype is untouched', await run('({}).title === undefined && ({}).body === undefined'));

  // Report and Delete act on the post they are under.
  const acts = await run(`(async () => {
    window.__sent.length = 0;
    openTopic(__ids.good);
    const report = [...document.querySelectorAll('#view .p-foot a')].find((a) => /Report/.test(a.textContent));
    if (report) report.click();
    openTopic(__ids.mine);
    const del = [...document.querySelectorAll('#view .p-foot a')].find((a) => /Delete/.test(a.textContent));
    if (del) del.click();
    await new Promise((r) => setTimeout(r, 300));
    return { sent: window.__sent, fp: state.me.fingerprint, ids: __ids, mineGone: !state.topics[__ids.mine] };
  })()`);
  check('Report reports the post it is under',
    acts.sent.some((a) => a[0] === `hforum/rep/${acts.ids.good}/${acts.fp}`), JSON.stringify(acts.sent));
  check('Delete deletes the post it is under, with a signed tombstone',
    acts.mineGone && acts.sent.some((a) => a[0] === `hforum/t/${acts.ids.mine}` && /"del":1/.test(a[1])), JSON.stringify(acts.sent));

  const good = await run(`(() => { openTopic(__ids.good); const b = document.querySelector('#view .p-body'); return b ? b.innerHTML : ''; })()`);
  check('ordinary markdown still renders',
    /<b>bold<\/b>/.test(good) && /<i>it<\/i>/.test(good) && /<code>code<\/code>/.test(good)
    && /<a href="https:\/\/example.com\/a"[^>]*>link<\/a>/.test(good) && /<a href="https:\/\/example.org\/b"/.test(good), good);

  win.destroy();
  console.log(`\n${passed} passed, ${failed} failed`);
  app.exit(failed ? 1 : 0);
}).catch((e) => { console.error(e); app.exit(2); });
