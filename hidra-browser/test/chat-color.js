// A chat member's colour is data from a stranger, and it must stay data.
//
// HidraChat used to paste the `color` field of other members' messages
// straight into the page's HTML (style="background:'+m.color+'"). A colour
// such as   red"><img src=x onerror=...>   closed the attribute and ran its
// script in every member's chat, inside one of our own pages. This loads the
// real page in Chromium and feeds it hostile colours by both roads a colour
// arrives, exactly as a stranger would send them:
//
//   - the public relay: messages encrypted with the room password and
//     delivered through the MQTT client (a stand-in that only delivers);
//   - a chat server of one's own: a WebSocket server that sends the member
//     list, the history, a "joined" notice and a message.
//
// It checks that nothing runs, nothing is injected, and the colour shown is
// the one sent when it is a real colour (#rgb … #rrggbbaa), or the member's
// usual colour when it is not.
//
//   cd hidra-browser && xvfb-run -a npx electron test/chat-color.js

const { app, BrowserWindow } = require('electron');
const path = require('path');
const { pathToFileURL } = require('url');
const { WebSocketServer } = require('ws');

const PAGE = pathToFileURL(path.join(__dirname, '..', 'src', 'ui', 'hidrachat.html')).href;

const HOSTILE = [
  'red"><img src=x onerror="window.__pwned=(window.__pwned||0)+1">',
  "red'><img src=x onerror=window.__pwned=1>",
  '#fff" onmouseover="window.__pwned=1',
  'red;background-image:url(https://example.com/track.png)',
  'expression(alert(1))',
  '#12345g',
  '#ff0000"><b>x</b>',
  ['#ff0000"><b>x</b>'],
  { a: 1 },
  42,
  null,
];
const GOOD = '#ff0000';
const VALID = /^#[0-9a-fA-F]{3,8}$/;
// What the page may put in a style attribute: one colour, nothing else.
const STYLE_OK = /^(background|color): ?(rgb\(\d+, \d+, \d+\)|rgba\(\d+, \d+, \d+, [\d.]+\)|#[0-9a-fA-F]{3,8});?$/;

let passed = 0;
let failed = 0;
const check = (name, cond, why) => {
  if (cond) { passed++; console.log('ok    ' + name); }
  else { failed++; console.log('FAIL  ' + name + (why ? '\n      ' + why : '')); }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function newWindow() {
  return new BrowserWindow({
    show: false,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
}

// What the page shows, read back from its DOM.
const INSPECT = `(() => {
  const styled = [...document.querySelectorAll('#messages [style], #userList [style]')];
  return {
    pwned: window.__pwned || 0,
    injected: document.querySelectorAll('#messages img, #messages b, #userList img, #userList b, [onmouseover]').length,
    styles: styled.map((el) => el.getAttribute('style')),
    avatars: [...document.querySelectorAll('#messages .msg.other')].map((m) => ({
      nick: (m.querySelector('.bubble-nick') || {}).textContent,
      avatar: (m.querySelector('.avatar') || {}).style ? m.querySelector('.avatar').style.background : '',
      name: (m.querySelector('.bubble-nick') || {}).style ? m.querySelector('.bubble-nick').style.color : '',
    })),
    dots: [...document.querySelectorAll('#userList .user-item')].map((d) => ({
      nick: d.dataset.nick, dot: d.querySelector('.user-dot').style.background,
    })),
  };
})()`;

// The page's usual colour for a nickname, computed the way the page does.
const PALETTE = ['#00d4aa', '#ff6b6b', '#4ecdc4', '#45b7d1', '#f9ca24', '#fd79a8', '#6c5ce7', '#e17055',
  '#0984e3', '#00b894', '#e84393', '#00cec9', '#fdcb6e', '#a29bfe', '#74b9ff'];
function colorFor(s) { let h = 0; s = s || ''; for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0; return PALETTE[h % PALETTE.length]; }
const rgb = (hex) => { const n = parseInt(hex.slice(1), 16); return `rgb(${n >> 16}, ${(n >> 8) & 255}, ${n & 255})`; };

function judge(where, seen) {
  check(`${where}: no script from a colour ran`, seen.pwned === 0, `window.__pwned = ${seen.pwned}`);
  check(`${where}: no element was injected through a colour`, seen.injected === 0, `${seen.injected} injected`);
  const badStyles = seen.styles.filter((s) => !STYLE_OK.test(String(s).trim()));
  check(`${where}: every style the page set is one colour and nothing else`,
    seen.styles.length > 0 && badStyles.length === 0, badStyles.join(' | ') || 'no styled elements at all');
  const wrong = [];
  for (const a of seen.avatars) {
    const want = a.nick.startsWith('good') ? rgb(GOOD) : rgb(colorFor(a.nick));
    if (a.avatar !== want || a.name !== want) wrong.push(`${a.nick}: ${a.avatar} / ${a.name}, want ${want}`);
  }
  for (const d of seen.dots) {
    const want = d.nick.startsWith('good') ? rgb(GOOD) : rgb(colorFor(d.nick));
    if (d.dot !== want) wrong.push(`list ${d.nick}: ${d.dot}, want ${want}`);
  }
  check(`${where}: a real colour is kept, any other falls back to the member's usual colour`,
    seen.avatars.length > 0 && wrong.length === 0, wrong.join('\n      ') || 'no messages from others rendered');
}

// ── 1. The public relay ────────────────────────────────────────────────────
async function viaRelay() {
  const win = newWindow();
  await win.loadURL(PAGE);
  const run = (js) => win.webContents.executeJavaScript(js);
  const PASS = 'correct horse battery staple 1729';
  // A stand-in MQTT client: it connects at once and hands the page whatever
  // the test delivers. Nothing leaves the machine.
  await run(`window.mqtt = { connect() {
    const h = {}; const c = {
      on(ev, fn) { h[ev] = fn; if (ev === 'connect') setTimeout(fn, 0); return c; },
      subscribe() {}, publish() {}, end() {},
    }; window.__relay = h; return c; } }; 1`);
  await run(`document.getElementById('inNick').value = 'me';
    document.getElementById('inPass').value = ${JSON.stringify(PASS)};
    document.getElementById('btnJoin').click(); 1`);
  for (let i = 0; i < 50 && !(await run('!!(window.__relay && window.__relay.message)')); i++) await sleep(100);
  // The stranger: the room password, a colour of their choosing. Messages
  // are made with the page's own room crypto (scrypt key, signed, sealed),
  // each from a fresh identity, exactly as another member's client makes them.
  await run(`(async () => {
    const room = await hidraRoom.deriveRoom(${JSON.stringify(PASS)});
    const deliver = async (who, obj) => {
      const sealed = await hidraRoom.seal(room.key, who, obj);
      window.__relay.message('hidra/' + room.topic, { toString: () => sealed.wire });
    };
    const HOSTILE = ${JSON.stringify(HOSTILE)};
    for (let i = 0; i < HOSTILE.length; i++) {
      const eve = await hidraRoom.newIdentity();
      await deliver(eve, { k: 'presence', nick: 'eve' + i, color: HOSTILE[i] });
      await deliver(eve, { k: 'msg', nick: 'eve' + i, color: HOSTILE[i], text: 'hi' });
    }
    await deliver(await hidraRoom.newIdentity(), { k: 'msg', nick: 'good-relay', color: ${JSON.stringify(GOOD)}, text: 'hi' });
  })()`);
  await sleep(800); // let every render finish and any onerror fire
  const seen = await run(INSPECT);
  win.destroy();
  return seen;
}

// ── 2. A chat server of one's own ──────────────────────────────────────────
async function viaServer() {
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((r) => wss.on('listening', r));
  const port = wss.address().port;
  wss.on('connection', (sock) => {
    sock.on('message', () => {
      const send = (o) => sock.send(JSON.stringify(o));
      send({
        type: 'welcome', count: HOSTILE.length + 2,
        users: HOSTILE.map((c, i) => ({ nick: 'listed' + i, color: c })).concat([{ nick: 'good-listed', color: GOOD }]),
        history: HOSTILE.map((c, i) => ({ type: 'msg', nick: 'old' + i, color: c, text: 'earlier' })),
      });
      HOSTILE.forEach((c, i) => {
        send({ type: 'joined', nick: 'joiner' + i, color: c, count: 3 });
        send({ type: 'msg', nick: 'mallory' + i, color: c, text: 'hi' });
      });
      send({ type: 'msg', nick: 'good-server', color: GOOD, text: 'hi' });
    });
  });
  const win = newWindow();
  await win.loadURL(PAGE);
  const run = (js) => win.webContents.executeJavaScript(js);
  await run(`document.getElementById('inNick').value = 'me';
    document.getElementById('inServer').value = '127.0.0.1:${port}';
    document.getElementById('btnJoin').click(); 1`);
  for (let i = 0; i < 50 && !(await run("document.querySelectorAll('#messages .msg.other').length > 0")); i++) await sleep(100);
  await sleep(800);
  const seen = await run(INSPECT);
  win.destroy();
  wss.close();
  return seen;
}

app.on('window-all-closed', () => {});

app.whenReady().then(async () => {
  judge('relay', await viaRelay());
  judge('own server', await viaServer());
  console.log(`\n${passed} passed, ${failed} failed`);
  app.exit(failed ? 1 : 0);
}).catch((e) => { console.error(e); app.exit(2); });
