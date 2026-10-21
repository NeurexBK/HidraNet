// HidraChat, HidraMail and the forum, between separate people, through real
// MQTT brokers, including what happens when a broker goes down.
//
// The apps talk through public brokers run by third parties. Each person
// here is a window with a persistent partition of its own (its own storage,
// keys and identity), on the real pages from src/ui, served the way main.js
// serves them: one origin per app under *.localhost, with the same vendor
// and shared scripts. Two local Mosquitto brokers stand in for the public
// ones, and the only change made to the pages is the broker address, in the
// broker list and in the content security policy. Each substitution is
// counted, so the test stops if the pages change under it.
//
// The outage part is what this test is for. When the apps used one broker
// at a time it showed: with the first broker down Mail could not send, a
// newcomer to the forum found it empty and could take someone else's name,
// and once the broker was back the chat room and the forum were split in
// two halves that could not see each other. A broker that was down and comes
// back has also missed what was published meanwhile, so the end of the test
// reads the network through that broker alone.
//
//   cd hidra-browser && xvfb-run -a npx electron --no-sandbox test/apps-e2e.js
//
// Needs mosquitto (apt-get install mosquitto). Exits non-zero if any check
// fails.

const { app, BrowserWindow } = require('electron');
const http = require('http');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const UI = path.join(__dirname, '..', 'src', 'ui');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-apps-e2e-'));

let passed = 0, failed = 0;
function check(name, cond, why) {
  if (cond) { passed++; console.log('ok    ' + name); }
  else { failed++; console.log('FAIL  ' + name + (why ? '\n      ' + why : '')); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const q = (s) => JSON.stringify(s);
const T = (id) => `document.getElementById(${q(id)})`;

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}

// ── two brokers ──

class Broker {
  constructor(name, port) {
    this.name = name;
    this.port = port;
    this.dir = path.join(TMP, name);
    fs.mkdirSync(this.dir, { recursive: true });
    this.conf = path.join(this.dir, 'mosquitto.conf');
    // Persistent, as a public broker is: what it retained is still there
    // when it comes back, and what was published while it was down is not.
    fs.writeFileSync(this.conf, [
      'user root',                 // ignored unless run as root, where it keeps the files writable
      'allow_anonymous true',
      'persistence true',
      `persistence_location ${this.dir}/`,
      'log_dest none',
      `listener ${port} 127.0.0.1`,
      'protocol websockets',
      '',
    ].join('\n'));
    this.proc = null;
  }
  get url() { return `ws://127.0.0.1:${this.port}/mqtt`; }
  async start() {
    this.proc = spawn('mosquitto', ['-c', this.conf], { stdio: 'ignore' });
    for (let i = 0; i < 50; i++) {
      if (await new Promise((r) => { const s = net.connect(this.port, '127.0.0.1', () => { s.end(); r(true); }); s.on('error', () => r(false)); })) return;
      await sleep(100);
    }
    throw new Error(this.name + ' did not start');
  }
  async stop() {
    if (!this.proc) return;
    const p = this.proc;
    this.proc = null;
    await new Promise((r) => { p.once('exit', r); p.kill('SIGTERM'); });
  }
}

// ── the pages, with only the broker address swapped ──

function swap(text, file, pairs) {
  for (const [from, to, n] of pairs) {
    const got = text.split(from).length - 1;
    if (got !== n) throw new Error(`${file}: expected ${n} of ${q(from)}, found ${got}`);
    text = text.split(from).join(to);
  }
  return text;
}
function pages(b1, b2) {
  const list = [
    ["'wss://broker.emqx.io:8084/mqtt'", `'${b1.url}'`, 1],
    ["'wss://broker.hivemq.com:8884/mqtt'", `'${b2.url}'`, 1],
  ];
  const csp = ["connect-src 'self' wss://broker.emqx.io:8084 wss://broker.hivemq.com:8884",
    `connect-src 'self' ws://127.0.0.1:${b1.port} ws://127.0.0.1:${b2.port}`, 1];
  const read = (f) => fs.readFileSync(path.join(UI, f), 'utf8');
  return {
    chat: swap(read('hidrachat.html'), 'hidrachat.html', list),   // its policy already allows ws:
    mail: swap(read('hidramail.html'), 'hidramail.html', [...list, csp]),
    forum: swap(read('forum.html'), 'forum.html', [...list, csp]),
  };
}
const SHARED = {
  '/hidra-store.js': 'hidra-store.js', '/hidrachat-crypto.js': 'hidrachat-crypto.js',
  '/hidra-relays.js': 'hidra-relays.js', '/vendor/mqtt.min.js': 'vendor/mqtt.min.js',
};
function serve(PAGES) {
  return http.createServer((req, res) => {
    const m = /^([a-z]+)\.localhost:\d+$/.exec(String(req.headers.host || ''));
    const name = m && PAGES[m[1]] ? m[1] : null;
    const p = (req.url || '/').split('?')[0];
    if (!name) { res.writeHead(404); res.end(); return; }
    if (p === '/') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(PAGES[name]); return; }
    if (SHARED[p]) { res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' }); res.end(fs.readFileSync(path.join(UI, SHARED[p]))); return; }
    res.writeHead(404); res.end();
  });
}

// ── people ──

let PORT = 0;
const RUN = Date.now().toString(36);
const pageErrors = [];
function person(name) {
  const partition = `persist:apps-e2e-${name}-${RUN}`;
  return {
    async open(appName) {
      const win = new BrowserWindow({
        show: false,
        webPreferences: { partition, contextIsolation: true, nodeIntegration: false, sandbox: true, backgroundThrottling: false },
      });
      win.webContents.on('console-message', (e) => {
        if (e.level === 'error' && !/Electron Security Warning/.test(e.message)) pageErrors.push(`${name}/${appName}: ${e.message}`);
      });
      await win.loadURL(`http://${appName}.localhost:${PORT}/`);
      const run = (js) => win.webContents.executeJavaScript(js);
      const waitFor = async (js, ms) => {
        const end = Date.now() + (ms || 20000);
        while (Date.now() < end) {
          try { const v = await run(js); if (v) return v; } catch (e) { /* not there yet */ }
          await sleep(200);
        }
        return null;
      };
      return { run, waitFor, close: () => win.destroy() };
    },
  };
}

const say = async (w, text) => w.run(`${T('msgInput')}.value=${q(text)}; ${T('sendBtn')}.click(); true`);
const heard = (w, text, ms) => w.waitFor(`${T('messages')}.textContent.indexOf(${q(text)})>=0`, ms || 15000);
const times = (w, text) => w.run(`${T('messages')}.textContent.split(${q(text)}).length-1`);
async function joinChat(w, nick, pass) {
  await w.run(`${T('inNick')}.value=${q(nick)}; ${T('inPass')}.value=${q(pass)}; ${T('btnJoin')}.click(); true`);
  return w.waitFor(`${T('app')}.classList.contains('active') && ${T('connStatus')}.textContent.indexOf('Connected')===0 && ${T('inPass')}.value`, 30000);
}
const mailUp = `${T('ctxt')}.textContent.indexOf('connected')===0 && state.ids.length && state.ids[state.active].addr`;
const send = (w, to, subject, body) => w.run(`sendMail(${q(to)}, ${q(subject)}, ${q(body)}).then(r=>JSON.stringify(r))`).then(JSON.parse);
const inbox = (w, subject) => `state.box.inbox.filter(m=>m.subject===${q(subject)} && m.verified).length`;
const forumUp = `${T('ctxt')}.textContent.indexOf('connected')===0 && state.ready`;
async function signIn(w, name, pass) {
  return w.run(`signIn(${q(name)}, ${q(pass)}).then(ok => ok ? 'in' : (/taken|wrong/i.test(${T('acct-state')}.textContent) ? 'refused' : 'failed'))`);
}
async function post(w, title, body) {
  await w.run(`postTopic('Privacy', ${q(title)}, ${q(body)}); true`);
  return w.waitFor(`(Object.values(state.topics).find(t=>t.title===${q(title)})||{}).id`, 15000);
}
const hasTopic = (w, id) => w.run(`!!state.topics[${q(id)}]`);
const counts = (w) => w.run(`Object.keys(state.claims).length + ' names, ' + Object.keys(state.topics).length + ' topics'`);

app.setPath('userData', TMP);
app.on('window-all-closed', () => {});
app.whenReady().then(async () => {
  if (spawnSync('mosquitto', ['-h']).error) {
    console.log('FAIL  mosquitto is not installed (apt-get install mosquitto)');
    app.exit(1);
    return;
  }
  const b1 = new Broker('first', await freePort());
  const b2 = new Broker('second', await freePort());
  await b1.start(); await b2.start();
  const server = serve(pages(b1, b2));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  PORT = server.address().port;

  const alice = person('alice'), bob = person('bob'), carol = person('carol');
  try {
    // ── 1. Both brokers up ──
    console.log('\n== both brokers up: chat');
    const ca = await A(alice, 'chat');
    const pass = await joinChat(ca, 'alice', '');
    check('Alice creates a room and is given a password to share', pass && pass.length >= 16, String(pass));
    check('the chat connects to both relays', await ca.waitFor(`${T('connStatus')}.textContent==='Connected (2 relays)'`, 15000));
    const cb = await A(bob, 'chat');
    check('Bob joins with the password', !!(await joinChat(cb, 'bob', pass)));
    check('Alice sees Bob join, once', await ca.waitFor(`${T('messages')}.textContent.indexOf('bob joined the room')>=0`, 15000)
      && (await sleep(1500), (await times(ca, 'bob joined the room')) === 1), 'shown ' + (await times(ca, 'bob joined the room')) + ' times');
    await say(ca, 'one ' + RUN);
    check('Bob receives Alice\'s message, once (the copy from the other relay is dropped)',
      await heard(cb, 'one ' + RUN) && (await sleep(1000), (await times(cb, 'one ' + RUN)) === 1));
    await say(cb, 'two ' + RUN);
    check('Alice receives Bob\'s reply', await heard(ca, 'two ' + RUN));
    const cc0 = await A(carol, 'chat');
    await joinChat(cc0, 'carol', 'a-wrong-password-for-this-room');
    await say(ca, 'secret ' + RUN);
    await heard(cb, 'secret ' + RUN);
    await sleep(1000);
    check('a wrong password is another room: Carol sees nothing of it', (await times(cc0, 'secret ' + RUN)) === 0);
    cc0.close();

    console.log('\n== both brokers up: mail');
    const ma = await A(alice, 'mail');
    const addrA = await ma.waitFor(mailUp, 20000);
    let mb = await A(bob, 'mail');
    const addrB = await mb.waitFor(mailUp, 20000);
    check('Alice and Bob each get an address', /^[a-z2-7]{16}@hidra$/.test(addrA || '') && /^[a-z2-7]{16}@hidra$/.test(addrB || '') && addrA !== addrB);
    await sleep(800);
    check('Alice sends to Bob', (await send(ma, addrB, 'hello ' + RUN, 'body one')).ok === true);
    check('Bob receives it once, decrypted and proven to be from Alice',
      await mb.waitFor(`${inbox(mb, 'hello ' + RUN)}===1`, 15000)
      && (await sleep(1000), (await mb.run(inbox(mb, 'hello ' + RUN))) === 1)
      && (await mb.run(`state.box.inbox.find(m=>m.subject===${q('hello ' + RUN)}).from`)) === addrA);
    check('Bob replies and Alice receives it', (await send(mb, addrA, 're ' + RUN, 'body two')).ok === true
      && !!(await ma.waitFor(`${inbox(ma, 're ' + RUN)}===1`, 15000)));
    mb.close();
    check('Alice sends while Bob is away', (await send(ma, addrB, 'away ' + RUN, 'body three')).ok === true);
    mb = await A(bob, 'mail');
    check('Bob comes back to the same address and finds it', (await mb.waitFor(mailUp, 20000)) === addrB
      && !!(await mb.waitFor(`${inbox(mb, 'away ' + RUN)}===1`, 15000)));
    check('an address nobody has is a clear error', /not found/i.test((await send(ma, 'aaaaaaaaaaaaaaaa@hidra', 'x', 'y')).err || ''));

    console.log('\n== both brokers up: forum');
    const fa = await A(alice, 'forum');
    check('Alice reaches the forum', !!(await fa.waitFor(forumUp, 20000)));
    const nameA = 'alice_' + RUN, nameB = 'bob_' + RUN;
    check('Alice registers a username', (await signIn(fa, nameA, 'alice-password-long-' + RUN)) === 'in');
    const t1 = await post(fa, 'first ' + RUN, 'one');
    const t2 = await post(fa, 'second ' + RUN, 'two');
    check('Alice posts two topics', !!t1 && !!t2);
    const fb = await A(bob, 'forum');
    await fb.waitFor(forumUp, 20000);
    check('Bob sees them, signed by Alice', !!(await fb.waitFor(`state.topics[${q(t1)}] && state.topics[${q(t2)}] && state.topics[${q(t2)}].nick===${q(nameA)} && !!state.topics[${q(t2)}].pk`, 15000)));
    check('Bob registers and replies; Alice sees the reply',
      (await signIn(fb, nameB, 'bob-password-long-' + RUN)) === 'in'
      && (await fb.run(`postReply(${q(t2)}, ${q('reply ' + RUN)}); true`))
      && !!(await fa.waitFor(`Object.values(state.replies).some(r=>r.body===${q('reply ' + RUN)} && r.nick===${q(nameB)})`, 15000)));
    const fc0 = await A(carol, 'forum');
    await fc0.waitFor(forumUp, 20000);
    check('Carol cannot take Alice\'s name', (await signIn(fc0, nameA, 'carol-password-long-' + RUN)) === 'refused');
    fc0.close();
    await fa.run(`delOwn('t', ${q(t1)}, ''); true`);
    check('Alice deletes a topic and it goes for Bob too', !!(await fb.waitFor(`!state.topics[${q(t1)}]`, 15000)));

    // ── 2. The first broker down ──
    console.log('\n== the first broker down');
    await b1.stop();
    check('the chat stays connected, on the second relay', !!(await ca.waitFor(`${T('connStatus')}.textContent==='Connected (1 of 2 relays)'`, 20000))
      && !!(await cb.waitFor(`${T('connStatus')}.textContent==='Connected (1 of 2 relays)'`, 20000)));
    await say(ca, 'during ' + RUN);
    check('chat messages still flow', await heard(cb, 'during ' + RUN));
    await ma.waitFor(`${T('ctxt')}.textContent==='connected (1 of 2 relays)'`, 20000);
    check('Mail still sends, and Bob receives it', (await send(ma, addrB, 'outage ' + RUN, 'body four')).ok === true
      && !!(await mb.waitFor(`${inbox(mb, 'outage ' + RUN)}===1`, 15000)));
    const dave = person('dave');
    const fd = await A(dave, 'forum');
    await fd.waitFor(forumUp, 30000);
    const want = await counts(fb), got = await counts(fd);
    check('a newcomer to the forum sees what everyone else does', got === want, `newcomer: ${got}; Bob: ${want}`);
    check('and cannot take Alice\'s name', (await signIn(fd, nameA, 'dave-password-long-' + RUN)) === 'refused');
    fd.close();
    // Meanwhile, things the first broker will have missed.
    const fiona = person('fiona');
    const ff = await A(fiona, 'forum');
    await ff.waitFor(forumUp, 20000);
    const nameF = 'fiona_' + RUN;
    await signIn(ff, nameF, 'fiona-password-long-' + RUN);
    const t3 = await post(ff, 'third ' + RUN, 'posted while the first broker was down');
    check('Fiona registers and posts while the first broker is down', !!t3);
    await fa.run(`delOwn('t', ${q(t2)}, ''); true`);
    check('Alice deletes her other topic while the first broker is down', !!(await fb.waitFor(`!state.topics[${q(t2)}]`, 15000)));
    const mid = await mb.run(`state.box.inbox.find(m=>m.subject===${q('hello ' + RUN)}).mid`);
    await mb.run(`trash(${q(mid)}); trash(${q(mid)}); true`);
    check('Bob deletes a mail for good while the first broker is down', !(await mb.run(`!!findByMid(${q(mid)})`)));

    // ── 3. The first broker back, with what it held before ──
    console.log('\n== the first broker back');
    await b1.start();
    // Each page retries on its own clock, up to 20 s apart after a long outage.
    check('the chat is on both relays again', !!(await ca.waitFor(`${T('connStatus')}.textContent==='Connected (2 relays)'`, 30000)));
    check('so are Mail and the forum', !!(await ma.waitFor(`${T('ctxt')}.textContent==='connected'`, 30000))
      && !!(await mb.waitFor(`${T('ctxt')}.textContent==='connected'`, 30000))
      && !!(await fa.waitFor(`${T('ctxt')}.textContent==='connected'`, 30000))
      && !!(await ff.waitFor(`${T('ctxt')}.textContent==='connected'`, 30000)));
    const cc = await A(carol, 'chat');
    await joinChat(cc, 'carol', pass);
    await say(cc, 'late ' + RUN);
    check('someone joining now reaches the people already in the room', await heard(ca, 'late ' + RUN) && await heard(cb, 'late ' + RUN));
    await say(ca, 'welcome ' + RUN);
    check('and hears them', await heard(cc, 'welcome ' + RUN));
    const t4 = await post(fa, 'fourth ' + RUN, 'after');
    const erin = person('erin');
    const fe = await A(erin, 'forum');
    await fe.waitFor(forumUp, 20000);
    check('a topic posted now reaches someone who just arrived', !!(await fe.waitFor(`!!state.topics[${q(t4)}]`, 15000)));
    fe.close();
    check('the mail Bob deleted does not come back from the first broker', !(await mb.run(`!!findByMid(${q(mid)})`)));
    await sleep(3000);   // each page has had its relay settle and passed on what it was missing

    // ── 4. Only the broker that was down ──
    console.log('\n== only the broker that was down');
    await b2.stop();
    const gina = person('gina');
    const fg = await A(gina, 'forum');
    await fg.waitFor(forumUp, 30000);
    check('Fiona\'s topic, posted while it was down, is there now', !!(await fg.waitFor(`!!state.topics[${q(t3)}]`, 10000)));
    check('Fiona\'s name, registered while it was down, is taken', (await signIn(fg, nameF, 'gina-password-long-' + RUN)) === 'refused');
    check('the topic Alice deleted while it was down is gone', !(await hasTopic(fg, t2)));
    fg.close();
    const mg = await A(gina, 'mail');
    await mg.waitFor(mailUp, 20000);
    check('Mail reaches Bob through it', (await send(mg, addrB, 'only-first ' + RUN, 'body five')).ok === true
      && !!(await mb.waitFor(`${inbox(mb, 'only-first ' + RUN)}===1`, 15000)));
    check('no page logged an error', pageErrors.length === 0, pageErrors.slice(0, 5).join('\n      '));
  } catch (e) {
    check('the run finished', false, e.stack);
  }
  await b1.stop(); await b2.stop();
  console.log(failed ? `\n${failed} check(s) failed` : `\n${passed} checks passed: chat, mail and forum work between people, and through a broker outage`);
  app.exit(failed ? 1 : 0);
});

// A person opening an app.
function A(who, appName) { return who.open(appName); }
