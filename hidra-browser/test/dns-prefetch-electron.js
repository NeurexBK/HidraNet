// A page cannot make this machine look a name up.
//
// A <link rel="dns-prefetch"> hint is not a URL request: Chromium hands the
// name straight to its host resolver, which knows nothing of the socks5://
// proxy, and neither Tor's route nor the network lock's request filter ever
// sees it. So any page, or any script on one, could have the system resolver
// (the ISP's, usually) look up a name it chose, with a token in it, while the
// panel said names were resolved at the exit relay. main.js now gives
// Chromium HOST_RESOLVER_RULES (network-lock.js), which fail every lookup but
// this machine's own names.
//
// This loads a page full of hints under those rules and reads Chromium's own
// net log: no host-resolver event may name a hinted host. It also checks
// that what the browser needs still works under the rules: a page on
// 127.0.0.1 and on localhost, an app on its *.localhost origin, and Tor's
// SOCKS port on loopback, which must be handed the hostname to resolve.
//
// With HIDRA_DNS_STUB=<address> it also listens for DNS on <address>:53 and
// fails on any query for a hinted name. That needs the system resolver to be
// that address, which needs root, so CI does not do it; on a machine where
// you are root:
//
//   echo nameserver 127.0.0.77 > /tmp/resolv.stub
//   sudo unshare -m sh -c 'mount --bind /tmp/resolv.stub /etc/resolv.conf &&
//     HIDRA_DNS_STUB=127.0.0.77 xvfb-run -a ./node_modules/.bin/electron --no-sandbox test/dns-prefetch-electron.js'
//
//   cd hidra-browser && xvfb-run -a npx electron test/dns-prefetch-electron.js

const { app, BrowserWindow, session, netLog } = require('electron');
const dgram = require('dgram');
const fs = require('fs');
const http = require('http');
const net = require('net');
const os = require('os');
const path = require('path');
const { HOST_RESOLVER_RULES } = require('../src/main/network-lock');
const { LOOPBACK_ONLY } = require('../src/main/proxy-manager');

// As main.js does, before the app is ready.
app.commandLine.appendSwitch('host-resolver-rules', HOST_RESOLVER_RULES);

const failures = [];
const check = (name, ok, detail) => {
  if (ok) console.log('ok    ' + name);
  else {
    console.log('FAIL  ' + name + (detail ? '\n      ' + detail : ''));
    failures.push(name);
  }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const guard = setTimeout(() => { console.log('FAIL  timed out'); process.exit(1); }, 60000);

// Names under .invalid (RFC 6761), each one new, so a query for one can only
// have come from this run.
const tag = 'hidra' + process.pid + Date.now().toString(36);
const HINTED = ['prefetch', 'preconnect', 'anchor', 'late'].map((k) => `${k}-${tag}.invalid`);

const PAGE = `<!doctype html><meta charset="utf-8"><title>hints</title>
<link rel="dns-prefetch" href="//${HINTED[0]}">
<link rel="preconnect" href="https://${HINTED[1]}">
<a href="http://${HINTED[2]}/">a link</a>
<script>
  const l = document.createElement('link');
  l.rel = 'dns-prefetch'; l.href = '//${HINTED[3]}';
  document.head.appendChild(l);
</script>`;

// A stand-in for Tor's SOCKS port: notes the hostname of each CONNECT and
// refuses it.
function fakeTor() {
  const asked = [];
  const server = net.createServer((s) => {
    s.on('error', () => {});
    s.once('data', () => {
      s.write(Buffer.from([5, 0]));
      s.once('data', (d) => {
        if (d[3] === 3) asked.push(d.slice(5, 5 + d[4]).toString());
        s.end(Buffer.from([5, 1, 0, 1, 0, 0, 0, 0, 0, 0]));
      });
    });
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r({ asked, port: server.address().port })));
}

// The names asked of a DNS server on host:53; every answer is NXDOMAIN.
function dnsStub(host) {
  const asked = [];
  const sock = dgram.createSocket('udp4');
  sock.on('message', (m, from) => {
    let i = 12;
    const labels = [];
    while (i < m.length && m[i]) { labels.push(m.slice(i + 1, i + 1 + m[i]).toString()); i += m[i] + 1; }
    asked.push(labels.join('.').toLowerCase());
    const reply = Buffer.from(m.slice(0, i + 5));
    reply[2] = 0x81; reply[3] = 0x83;
    reply.writeUInt16BE(0, 6); reply.writeUInt16BE(0, 8); reply.writeUInt16BE(0, 10);
    sock.send(reply, from.port, from.address);
  });
  return new Promise((resolve, reject) => {
    sock.once('error', reject);
    sock.bind(53, host, () => resolve(asked));
  });
}

async function load(contents, url) {
  try {
    await contents.loadURL(url);
    return 'loaded';
  } catch (e) {
    return e.code || String(e);
  }
}

// Every host-resolver event in a net log, as the text of its parameters.
function resolverEvents(file) {
  const log = JSON.parse(fs.readFileSync(file, 'utf8'));
  const types = new Set(Object.entries(log.constants.logEventTypes)
    .filter(([name]) => name.startsWith('HOST_RESOLVER')).map(([, id]) => id));
  return log.events.filter((e) => types.has(e.type)).map((e) => JSON.stringify(e.params || {}).toLowerCase());
}

app.on('window-all-closed', () => {});

app.whenReady().then(async () => {
  const stub = process.env.HIDRA_DNS_STUB ? await dnsStub(process.env.HIDRA_DNS_STUB) : null;
  const tor = await fakeTor();

  const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.end(req.url === '/hints' ? PAGE : '<!doctype html><title>ok</title>ok');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  const logFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-netlog-')), 'net.json');
  await netLog.startLogging(logFile);

  // A tab's session: Tor's route, loopback around it, as the lock sets it.
  const ses = session.fromPartition('dns-prefetch-test', { cache: false });
  await ses.setProxy({ proxyRules: `socks5://127.0.0.1:${tor.port}`, proxyBypassRules: LOOPBACK_ONLY });
  const win = new BrowserWindow({ show: false, webPreferences: { session: ses, sandbox: true, contextIsolation: true } });

  // What the browser itself needs, under the rules.
  check('a page on 127.0.0.1 still loads (Tor\'s port and SevenNine are there)', (await load(win.webContents, `http://127.0.0.1:${port}/`)) === 'loaded');
  check('a page on localhost still loads', (await load(win.webContents, `http://localhost:${port}/`)) === 'loaded');
  check('an app on its *.localhost origin still loads', (await load(win.webContents, `http://chat.localhost:${port}/`)) === 'loaded');
  const remote = `site-${tag}.example`;
  await load(win.webContents, `http://${remote}/`);
  check('a website goes to Tor\'s port by name, for Tor to resolve', tor.asked.includes(remote), JSON.stringify(tor.asked));

  // The hints, from a page on the apps' kind of origin.
  check('the page with the hints loads', (await load(win.webContents, `http://localhost:${port}/hints`)) === 'loaded');
  await sleep(2500);
  await netLog.stopLogging();

  const events = resolverEvents(logFile);
  check('the net log records host lookups at all (it names localhost)', events.some((p) => p.includes('localhost')), `${events.length} resolver event(s)`);
  for (const name of HINTED) {
    check(`no lookup of the ${name.split('-')[0]} hint's name reaches the host resolver`, !events.some((p) => p.includes(name)),
      events.filter((p) => p.includes(name)).slice(0, 2).join('\n      '));
  }
  check('no hinted name was sent to Tor either (nothing asked for it)', HINTED.every((n) => !tor.asked.includes(n)), JSON.stringify(tor.asked));

  if (stub) {
    const leaked = stub.filter((q) => q.includes(tag));
    check('the system resolver was asked for none of the hinted names', leaked.length === 0, JSON.stringify(leaked));
  } else {
    console.log('skip  HIDRA_DNS_STUB is not set: the system resolver itself was not watched');
  }

  clearTimeout(guard);
  console.log(`\n${failures.length ? failures.length + ' failed' : 'no page can make this machine look a name up'}`);
  process.exit(failures.length ? 1 : 0);
}).catch((e) => { console.error(e); process.exit(1); });
