// Connecting to Tor holds, whoever asks and however often.
//
// The browser starts Tor by itself when it opens, and the new tab page has a
// Connect button. Tor takes from a few seconds to a minute to bootstrap, and
// during that time a second start used to run beside the first: it found the
// port taken by the first Tor, waited twenty seconds, then marked the
// connection failed — while the first Tor was up and carrying the traffic —
// and the kill switch closed again. Pressed once more, the same thing
// happened. To the person at the screen the connection came up and went down
// on its own, and it did so most on a slow network, where the bootstrap is
// long enough to press Connect during it.
//
// This runs the real TorManager against a stand-in for the tor binary that
// behaves as tor does where it matters here: it opens its SOCKS port, climbs
// to 100% over a couple of seconds, and refuses to start on a data directory
// another tor holds.
//
//   node hidra-browser/test/tor-connect.js

'use strict';

const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { TorManager } = require('../src/main/tor-manager');

let passed = 0;
let failed = 0;
const check = (name, cond, why) => {
  if (cond) { passed++; console.log('ok    ' + name); }
  else { failed++; console.log('FAIL  ' + name + (why ? '\n      ' + why : '')); }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-tor-'));
const FAKE = path.join(tmp, 'tor');
const SPAWNS = path.join(tmp, 'spawns.log');
fs.writeFileSync(FAKE, `#!${process.execPath}
'use strict';
const fs = require('fs'), net = require('net'), path = require('path');
const a = process.argv.slice(2);
const port = parseInt(a[a.indexOf('--SocksPort') + 1], 10);
const dir = a[a.indexOf('--DataDirectory') + 1];
fs.appendFileSync(${JSON.stringify(SPAWNS)}, process.pid + '\\n');
const lock = path.join(dir, 'lock');
try { fs.writeFileSync(lock, String(process.pid), { flag: 'wx' }); }
catch (e) {
  console.log('[err] It looks like another Tor process is running with the same data directory.');
  process.exit(1);
}
const bye = () => { try { fs.unlinkSync(lock); } catch (e) {} process.exit(0); };
process.on('SIGTERM', bye);
process.on('SIGINT', bye);
const srv = net.createServer((s) => s.destroy());
srv.on('error', (e) => { console.log('[err] Could not bind to 127.0.0.1:' + port + ': ' + e.code); bye(); });
srv.listen(port, '127.0.0.1', () => {
  console.log('[notice] Opened Socks listener connection (ready) on 127.0.0.1:' + port);
  console.log('[notice] Bootstrapped 0% (starting): Starting');
  setTimeout(() => console.log('[notice] Bootstrapped 50% (loading_descriptors): Loading relay descriptors'), 800);
  setTimeout(() => console.log('[notice] Bootstrapped 100% (done): Done'), 1600);
});
setInterval(() => {}, 1 << 30);
`, { mode: 0o755 });

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

function spawns() {
  try { return fs.readFileSync(SPAWNS, 'utf8').trim().split('\n').filter(Boolean).length; } catch (e) { return 0; }
}

async function manager() {
  const tm = new TorManager(await freePort(), await freePort());
  tm.findBinary = () => FAKE;
  return tm;
}

(async () => {
  // ── Connect pressed while the automatic start is still bootstrapping ──
  {
    fs.rmSync(SPAWNS, { force: true });
    const tm = await manager();
    const data = fs.mkdtempSync(path.join(tmp, 'ud-'));
    const exits = [];
    tm.onUnexpectedExit = (why) => exits.push(why);
    const auto = tm.start(data);
    await sleep(400);                       // the page shows the bootstrap; the person presses Connect
    const pressed = tm.start(data);
    const [a, b] = await Promise.all([auto, pressed]);
    check('the automatic start succeeds', a.ok, JSON.stringify(a));
    check('Connect pressed during the bootstrap succeeds too, instead of "port in use"', b.ok, JSON.stringify(b));
    check('only one tor was started', spawns() === 1, `${spawns()} started`);
    check('the state is ready afterwards', tm.getStatus().state === 'ready', JSON.stringify(tm.getStatus()));
    check('the running tor is not reported as gone', exits.length === 0, exits.join('; '));
    // And again, once it is up: nothing new starts, nothing goes down.
    const again = await tm.start(data);
    check('Connect pressed while connected keeps the connection', again.ok && tm.getStatus().state === 'ready', JSON.stringify(again));
    check('and starts nothing new', spawns() === 1, `${spawns()} started`);
    await tm.stop();
    check('Disconnect stops it', tm.getStatus().state === 'stopped');
  }

  // ── Connect pressed at the very moment the automatic start begins ──
  {
    fs.rmSync(SPAWNS, { force: true });
    const tm = await manager();
    const data = fs.mkdtempSync(path.join(tmp, 'ud-'));
    const exits = [];
    tm.onUnexpectedExit = (why) => exits.push(why);
    const [a, b] = await Promise.all([tm.start(data), tm.start(data)]);
    check('two starts at once both succeed', a.ok && b.ok, JSON.stringify([a, b]));
    check('two starts at once start one tor', spawns() === 1, `${spawns()} started`);
    check('and nothing reports the tor as gone', exits.length === 0, exits.join('; '));
    await tm.stop();
  }

  // ── Disconnect pressed while Tor is still bootstrapping ──
  {
    fs.rmSync(SPAWNS, { force: true });
    const tm = await manager();
    const data = fs.mkdtempSync(path.join(tmp, 'ud-'));
    const pending = tm.start(data);
    await sleep(400);
    const t0 = Date.now();
    await tm.stop();
    const r = await Promise.race([pending, sleep(5000).then(() => 'still waiting')]);
    check('the start that was under way ends at once, as not started', r !== 'still waiting' && !r.ok && Date.now() - t0 < 5000, JSON.stringify(r));
    check('the state is stopped, not failed', tm.getStatus().state === 'stopped', JSON.stringify(tm.getStatus()));
    const again = await tm.start(data);
    check('Connect afterwards starts a fresh tor', again.ok && tm.getStatus().state === 'ready' && spawns() === 2, JSON.stringify(again) + ` ${spawns()} started`);
    await tm.stop();
  }

  // ── A failed start forgets the exit address it no longer has ──
  {
    const tm = await manager();
    tm.exitIp = '185.220.101.147';
    tm.findBinary = () => null;
    const r = await tm.start(fs.mkdtempSync(path.join(tmp, 'ud-')));
    check('a start that fails reports failure', !r.ok && tm.getStatus().state === 'failed', JSON.stringify(r));
    check('and does not keep showing an exit address', tm.getStatus().exitIp === null, String(tm.getStatus().exitIp));
  }

  // ── A port held by something else is still refused ──
  {
    const tm = await manager();
    const squatter = net.createServer((s) => s.destroy());
    await new Promise((r) => squatter.listen(tm.socksPort, '127.0.0.1', r));
    tm._waitPortFree = () => tm._portFree();      // do not wait the full twenty seconds
    const r = await tm.start(fs.mkdtempSync(path.join(tmp, 'ud-')));
    check('a port held by another program is reported, not taken over', !r.ok && /already in use/.test(r.error || ''), JSON.stringify(r));
    squatter.close();
  }

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
