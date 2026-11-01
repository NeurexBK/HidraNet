// Starting SevenNine reports what is running, and nothing else.
//
// The browser starts the engine's site builder when the new tab page's card
// is pressed, and it is ready once its port answers. This runs the real
// ProxyManager against stand-ins for hidra-node: one that never opens its
// port, and one that serves it and, asked to stop, closes the port at once
// but takes a moment to exit.
//
//   node hidra-browser/test/sevennine-start.js

'use strict';

const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { ProxyManager } = require('../src/main/proxy-manager');

let passed = 0;
let failed = 0;
const check = (name, cond, why) => {
  if (cond) { passed++; console.log('ok    ' + name); }
  else { failed++; console.log('FAIL  ' + name + (why ? '\n      ' + why : '')); }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch (e) { return false; } };

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-sevennine-'));
const SPAWNS = path.join(tmp, 'spawns.log');
const spawned = () => { try { return fs.readFileSync(SPAWNS, 'utf8').trim().split('\n').filter(Boolean).map(Number); } catch (e) { return []; } };

function fake(name, port, serves) {
  const file = path.join(tmp, name);
  fs.writeFileSync(file, `#!${process.execPath}
'use strict';
require('fs').appendFileSync(${JSON.stringify(SPAWNS)}, process.pid + '\\n');
let srv = null;
if (${serves}) srv = require('http').createServer((q, s) => s.end('ok')).listen(${port}, '127.0.0.1');
process.on('SIGTERM', () => { if (srv) srv.close(); setTimeout(() => process.exit(0), 800); });
setInterval(() => {}, 1 << 30);
`, { mode: 0o755 });
  return file;
}

(async () => {
  const port = await freePort();
  const SILENT = fake('silent', port, false);
  const SERVES = fake('serves', port, true);
  const pm = new ProxyManager();
  pm._findConfig = () => null;
  pm.readyTimeoutMs = 600;
  const start = () => pm._startEngineApp('sevenNineProcess', '--sevennine', port, 'sevennine');

  // ── A child that never opens its port ──
  pm._findHidraNode = () => SILENT;
  const r = await start();
  const [silentPid] = spawned();
  check('a start whose port never opens is reported as failed', !r.ok && /did not open port/.test(r.error || ''), JSON.stringify(r));
  check('and that child is stopped', silentPid && !alive(silentPid), `pid ${silentPid} still running`);
  check('and nothing is left registered as running', !pm.sevenNineRunning());
  pm._findHidraNode = () => SERVES;
  pm.readyTimeoutMs = 20000;
  const again = await start();
  check('the next start runs a new child instead of answering "already running"',
    again.ok && !again.alreadyRunning && spawned().length === 2, JSON.stringify(again));

  // ── A start made while the last child is still exiting ──
  const stopping = pm.stopSevenNine();
  while (await pm._httpPing('127.0.0.1', port, '/')) await sleep(20);   // port closed, process not gone yet
  const next = await start();
  const newer = pm.sevenNineProcess;
  await stopping;
  await sleep(200);
  check('a start during a stop runs its own child', next.ok && !next.alreadyRunning && spawned().length === 3, JSON.stringify(next));
  check('the old child\'s exit does not unregister the new one', pm.sevenNineRunning() && pm.sevenNineProcess === newer);

  await pm.stopSevenNine();
  for (const pid of spawned()) if (alive(pid)) process.kill(pid, 'SIGKILL');
  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
