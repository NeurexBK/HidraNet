// The browser's side of the VPN control channel, against a stand-in service.
//
// The real service is Rust, needs root and a TUN device, and is proven end to
// end by hidravpn/scripts/test-browser-netns.sh. This test is about the
// browser's half of the conversation: that every request is one line of JSON
// carrying the token, that every answer the protocol allows is read
// correctly, and above all that every way the service can be absent — not
// installed, not running, not ours to open, answering nonsense, never
// answering — comes back as a state a page can show, never as a crash.
//
//   node hidravpn/browser/test/vpn-manager.js

'use strict';

const assert = require('assert');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');

const { VpnManager, VpnUnavailable, defaultPaths, MAX_ANSWER_BYTES } = require('../src/main/vpn-manager');

if (process.platform === 'win32') {
  console.log('skip  Unix sockets only; the Windows pipe is exercised by the phase-4 Windows test');
  process.exit(0);
}

let failed = 0;
let passed = 0;
const ok = (name) => { passed++; console.log('ok    ' + name); };
const bad = (name, why) => { failed++; console.log('FAIL  ' + name + '\n      ' + why); };

async function check(name, fn) {
  try {
    await fn();
    ok(name);
  } catch (e) {
    bad(name, (e && e.stack) || String(e));
  }
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-vpn-'));
const TOKEN = 'the-token-the-service-wrote';

// A stand-in for hidravpn-service: the same protocol, canned answers, and a
// record of what it was asked.
function fakeService(behaviour) {
  const sockPath = path.join(tmp, `svc-${Math.random().toString(36).slice(2)}.sock`);
  const tokenPath = path.join(tmp, `tok-${Math.random().toString(36).slice(2)}`);
  fs.writeFileSync(tokenPath, TOKEN + '\n', { mode: 0o600 });
  const seen = [];
  let connected = false;
  let refillOn = true;
  const status = () => ({
    connected,
    node_name: connected ? 'exit-a' : null,
    endpoint: connected ? '203.0.113.10:51820' : null,
    last_handshake_secs: connected ? 3 : null,
    tx_bytes: connected ? 1200 : 0,
    rx_bytes: connected ? 34000 : 0,
    killswitch: connected,
    hops: connected ? 2 : 0,
    mode: connected ? 'privado' : '',
    entry_name: connected ? 'entry-a' : null,
    hops_detail: connected
      ? [
          { role: 'entry', node_name: 'entry-a', endpoint: '203.0.113.20:51820', last_handshake_secs: 4, connected: true },
          { role: 'exit', node_name: 'exit-a', endpoint: '203.0.113.10:51820', last_handshake_secs: 3, connected: true },
        ]
      : [],
  });
  const server = net.createServer((sock) => {
    let buf = '';
    sock.on('data', (d) => {
      buf += d.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl === -1) return;
      const line = buf.slice(0, nl);
      seen.push(line);
      if (behaviour && behaviour.raw) { behaviour.raw(sock, line); return; }
      let req;
      try { req = JSON.parse(line); } catch { sock.end(JSON.stringify({ ok: false, error: 'bad request' }) + '\n'); return; }
      let answer;
      if (req.token !== TOKEN) answer = { ok: false, error: 'unauthorised: wrong or missing control token' };
      else if (req.cmd === 'ping') answer = { ok: true };
      else if (req.cmd === 'status') answer = { ok: true, status: status() };
      else if (req.cmd === 'connect') {
        if (req.mode !== 'rapido' && req.mode !== 'privado') answer = { ok: false, error: `unknown mode "${req.mode}": use "rapido" (one hop) or "privado" (two hops)` };
        else if (behaviour && behaviour.emptyPocket) answer = { ok: false, error: 'the pocket has no nodes; add some with `hidravpn nodes add --entry e.json` and `--exit x.json`' };
        else { connected = true; answer = { ok: true, status: status() }; }
      } else if (req.cmd === 'down') { connected = false; answer = { ok: true }; }
      else if (req.cmd === 'new_identity') answer = connected ? { ok: true, status: status(), note: 'new identity: the exit is now exit-b (was exit-a)' } : { ok: false, error: 'not connected; nothing to rotate' };
      else if (req.cmd === 'import_nodes') {
        if (req.signature === 'good-signature' && typeof req.list === 'string') answer = { ok: true, note: 'added 2 node(s)', nodes: [
          { slot: 'entry', node_name: 'entry-1', endpoint: '203.0.113.20:51820' },
          { slot: 'exit', node_name: 'exit-1', endpoint: '203.0.113.10:51820' },
        ] };
        else answer = { ok: false, error: 'the node list is not accepted: the signature does not match: the file was changed, or was not signed with the release key' };
      }
      else if (req.cmd === 'get_passes') {
        if (!fs.existsSync(tokenPath + '.pass')) answer = { ok: false, error: 'no pass account token at /etc/hidravpn/pass.token' };
        else answer = { ok: true, note: `${req.count} pass(es) for 1 node(s); the account has 7 left today`, nodes: [
          { slot: 'exit', node_name: 'node-p', endpoint: '203.0.113.30:51820', admitted: true, admission: 'pass', passes: req.count },
        ] };
      }
      else if (req.cmd === 'refill') {
        if (typeof req.enabled === 'boolean') refillOn = req.enabled;
        answer = { ok: true, refill: { enabled: refillOn, low: 3, count: 10 }, note: refillOn ? 'automatic passes on' : 'automatic passes off' };
      }
      else if (req.cmd === 'set_pass_token') {
        fs.writeFileSync(tokenPath + '.pass', req.pass_token);
        answer = { ok: true, note: 'the account token is kept on this machine, readable by root only' };
      }
      else if (req.cmd === 'nodes') answer = { ok: true, nodes: [
        { slot: 'entry', node_name: 'entry-a', endpoint: '203.0.113.20:51820' },
        { slot: 'exit', node_name: 'exit-a', endpoint: '203.0.113.10:51820' },
      ] };
      else answer = { ok: false, error: `bad request: unknown variant \`${req.cmd}\`` };
      sock.end(JSON.stringify(answer) + '\n');
    });
  });
  return new Promise((resolve) => {
    server.listen(sockPath, () => resolve({ sockPath, tokenPath, seen, server, close: () => new Promise((r) => server.close(r)) }));
  });
}

(async () => {
  // ── The happy path ───────────────────────────────────────────────────────
  {
    const svc = await fakeService();
    const vpn = new VpnManager({ endpoint: svc.sockPath, tokenPath: svc.tokenPath, timeoutMs: 2000 });

    await check('status before connecting is "disconnected" with the kill switch off', async () => {
      const s = await vpn.status();
      assert.strictEqual(s.state, 'disconnected');
      assert.strictEqual(s.report.killswitch, false);
      assert.strictEqual(s.error, null);
    });

    await check('every request is one line of JSON that carries the token', async () => {
      const line = svc.seen[svc.seen.length - 1];
      assert.ok(!line.includes('\n'));
      const req = JSON.parse(line);
      assert.strictEqual(req.token, TOKEN);
      assert.strictEqual(req.cmd, 'status');
    });

    await check('connect("privado") asks the service to pick from the pocket, and comes back connected', async () => {
      const r = await vpn.connect('Privado ');
      assert.strictEqual(r.ok, true, JSON.stringify(r));
      const req = JSON.parse(svc.seen[svc.seen.length - 1]);
      assert.deepStrictEqual(req, { token: TOKEN, cmd: 'connect', mode: 'privado', allow_lan: false, keep_ipv6: false });
      assert.strictEqual(r.status.connected, true);
      assert.strictEqual(r.status.mode, 'privado');
      assert.strictEqual(r.status.hops, 2);
      const s = await vpn.status();
      assert.strictEqual(s.state, 'connected');
      assert.strictEqual(s.report.killswitch, true);
      assert.strictEqual(s.report.hops_detail.length, 2);
    });

    await check('two hops under one operator are asked for only on a strict true', async () => {
      await vpn.connect('privado', { allowSameOperator: 'yes' });
      assert.ok(!('allow_same_operator' in JSON.parse(svc.seen[svc.seen.length - 1])));
      await vpn.connect('privado', { allowSameOperator: true });
      assert.strictEqual(JSON.parse(svc.seen[svc.seen.length - 1]).allow_same_operator, true);
    });

    await check('no invite and no key ever travel between the browser and the service', async () => {
      for (const line of svc.seen) {
        assert.ok(!/public_key|client_address|invite/.test(line), line);
      }
    });

    await check('a mode the service does not know is refused with the two it does', async () => {
      const r = await vpn.connect('turbo');
      assert.strictEqual(r.ok, false);
      assert.ok(/rapido/.test(r.error) && /privado/.test(r.error), r.error);
      // Refused here, before the service was even asked.
      assert.ok(!svc.seen.some((l) => l.includes('turbo')));
    });

    await check('new identity carries the service\'s note about which exit it got', async () => {
      const r = await vpn.newIdentity();
      assert.strictEqual(r.ok, true);
      assert.ok(/exit is now exit-b/.test(r.note), r.note);
    });

    await check('nodes lists slots, names and endpoints, never keys', async () => {
      const r = await vpn.nodes();
      assert.strictEqual(r.ok, true);
      assert.deepStrictEqual(r.nodes.map((n) => [n.slot, n.node_name]), [['entry', 'entry-a'], ['exit', 'exit-a']]);
      assert.ok(r.nodes.every((n) => !('node_public_key' in n)));
    });

    await check('a signed node list goes to the service byte for byte, with its .sig', async () => {
      const list = path.join(tmp, 'nodes.json');
      const text = '{\n  "version": 1,\n  "exits": []\n}\n';
      fs.writeFileSync(list, text);
      fs.writeFileSync(list + '.sig', 'good-signature\n');
      const r = await vpn.importNodesFromFiles(list);
      assert.strictEqual(r.ok, true, JSON.stringify(r));
      assert.strictEqual(r.note, 'added 2 node(s)');
      const req = JSON.parse(svc.seen[svc.seen.length - 1]);
      assert.strictEqual(req.cmd, 'import_nodes');
      assert.strictEqual(req.list, text, 'the list must reach the service exactly as signed');
      assert.strictEqual(req.signature, 'good-signature');
    });

    await check('a list with no .sig beside it is not even sent', async () => {
      const lonely = path.join(tmp, 'lonely.json');
      fs.writeFileSync(lonely, '{}');
      const before = svc.seen.length;
      const r = await vpn.importNodesFromFiles(lonely);
      assert.strictEqual(r.ok, false);
      assert.ok(/no signature beside/.test(r.error), r.error);
      assert.strictEqual(svc.seen.length, before);
    });

    await check('a list the service refuses is reported in the service\'s words', async () => {
      const list = path.join(tmp, 'bad.json');
      fs.writeFileSync(list, '{"version":1}');
      fs.writeFileSync(list + '.sig', 'forged');
      const r = await vpn.importNodesFromFiles(list);
      assert.strictEqual(r.ok, false);
      assert.ok(/not accepted/.test(r.error), r.error);
    });

    await check('a list that is not a regular file is refused before it is read', async () => {
      const r = await vpn.importNodesFromFiles(tmp);
      assert.strictEqual(r.ok, false);
      assert.ok(/not a regular file/.test(r.error), r.error);
    });

    await check('an absurdly large file is refused before it is read', async () => {
      const big = path.join(tmp, 'big.json');
      fs.writeFileSync(big, Buffer.alloc(3 * 1024 * 1024, 0x20));
      fs.writeFileSync(big + '.sig', 'good-signature');
      const r = await vpn.importNodesFromFiles(big);
      assert.strictEqual(r.ok, false);
      assert.ok(/far smaller/.test(r.error), r.error);
    });

    await check('the browser has no way to join a node: open nodes are asked for a fresh key on every connection', async () => {
      assert.strictEqual(typeof vpn.join, 'undefined');
    });

    await check('passes: the token goes to the service once, is never echoed, and passes are counted per node', async () => {
      let r = await vpn.getPasses(5);
      assert.strictEqual(r.ok, false);
      assert.ok(/token/.test(r.error), r.error);
      r = await vpn.setPassToken('two words');
      assert.strictEqual(r.ok, false, 'a token with a space never reaches the service');
      r = await vpn.setPassToken('  acct-token-123\n');
      assert.strictEqual(r.ok, true, JSON.stringify(r));
      assert.deepStrictEqual(JSON.parse(svc.seen[svc.seen.length - 1]), { token: TOKEN, cmd: 'set_pass_token', pass_token: 'acct-token-123' });
      assert.ok(!JSON.stringify(r).includes('acct-token-123'));
      r = await vpn.getPasses(5);
      assert.strictEqual(r.ok, true, JSON.stringify(r));
      assert.strictEqual(r.nodes[0].passes, 5);
      assert.deepStrictEqual(JSON.parse(svc.seen[svc.seen.length - 1]), { token: TOKEN, cmd: 'get_passes', count: 5 });
      await vpn.getPasses(1000, 'node-p');
      assert.deepStrictEqual(JSON.parse(svc.seen[svc.seen.length - 1]), { token: TOKEN, cmd: 'get_passes', count: 10, name: 'node-p' });
    });

    await check('automatic passes are read without changing them, and switched with a boolean only', async () => {
      let r = await vpn.refill();
      assert.strictEqual(r.ok, true, JSON.stringify(r));
      assert.strictEqual(r.refill.enabled, true);
      assert.deepStrictEqual(JSON.parse(svc.seen[svc.seen.length - 1]), { token: TOKEN, cmd: 'refill' });
      r = await vpn.refill(false);
      assert.strictEqual(r.refill.enabled, false);
      assert.deepStrictEqual(JSON.parse(svc.seen[svc.seen.length - 1]), { token: TOKEN, cmd: 'refill', enabled: false });
      r = await vpn.refill('off');
      assert.deepStrictEqual(JSON.parse(svc.seen[svc.seen.length - 1]), { token: TOKEN, cmd: 'refill' }, 'anything but a boolean only reads');
      await vpn.refill(true);
    });

    await check('a list fetched as text goes to the service only with its signature', async () => {
      let r = await vpn.importNodesFromTexts('{"version":1}', 'good-signature\n');
      assert.strictEqual(r.ok, true, JSON.stringify(r));
      assert.strictEqual(JSON.parse(svc.seen[svc.seen.length - 1]).signature, 'good-signature');
      const before = svc.seen.length;
      r = await vpn.importNodesFromTexts('{"version":1}', '');
      assert.strictEqual(r.ok, false);
      assert.ok(/without its signature/.test(r.error), r.error);
      r = await vpn.importNodesFromTexts('', 'sig');
      assert.strictEqual(r.ok, false);
      assert.strictEqual(svc.seen.length, before, 'nothing was sent');
    });

    await check('disconnect brings the state back to "disconnected"', async () => {
      const r = await vpn.disconnect();
      assert.strictEqual(r.ok, true);
      const s = await vpn.status();
      assert.strictEqual(s.state, 'disconnected');
    });

    await check('a service older than the browser is reported as "outdated", with a way out', async () => {
      const old = await fakeService({ raw: (sock, line) => {
        const req = JSON.parse(line);
        sock.end(JSON.stringify(req.cmd === 'status'
          ? { ok: true, status: { connected: false, tx_bytes: 0, rx_bytes: 0, killswitch: false } }
          : { ok: false, error: 'bad request: unknown variant `connect`, expected one of `ping`, `up`, `down`, `status`, `new_identity`' }) + '\n');
      } });
      const v = new VpnManager({ endpoint: old.sockPath, tokenPath: old.tokenPath, timeoutMs: 2000 });
      const s = await v.status();
      assert.strictEqual(s.state, 'disconnected', 'status still works against an old service');
      const r = await v.connect('rapido');
      assert.strictEqual(r.ok, false);
      assert.strictEqual(r.state, 'outdated');
      assert.ok(/Update HidraVPN/.test(r.hint), r.hint);
      await old.close();
    });

    await check('a wrong token is reported as "unauthorised", with a way out', async () => {
      const stale = new VpnManager({ endpoint: svc.sockPath, tokenPath: svc.tokenPath, timeoutMs: 2000,
        fs: { promises: { readFile: async () => 'not-the-token', access: fs.promises.access } } });
      const s = await stale.status();
      assert.strictEqual(s.state, 'unauthorised');
      assert.ok(/Restart/.test(s.hint), s.hint);
      const r = await stale.connect('rapido');
      assert.strictEqual(r.ok, false);
      assert.strictEqual(r.state, 'unauthorised');
    });

    await check('an empty pocket is the service\'s refusal, shown as it was said', async () => {
      const empty = await fakeService({ emptyPocket: true });
      const v = new VpnManager({ endpoint: empty.sockPath, tokenPath: empty.tokenPath, timeoutMs: 2000 });
      const r = await v.connect('rapido');
      assert.strictEqual(r.ok, false);
      assert.ok(/pocket has no nodes/.test(r.error), r.error);
      await empty.close();
    });

    await svc.close();
  }

  // ── Every way the service can be absent ──────────────────────────────────
  await check('no token and no socket: "not-installed"', async () => {
    const vpn = new VpnManager({ endpoint: path.join(tmp, 'nowhere.sock'), tokenPath: path.join(tmp, 'no-token'), timeoutMs: 1000 });
    const s = await vpn.status();
    assert.strictEqual(s.state, 'not-installed');
    assert.ok(s.hint.length > 0);
    const r = await vpn.connect('rapido');
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.state, 'not-installed');
  });

  await check('no token but a socket left from before: "stopped"', async () => {
    const svc = await fakeService();
    await svc.close();
    // node unlinks its socket on close; the real service's socket file stays
    // in /run until the next boot, so put a stand-in back.
    fs.writeFileSync(svc.sockPath, '');
    const vpn = new VpnManager({ endpoint: svc.sockPath, tokenPath: path.join(tmp, 'no-token-either'), timeoutMs: 1000 });
    const s = await vpn.status();
    assert.strictEqual(s.state, 'stopped');
  });

  await check('a token but nothing listening: "stopped"', async () => {
    const svc = await fakeService();
    await svc.close();
    const vpn = new VpnManager({ endpoint: svc.sockPath, tokenPath: svc.tokenPath, timeoutMs: 1000 });
    const s = await vpn.status();
    assert.strictEqual(s.state, 'stopped');
    assert.ok(/start/i.test(s.hint));
  });

  await check('a token this user may not read: "no-permission", naming the group', async () => {
    const denied = new Error('EACCES: permission denied'); denied.code = 'EACCES';
    const vpn = new VpnManager({ endpoint: path.join(tmp, 'x.sock'), tokenPath: path.join(tmp, 'x.tok'), timeoutMs: 1000,
      fs: { promises: { readFile: async () => { throw denied; }, access: fs.promises.access } } });
    const s = await vpn.status();
    assert.strictEqual(s.state, 'no-permission');
    assert.ok(/hidravpn group/.test(s.hint), s.hint);
  });

  await check('a socket this user may not open: "no-permission"', async () => {
    const svc = await fakeService();
    // Root bypasses file modes, so the refusal is what a fake socket reports.
    const { EventEmitter } = require('events');
    const refusing = { createConnection: () => {
      const s = new EventEmitter(); s.destroy = () => {}; s.write = () => {};
      setImmediate(() => { const e = new Error('EACCES: permission denied'); e.code = 'EACCES'; s.emit('error', e); });
      return s;
    } };
    const vpn = new VpnManager({ endpoint: svc.sockPath, tokenPath: svc.tokenPath, timeoutMs: 1000, net: refusing });
    const s = await vpn.status();
    assert.strictEqual(s.state, 'no-permission');
    assert.ok(/hidravpn group/.test(s.hint), s.hint);
    await svc.close();
  });

  await check('an answer that is not JSON: "bad-answer", not a crash', async () => {
    const svc = await fakeService({ raw: (sock) => sock.end('this is not json\n') });
    const vpn = new VpnManager({ endpoint: svc.sockPath, tokenPath: svc.tokenPath, timeoutMs: 1000 });
    const s = await vpn.status();
    assert.strictEqual(s.state, 'bad-answer');
    await svc.close();
  });

  await check('an answer with no verdict: "bad-answer"', async () => {
    const svc = await fakeService({ raw: (sock) => sock.end('{"hello":1}\n') });
    const vpn = new VpnManager({ endpoint: svc.sockPath, tokenPath: svc.tokenPath, timeoutMs: 1000 });
    const s = await vpn.status();
    assert.strictEqual(s.state, 'bad-answer');
    await svc.close();
  });

  await check('a service that closes without a word: "bad-answer"', async () => {
    const svc = await fakeService({ raw: (sock) => sock.end() });
    const vpn = new VpnManager({ endpoint: svc.sockPath, tokenPath: svc.tokenPath, timeoutMs: 1000 });
    const s = await vpn.status();
    assert.strictEqual(s.state, 'bad-answer');
    await svc.close();
  });

  await check('a service that never answers: "timeout", and the socket is closed', async () => {
    const svc = await fakeService({ raw: () => {} });
    const vpn = new VpnManager({ endpoint: svc.sockPath, tokenPath: svc.tokenPath, timeoutMs: 200 });
    const t0 = Date.now();
    const s = await vpn.status();
    assert.strictEqual(s.state, 'timeout');
    assert.ok(Date.now() - t0 < 2000);
    await svc.close();
  });

  await check('a flood instead of an answer is cut off at the limit', async () => {
    const svc = await fakeService({ raw: (sock) => { sock.write(Buffer.alloc(MAX_ANSWER_BYTES + 4096, 0x61)); } });
    const vpn = new VpnManager({ endpoint: svc.sockPath, tokenPath: svc.tokenPath, timeoutMs: 3000 });
    const s = await vpn.status();
    assert.strictEqual(s.state, 'bad-answer');
    await svc.close();
  });

  await check('a command that waits on the network gets the long timeout, a status the short one', async () => {
    const svc = await fakeService({ raw: (sock, line) => {
      setTimeout(() => sock.end('{"ok":true}\n'), 1500);
    } });
    const vpn = new VpnManager({ endpoint: svc.sockPath, tokenPath: svc.tokenPath, timeoutMs: 1000, slowTimeoutMs: 4000 });
    const r = await vpn.request({ cmd: 'connect', mode: 'rapido' });
    assert.strictEqual(r.ok, true, 'a connect that takes longer than the short timeout is still waited for');
    await assert.rejects(vpn.request({ cmd: 'status' }), (e) => e instanceof VpnUnavailable && e.code === 'timeout');
    const d = new VpnManager({});
    assert.strictEqual(d.timeoutMs, 8000);
    assert.strictEqual(d.slowTimeoutMs, 120000);
    await svc.close();
  });

  await check('the default paths are the service\'s own, per platform', async () => {
    assert.deepStrictEqual(defaultPaths('linux'), { endpoint: '/run/hidravpn/control.sock', tokenPath: '/run/hidravpn/control.token' });
    const w = defaultPaths('win32', { ProgramData: 'D:\\PD' });
    assert.strictEqual(w.endpoint, '\\\\.\\pipe\\hidravpn');
    assert.ok(w.tokenPath.endsWith(path.join('HidraVPN', 'control.token')));
  });

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})();
