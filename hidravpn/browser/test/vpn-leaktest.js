// The one-click leak test: every verdict comes from the service or from what
// the address checks actually answered, and nothing is green by default.
//
//   node hidravpn/browser/test/vpn-leaktest.js

'use strict';

const assert = require('assert');
const { runLeakTest, IPV4_URL, IPV6_URL, hostOf, normalizeIp } = require('../src/main/vpn-leaktest');

let passed = 0;
let failed = 0;
async function check(name, fn) {
  try {
    await fn();
    passed++;
    console.log('ok    ' + name);
  } catch (e) {
    failed++;
    console.log('FAIL  ' + name + '\n      ' + (e && e.stack ? e.stack.split('\n').slice(0, 3).join('\n      ') : e));
  }
}

const connected = (over = {}) => ({
  state: 'connected',
  report: {
    connected: true,
    killswitch: true,
    endpoint: '203.0.113.20:51820',
    last_handshake_secs: 5,
    hops_detail: [
      { role: 'entry', node_name: 'n1', endpoint: '203.0.113.10:51820', connected: true, last_handshake_secs: 4 },
      { role: 'exit', node_name: 'n2', endpoint: '203.0.113.20:51820', connected: true, last_handshake_secs: 5 },
    ],
    ...over,
  },
});
const answers = (v4, v6) => async (url) => {
  if (url === IPV4_URL) { if (v4 instanceof Error) throw v4; return JSON.stringify({ ip: v4 }); }
  if (url === IPV6_URL) { if (v6 instanceof Error) throw v6; return JSON.stringify({ ip: v6 }); }
  throw new Error('unexpected ' + url);
};
const by = (r, id) => r.checks.find((c) => c.id === id);

(async () => {
  await check('not connected: the test does not run and says why', async () => {
    const r = await runLeakTest({ state: 'disconnected', report: { connected: false } }, answers('192.0.2.4', new Error('x')));
    assert.strictEqual(r.ran, false);
    assert.ok(/connect first/.test(r.error));
    const u = await runLeakTest({ state: 'not-installed', report: null }, answers('192.0.2.4', new Error('x')));
    assert.strictEqual(u.ran, false);
  });

  await check('the exit address seen, no IPv6, kill switch armed: all pass', async () => {
    const r = await runLeakTest(connected(), answers('203.0.113.20', new Error('no route')));
    assert.strictEqual(r.verdict, 'pass');
    assert.deepStrictEqual(r.checks.map((c) => c.verdict), ['pass', 'pass', 'pass', 'pass']);
    assert.ok(/203\.0\.113\.20/.test(by(r, 'ipv4').detail));
  });

  await check('the exit address is the exit hop\'s, not the entry\'s', async () => {
    const r = await runLeakTest(connected(), answers('203.0.113.10', new Error('no route')));
    assert.strictEqual(by(r, 'ipv4').verdict, 'warn');
  });

  await check('with an exit that carries IPv6, an IPv6 answer is the tunnel working, and no answer is a doubt', async () => {
    let r = await runLeakTest(connected({ ipv6: true }), answers('203.0.113.20', '2001:db8::20'));
    assert.strictEqual(by(r, 'ipv6').verdict, 'pass');
    assert.ok(by(r, 'ipv6').detail.includes('2001:db8::20'));
    r = await runLeakTest(connected({ ipv6: true }), answers('203.0.113.20', new Error('no route')));
    assert.strictEqual(by(r, 'ipv6').verdict, 'warn');
  });

  await check('an IPv6 answer is a leak', async () => {
    const r = await runLeakTest(connected(), answers('203.0.113.20', '2001:db8::1'));
    assert.strictEqual(by(r, 'ipv6').verdict, 'fail');
    assert.strictEqual(r.verdict, 'fail');
  });

  await check('another IPv4 address is a warning that names both, not a pass', async () => {
    const r = await runLeakTest(connected(), answers('198.51.100.7', new Error('x')));
    const c = by(r, 'ipv4');
    assert.strictEqual(c.verdict, 'warn');
    assert.ok(/198\.51\.100\.7/.test(c.detail) && /203\.0\.113\.20/.test(c.detail), c.detail);
  });

  await check('no answer from the address check is unknown, never a pass', async () => {
    const r = await runLeakTest(connected(), answers(new Error('timeout'), new Error('x')));
    assert.strictEqual(by(r, 'ipv4').verdict, 'warn');
  });

  await check('kill switch off fails the kill switch and DNS, and asks no website anything', async () => {
    let asked = 0;
    const r = await runLeakTest(connected({ killswitch: false }), async () => { asked++; return JSON.stringify({ ip: '203.0.113.20' }); });
    assert.strictEqual(by(r, 'killswitch').verdict, 'fail');
    assert.strictEqual(by(r, 'dns').verdict, 'fail');
    assert.strictEqual(by(r, 'ipv4').verdict, 'fail');
    assert.ok(/Not run/.test(by(r, 'ipv4').detail));
    assert.strictEqual(asked, 0, 'with the kill switch off the address check could see this machine\'s own address');
  });

  await check('an exit that has not shaken hands lately: the test waits, asking nothing', async () => {
    let asked = 0;
    const stale = connected();
    stale.report.hops_detail[1].last_handshake_secs = 600;
    const r = await runLeakTest(stale, async () => { asked++; return '{}'; });
    assert.strictEqual(r.ran, false);
    assert.ok(/shaken hands/.test(r.error), r.error);
    const never = connected();
    never.report.hops_detail[1].last_handshake_secs = null;
    never.report.last_handshake_secs = null;
    assert.strictEqual((await runLeakTest(never, async () => { asked++; return '{}'; })).ran, false);
    assert.strictEqual(asked, 0);
  });

  await check('an answer that is not an address is not trusted', async () => {
    const r = await runLeakTest(connected(), async (url) => (url === IPV4_URL ? '<html>' : JSON.stringify({ ip: '<b>x</b>' })));
    assert.strictEqual(by(r, 'ipv4').verdict, 'warn');
    assert.strictEqual(by(r, 'ipv6').verdict, 'pass');
  });

  // ── Endpoints in every form a node can be listed with ──────────────────
  // Documentation addresses only (RFC 5737, RFC 3849).
  await check('hostOf reads all four forms: [v6]:port, v6, v4:port and v4', async () => {
    assert.strictEqual(hostOf('[2001:db8::1]:51820'), '2001:db8::1');
    assert.strictEqual(hostOf('2001:db8::1'), '2001:db8::1');
    assert.strictEqual(hostOf('192.0.2.1:51820'), '192.0.2.1');
    assert.strictEqual(hostOf('192.0.2.1'), '192.0.2.1');
    assert.strictEqual(hostOf('[2001:db8::1]'), '2001:db8::1');
    assert.strictEqual(hostOf(' 198.51.100.7:51820 '), '198.51.100.7');
  });

  await check('IPv6 is put in one canonical form before comparing', async () => {
    assert.strictEqual(hostOf('[2001:DB8:0:0:0:0:0:1]:51820'), '2001:db8::1');
    assert.strictEqual(hostOf('2001:0db8:0000::0001'), '2001:db8::1');
    assert.strictEqual(normalizeIp('2001:DB8::A'), '2001:db8::a');
    assert.strictEqual(normalizeIp('::ffff:192.0.2.1'), '192.0.2.1', 'an IPv4 address written as IPv6 is that IPv4 address');
    assert.strictEqual(normalizeIp('not-an-address'), 'not-an-address');
  });

  const exitAt = (endpoint) => connected({
    endpoint,
    hops_detail: [
      { role: 'entry', node_name: 'n1', endpoint: '198.51.100.10:51820', connected: true, last_handshake_secs: 4 },
      { role: 'exit', node_name: 'n2', endpoint, connected: true, last_handshake_secs: 5 },
    ],
  });

  await check('an exit listed as [v6]:port passes when its address is seen', async () => {
    const r = await runLeakTest(exitAt('[2001:db8::20]:51820'), answers('2001:db8:0:0::20', new Error('no route')));
    assert.strictEqual(by(r, 'ipv4').verdict, 'pass', by(r, 'ipv4').detail);
  });

  await check('an exit listed as a bare v6 address passes when its address is seen', async () => {
    const r = await runLeakTest(exitAt('2001:db8::20'), answers('2001:DB8::20', new Error('no route')));
    assert.strictEqual(by(r, 'ipv4').verdict, 'pass', by(r, 'ipv4').detail);
  });

  await check('an exit listed as v4:port and as bare v4 both pass when its address is seen', async () => {
    for (const ep of ['192.0.2.20:51820', '192.0.2.20']) {
      const r = await runLeakTest(exitAt(ep), answers('192.0.2.20', new Error('no route')));
      assert.strictEqual(by(r, 'ipv4').verdict, 'pass', `${ep}: ${by(r, 'ipv4').detail}`);
    }
  });

  await check('an IPv4 exit seen as ::ffff:v4 is the same address', async () => {
    const r = await runLeakTest(exitAt('192.0.2.20:51820'), answers('::ffff:192.0.2.20', new Error('no route')));
    assert.strictEqual(by(r, 'ipv4').verdict, 'pass', by(r, 'ipv4').detail);
  });

  await check('another IPv6 address is still a warning that names both', async () => {
    const r = await runLeakTest(exitAt('[2001:db8::20]:51820'), answers('2001:db8::21', new Error('no route')));
    const c = by(r, 'ipv4');
    assert.strictEqual(c.verdict, 'warn');
    assert.ok(/2001:db8::21/.test(c.detail) && /2001:db8::20/.test(c.detail), c.detail);
  });

  await check('a port is never taken for part of the address', async () => {
    const r = await runLeakTest(exitAt('192.0.2.20:51820'), answers('192.0.2.2', new Error('no route')));
    assert.strictEqual(by(r, 'ipv4').verdict, 'warn', 'a prefix of the address passed');
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})();
