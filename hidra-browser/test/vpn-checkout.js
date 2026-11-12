// Buying passes from the VPN page: what crosses from the page to the
// service (vpn-manager.js `checkout`), and what an older service answers.
//
// The page may name an action, a pack (with the person's word that the open
// order on screen is unpaid, naming it by its amount in raw units) and a
// transaction's signature, and nothing else: a
// wallet, a mint, an issuer, a price or an account token it puts in never
// reaches the service. Bad input is refused before anything is sent. A
// service from before checkout answers "unknown variant", which comes back
// as `older`, so the page can say to update HidraVPN instead of breaking.
//
//   node hidra-browser/test/vpn-checkout.js

'use strict';

const assert = require('assert');
const { VpnManager } = require('../src/main/vpn-manager');

let passed = 0;
let failed = 0;
async function check(name, fn) {
  try {
    await fn();
    passed++;
    console.log('ok    ' + name);
  } catch (e) {
    failed++;
    console.log('FAIL  ' + name + '\n      ' + (e && e.message ? e.message : e));
  }
}

// A manager whose channel is a function: it records the commands sent and
// answers them as `answer` says, without a socket.
function manager(answer = () => ({ ok: true, checkout: { state: 'idle', message: '' } })) {
  const m = Object.create(VpnManager.prototype);
  const seen = [];
  m.request = async (cmd) => { seen.push(cmd); return answer(cmd); };
  return { m, seen };
}

const SIG = '5VERv8NMvzbJMEkV8xnrLkEaWRtSz2CosKDYVCJjrRo'.padEnd(87, '1');

(async () => {
  await check('bad input is refused before anything reaches the service', async () => {
    const { m, seen } = manager();
    for (const input of [undefined, null, 'buy', 42, {}, { action: 'delete' }, { action: 'pay' }, { action: 'Buy', passes: 10 },
      { action: 'buy' }, { action: 'buy', passes: -1 }, { action: 'buy', passes: 0 }, { action: 'buy', passes: 1.5 },
      { action: 'buy', passes: '150' }, { action: 'buy', passes: 2 ** 32 }, { action: 'claim' },
      { action: 'claim', signature: 'invalid' }, { action: 'claim', signature: '0'.repeat(64) },
      { action: 'claim', signature: 'l'.repeat(64) }, { action: 'claim', signature: '1'.repeat(89) },
      { action: 'claim', signature: ['1'.repeat(64)] }]) {
      const r = await m.checkout(input);
      assert.strictEqual(r.ok, false, JSON.stringify(input));
      assert.ok(typeof r.error === 'string' && r.error.length > 0, JSON.stringify(input));
    }
    assert.strictEqual(seen.length, 0, JSON.stringify(seen));
  });

  await check('a wallet, mint, issuer, price or token the page puts in never reaches the service', async () => {
    const { m, seen } = manager();
    const extra = { wallet: 'ExYv4idyqxmuodpoZtxyGxeTGi6oYrqFAshAgCsRissc', recipient: 'x', mint: 'y', issuer: 'https://attacker.invalid',
      url: 'https://attacker.invalid', amount: '5.99', price: '1', usd: '5.99', token: 'secret', pass_token: 'secret', cmd: 'up' };
    await m.checkout({ action: 'status', signature: 'secret', passes: 10, ...extra });
    assert.deepStrictEqual(seen.pop(), { cmd: 'checkout', action: 'status' });
    await m.checkout({ action: 'packs', ...extra });
    assert.deepStrictEqual(seen.pop(), { cmd: 'checkout', action: 'packs' });
    // The word that the order on screen is unpaid names it by its amount,
    // digits only; anything else is no such word, and replaces nothing.
    for (const notOne of ['true', true, 149563032846, '', ' 149563032846', '1.5', '-1', '1'.repeat(21), ['1'], { raw: '1' }]) {
      await m.checkout({ action: 'buy', passes: 150, replace_unpaid: notOne, ...extra });
      assert.deepStrictEqual(seen.pop(), { cmd: 'checkout', action: 'buy', passes: 150 }, JSON.stringify(notOne));
    }
    await m.checkout({ action: 'buy', passes: 150, replace_unpaid: '149563032846', ...extra });
    assert.deepStrictEqual(seen.pop(), { cmd: 'checkout', action: 'buy', passes: 150, replace_unpaid: '149563032846' });
    await m.checkout({ action: 'claim', signature: '  ' + SIG + '\n', passes: 150, replace_unpaid: true, ...extra });
    assert.deepStrictEqual(seen.pop(), { cmd: 'checkout', action: 'claim', signature: SIG });
    assert.strictEqual(seen.length, 0);
  });

  await check('an order or a claim waits as long as the issuer may take: checkout is a slow command', async () => {
    const m = Object.create(VpnManager.prototype);
    m.timeoutMs = 8000;
    m.slowTimeoutMs = 120000;
    m.platform = 'linux';
    m._readToken = async () => 'control';
    m._readServiceKey = async () => null;
    let waited = null;
    m._roundTrip = async (line, ms) => { waited = ms; return JSON.stringify({ ok: true, checkout: { state: 'idle', message: '' } }); };
    const r = await m.checkout({ action: 'claim', signature: SIG });
    assert.strictEqual(r.ok, true);
    assert.strictEqual(waited, 120000);
  });

  await check('a service older than checkout makes the page say to update HidraVPN, not break', async () => {
    // What a 0.1.2 service answers: it does not know the command.
    const m = Object.create(VpnManager.prototype);
    m.timeoutMs = 8000;
    m.slowTimeoutMs = 120000;
    m.platform = 'linux';
    m._readToken = async () => 'control';
    m._readServiceKey = async () => null;
    m._roundTrip = async () => JSON.stringify({ ok: false,
      error: 'bad request: unknown variant `checkout`, expected one of `ping`, `up`, `down`, `status`, `new_identity`, `connect`, `nodes`, `import_nodes`, `join`, `get_passes`, `set_pass_token`, `refill`' });
    const r = await m.checkout({ action: 'status' });
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.older, true);
    assert.strictEqual(r.state, 'outdated');
    assert.ok(/Update HidraVPN/.test(r.hint), r.hint);
  });

  await check('the service\'s answer comes back as it is, checkout and all', async () => {
    const view = { state: 'awaiting_payment', message: 'm', order: { passes: 150, amount: '149563.032846', token: 'HNET',
      wallet: 'So11111111111111111111111111111111111111112', expires: '2099-01-01T00:00:00Z', payable: true } };
    const { m } = manager(() => ({ ok: true, checkout: view }));
    const r = await m.checkout({ action: 'status' });
    assert.deepStrictEqual(r, { ok: true, checkout: view });
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
