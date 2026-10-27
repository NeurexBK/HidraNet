'use strict';
const assert = require('assert');
const { VpnManager } = require('../src/main/vpn-manager');
(async () => {
  const manager = Object.create(VpnManager.prototype);
  const seen = [];
  manager._command = async cmd => { seen.push(cmd); return { ok: true }; };
  for (const input of [null, {}, { action: 'delete' }, { action: 'buy', passes: -1 }, { action: 'buy', passes: 1.5 }, { action: 'claim', signature: 'invalid' }]) {
    assert.strictEqual((await manager.checkout(input)).ok, false);
  }
  assert.strictEqual(seen.length, 0);
  await manager.checkout({ action: 'buy', passes: 150, url: 'https://attacker.invalid', token: 'secret', replace_unpaid: 'true' });
  assert.deepStrictEqual(seen.pop(), { cmd: 'checkout', action: 'buy', passes: 150, replace_unpaid: false });
  await manager.checkout({ action: 'claim', signature: '1'.repeat(64), url: 'https://attacker.invalid' });
  assert.deepStrictEqual(seen.pop(), { cmd: 'checkout', action: 'claim', signature: '1'.repeat(64) });
  await manager.checkout({ action: 'status', signature: 'secret' });
  assert.deepStrictEqual(seen.pop(), { cmd: 'checkout', action: 'status' });
  console.log('PASS: invalid checkout inputs rejected; only allowed fields cross the service channel');
})().catch(error => { console.error(error); process.exitCode = 1; });
