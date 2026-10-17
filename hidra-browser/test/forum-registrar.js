// The forum's registrar (tools/forum-registrar.js), driven without a relay:
// claims go in as the relay would hand them over, and what comes out is the
// signed list the page trusts. Then the page's side of the contract, through
// the shared module: a list signed by the wrong key, or an older sequence,
// is refused.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..');
const room = require(path.join(ROOT, 'hidra-browser', 'src', 'ui', 'hidrachat-crypto.js'));
const tool = require(path.join(ROOT, 'hidra-browser', 'tools', 'forum-registrar.js'));
const FAST = { N: 16, r: 1, p: 1 };
let passed = 0;

async function test(name, fn) {
  await fn();
  console.log('ok    ' + name);
  passed++;
}

async function claimFor(id, norm, shown, ts) {
  const c = { v: 2, name: shown, pk: id.pub, ts };
  c.sig = await room.signFields(id, ['claim', norm, shown, id.pub, ts]);
  return JSON.stringify(c);
}

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-registrar-'));

  await test('keygen writes a private key the owner keeps, and prints the public half', async () => {
    const r = await tool.keygen(dir);
    assert.ok(fs.existsSync(r.file));
    assert.strictEqual(fs.statSync(r.file).mode & 0o777, 0o600);
    assert.strictEqual(room.fromB64(r.pub).length, 65);
    assert.match(r.fingerprint, /^[0-9a-f]{8}$/);
    await assert.rejects(() => tool.keygen(dir), /not overwriting/);
    const id = await tool.loadIdentity(dir);
    assert.strictEqual(id.pub, r.pub);
    const sig = await room.signFields(id, ['x']);
    assert.strictEqual(await room.verifyFields(r.pub, ['x'], sig), true);
  });

  const identity = await tool.loadIdentity(dir);
  const alice = await room.deriveIdentity('alice', 'alice-password-one', FAST);
  const mallory = await room.deriveIdentity('mallory', 'mallory-password-3', FAST);
  const logs = [];
  const reg = new tool.Registrar(identity, tool.loadState(dir), (m) => logs.push(m));

  await test('the first valid claim on a name is recorded; later ones are not', async () => {
    await reg.onClaim('alice', await claimFor(alice, 'alice', 'Alice', 1000));
    assert.deepStrictEqual(Object.keys(reg.state.names), ['alice']);
    assert.strictEqual(reg.state.names.alice.pk, alice.pub);
    assert.strictEqual(reg.dirty, true);
    await reg.onClaim('alice', await claimFor(mallory, 'alice', 'Alice', 1));   // backdated, still later
    assert.strictEqual(reg.state.names.alice.pk, alice.pub);
    assert.strictEqual(reg.rivals, 1);
  });

  await test('claims that do not hold up are ignored', async () => {
    const good = JSON.parse(await claimFor(mallory, 'mallory', 'Mallory', 5));
    const wrongName = Object.assign({}, good, { name: 'Mallorie' });
    const wrongSig = Object.assign({}, good, { sig: good.sig.slice(0, -4) + 'AAAA' });
    const notV2 = Object.assign({}, good, { v: 1 });
    for (const bad of [JSON.stringify(wrongName), JSON.stringify(wrongSig), JSON.stringify(notV2), 'not json', '']) {
      await reg.onClaim('mallory', bad);
    }
    await reg.onClaim('Mallory', JSON.stringify(good));           // topic not normalised
    await reg.onClaim("x');alert(1)", JSON.stringify(good));
    assert.deepStrictEqual(Object.keys(reg.state.names), ['alice']);
    await reg.onClaim('mallory', JSON.stringify(good));
    assert.deepStrictEqual(Object.keys(reg.state.names).sort(), ['alice', 'mallory']);
  });

  await test('moderation goes to the first signed claim; the old password hash is not one', async () => {
    await reg.onAdmin('a'.repeat(64));
    assert.strictEqual(reg.state.admin, null);
    const a = { v: 2, pk: alice.pub, ts: 7 }; a.sig = await room.signFields(alice, ['admin', alice.pub, 7]);
    const m = { v: 2, pk: mallory.pub, ts: 8 }; m.sig = await room.signFields(mallory, ['admin', mallory.pub, 8]);
    await reg.onAdmin(JSON.stringify(m));
    await reg.onAdmin(JSON.stringify(a));
    assert.strictEqual(reg.state.admin, mallory.pub);
  });

  let first, second;
  await test('the published list is signed, sorted and verifiable with the public key', async () => {
    first = await reg.build();
    assert.strictEqual(first.seq, 1);
    assert.deepStrictEqual(first.names.map((e) => e[0]), ['alice', 'mallory']);
    assert.strictEqual(first.admin, mallory.pub);
    assert.strictEqual(reg.dirty, false);
    assert.ok(await room.verifyRegistry(identity.pub, JSON.parse(JSON.stringify(first))));
    tool.saveState(dir, reg.state);
    assert.strictEqual(tool.loadState(dir).seq, 1);
  });

  await test('the page refuses a list signed by another key, an edited list, or an unsorted one', async () => {
    const other = await room.deriveIdentity('other', 'other-password-9', FAST);
    const forged = JSON.parse(JSON.stringify(first));
    assert.strictEqual(await room.verifyRegistry(other.pub, forged), null);
    const resigned = await room.signRegistry(other, JSON.parse(JSON.stringify(first)));
    assert.strictEqual(await room.verifyRegistry(identity.pub, resigned), null);
    const edited = JSON.parse(JSON.stringify(first)); edited.names[0][2] = mallory.pub;
    assert.strictEqual(await room.verifyRegistry(identity.pub, edited), null);
    const unsorted = JSON.parse(JSON.stringify(first)); unsorted.names.reverse();
    assert.strictEqual(await room.verifyRegistry(identity.pub, unsorted), null);
    const dup = JSON.parse(JSON.stringify(first)); dup.names.push(dup.names[1]);
    assert.strictEqual(await room.verifyRegistry(identity.pub, dup), null);
  });

  await test('a wiped or foreign registry on the relay makes the registrar republish', async () => {
    reg.dirty = false;
    await reg.onRegistry('');
    assert.strictEqual(reg.dirty, true);
    reg.dirty = false;
    await reg.onRegistry(JSON.stringify({ v: 1, seq: 99, ts: 0, names: [], admin: null, sig: 'AAAA' }));
    assert.strictEqual(reg.dirty, true);
    reg.dirty = false;
    await reg.onRegistry(JSON.stringify(first));
    assert.strictEqual(reg.dirty, false);
  });

  await test('the sequence only grows, so an old list cannot be replayed over a new one', async () => {
    second = await reg.build();
    assert.strictEqual(second.seq, 2);
    assert.ok(second.seq > first.seq);
    // What the page does: keep the highest sequence it has verified.
    let held = -1;
    for (const r of [second, first]) {
      const ok = await room.verifyRegistry(identity.pub, JSON.parse(JSON.stringify(r)));
      if (ok && ok.seq > held) held = ok.seq;
    }
    assert.strictEqual(held, 2);
  });

  await test('the shipped page has an empty registry key until the operator fills it in', async () => {
    const html = fs.readFileSync(path.join(ROOT, 'hidra-browser', 'src', 'ui', 'forum.html'), 'utf8');
    const m = html.match(/var REGISTRY_PUBKEY='([^']*)';/);
    assert.ok(m, 'REGISTRY_PUBKEY present');
    if (m[1]) assert.strictEqual(room.fromB64(m[1]).length, 65, 'a filled-in key is a raw P-256 point');
  });

  fs.rmSync(dir, { recursive: true, force: true });
  console.log('\n' + passed + ' checks passed');
})().catch((e) => {
  console.log('FAIL  ' + (e && e.stack || e));
  process.exit(1);
});
