// The forum's registrar (tools/forum-registrar.js), driven without a relay:
// claims go in as the relay would hand them over, and what comes out is the
// signed list the page trusts. Then the page's side of the contract, through
// the shared module: a list signed by the wrong key, or an older sequence,
// is refused. And the guards an attacker with relay access runs into: a
// poisoned timestamp, a flood of free names, a wiped list poked over and
// over, moderation taken from the relay.
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

// A registrar past its first run, with a clock the test controls.
function liveRegistrar(identity, state, logs, clock) {
  const reg = new tool.Registrar(identity, state, (m) => logs.push(m), { now: () => clock.t });
  reg.bootstrapping = false;
  return reg;
}

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-registrar-'));

  await test('keygen writes a private key the owner keeps, and prints the public half', async () => {
    const r = await tool.keygen(dir);
    assert.ok(fs.existsSync(r.file));
    if (process.platform !== 'win32') assert.strictEqual(fs.statSync(r.file).mode & 0o777, 0o600);
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
  const clock = { t: 1_700_000_000_000 };
  const reg = liveRegistrar(identity, tool.loadState(dir), logs, clock);

  await test('the first valid claim on a name is recorded; later ones are not', async () => {
    await reg.onClaim('alice', await claimFor(alice, 'alice', 'Alice', 1000));
    assert.deepStrictEqual(Object.keys(reg.state.names), ['alice']);
    assert.strictEqual(reg.state.names.alice.pk, alice.pub);
    assert.strictEqual(reg.dirty, true);
    await reg.onClaim('alice', await claimFor(mallory, 'alice', 'Alice', 1));   // backdated, still later
    assert.strictEqual(reg.state.names.alice.pk, alice.pub);
    assert.strictEqual(reg.rivals, 1);
    assert.ok(!logs.some((m) => /alice/i.test(m)), 'names never reach the log');
  });

  await test('claims that do not hold up are ignored', async () => {
    const good = JSON.parse(await claimFor(mallory, 'mallory', 'Mallory', 5));
    const wrongName = Object.assign({}, good, { name: 'Mallorie' });
    const wrongSig = Object.assign({}, good, { sig: good.sig.slice(0, -4) + 'AAAA' });
    const notV2 = Object.assign({}, good, { v: 1 });
    for (const bad of [JSON.stringify(wrongName), JSON.stringify(wrongSig), JSON.stringify(notV2), 'not json', '', 'x'.repeat(5000)]) {
      await reg.onClaim('mallory', bad);
    }
    await reg.onClaim('Mallory', JSON.stringify(good));           // topic not normalised
    await reg.onClaim("x');alert(1)", JSON.stringify(good));
    assert.deepStrictEqual(Object.keys(reg.state.names), ['alice']);
    await reg.onClaim('mallory', JSON.stringify(good));
    assert.deepStrictEqual(Object.keys(reg.state.names).sort(), ['alice', 'mallory']);
  });

  await test('a timestamp that is not a finite integer cannot poison the list', async () => {
    // JSON.stringify writes null for Infinity, on the signer's side and on
    // ours, so such a claim verifies and would have put a null into the
    // signed list, which every page then refuses, for good.
    const evil = await room.deriveIdentity('evil', 'evil-password-xx', FAST);
    for (const ts of [Infinity, -Infinity, NaN, 1.5, -1]) {
      const c = { v: 2, name: 'evil', pk: evil.pub, ts };
      c.sig = await room.signFields(evil, ['claim', 'evil', 'evil', evil.pub, ts]);
      await reg.onClaim('evil', JSON.stringify(c).replace('null', '1e999'));
      await reg.onClaim('evil', JSON.stringify(c));
    }
    await reg.onClaim('evil', '{"v":2,"name":"evil","pk":"' + evil.pub + '","ts":"1e999","sig":"AAAA"}');
    assert.ok(!reg.state.names.evil);
    const built = await reg.build();
    assert.ok(built.names.every((e) => Number.isFinite(e[3])));
    assert.ok(await room.verifyRegistry(identity.pub, JSON.parse(JSON.stringify(built))));
  });

  await test('moderation is not taken from the relay; the operator sets it', async () => {
    const m = { v: 2, pk: mallory.pub, ts: 8 }; m.sig = await room.signFields(mallory, ['admin', mallory.pub, 8]);
    await reg.onAdmin(JSON.stringify(m));
    await reg.onAdmin('a'.repeat(64));
    assert.strictEqual(reg.state.admin, null);
    assert.ok(logs.some((m) => /moderation claim is on the relay/.test(m)));
    assert.throws(() => reg.setAdmin('not a key'), /public key/);
    reg.setAdmin(alice.pub);
    assert.strictEqual(reg.state.admin, alice.pub);
    assert.strictEqual(reg.dirty, true);
  });

  let first, second;
  await test('the published list is signed, sorted and verifiable with the public key', async () => {
    first = await reg.build();
    assert.deepStrictEqual(first.names.map((e) => e[0]), ['alice', 'mallory']);
    assert.strictEqual(first.admin, alice.pub);
    assert.strictEqual(reg.dirty, false);
    assert.ok(await room.verifyRegistry(identity.pub, JSON.parse(JSON.stringify(first))));
    tool.saveState(dir, reg.state);
    assert.strictEqual(tool.loadState(dir).seq, first.seq);
  });

  await test('the page refuses a list signed by another key, an edited list, or an unsorted one', async () => {
    const other = await room.deriveIdentity('other', 'other-password-9', FAST);
    assert.strictEqual(await room.verifyRegistry(other.pub, JSON.parse(JSON.stringify(first))), null);
    const resigned = await room.signRegistry(other, JSON.parse(JSON.stringify(first)));
    assert.strictEqual(await room.verifyRegistry(identity.pub, resigned), null);
    const edited = JSON.parse(JSON.stringify(first)); edited.names[0][2] = mallory.pub;
    assert.strictEqual(await room.verifyRegistry(identity.pub, edited), null);
    const unsorted = JSON.parse(JSON.stringify(first)); unsorted.names.reverse();
    assert.strictEqual(await room.verifyRegistry(identity.pub, unsorted), null);
    const dup = JSON.parse(JSON.stringify(first)); dup.names.push(dup.names[1]);
    assert.strictEqual(await room.verifyRegistry(identity.pub, dup), null);
  });

  await test('a wiped or foreign registry is answered once per cooldown, not once per poke', async () => {
    reg.dirty = false;
    await reg.onRegistry('');
    assert.strictEqual(reg.dirty, true);
    reg.dirty = false;
    for (let i = 0; i < 50; i++) await reg.onRegistry('');
    await reg.onRegistry(JSON.stringify({ v: 1, seq: 99, ts: 0, names: [], admin: null, sig: 'AAAA' }));
    assert.strictEqual(reg.dirty, false, 'inside the cooldown nothing is republished');
    clock.t += 61_000;
    await reg.onRegistry('');
    assert.strictEqual(reg.dirty, true);
    assert.ok(logs.some((m) => /51 more such messages/.test(m)));
    reg.dirty = false;
    await reg.onRegistry(JSON.stringify(first));
    assert.strictEqual(reg.dirty, false, 'our own current list changes nothing');
  });

  await test('the sequence only grows, so an old list cannot be replayed over a new one', async () => {
    second = await reg.build();
    assert.ok(second.seq > first.seq);
    let held = -1;
    for (const r of [second, first]) {
      const ok = await room.verifyRegistry(identity.pub, JSON.parse(JSON.stringify(r)));
      if (ok && ok.seq > held) held = ok.seq;
    }
    assert.strictEqual(held, second.seq);
  });

  await test('a copy that lost its state adopts the list it finds under its own key', async () => {
    const fresh = liveRegistrar(identity, { seq: 0, names: {}, admin: null }, [], clock);
    await fresh.onRegistry(JSON.stringify(second));
    assert.strictEqual(fresh.state.seq, second.seq);
    assert.deepStrictEqual(Object.keys(fresh.state.names).sort(), ['alice', 'mallory']);
    assert.strictEqual(fresh.state.admin, alice.pub);
    const next = await fresh.build();
    assert.ok(next.seq > second.seq);
  });

  await test('on a first run, claims already on the relay are counted, not recorded', async () => {
    const boot = new tool.Registrar(identity, { seq: 0, names: {}, admin: null }, () => {}, { now: () => clock.t });
    assert.strictEqual(boot.bootstrapping, true);
    await boot.onClaim('alice', await claimFor(alice, 'alice', 'Alice', 1000));
    assert.deepStrictEqual(boot.state.names, {});
    assert.strictEqual(boot.preexisting, 1);
    boot.bootstrapping = false;                        // the settle window has passed
    await boot.onClaim('alice', await claimFor(alice, 'alice', 'Alice', 1000));
    assert.deepStrictEqual(Object.keys(boot.state.names), ['alice']);
    const adopt = new tool.Registrar(identity, { seq: 0, names: {}, admin: null }, () => {}, { adoptExisting: true, now: () => clock.t });
    await adopt.onClaim('alice', await claimFor(alice, 'alice', 'Alice', 1000));
    assert.deepStrictEqual(Object.keys(adopt.state.names), ['alice']);
  });

  await test('a burst of new names is refused while it lasts', async () => {
    const burst = liveRegistrar(identity, { seq: 0, names: {}, admin: null }, [], clock);
    const n = tool.RATE_MAX_NEW + 5;
    for (let i = 0; i < n; i++) {
      const id = await room.deriveIdentity('name' + i, 'burst-password-' + i, FAST);
      await burst.onClaim('name' + i, await claimFor(id, 'name' + i, 'name' + i, i));
    }
    assert.strictEqual(Object.keys(burst.state.names).length, tool.RATE_MAX_NEW);
    assert.strictEqual(burst.refused, 5);
    clock.t += tool.RATE_WINDOW_MS + 1;
    const late = await room.deriveIdentity('latecomer', 'late-password-xxx', FAST);
    await burst.onClaim('latecomer', await claimFor(late, 'latecomer', 'latecomer', 1));
    assert.ok(burst.state.names.latecomer, 'after the window a new name is recorded again');
  });

  await test('the list has a ceiling, and a full list refuses new names', async () => {
    const full = liveRegistrar(identity, { seq: 0, names: {}, admin: null }, [], clock);
    for (let i = 0; i < tool.MAX_NAMES; i++) full.state.names['n' + i] = { name: 'n' + i, pk: alice.pub, ts: i };
    const one = await room.deriveIdentity('onemore', 'onemore-password-x', FAST);
    await full.onClaim('onemore', await claimFor(one, 'onemore', 'onemore', 1));
    assert.ok(!full.state.names.onemore);
    assert.strictEqual(full.refused, 1);
    const built = await full.build();
    assert.ok(JSON.stringify(built).length < tool.MAX_LIST_BYTES, 'a full list still fits under the byte limit');
  });

  await test('hides by the moderator key travel in the list; other hides do not', async () => {
    const r = liveRegistrar(identity, { seq: 0, names: {}, admin: null, hides: {} }, [], clock);
    const hideBy = async (id, who, ts) => { const h = { id, ts, pk: who.pub }; h.sig = await room.signFields(who, ['hide', id, ts]); return JSON.stringify(h); };
    await r.onHide('tabcdefghij', await hideBy('tabcdefghij', alice, 1));   // no moderator set yet
    assert.deepStrictEqual(r.state.hides, {});
    r.setAdmin(alice.pub);
    await r.onHide('tabcdefghij', await hideBy('tabcdefghij', alice, 1));
    await r.onHide('tbbbbbbbbbb', await hideBy('tbbbbbbbbbb', mallory, 2));  // another key
    await r.onHide('tccccccccc', await hideBy('tccccccccc', alice, 3));        // id too short
    await r.onHide('tdddddddddd', '1');                                        // the old unsigned flag
    await r.onHide('teeeeeeeeee', await hideBy('teeeeeeeeee', alice, Infinity));
    assert.deepStrictEqual(Object.keys(r.state.hides), ['tabcdefghij']);
    const built = await r.build();
    assert.deepStrictEqual(built.hides, ['tabcdefghij']);
    assert.ok(await room.verifyRegistry(identity.pub, JSON.parse(JSON.stringify(built))));
    const tampered = JSON.parse(JSON.stringify(built)); tampered.hides.push('tzzzzzzzzzz');
    assert.strictEqual(await room.verifyRegistry(identity.pub, tampered), null);
  });

  await test('a list signed before hides existed still verifies', async () => {
    const old = { v: 1, seq: 3, ts: 1, names: [['alice', 'Alice', alice.pub, 1000]], admin: null };
    old.sig = await room.signFields(identity, ['registry', 3, 1, old.names, '']);
    assert.ok(await room.verifyRegistry(identity.pub, JSON.parse(JSON.stringify(old))));
    const withHides = await room.signRegistry(identity, { seq: 4, ts: 2, names: old.names, admin: null, hides: ['tabcdefghij'] });
    assert.ok(await room.verifyRegistry(identity.pub, JSON.parse(JSON.stringify(withHides))));
    const stripped = JSON.parse(JSON.stringify(withHides)); delete stripped.hides;
    assert.strictEqual(await room.verifyRegistry(identity.pub, stripped), null, 'dropping the hides breaks the signature');
  });

  await test('the shipped page carries a public key, or none', async () => {
    const html = fs.readFileSync(path.join(ROOT, 'hidra-browser', 'src', 'ui', 'forum.html'), 'utf8');
    const m = html.match(/var REGISTRY_PUBKEY='([^']*)';/);
    assert.ok(m, 'REGISTRY_PUBKEY present');
    if (m[1]) assert.ok(room.canonicalPub(m[1]), 'a filled-in key is a raw P-256 point in its one encoding');
  });

  fs.rmSync(dir, { recursive: true, force: true });
  console.log('\n' + passed + ' checks passed');
})().catch((e) => {
  console.log('FAIL  ' + (e && e.stack || e));
  process.exit(1);
});
