#!/usr/bin/env node
// The forum's name registrar.
//
// The forum keeps its accounts on a public MQTT relay that enforces nothing:
// a claim on a name can be overwritten by anyone, and a page that never saw
// the name before believes whatever is there. This program is the one party
// whose word on names the forum page takes over the relay's. It watches the
// claims, records the first key seen for each name, and publishes the whole
// list signed, under hforum/registry. The page ships the public half of the
// key (REGISTRY_PUBKEY in forum.html) and trusts nothing else for names it
// finds in the list.
//
// It sees only what every client of the relay sees: names, public keys and
// times. No addresses reach it, and none are logged; nor are names.
//
//   node forum-registrar.js keygen <dir>            make the key pair, once
//   node forum-registrar.js run <dir> [options]     watch and publish
//   node forum-registrar.js set-admin <dir> <pk>    name the moderator's key
//   node forum-registrar.js show <dir>              what is recorded
//
//   --broker <url>      wss://broker.emqx.io:8084/mqtt by default
//   --interval <s>      republish at least this often, 1800 by default
//   --adopt-existing    on a first run, record the claims the relay already
//                       holds (see "Starting out" in README.md)
//
// <dir> holds registry.secret (the private key, never to leave the machine)
// and registry-state.json (what has been recorded so far). Back up both.

'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const room = require(path.join(__dirname, '..', 'src', 'ui', 'hidrachat-crypto.js'));

const SECRET = 'registry.secret';
const STATE = 'registry-state.json';
const TOPIC = 'hforum/registry';
const DEFAULT_BROKER = 'wss://broker.emqx.io:8084/mqtt';
const SETTLE_MS = 5000;
// Publishing is coalesced: one list per COALESCE_MS however many changes
// arrive, and a wiped or foreign list on the relay is answered at most once
// per REPUBLISH_COOLDOWN_MS. Otherwise anyone could make this program flood
// the relay with full lists by poking the topic.
const COALESCE_MS = 15000;
const REPUBLISH_COOLDOWN_MS = 60000;
// A public relay refuses large messages (EMQX's default ceiling is 1 MB), and
// a client that keeps resending one is cut off for good. The list is kept
// well under that, and names past the cap are refused rather than recorded.
// A few thousand names is also where this design ends and a hub begins.
const MAX_NAMES = 3000;
const MAX_LIST_BYTES = 512 * 1024;
// New names are free to make, so a burst of them is a flood, not a crowd.
const RATE_WINDOW_MS = 10 * 60 * 1000;
const RATE_MAX_NEW = 200;
// Hides by the moderator key travel in the list too, so that a hide wiped
// from the relay still reaches pages that arrive later.
const MAX_HIDES = 5000;
const POST_ID_RE = /^[tr][a-z2-7]{10}$/;

// ── State ───────────────────────────────────────────────────────────────

function emptyState() {
  return { seq: 0, names: {}, admin: null, hides: {} };
}

function loadState(dir) {
  try {
    const s = JSON.parse(fs.readFileSync(path.join(dir, STATE), 'utf8'));
    if (!s || typeof s !== 'object' || !Number.isInteger(s.seq)) return emptyState();
    if (!s.names || typeof s.names !== 'object') s.names = {};
    if (typeof s.admin !== 'string') s.admin = null;
    if (!s.hides || typeof s.hides !== 'object') s.hides = {};
    return s;
  } catch (e) {
    return emptyState();
  }
}

function saveState(dir, state) {
  const file = path.join(dir, STATE);
  fs.writeFileSync(file + '.tmp', JSON.stringify(state, null, 1));
  fs.renameSync(file + '.tmp', file);
}

// ── The registrar itself: no network in it, so the tests can drive it ───

class Registrar {
  // identity: { privateKey, pub } ; state: from loadState ; log: function
  constructor(identity, state, log, opts) {
    this.identity = identity;
    this.state = state;
    this.log = log || function () {};
    this.opts = opts || {};
    this.dirty = false;
    this.rivals = 0;
    this.refused = 0;
    this.recent = [];                       // times of recently recorded names
    // Until the first run has settled, claims already on the relay are only
    // counted (see adoptExisting) unless the operator asked to adopt them.
    this.bootstrapping = this.state.seq === 0 && Object.keys(this.state.names).length === 0;
    this.preexisting = 0;
    this.now = this.opts.now || function () { return Date.now(); };
  }

  rateLimited() {
    const t = this.now();
    this.recent = this.recent.filter((x) => t - x < RATE_WINDOW_MS);
    return this.recent.length >= RATE_MAX_NEW;
  }

  async onClaim(norm, payload) {
    if (!payload || payload.length > 4096 || !room.validName(norm) || norm !== room.normalizeName(norm)) return;
    let o;
    try { o = JSON.parse(payload); } catch (e) { return; }
    if (!o || o.v !== 2 || typeof o.name !== 'string' || typeof o.pk !== 'string' || typeof o.sig !== 'string') return;
    const name = o.name.slice(0, 24), pk = o.pk.slice(0, 200), ts = Number(o.ts);
    if (!Number.isSafeInteger(ts) || ts < 0) return;   // a time JavaScript cannot hold exactly would poison the signed list
    if (room.normalizeName(name) !== norm || !room.canonicalPub(pk)) return;
    if (!(await room.verifyFields(pk, ['claim', norm, name, pk, ts], o.sig.slice(0, 200)))) return;
    const known = this.state.names[norm];
    if (known) {
      if (known.pk !== pk) {
        this.rivals++;
        this.log('rival claim ignored for a registered name (' + (await room.fingerprint(pk)).slice(0, 6) + ')');
      }
      return;
    }
    if (this.bootstrapping && !this.opts.adoptExisting) {
      this.preexisting++;
      return;
    }
    if (Object.keys(this.state.names).length >= MAX_NAMES) {
      if (this.refused++ === 0) this.log('the list is full (' + MAX_NAMES + ' names); new names are refused. Time for the hub.');
      return;
    }
    if (this.rateLimited()) {
      if (this.refused++ % 100 === 0) this.log('too many new names at once; refusing until the burst passes');
      return;
    }
    this.recent.push(this.now());
    this.state.names[norm] = { name, pk, ts, seen: this.now() };
    this.dirty = true;
    this.log('new name recorded (' + (await room.fingerprint(pk)).slice(0, 6) + ')');
  }

  // Moderation is not taken from the relay: whoever could write there first
  // would hold it. The operator names the moderator's key with set-admin;
  // claims on the relay are only logged.
  async onAdmin(payload) {
    if (!payload || payload.length > 4096) return;
    let o;
    try { o = JSON.parse(payload); } catch (e) { return; }  // the old password hash is not a key
    if (!o || o.v !== 2 || typeof o.pk !== 'string' || typeof o.sig !== 'string') return;
    const pk = o.pk.slice(0, 200), ts = Number(o.ts);
    if (!Number.isFinite(ts) || !room.canonicalPub(pk)) return;
    if (!(await room.verifyFields(pk, ['admin', pk, ts], o.sig.slice(0, 200)))) return;
    if (this.state.admin !== pk) this.log('a moderation claim is on the relay (' + (await room.fingerprint(pk)).slice(0, 6) + '); it is not the registry\'s moderator. Use set-admin to change that.');
  }

  setAdmin(pk) {
    if (!room.canonicalPub(pk)) throw new Error('not a public key in the form the pages use');
    this.state.admin = pk;
    if (!this.state.hides) this.state.hides = {};
    this.dirty = true;
  }

  // A signed hide from the moderator key is recorded; anything else on the
  // topic (the old unsigned flag, another key's hide) is not.
  async onHide(id, payload) {
    if (!payload || payload.length > 4096 || !POST_ID_RE.test(id) || !this.state.admin) return;
    let o;
    try { o = JSON.parse(payload); } catch (e) { return; }
    if (!o || typeof o.pk !== 'string' || typeof o.sig !== 'string') return;
    const pk = o.pk.slice(0, 200), ts = Number(o.ts);
    if (pk !== this.state.admin || !Number.isFinite(ts)) return;
    if (!(await room.verifyFields(pk, ['hide', id, ts], o.sig.slice(0, 200)))) return;
    if (!this.state.hides) this.state.hides = {};
    if (this.state.hides[id]) return;
    if (Object.keys(this.state.hides).length >= MAX_HIDES) {
      if (this.refused++ === 0) this.log('the hide list is full (' + MAX_HIDES + '); new hides are not carried');
      return;
    }
    this.state.hides[id] = ts;
    this.dirty = true;
    this.log('moderator hide recorded');
  }

  // Our own list, as the relay has it. A list signed by our key with a higher
  // sequence than ours is a record this copy lost: adopt it. Anything else
  // there is answered with a fresh list, at most once per cooldown.
  async onRegistry(payload) {
    if (!payload) { this.foreign('the registry on the relay was wiped'); return; }
    let o;
    try { o = JSON.parse(payload); } catch (e) { this.foreign('the registry on the relay is not valid JSON'); return; }
    const reg = await room.verifyRegistry(this.identity.pub, o);
    if (!reg) { this.foreign('the registry on the relay is not ours'); return; }
    if (reg.seq > this.state.seq) {
      let added = 0;
      for (const e of reg.names) {
        if (!this.state.names[e[0]] && Number.isSafeInteger(e[3]) && e[3] >= 0) { this.state.names[e[0]] = { name: e[1], pk: e[2], ts: e[3], seen: this.now() }; added++; }
      }
      if (reg.admin && !this.state.admin) this.state.admin = reg.admin;
      if (!this.state.hides) this.state.hides = {};
      for (const h of reg.hides || []) if (!this.state.hides[h]) this.state.hides[h] = reg.ts;
      this.state.seq = reg.seq;
      this.bootstrapping = false;
      this.dirty = true;
      this.log('adopted our own list from the relay: sequence ' + reg.seq + ', ' + added + ' name(s) this copy did not have. Is another registrar running on this key?');
    }
  }

  foreign(why) {
    const t = this.now();
    if (this.lastForeign && t - this.lastForeign < REPUBLISH_COOLDOWN_MS) { this.foreignCount = (this.foreignCount || 0) + 1; return; }
    this.lastForeign = t;
    this.dirty = true;
    this.log(why + '; republishing' + (this.foreignCount ? ' (' + this.foreignCount + ' more such messages since the last one)' : ''));
    this.foreignCount = 0;
  }

  async build() {
    this.state.seq += 1;
    const names = Object.keys(this.state.names).map((norm) => {
      const e = this.state.names[norm];
      return [norm, e.name, e.pk, Number.isFinite(e.ts) ? e.ts : 0];
    });
    const reg = { v: 1, seq: this.state.seq, ts: this.now(), names, admin: this.state.admin, hides: Object.keys(this.state.hides || {}) };
    await room.signRegistry(this.identity, reg);
    this.dirty = false;
    return reg;
  }
}

// ── Keys ────────────────────────────────────────────────────────────────

async function keygen(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, SECRET);
  if (fs.existsSync(file)) throw new Error(file + ' already exists; not overwriting a key');
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  fs.writeFileSync(file, JSON.stringify({ kty: jwk.kty, crv: jwk.crv, d: jwk.d, x: jwk.x, y: jwk.y }), { mode: 0o600 });
  const pub = pubFromJwk(jwk);
  return { file, pub, fingerprint: await room.fingerprint(pub), windows: process.platform === 'win32' };
}

function b64urlToBytes(s) {
  return new Uint8Array(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
}

function pubFromJwk(jwk) {
  const raw = new Uint8Array(65);
  raw[0] = 4;
  raw.set(b64urlToBytes(jwk.x), 1);
  raw.set(b64urlToBytes(jwk.y), 33);
  return room.toB64(raw);
}

async function loadIdentity(dir) {
  const jwk = JSON.parse(fs.readFileSync(path.join(dir, SECRET), 'utf8'));
  const privateKey = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  return { privateKey, pub: pubFromJwk(jwk) };
}

// ── Running against the relay ───────────────────────────────────────────

function loadMqtt() {
  const code = fs.readFileSync(path.join(__dirname, '..', 'src', 'ui', 'vendor', 'mqtt.min.js'), 'utf8');
  // The bundle asks whether localStorage exists; recent Node versions have
  // one that warns when touched without a file to back it. It is given a
  // stub that holds nothing, before the bundle looks.
  if (!Object.getOwnPropertyDescriptor(globalThis, '__hidraStorageStub')) {
    Object.defineProperty(globalThis, 'localStorage', { value: { getItem() { return null; }, setItem() {}, removeItem() {}, clear() {}, key() { return null; }, length: 0 }, configurable: true, writable: true });
    Object.defineProperty(globalThis, '__hidraStorageStub', { value: true, configurable: true });
  }
  // The bundle declares `var mqtt` at the top level of a script; run as a
  // script in this context, it needs the globals a browser would have and
  // Node provides. The handle is taken off the global right after.
  vm.runInThisContext(code + '\n;globalThis.__hidraMqtt = mqtt;', { filename: 'mqtt.min.js' });
  const mqtt = globalThis.__hidraMqtt;
  delete globalThis.__hidraMqtt;
  return mqtt;
}

function randomClientId() {
  // No prefix: a recognisable id lets a stranger connect with the same one
  // and have the relay drop this session every few seconds.
  return room.toHex(crypto.getRandomValues(new Uint8Array(16)));
}

async function run(dir, opts) {
  if (typeof globalThis.WebSocket !== 'function') throw new Error('this needs Node 22 or newer, which has WebSocket built in');
  const identity = await loadIdentity(dir);
  const state = loadState(dir);
  const log = (msg) => console.log(new Date().toISOString() + '  ' + msg);
  const reg = new Registrar(identity, state, log, { adoptExisting: !!opts.adoptExisting });
  log('registrar key ' + (await room.fingerprint(identity.pub)) + ', ' + Object.keys(state.names).length + ' names recorded, sequence ' + state.seq + (state.admin ? ', moderator set' : ', no moderator set (use set-admin)'));
  if (reg.bootstrapping) log(opts.adoptExisting ? 'first run: claims already on the relay will be recorded' : 'first run: claims already on the relay are counted, not recorded (pass --adopt-existing to record them)');

  const mqtt = opts.mqtt || loadMqtt();
  const client = mqtt.connect(opts.broker || DEFAULT_BROKER, {
    forceNativeWebSocket: true, clean: true, reconnectPeriod: 4000, connectTimeout: 9000, keepalive: 30,
    clientId: randomClientId(),
  });
  const settleMs = opts.settleMs || SETTLE_MS;
  const coalesceMs = opts.coalesceMs || COALESCE_MS;
  let first = true, settling = false, settleTimer = null, coalesceTimer = null, periodic = null;
  let chain = Promise.resolve();
  // Whether the relay handed over a list since this connection was made. A
  // relay that comes back empty (a restart without its data, or a new
  // relay) hands over none, and must be given the list again at once.
  let sawList = false;

  async function publish(why) {
    const r = await reg.build();
    const body = JSON.stringify(r);
    if (body.length > MAX_LIST_BYTES) {
      log('the list is ' + body.length + ' bytes, above what a public relay carries; not published. Time for the hub.');
      return;
    }
    saveState(dir, state);
    await new Promise((resolve) => client.publish(TOPIC, body, { qos: 1, retain: true }, () => resolve()));
    log('published sequence ' + r.seq + ' with ' + r.names.length + ' names (' + why + ')');
  }

  function schedulePublish(why) {
    if (coalesceTimer) return;
    coalesceTimer = setTimeout(() => {
      coalesceTimer = null;
      chain = chain.then(async () => { if (reg.dirty) await publish(why); });
    }, coalesceMs);
  }

  client.on('connect', () => {
    log('connected to the relay');
    sawList = false;
    client.subscribe(['hforum/u/+', 'hforum/admin', 'hforum/mod/+', TOPIC], { qos: 1 });
    if (first) {
      // The retained claims arrive in a burst right after subscribing; they
      // are collected for a settle window, then the list goes out once, so
      // that it exists on the relay even while nobody has registered yet.
      settling = true;
      clearTimeout(settleTimer);
      settleTimer = setTimeout(() => {
        chain = chain.then(async () => {
          settling = false;
          first = false;
          if (reg.bootstrapping) {
            reg.bootstrapping = false;
            if (reg.preexisting) log(reg.preexisting + ' claim(s) were already on the relay and were not recorded; names registered from now on are');
          }
          await publish(reg.dirty ? 'changes' : 'startup');
          clearInterval(periodic);
          periodic = setInterval(() => { chain = chain.then(() => publish('periodic')); }, (opts.interval || 1800) * 1000);
        });
      }, settleMs);
    } else {
      // Reconnected: once the relay's retained burst has passed, a relay
      // that holds no list gets ours, and changes made meanwhile go out.
      clearTimeout(settleTimer);
      settleTimer = setTimeout(() => {
        chain = chain.then(async () => {
          if (!sawList) await publish('reconnect: the relay holds no list');
          else if (reg.dirty) await publish('changes');
        });
      }, settleMs);
    }
  });
  client.on('close', () => {
    log('relay connection closed; reconnecting');
    client.options.clientId = randomClientId();
  });
  client.on('error', (e) => log('relay error: ' + (e && e.message || e)));
  client.on('message', (topic, payload) => {
    const s = payload.toString();
    chain = chain.then(async () => {
      if (topic === TOPIC) { sawList = true; await reg.onRegistry(s); }
      else if (topic === 'hforum/admin') await reg.onAdmin(s);
      else if (topic.startsWith('hforum/u/')) await reg.onClaim(topic.slice(9), s);
      else if (topic.startsWith('hforum/mod/')) await reg.onHide(topic.slice(11), s);
      if (reg.dirty && !settling) schedulePublish('changes');
    }).catch((e) => log('error handling a message: ' + (e && e.message || e)));
  });
  return { client, registrar: reg, publish, stop: () => { clearTimeout(settleTimer); clearTimeout(coalesceTimer); clearInterval(periodic); client.end(true); } };
}

function parseArgs(argv) {
  const opts = { adoptExisting: false };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--broker') opts.broker = argv[++i];
    else if (argv[i] === '--interval') opts.interval = Number(argv[++i]);
    else if (argv[i] === '--adopt-existing') opts.adoptExisting = true;
    else rest.push(argv[i]);
  }
  return { opts, rest };
}

async function main() {
  const { opts, rest } = parseArgs(process.argv.slice(2));
  const [cmd, dir, arg] = rest;
  if (cmd === 'keygen' && dir) {
    const r = await keygen(dir);
    console.log('Private key written to ' + r.file + ' (keep it there, back it up, never commit it).');
    if (r.windows) console.log('On Windows the file is not made owner-only automatically: keep it under your own user profile, or set its permissions yourself.');
    console.log('Fingerprint: ' + r.fingerprint);
    console.log('Public key, to paste into REGISTRY_PUBKEY in hidra-browser/src/ui/forum.html:');
    console.log(r.pub);
    return;
  }
  if (cmd === 'set-admin' && dir && arg) {
    const identity = await loadIdentity(dir);
    const state = loadState(dir);
    const reg = new Registrar(identity, state);
    reg.setAdmin(arg);
    saveState(dir, state);
    console.log('Moderator key set (' + (await room.fingerprint(arg)) + '). It goes out with the next list the running registrar publishes; restart it if it is running.');
    return;
  }
  if (cmd === 'show' && dir) {
    const state = loadState(dir);
    console.log('sequence ' + state.seq + ', ' + Object.keys(state.names).length + ' names, ' + Object.keys(state.hides || {}).length + ' hides, moderator ' + (state.admin ? await room.fingerprint(state.admin) : 'not set'));
    return;
  }
  if (cmd === 'run' && dir) {
    await run(dir, opts);
    return;
  }
  console.log('usage: forum-registrar.js keygen <dir> | run <dir> [--broker <url>] [--interval <seconds>] [--adopt-existing] | set-admin <dir> <public key> | show <dir>');
  process.exit(2);
}

module.exports = { Registrar, keygen, loadIdentity, loadState, saveState, pubFromJwk, run, loadMqtt, TOPIC, MAX_NAMES, MAX_LIST_BYTES, MAX_HIDES, RATE_MAX_NEW, RATE_WINDOW_MS };

if (require.main === module) main().catch((e) => { console.error(e && e.message || e); process.exit(1); });
