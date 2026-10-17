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
// times. No addresses reach it, and none are logged.
//
//   node forum-registrar.js keygen <dir>        make the key pair, once
//   node forum-registrar.js run <dir> [options]  watch and publish
//
//   --broker <url>     wss://broker.emqx.io:8084/mqtt by default
//   --interval <s>     republish at least this often, 1800 by default
//   --verbose          log names, not only counts
//
// <dir> holds registry.secret (the private key, never to leave the machine)
// and registry-state.json (what has been recorded so far).

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
// A public relay refuses large messages. The page is told to expect the
// list to be split long before that; this is the point to do it.
const WARN_BYTES = 200 * 1024;

// ── State ───────────────────────────────────────────────────────────────

function emptyState() {
  return { seq: 0, names: {}, admin: null };
}

function loadState(dir) {
  try {
    const s = JSON.parse(fs.readFileSync(path.join(dir, STATE), 'utf8'));
    if (!s || typeof s !== 'object' || !Number.isInteger(s.seq)) return emptyState();
    if (!s.names || typeof s.names !== 'object') s.names = {};
    if (typeof s.admin !== 'string') s.admin = null;
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
  constructor(identity, state, log) {
    this.identity = identity;
    this.state = state;
    this.log = log || function () {};
    this.dirty = false;
    this.rivals = 0;
  }

  async onClaim(norm, payload) {
    if (!payload || !room.validName(norm) || norm !== room.normalizeName(norm)) return;
    let o;
    try { o = JSON.parse(payload); } catch (e) { return; }
    if (!o || o.v !== 2 || typeof o.name !== 'string' || typeof o.pk !== 'string' || typeof o.sig !== 'string') return;
    const name = o.name.slice(0, 24), pk = o.pk.slice(0, 200), ts = Number(o.ts) || 0;
    if (room.normalizeName(name) !== norm) return;
    if (!(await room.verifyFields(pk, ['claim', norm, name, pk, ts], o.sig.slice(0, 200)))) return;
    const known = this.state.names[norm];
    if (known) {
      if (known.pk !== pk) {
        this.rivals++;
        this.log('rival claim ignored for a registered name (' + (await room.fingerprint(pk)).slice(0, 6) + ')');
      }
      return;
    }
    this.state.names[norm] = { name, pk, ts, seen: Date.now() };
    this.dirty = true;
    this.log('new name recorded (' + (await room.fingerprint(pk)).slice(0, 6) + ')', norm);
  }

  async onAdmin(payload) {
    if (!payload) return;
    let o;
    try { o = JSON.parse(payload); } catch (e) { return; }  // the old password hash is not a key
    if (!o || o.v !== 2 || typeof o.pk !== 'string' || typeof o.sig !== 'string') return;
    const pk = o.pk.slice(0, 200), ts = Number(o.ts) || 0;
    if (!(await room.verifyFields(pk, ['admin', pk, ts], o.sig.slice(0, 200)))) return;
    if (this.state.admin) {
      if (this.state.admin !== pk) this.log('rival moderation claim ignored');
      return;
    }
    this.state.admin = pk;
    this.dirty = true;
    this.log('moderation key recorded (' + (await room.fingerprint(pk)).slice(0, 6) + ')');
  }

  // Our own list, as the relay has it. A higher sequence than ours means
  // another copy of this program is running on the same key.
  async onRegistry(payload) {
    if (!payload) { this.dirty = true; this.log('the registry on the relay was wiped; republishing'); return; }
    let o;
    try { o = JSON.parse(payload); } catch (e) { this.dirty = true; return; }
    const reg = await room.verifyRegistry(this.identity.pub, o);
    if (!reg) { this.dirty = true; this.log('the registry on the relay is not ours; republishing'); return; }
    if (reg.seq > this.state.seq) this.log('warning: the relay holds sequence ' + reg.seq + ', above ours (' + this.state.seq + '). Is another registrar running on this key?');
  }

  async build() {
    this.state.seq += 1;
    const names = Object.keys(this.state.names).map((norm) => {
      const e = this.state.names[norm];
      return [norm, e.name, e.pk, e.ts];
    });
    const reg = { v: 1, seq: this.state.seq, ts: Date.now(), names, admin: this.state.admin };
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
  return { file, pub, fingerprint: await room.fingerprint(pub) };
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
  // The same bundle the browser ships, loaded as a script. Under Node it
  // would reach for the `ws` package; forceNativeWebSocket makes it use
  // the WebSocket Node has had since version 22.
  const code = fs.readFileSync(path.join(__dirname, '..', 'src', 'ui', 'vendor', 'mqtt.min.js'), 'utf8');
  // The bundle declares `var mqtt` at the top level of a script; run as a
  // script in this context, it needs the globals a browser would have and
  // Node provides. The handle is taken off the global right after.
  vm.runInThisContext(code + '\n;globalThis.__hidraMqtt = mqtt;', { filename: 'mqtt.min.js' });
  const mqtt = globalThis.__hidraMqtt;
  delete globalThis.__hidraMqtt;
  return mqtt;
}

async function run(dir, opts) {
  if (typeof globalThis.WebSocket !== 'function') throw new Error('this needs Node 22 or newer, which has WebSocket built in');
  const identity = await loadIdentity(dir);
  const state = loadState(dir);
  const log = (msg, name) => console.log(new Date().toISOString() + '  ' + msg + (opts.verbose && name ? '  ' + name : ''));
  const reg = new Registrar(identity, state, log);
  log('registrar key ' + (await room.fingerprint(identity.pub)) + ', ' + Object.keys(state.names).length + ' names recorded, sequence ' + state.seq);

  const mqtt = opts.mqtt || loadMqtt();
  const client = mqtt.connect(opts.broker || DEFAULT_BROKER, {
    forceNativeWebSocket: true, clean: true, reconnectPeriod: 4000, connectTimeout: 9000, keepalive: 30,
    clientId: 'hregistrar_' + room.toHex(crypto.getRandomValues(new Uint8Array(6))),
  });
  // After connecting, the retained claims arrive in a burst; they are
  // collected for a settle window and published once, then on every change.
  let settling = false, settleTimer = null, periodic = null;
  const settleMs = opts.settleMs || SETTLE_MS;

  async function publish(why) {
    const r = await reg.build();
    const body = JSON.stringify(r);
    if (body.length > WARN_BYTES) log('warning: the registry is ' + body.length + ' bytes; a public relay may refuse it soon. Time for the hub.');
    saveState(dir, state);
    await new Promise((resolve) => client.publish(TOPIC, body, { qos: 1, retain: true }, () => resolve()));
    log('published sequence ' + r.seq + ' with ' + r.names.length + ' names (' + why + ')');
  }

  client.on('connect', () => {
    log('connected to the relay');
    settling = true;
    client.subscribe(['hforum/u/+', 'hforum/admin', TOPIC], { qos: 1 });
    clearTimeout(settleTimer);
    settleTimer = setTimeout(() => {
      chain = chain.then(async () => {
        settling = false;
        if (reg.dirty) await publish('changes');
        clearInterval(periodic);
        periodic = setInterval(() => { chain = chain.then(() => publish('periodic')); }, (opts.interval || 1800) * 1000);
      });
    }, settleMs);
  });
  client.on('close', () => { log('relay connection closed; reconnecting'); clearInterval(periodic); });
  client.on('error', (e) => log('relay error: ' + (e && e.message || e)));
  let chain = Promise.resolve();
  client.on('message', (topic, payload) => {
    const s = payload.toString();
    chain = chain.then(async () => {
      if (topic === TOPIC) await reg.onRegistry(s);
      else if (topic === 'hforum/admin') await reg.onAdmin(s);
      else if (topic.startsWith('hforum/u/')) await reg.onClaim(topic.slice(9), s);
      if (reg.dirty && !settling) await publish('changes');
    }).catch((e) => log('error handling a message: ' + (e && e.message || e)));
  });
  return { client, registrar: reg, publish, stop: () => { clearTimeout(settleTimer); clearInterval(periodic); client.end(true); } };
}

function parseArgs(argv) {
  const opts = { verbose: false };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--broker') opts.broker = argv[++i];
    else if (argv[i] === '--interval') opts.interval = Number(argv[++i]);
    else if (argv[i] === '--verbose') opts.verbose = true;
    else rest.push(argv[i]);
  }
  return { opts, rest };
}

async function main() {
  const { opts, rest } = parseArgs(process.argv.slice(2));
  const [cmd, dir] = rest;
  if (cmd === 'keygen' && dir) {
    const r = await keygen(dir);
    console.log('Private key written to ' + r.file + ' (keep it there, back it up, never commit it).');
    console.log('Fingerprint: ' + r.fingerprint);
    console.log('Public key, to paste into REGISTRY_PUBKEY in hidra-browser/src/ui/forum.html:');
    console.log(r.pub);
    return;
  }
  if (cmd === 'run' && dir) {
    await run(dir, opts);
    return;
  }
  console.log('usage: forum-registrar.js keygen <dir> | run <dir> [--broker <url>] [--interval <seconds>] [--verbose]');
  process.exit(2);
}

module.exports = { Registrar, keygen, loadIdentity, loadState, saveState, pubFromJwk, run, loadMqtt, TOPIC };

if (require.main === module) main().catch((e) => { console.error(e && e.message || e); process.exit(1); });
