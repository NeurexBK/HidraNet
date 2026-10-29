// The browser's side of the HidraVPN control channel.
//
// The VPN is a separate program: a background service that holds the tunnel,
// arms the kill switch and puts the network back (hidravpn/). This module is
// how the browser talks to it, and it is deliberately thin: one request, one
// answer, one connection, each a single line of JSON — the same protocol the
// `hidravpn` command line speaks (hidravpn-service/src/ipc.rs). The service
// picks the nodes from the pocket this machine holds, so nothing here ever
// sees an invite or a key, and nothing here could leak one.
//
// Every request carries the control token, a secret the service writes where
// only root and the hidravpn group may read it (on Linux) or under
// ProgramData (on Windows). A web page cannot reach the token or the socket:
// this runs in the main process, and the renderer only gets the handful of
// calls in tab-preload.js, on our own pages.
//
// And every request is sealed to the service's key, whose public half the
// service writes beside the token at every start (hidravpn-service/src/
// seal.rs): X25519 with a key made for this one request, HKDF-SHA256, and
// AES-256-GCM, all in Node's own crypto. Only the service can open the
// request, and an answer is believed only when it opens under the key the
// service derived for it. That is what tells the service apart from anything
// else answering on its address: on Windows a pipe's name is no proof, since
// a signed-in user may make \\.\pipe\hidravpn while the service is stopped,
// or add an instance beside the service's. Such a pipe sees nothing it can
// read, not the token and not an account token, and whatever it answers is
// shown as "unavailable", never as the state of the VPN.
//
// Failures are reported as states a page can show, not as exceptions a page
// has to guess at: the service is not installed, it is installed but not
// running, this user may not open it, or it answered something unreadable.

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const path = require('path');

const LINUX_SOCKET = '/run/hidravpn/control.sock';
const LINUX_TOKEN = '/run/hidravpn/control.token';
const LINUX_KEY = '/run/hidravpn/control.pub';
const WINDOWS_PIPE = '\\\\.\\pipe\\hidravpn';

// An answer is one line of JSON; a status report is a few hundred bytes and a
// node list a few kilobytes. Anything past this is not the service talking.
const MAX_ANSWER_BYTES = 1024 * 1024;
// A published node list, read from disk to be handed to the service: hundreds
// of invites fit in a fraction of this.
const MAX_LIST_BYTES = 1024 * 1024;

const MODES = new Set(['rapido', 'privado']);

function defaultPaths(platform = process.platform, env = process.env) {
  if (platform === 'win32') {
    const base = env.ProgramData || 'C:\\ProgramData';
    return {
      endpoint: WINDOWS_PIPE,
      tokenPath: path.join(base, 'HidraVPN', 'control.token'),
      keyPath: path.join(base, 'HidraVPN', 'control.pub'),
    };
  }
  return { endpoint: LINUX_SOCKET, tokenPath: LINUX_TOKEN, keyPath: LINUX_KEY };
}

// ── Sealed requests (the same scheme as hidravpn-service/src/seal.rs) ──────

const SEAL = 'x25519-aes256gcm';
const SEAL_INFO = Buffer.from('hidravpn control channel v1');
const GCM_TAG = 16;
const GCM_NONCE = 12;

function x25519Public(raw) {
  return crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: raw.toString('base64url') }, format: 'jwk' });
}

function rawPublic(keyObject) {
  return Buffer.from(keyObject.export({ format: 'jwk' }).x, 'base64url');
}

// The request key seals this one request, so its nonce is fixed; the
// service seals its answer under a random nonce it sends with it.
function aesSeal(key, plain) {
  const c = crypto.createCipheriv('aes-256-gcm', key, Buffer.alloc(GCM_NONCE), { authTagLength: GCM_TAG });
  return Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
}

function aesOpen(key, nonce, data) {
  if (nonce.length !== GCM_NONCE || data.length < GCM_TAG) throw new Error('too short');
  const d = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: GCM_TAG });
  d.setAuthTag(data.subarray(data.length - GCM_TAG));
  return Buffer.concat([d.update(data.subarray(0, data.length - GCM_TAG)), d.final()]);
}

// Seals a request line (without its newline) to the service's public key,
// 32 bytes. Returns the line to send and `open(answer)`, which gives the
// answer's plain line, or null when the answer is not one the service
// sealed for this request. `mine` (a private X25519 KeyObject) is for
// tests: otherwise every request has a key of its own.
function sealRequest(servicePublic, plain, mine) {
  const priv = mine || crypto.generateKeyPairSync('x25519').privateKey;
  const from = rawPublic(crypto.createPublicKey(priv));
  const shared = crypto.diffieHellman({ privateKey: priv, publicKey: x25519Public(servicePublic) });
  if (shared.every((b) => b === 0)) throw new Error('the service\'s key is not a usable key');
  const okm = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.concat([from, servicePublic]), SEAL_INFO, 64));
  const requestKey = okm.subarray(0, 32);
  const answerKey = okm.subarray(32);
  const line = JSON.stringify({ seal: SEAL, from: from.toString('base64'), data: aesSeal(requestKey, Buffer.from(plain, 'utf8')).toString('base64') });
  const open = (answer) => {
    let sealed;
    try {
      sealed = JSON.parse(answer);
    } catch {
      return null;
    }
    if (!sealed || sealed.seal !== SEAL || typeof sealed.nonce !== 'string' || typeof sealed.data !== 'string') return null;
    try {
      return aesOpen(answerKey, Buffer.from(sealed.nonce, 'base64'), Buffer.from(sealed.data, 'base64')).toString('utf8');
    } catch {
      return null;
    }
  };
  return { line, open };
}

// Why the service could not be reached, in words a page can show. `code` is
// what the page switches on; `hint` is what the person can do about it.
class VpnUnavailable extends Error {
  constructor(code, message, hint) {
    super(message);
    this.name = 'VpnUnavailable';
    this.code = code;
    this.hint = hint || '';
  }
}

const GROUP_HINT =
  'On Linux the browser must run as a member of the hidravpn group: the installer adds ' +
  'the user who ran it; log out and in once, or run `sudo usermod -aG hidravpn $USER`.';

// What a page is told when the answer did not open: whatever answered, it
// was not the service, and it was shown nothing it could read.
const NOT_THE_SERVICE = 'something other than the HidraVPN service answered on its control channel, so the answer was not believed';
const NOT_THE_SERVICE_HINT =
  'Nothing readable was sent to it. Restart the HidraVPN service, or this computer; if this comes back, ' +
  'another program on this computer is holding the service\'s channel.';

const SLOW_COMMANDS = new Set(['connect', 'new_identity', 'join', 'get_passes', 'import_nodes']);

class VpnManager {
  constructor(options = {}) {
    const defaults = defaultPaths();
    this.endpoint = options.endpoint || defaults.endpoint;
    this.tokenPath = options.tokenPath || defaults.tokenPath;
    this.keyPath = options.keyPath || defaults.keyPath;
    // Where a service with no key may still be asked in the clear: not on
    // Windows, where the pipe's name proves nothing. Tests set it.
    this.platform = options.platform || process.platform;
    this.timeoutMs = options.timeoutMs || 8000;
    // Commands that wait on the network (an admission, a pass redeemed, the
    // issuer, a circuit built): eight seconds would give up while the
    // service is still working, and the page would say it did not answer
    // while the machine was being routed. A shorter timeoutMs never
    // shortens this one.
    this.slowTimeoutMs = options.slowTimeoutMs || Math.max(this.timeoutMs, 120000);
    // Injected by tests to stand in for the file system and the socket.
    this._fs = options.fs || fs;
    this._net = options.net || net;
  }

  // ── The protocol ────────────────────────────────────────────────────────

  async _readToken() {
    let token;
    try {
      token = await this._fs.promises.readFile(this.tokenPath, 'utf8');
    } catch (e) {
      if (e && e.code === 'ENOENT') {
        // The token is written when the service starts, so without it the
        // service is either not installed or not running. The socket says
        // which: it survives until the next boot.
        const socketThere = await this._exists(this.endpoint);
        if (socketThere) {
          throw new VpnUnavailable('stopped', 'the HidraVPN service is installed but not running',
            'Start it: `sudo hidravpn-service start` on Linux, or start the HidraVPN service on Windows.');
        }
        throw new VpnUnavailable('not-installed', 'the HidraVPN service is not installed',
          'Install HidraVPN first; the browser only drives the service, it does not contain it.');
      }
      if (e && (e.code === 'EACCES' || e.code === 'EPERM')) {
        throw new VpnUnavailable('no-permission', 'this user may not open the HidraVPN control channel', GROUP_HINT);
      }
      throw new VpnUnavailable('unavailable', `could not read the control token (${e && e.code ? e.code : e})`);
    }
    token = String(token).trim();
    if (!token) throw new VpnUnavailable('unavailable', 'the control token is empty');
    return token;
  }

  // The service's public key, 32 bytes, or null from a service older than
  // sealed requests, which writes none.
  async _readServiceKey() {
    let text;
    try {
      text = await this._fs.promises.readFile(this.keyPath, 'utf8');
    } catch (e) {
      if (e && e.code === 'ENOENT') return null;
      if (e && (e.code === 'EACCES' || e.code === 'EPERM')) {
        throw new VpnUnavailable('no-permission', 'this user may not open the HidraVPN control channel', GROUP_HINT);
      }
      throw new VpnUnavailable('unavailable', `could not read the service's key (${e && e.code ? e.code : e})`);
    }
    const raw = Buffer.from(String(text).trim(), 'base64');
    // Never a reason to ask in the clear: a key file only the service may
    // write is there, so it is the service that must answer.
    if (raw.length !== 32) throw new VpnUnavailable('unavailable', 'the service\'s key file is not a key', 'Restart the HidraVPN service so it writes a fresh one.');
    return raw;
  }

  async _exists(p) {
    try {
      await this._fs.promises.access(p);
      return true;
    } catch {
      return false;
    }
  }

  // Sends one command and returns the service's answer: { ok, error?, status?,
  // note?, nodes? }. Throws VpnUnavailable when the service cannot be reached
  // or does not answer in the protocol.
  async request(cmd) {
    const token = await this._readToken();
    const key = await this._readServiceKey();
    const plain = JSON.stringify({ token, ...cmd });
    let sealed = null;
    if (key) {
      sealed = sealRequest(key, plain);
    } else if (this.platform === 'win32') {
      // An older service writes no key, so nothing it answers could be told
      // from what any signed-in user's pipe might answer: it is not asked.
      throw new VpnUnavailable('outdated', 'the HidraVPN service on this machine is older than the browser',
        'Update HidraVPN: this browser talks only to a service that can prove it is HidraVPN, and the installed one cannot.');
    }
    // A service older than sealed requests on Linux is asked in the clear,
    // as before: only root can make the socket where it lives.
    let answer = await this._roundTrip((sealed ? sealed.line : plain) + '\n', SLOW_COMMANDS.has(cmd.cmd) ? this.slowTimeoutMs : this.timeoutMs);
    if (sealed) {
      answer = sealed.open(answer);
      if (answer === null) throw new VpnUnavailable('unavailable', NOT_THE_SERVICE, NOT_THE_SERVICE_HINT);
    }
    let parsed;
    try {
      parsed = JSON.parse(answer);
    } catch {
      throw new VpnUnavailable('bad-answer', 'the service sent an unreadable answer');
    }
    if (!parsed || typeof parsed !== 'object' || typeof parsed.ok !== 'boolean') {
      throw new VpnUnavailable('bad-answer', 'the service sent an answer with no verdict');
    }
    if (!parsed.ok && typeof parsed.error === 'string' && /unknown variant/.test(parsed.error)) {
      // A service from before this command existed: it answers, but not to this.
      throw new VpnUnavailable('outdated', 'the HidraVPN service on this machine is older than the browser',
        'Update HidraVPN: the installed service does not know the commands this page uses.');
    }
    if (!parsed.ok && typeof parsed.error === 'string' && /unauthorised/.test(parsed.error)) {
      // The token on disk is not the one the service holds: it was restarted
      // under another token and this one is stale, or something else wrote it.
      throw new VpnUnavailable('unauthorised', 'the service refused the control token',
        'Restart the HidraVPN service so it writes a fresh token.');
    }
    return parsed;
  }

  _roundTrip(line, timeoutMs) {
    return new Promise((resolve, reject) => {
      const socket = this._net.createConnection(this.endpoint);
      const chunks = [];
      let size = 0;
      let settled = false;
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        fn(value);
      };
      const timer = setTimeout(
        () => finish(reject, new VpnUnavailable('timeout', 'the service did not answer in time')),
        timeoutMs || this.timeoutMs
      );
      socket.on('connect', () => socket.write(line));
      socket.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_ANSWER_BYTES) {
          finish(reject, new VpnUnavailable('bad-answer', 'the service sent far more than an answer'));
          return;
        }
        chunks.push(chunk);
        const text = Buffer.concat(chunks).toString('utf8');
        const nl = text.indexOf('\n');
        if (nl !== -1) finish(resolve, text.slice(0, nl));
      });
      socket.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8').trim();
        if (text) finish(resolve, text);
        else finish(reject, new VpnUnavailable('bad-answer', 'the service closed without answering'));
      });
      socket.on('error', (e) => {
        const code = e && e.code;
        if (code === 'ENOENT' || code === 'ECONNREFUSED') {
          finish(reject, new VpnUnavailable('stopped', 'the HidraVPN service is not running',
            'Start it: `sudo hidravpn-service start` on Linux, or start the HidraVPN service on Windows.'));
        } else if (code === 'EACCES' || code === 'EPERM') {
          finish(reject, new VpnUnavailable('no-permission', 'this user may not open the HidraVPN control channel', GROUP_HINT));
        } else {
          finish(reject, new VpnUnavailable('unavailable', `could not reach the service (${code || e})`));
        }
      });
    });
  }

  // ── What a page asks for ────────────────────────────────────────────────

  // The state of the VPN as the page should show it. Never throws: when the
  // service cannot be reached, `state` says why and `hint` what to do.
  //
  //   { state: 'connected' | 'connecting' | 'disconnected' | 'stopped' |
  //            'not-installed' | 'no-permission' | 'unauthorised' | 'unavailable',
  //     report: the service's StatusReport when it answered, else null,
  //     error, hint }
  async status() {
    let answer;
    try {
      answer = await this.request({ cmd: 'status' });
    } catch (e) {
      return unavailable(e);
    }
    if (!answer.ok) return { state: 'unavailable', report: null, error: answer.error || 'no status', hint: '' };
    const r = answer.status || {};
    const state = r.connected ? 'connected' : r.hops > 0 ? 'connecting' : 'disconnected';
    return { state, report: r, error: null, hint: '' };
  }

  // Connect through nodes the service picks from the pocket. `mode` is
  // 'rapido' (one hop) or 'privado' (two hops). Resolves to the same shape as
  // status(); a refusal by the service (an empty pocket, say) comes back as
  // { ok: false, error } rather than a throw, so the page can show it.
  async connect(mode, options = {}) {
    const m = String(mode || '').trim().toLowerCase();
    if (!MODES.has(m)) {
      return { ok: false, error: 'mode must be "rapido" (one hop) or "privado" (two hops)' };
    }
    return this._command({
      cmd: 'connect',
      mode: m,
      allow_lan: Boolean(options.allowLan),
      keep_ipv6: Boolean(options.keepIpv6),
      // Sent only when true, so a service from before it existed still reads
      // the request.
      ...(options.allowSameOperator === true ? { allow_same_operator: true } : {}),
    });
  }

  async disconnect() {
    return this._command({ cmd: 'down' });
  }

  async newIdentity() {
    return this._command({ cmd: 'new_identity' });
  }

  // The nodes in the pocket: [{ slot, node_name, endpoint }], never a key.
  async nodes() {
    return this._command({ cmd: 'nodes' });
  }

  // Hands a published node list and its signature to the service, which
  // checks the signature against the list key it carries and, only then,
  // puts the nodes into the pocket. The browser does not verify here: the
  // service writes the pocket, so the service is what must be convinced, and
  // the bytes are passed exactly as they are on disk, because that is what
  // was signed.
  async importNodesFromFiles(listPath, sigPath) {
    const sig = sigPath || listPath + '.sig';
    let list;
    let signature;
    try {
      const st = await this._fs.promises.stat(listPath);
      if (!st.isFile()) return { ok: false, error: `${listPath} is not a regular file` };
      if (st.size > MAX_LIST_BYTES) return { ok: false, error: `the list is ${st.size} bytes; a node list is far smaller than ${MAX_LIST_BYTES}` };
      list = await this._fs.promises.readFile(listPath, 'utf8');
    } catch (e) {
      return { ok: false, error: `could not read the list ${listPath} (${(e && e.code) || e})` };
    }
    try {
      signature = (await this._fs.promises.readFile(sig, 'utf8')).trim();
    } catch (e) {
      return { ok: false, error: `no signature beside the list (expected ${sig}): ${(e && e.code) || e}. A list without its .sig cannot be checked, so it is not imported.` };
    }
    return this.importNodesFromTexts(list, signature);
  }

  // The same, with the two texts already in hand (fetched from the
  // maintainers' site by the main process). Still checked by the service.
  async importNodesFromTexts(list, signature) {
    if (typeof list !== 'string' || !list.trim()) return { ok: false, error: 'the list is empty' };
    if (Buffer.byteLength(list) > MAX_LIST_BYTES) return { ok: false, error: `the list is far larger than a node list (${MAX_LIST_BYTES} bytes at most)` };
    if (typeof signature !== 'string' || !signature.trim()) return { ok: false, error: 'the list came without its signature, so it cannot be checked and is not imported' };
    return this._command({ cmd: 'import_nodes', list, signature: signature.trim() });
  }

  // Passes (phase 5). The service asks the issuer the node list names, with
  // the account token it keeps; `count` passes for each node that admits
  // with one (10 when not given), or for the one named.
  async getPasses(count, name) {
    const n = Number.isInteger(count) && count > 0 && count <= 100 ? count : 10;
    const node = typeof name === 'string' && name.trim() ? name.trim() : null;
    return this._command(node ? { cmd: 'get_passes', count: n, name: node } : { cmd: 'get_passes', count: n });
  }

  // Hands the service the account token to keep (root-only on disk). The
  // browser keeps no copy, and the service never sends it back.
  async setPassToken(token) {
    const t = typeof token === 'string' ? token.trim() : '';
    if (!t || t.length > 512 || /\s/.test(t)) return { ok: false, error: 'that is not an account token (one word, no spaces)' };
    return this._command({ cmd: 'set_pass_token', pass_token: t });
  }

  // Automatic passes (phase 6): with a boolean, switched on or off; with
  // nothing, only read. The answer carries the setting as `refill`.
  async refill(enabled) {
    return this._command(typeof enabled === 'boolean' ? { cmd: 'refill', enabled } : { cmd: 'refill' });
  }

  async _command(cmd) {
    try {
      const answer = await this.request(cmd);
      return answer;
    } catch (e) {
      const u = unavailable(e);
      return { ok: false, error: u.error, state: u.state, hint: u.hint };
    }
  }
}

function unavailable(e) {
  if (e instanceof VpnUnavailable) {
    return { state: e.code, report: null, error: e.message, hint: e.hint };
  }
  return { state: 'unavailable', report: null, error: String((e && e.message) || e), hint: '' };
}

module.exports = { VpnManager, VpnUnavailable, defaultPaths, sealRequest, MODES, MAX_ANSWER_BYTES, MAX_LIST_BYTES };
