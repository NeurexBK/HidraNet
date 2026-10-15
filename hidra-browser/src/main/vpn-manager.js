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
// Failures are reported as states a page can show, not as exceptions a page
// has to guess at: the service is not installed, it is installed but not
// running, this user may not open it, or it answered something unreadable.

'use strict';

const fs = require('fs');
const net = require('net');
const path = require('path');

const LINUX_SOCKET = '/run/hidravpn/control.sock';
const LINUX_TOKEN = '/run/hidravpn/control.token';
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
    return { endpoint: WINDOWS_PIPE, tokenPath: path.join(base, 'HidraVPN', 'control.token') };
  }
  return { endpoint: LINUX_SOCKET, tokenPath: LINUX_TOKEN };
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

const SLOW_COMMANDS = new Set(['connect', 'new_identity', 'join', 'get_passes', 'import_nodes']);

class VpnManager {
  constructor(options = {}) {
    const defaults = defaultPaths();
    this.endpoint = options.endpoint || defaults.endpoint;
    this.tokenPath = options.tokenPath || defaults.tokenPath;
    this.timeoutMs = options.timeoutMs || 8000;
    // Commands that wait on the network (an admission, a pass redeemed, the
    // issuer, a circuit built): eight seconds would give up while the
    // service is still working, and the page would say it did not answer
    // while the machine was being routed.
    this.slowTimeoutMs = options.slowTimeoutMs || options.timeoutMs || 120000;
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
            'Start it: `sudo hidravpn-service start` on Linux, or start the HidraVPN task on Windows.');
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
    const line = JSON.stringify({ token, ...cmd }) + '\n';
    const answer = await this._roundTrip(line, SLOW_COMMANDS.has(cmd.cmd) ? this.slowTimeoutMs : this.timeoutMs);
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
            'Start it: `sudo hidravpn-service start` on Linux, or start the HidraVPN task on Windows.'));
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

  // Ask admission from known nodes that admit openly: one by name, or all
  // when `name` is empty. The service does the asking and the checking.
  async join(name) {
    const n = typeof name === 'string' && name.trim() ? name.trim() : null;
    return this._command(n ? { cmd: 'join', name: n } : { cmd: 'join' });
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

module.exports = { VpnManager, VpnUnavailable, defaultPaths, MODES, MAX_ANSWER_BYTES, MAX_LIST_BYTES };
