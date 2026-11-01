// The browser's own server for its apps, on the port and the origins of
// app-origins.js.
//
// A page on an app's origin is handed that app's compartment of the vault
// (vault.js), so whoever answers on the origin has to be this process.
// Chromium connects to ::1 first for a *.localhost name, then to 127.0.0.1,
// so the server listens on both, with one request handler. A host with no
// IPv6 loopback has no ::1 for anyone to listen on or connect to, and needs
// only 127.0.0.1. If another program holds either address, the apps are off
// for this run: no tab loads an app's address (refuses(), which the network
// lock's filter asks) and no vault call is answered (vaultCompartmentOf in
// tab-manager.js).
//
// Every response the server sends also carries a token made fresh for each
// run, and the tabs' sessions drop a response from an apps address that does
// not carry it (vetResponse). It is a second check, not the first: the binds
// are what keep any other program from answering, and anyone who can reach
// this server can read the token. It tells this server's responses from
// those of a program that has never asked it.

const crypto = require('crypto');
const http = require('http');
const { APPS_PORT, LEGACY_HOSTS, appOfUrl } = require('./app-origins');

const TOKEN_HEADER = 'x-hidra-apps-token';

// Every loopback address Chromium may connect to for the apps.
const LOOPBACK = ['127.0.0.1', '::1'];

// A bind to ::1 that fails with one of these means this host has no IPv6
// loopback. That is read once, at start: a ::1 added during the run is
// covered from the next start.
const NO_IPV6_LOOPBACK = new Set(['EAFNOSUPPORT', 'EADDRNOTAVAIL']);

// A copy of the browser that is still shutting down holds the port for a few
// seconds, so a busy port is tried again this many times before the apps are
// given up for the run.
const RETRIES = 5;
const RETRY_MS = 2000;

/** An address the apps server answers for: an app's origin, or the old shared one that sends to it. */
function isAppsAddress(rawUrl) {
  if (appOfUrl(rawUrl)) return true;
  let u;
  try { u = new URL(rawUrl); } catch { return false; }
  return u.protocol === 'http:' && LEGACY_HOSTS.has(u.host);
}

// What one round of binds comes to, from what each address gave: null when
// it is held, the error its bind failed with otherwise. Busy addresses are
// worth another try; any other failure is final.
function judgeBinds(outcome) {
  const busy = [];
  const failed = [];
  for (const [host, err] of Object.entries(outcome)) {
    if (!err) continue;
    if (host === '::1' && NO_IPV6_LOOPBACK.has(err.code)) continue;
    if (err.code === 'EADDRINUSE') busy.push(host);
    else failed.push(host);
  }
  return { busy, failed };
}

class AppsServer {
  // The options are for the tests. The browser takes the defaults: the
  // apps' origins are on APPS_PORT, and it needs every loopback address.
  constructor({ port = APPS_PORT, hosts = LOOPBACK, retries = RETRIES, retryMs = RETRY_MS } = {}) {
    this.port = port;
    this.hosts = hosts;
    this.retries = retries;
    this.retryMs = retryMs;
    this.token = crypto.randomBytes(32).toString('hex');
    // 'starting' until start() has every address, 'listening' once it has,
    // 'off' for the rest of the run if it cannot.
    this.state = 'starting';
    // Why the apps are not up, for the new tab page and the page a refused
    // tab shows.
    this.error = null;
    this._servers = new Map();
  }

  // Whether this process holds every address the apps need.
  get holds() {
    return this.state === 'listening';
  }

  // The addresses held, for the log.
  addresses() {
    return [...this._servers.keys()];
  }

  // Listens with `handler` on every address. Resolves true once each one is
  // held, false when the apps are off for this run.
  async start(handler) {
    const serve = (req, res) => {
      res.setHeader(TOKEN_HEADER, this.token);
      return handler(req, res);
    };
    for (let attempt = 0; ; attempt++) {
      const outcome = {};
      for (const host of this.hosts) {
        outcome[host] = this._servers.has(host) ? null : await this._bind(host, serve);
      }
      const { busy, failed } = judgeBinds(outcome);
      if (failed.length) {
        const host = failed[0];
        return this._off(`could not open port ${this.port} on ${host} (${outcome[host].message}), so the apps are off`);
      }
      if (!busy.length) {
        this.state = 'listening';
        this.error = null;
        return true;
      }
      const where = `port ${this.port} on ${busy.join(' and ')}`;
      if (attempt >= this.retries) {
        return this._off(`another program holds ${where}, so the apps are off`
          + ' until HidraNet is restarted with the port free');
      }
      this.error = `${where} is busy, retrying`;
      await new Promise((r) => setTimeout(r, this.retryMs));
    }
  }

  _bind(host, serve) {
    return new Promise((resolve) => {
      const server = http.createServer(serve);
      server.once('error', resolve);
      server.listen(this.port, host, () => {
        server.removeListener('error', resolve);
        // An error from here on (out of file descriptors, say) costs a
        // connection, not the address.
        server.on('error', (e) => console.error(`[srv] apps server on ${host}:`, e.message));
        this._servers.set(host, server);
        resolve(null);
      });
    });
  }

  // Nothing of this server answers anywhere once the apps are off.
  _off(reason) {
    this.state = 'off';
    this.error = reason;
    for (const server of this._servers.values()) {
      server.close();
      server.closeAllConnections();
    }
    this._servers.clear();
    return false;
  }

  // Stops listening; the apps are off from then on.
  close() {
    const closed = [...this._servers.values()].map((s) => new Promise((r) => s.once('close', r)));
    this._off('the apps server was stopped');
    return Promise.all(closed);
  }

  // For the network lock's filter: a request to an apps address is cancelled
  // before it is sent while this process does not hold every address.
  refuses(rawUrl) {
    return !this.holds && isAppsAddress(rawUrl);
  }

  // For the tabs' sessions' onHeadersReceived: a response from an apps
  // address goes through only with this run's token, exactly once, and the
  // token is taken off before the page sees it. Anything else passes as it
  // came.
  vetResponse(details) {
    if (!isAppsAddress(details.url)) return {};
    const responseHeaders = {};
    const tokens = [];
    for (const [name, value] of Object.entries(details.responseHeaders || {})) {
      if (name.toLowerCase() === TOKEN_HEADER) tokens.push(...[].concat(value));
      else responseHeaders[name] = value;
    }
    if (!this.holds || tokens.length !== 1 || tokens[0] !== this.token) {
      console.error(`[srv] dropped a response on ${new URL(details.url).host}: `
        + (this.holds ? 'it did not come from this browser\'s apps server' : 'the apps are off'));
      return { cancel: true };
    }
    return { responseHeaders };
  }

  // Why an apps address was refused, for the page the tab shows instead.
  reason() {
    if (this.state === 'off') return this.error;
    if (this.state === 'starting') return this.error || 'the apps server is still starting';
    return 'the answer on this address did not come from this browser\'s apps server';
  }
}

module.exports = { AppsServer, TOKEN_HEADER, isAppsAddress, judgeBinds };
