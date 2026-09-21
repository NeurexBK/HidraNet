// Kill switch: nothing leaves the machine until Tor is actually carrying the
// traffic.
//
// Without this the browser had a wide-open window. At startup the first tab is
// created and shown while connectTor() is still bootstrapping — 20 to 40
// seconds — and during that time every session is either direct or pointed at
// the engine's SOCKS port, which by design exits from the user's own machine.
// A user who typed an address into the freshly opened window sent it with their
// real IP while the panel read "Iniciando o Tor". The same held whenever Tor
// failed to start or died mid-session: the proxy fell back to direct and
// browsing silently carried on unprotected.
//
// So the default is inverted. The lock starts engaged, and only a Tor that
// reached 100% bootstrap and had its rules applied to every session releases
// it. Anything that never touches the network — the local apps server, the
// engine API, file:// pages — stays reachable throughout, so the interface
// still works while locked.

// The browser's own services: apps server (8090), engine API (9051),
// SevenNine (8084). All loopback, none of it leaves the machine.
const LOCAL_HOSTS = new Set([
  '127.0.0.1', 'localhost', '::1', '[::1]', '0.0.0.0', '',
]);

// Schemes with no network behind them at all.
const LOCAL_SCHEMES = new Set([
  'file:', 'data:', 'blob:', 'about:', 'devtools:', 'chrome:',
  'chrome-extension:', 'chrome-devtools:', 'hidra:',
]);

class NetworkLock {
  constructor() {
    this.engaged = true;
    this.reason = 'a ligação ao Tor ainda não está pronta';
    this.blockedCount = 0;
    this._sessions = new WeakSet();
  }

  getStatus() {
    return {
      engaged: this.engaged,
      reason: this.engaged ? this.reason : null,
      blocked: this.blockedCount,
    };
  }

  engage(reason) {
    if (!this.engaged) this.blockedCount = 0;
    this.engaged = true;
    this.reason = reason || 'a ligação ao Tor ainda não está pronta';
  }

  release() {
    this.engaged = false;
    this.reason = null;
  }

  // A request is allowed through a closed lock only if it provably stays on
  // this machine. Anything we cannot parse is treated as remote — an address
  // we do not understand is not one we can promise is local.
  isLocal(rawUrl) {
    let parsed;
    try {
      parsed = new URL(rawUrl);
    } catch (e) {
      return false;
    }
    if (LOCAL_SCHEMES.has(parsed.protocol)) return true;
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:'
      && parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') {
      return false;
    }
    return LOCAL_HOSTS.has(parsed.hostname.toLowerCase());
  }

  // Installs the filter on a session. Every session the browser owns has to go
  // through here — the default one plus each tab's partition — because a
  // session without the filter is a hole straight past the lock.
  protect(electronSession) {
    if (!electronSession || this._sessions.has(electronSession)) return;
    this._sessions.add(electronSession);

    electronSession.webRequest.onBeforeRequest((details, callback) => {
      if (!this.engaged || this.isLocal(details.url)) {
        callback({});
        return;
      }
      this.blockedCount++;
      callback({ cancel: true });
    });
  }
}

module.exports = { NetworkLock };
