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
// reached 100% bootstrap, with every session confirmed on its SOCKS port,
// releases it. Anything that never touches the network — the local apps
// server, the engine API, file:// pages — stays reachable throughout, so the
// interface still works while locked.
//
// The filter is the second layer, not the first. It sees URL requests only,
// and Chromium opens some sockets without one. So every session is also
// pointed at Tor's SOCKS port the moment it is protected, and stays pointed
// there for good: while Tor bootstraps, at 100%, after Disconnect and after
// a crash. A Tor that is not running leaves that port closed, and a socket
// the filter never saw fails there instead of leaving from this machine's
// own address. (Another program holding the port keeps Tor from starting,
// so the lock stays shut; but whatever the filter misses then goes to that
// program, hostname included, and it could forward it from this machine's
// own address. Tor on a port of its own choosing, read back over the
// control port, would close that too.) No session is ever set to
// 'direct', and the route never changes, so no late write can put one back
// on another route either. Tabs used to start out on whatever answered on
// port 9050, or on 'direct', and the switch to Tor's rules could miss a tab
// that was still being built.

const { LOOPBACK_ONLY } = require('./proxy-manager');

// The browser's own services: apps server (8090, one *.localhost host per
// app — app-origins.js), engine API (9051),
// SevenNine (8084). All loopback, none of it leaves the machine.
const LOCAL_HOSTS = new Set([
  '127.0.0.1', 'localhost', '::1', '[::1]', '0.0.0.0', '',
]);

// What Chromium may look up by itself: this machine's own names, and nothing
// else. Every other lookup fails inside Chromium before it reaches a
// resolver. A page's <link rel="dns-prefetch"> hint is not a URL request, so
// neither Tor's route nor the filter below ever sees it, and Chromium used to
// hand the name straight to the system resolver: the ISP's resolver learned
// the names a page chose, and the page's own DNS server learned whose
// resolver asked, connected or not. Loading a page still works, because
// Chromium sends the hostname itself to a socks5:// proxy and Tor resolves it
// at the exit. The loopback addresses are listed because Chromium runs IP
// literals through these rules too: without them, Tor's own port and the
// apps server would be unreachable. Chromium matches ::1 written bare.
const HOST_RESOLVER_RULES = 'MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE *.localhost, EXCLUDE 127.0.0.1, EXCLUDE ::1';

// Schemes with no network behind them at all.
const LOCAL_SCHEMES = new Set([
  'file:', 'data:', 'blob:', 'about:', 'devtools:', 'chrome:',
  'chrome-extension:', 'chrome-devtools:', 'hidra:',
]);

class NetworkLock {
  // `proxyRules` is Tor's SOCKS port as Chromium proxy rules, the only route
  // a session of this browser ever has.
  constructor(proxyRules) {
    if (!/^socks5:\/\/127\.0\.0\.1:\d+$/.test(String(proxyRules))) {
      throw new Error('the network lock needs Tor\'s SOCKS port on loopback, got ' + proxyRules);
    }
    this.proxyRules = proxyRules;
    this.engaged = true;
    this.reason = 'the Tor connection is not ready yet';
    this.blockedCount = 0;
    // Bumped by every engage(). A connect takes it before its checks and
    // may open the lock only if nothing closed it again in the meantime.
    this.generation = 0;
    // Each protected session, with its first setProxy still in flight or done.
    this._sessions = new Map();
  }

  getStatus() {
    return {
      engaged: this.engaged,
      reason: this.engaged ? this.reason : null,
      blocked: this.blockedCount,
    };
  }

  // The sessions keep Tor's route: with Tor gone it leads to a closed port,
  // which is what makes closing fail closed. What was open over the old
  // circuits is dropped, so nothing carries on over a socket from before.
  engage(reason) {
    if (!this.engaged) this.blockedCount = 0;
    this.engaged = true;
    this.reason = reason || 'the Tor connection is not ready yet';
    this.generation++;
    for (const s of this._sessions.keys()) {
      try { s.closeAllConnections().catch(() => {}); } catch (e) { /* a session being torn down */ }
    }
  }

  // Opens the lock for the connect that took `generation` before its
  // checks. If Tor died or the user disconnected while those checks were
  // awaited, engage() has moved the generation on and this refuses, so a
  // stale connect cannot reopen a lock that a later close shut.
  release(generation) {
    if (generation !== this.generation) return false;
    this.engaged = false;
    this.reason = null;
    return true;
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
    const host = parsed.hostname.toLowerCase();
    // *.localhost is this machine by definition (RFC 6761), and Chromium
    // resolves it without a DNS query: it is where each app has its origin.
    return LOCAL_HOSTS.has(host) || host.endsWith('.localhost');
  }

  // Installs the filter on a session and points it at Tor. Every session the
  // browser owns has to go through here — the default one plus each tab's
  // partition — because a session without the filter is a hole straight past
  // the lock. Call it the moment the session exists, before anything can load
  // in it; the promise is the route being set, which routed() also hands out.
  protect(electronSession) {
    if (!electronSession) return Promise.resolve();
    if (this._sessions.has(electronSession)) return this._sessions.get(electronSession);

    electronSession.webRequest.onBeforeRequest((details, callback) => {
      if (!this.engaged || this.isLocal(details.url)) {
        callback({});
        return;
      }
      this.blockedCount++;
      callback({ cancel: true });
    });

    const routing = Promise.resolve(electronSession.setProxy(this.proxyConfig()));
    // Whoever waits on it sees a failure; nobody waiting is not a crash.
    routing.catch(() => {});
    this._sessions.set(electronSession, routing);
    return routing;
  }

  proxyConfig() {
    return { proxyRules: this.proxyRules, proxyBypassRules: LOOPBACK_ONLY };
  }

  // Resolves once the session is on Tor's route. Nothing may load in a
  // session before this.
  routed(electronSession) {
    return this._sessions.get(electronSession) || this.protect(electronSession);
  }

  // A session that is gone for good (a closed tab's partition) is no longer
  // checked or closed with the others.
  forget(electronSession) {
    this._sessions.delete(electronSession);
  }

  // What Chromium itself says each protected session would use for a remote
  // address, checked before the lock opens. A session that answers anything
  // but Tor's SOCKS port has its route set again and is asked once more; the
  // ones still wrong after that are returned, and the lock must stay shut.
  async unrouted() {
    const expected = 'SOCKS5 ' + this.proxyRules.slice('socks5://'.length);
    const ask = async (s, routing) => {
      try {
        await routing;
        return (await s.resolveProxy('https://check.torproject.org/')) === expected;
      } catch (e) {
        return false;
      }
    };
    const wrong = [];
    for (const [s, routing] of [...this._sessions]) {
      if (await ask(s, routing)) continue;
      const again = Promise.resolve().then(() => s.setProxy(this.proxyConfig()));
      again.catch(() => {});
      if (this._sessions.has(s)) this._sessions.set(s, again);
      if (!(await ask(s, again))) wrong.push(s);
    }
    return wrong;
  }
}

module.exports = { NetworkLock, HOST_RESOLVER_RULES };
