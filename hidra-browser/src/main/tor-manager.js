const { spawn } = require('child_process');
const net = require('net');
const path = require('path');
const fs = require('fs');

// 9050/9051 belong to hidra-node, so Tor gets its own pair.
const SOCKS_PORT = 9052;
const CONTROL_PORT = 9053;

/**
 * Runs the bundled Tor daemon and reports its bootstrap progress.
 *
 * This is what gives the browser real anonymity. The HidraNet engine's own
 * onion circuit runs over relays listed in config.toml as 127.0.0.1:7001-7003,
 * so it encrypts in layers but exits from the user's own machine and never
 * changes their IP. Tor's volunteer relay network does.
 */
class TorManager {
  constructor(socksPort = SOCKS_PORT, controlPort = CONTROL_PORT) {
    this.socksPort = socksPort;
    this.controlPort = controlPort;
    this.dataDir = null;
    this.process = null;
    this.bootstrapPercent = 0;
    this.state = 'stopped'; // stopped | starting | ready | failed
    this.lastError = null;
    this.exitIp = null;
    this._stopping = false;
    // The start in progress, if any. See start().
    this._starting = null;
    // When the running Tor reached 100%: what the panel's uptime counts from.
    this.readyAt = null;
    // Set by the main process. Called when Tor dies without us having
    // asked — the moment traffic stops being protected and the kill
    // switch has to close again.
    this.onUnexpectedExit = null;
  }

  isRunning() {
    return this.process !== null && this.state === 'ready';
  }

  getStatus() {
    return {
      state: this.state,
      bootstrapPercent: this.bootstrapPercent,
      socksPort: this.socksPort,
      proxyRules: `socks5://127.0.0.1:${this.socksPort}`,
      exitIp: this.exitIp,
      lastError: this.lastError,
      readyAt: this.state === 'ready' ? this.readyAt : null,
    };
  }

  /**
   * Environment for the Tor process, with its own directory on the library
   * search path.
   *
   * The bundled Linux build is dynamically linked against libevent, which is
   * not part of a base system on most distributions. Without this it died at
   * startup with "error while loading shared libraries: libevent-2.1.so.7" —
   * the browser opened, Tor never came up, and nothing connected. The library
   * now ships next to the binary, and this is what lets it be found.
   */
  _env(torPath) {
    const dir = path.dirname(torPath);
    const key = process.platform === 'darwin' ? 'DYLD_LIBRARY_PATH' : 'LD_LIBRARY_PATH';
    if (process.platform === 'win32') return process.env;
    const existing = process.env[key];
    return {
      ...process.env,
      [key]: existing ? dir + path.delimiter + existing : dir,
    };
  }

  findBinary() {
    const exe = process.platform === 'win32' ? 'tor.exe' : 'tor';
    const candidates = [];

    // Packaged app: bundled next to hidra-node under resources/bin.
    if (process.resourcesPath) {
      candidates.push(path.join(process.resourcesPath, 'bin', 'tor', exe));
    }
    // Source tree: scripts/fetch-tor.js keeps one folder per platform/arch.
    const build = path.join(__dirname, '..', '..', 'build', 'bin', 'tor');
    candidates.push(path.join(build, `${process.platform}-${process.arch}`, exe));
    candidates.push(path.join(build, exe));

    for (const p of candidates) {
      if (fs.existsSync(p)) return p;
    }

    // Last resort: a Tor the user already has. Better to run theirs than to
    // tell someone with a working Tor that we could not find one.
    for (const dir of (process.env.PATH || '').split(path.delimiter)) {
      if (!dir) continue;
      const p = path.join(dir, exe);
      try {
        fs.accessSync(p, fs.constants.X_OK);
        return p;
      } catch { /* not here */ }
    }
    return null;
  }

  _dataFiles(torPath) {
    const dir = path.dirname(torPath);
    const geoip = path.join(dir, 'geoip');
    const geoip6 = path.join(dir, 'geoip6');
    return {
      geoip: fs.existsSync(geoip) ? geoip : null,
      geoip6: fs.existsSync(geoip6) ? geoip6 : null,
    };
  }

  async _waitPortFree(ms) {
    const until = Date.now() + ms;
    while (!(await this._portFree())) {
      if (Date.now() >= until) return false;
      await new Promise((r) => setTimeout(r, 1000));
    }
    return true;
  }

  _portFree() {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(1000);
      socket.once('connect', () => { socket.destroy(); resolve(false); });
      socket.once('timeout', () => { socket.destroy(); resolve(true); });
      socket.once('error', () => { socket.destroy(); resolve(true); });
      socket.connect(this.socksPort, '127.0.0.1');
    });
  }

  /**
   * Starts Tor and resolves once it reports 100% bootstrapped.
   * `onProgress({ percent, summary })` fires as it climbs.
   *
   * One start at a time. The browser starts Tor by itself when it opens, and
   * the new tab page's Connect button can be pressed while that start is
   * still bootstrapping. A second start used to run beside the first: it
   * found the port held by the first Tor, waited twenty seconds and marked
   * the connection failed while the first Tor was carrying the traffic, and
   * the kill switch closed again. Pressed at the same moment, it spawned a
   * second Tor on the same data directory, which refused to run and, dying,
   * took the first one's place in the bookkeeping. Now a start asked for
   * while one is under way waits for that one and gets its result.
   */
  start(dataDir, onProgress) {
    if (this.isRunning()) return Promise.resolve({ ok: true, alreadyRunning: true });
    if (!this._starting) {
      this._starting = this._start(dataDir, onProgress).finally(() => { this._starting = null; });
    }
    return this._starting;
  }

  async _start(dataDir, onProgress) {
    // Whatever address the last connection left through is not this one's.
    this.exitIp = null;

    const torPath = this.findBinary();
    if (!torPath) {
      this.state = 'failed';
      this.lastError = 'Tor binary not found — run: node scripts/fetch-tor.js';
      return { ok: false, error: this.lastError };
    }

    // A Tor left behind by a browser that never got to shut down — killed,
    // crashed, logged out — holds the port until it notices its owner is gone
    // (see __OwningControllerProcess below), which takes it up to about
    // fifteen seconds. Wait that out instead of failing the connection.
    if (!(await this._waitPortFree(20000))) {
      this.state = 'failed';
      this.lastError = `port ${this.socksPort} is already in use`;
      return { ok: false, error: this.lastError };
    }

    const torData = path.join(dataDir, 'tor-data');
    try {
      fs.mkdirSync(torData, { recursive: true });
    } catch (e) {
      this.state = 'failed';
      this.lastError = `could not create ${torData}: ${e.message}`;
      return { ok: false, error: this.lastError };
    }

    const { geoip, geoip6 } = this._dataFiles(torPath);

    this.dataDir = torData;

    const args = [
      // A circuit per destination. Chromium sends no SOCKS credentials, so
      // Tor's usual isolation by them cannot separate one tab from another;
      // without this, every site visited within ten minutes left through the
      // same exit, which links them for anyone watching that exit or
      // comparing what the sites saw. Each destination address now gets a
      // circuit of its own.
      '--SocksPort', `${this.socksPort} IsolateDestAddr`,
      // Needed for "new identity": SIGNAL NEWNYM tears down the current
      // circuits so the next request leaves through a different exit.
      '--ControlPort', String(this.controlPort),
      '--CookieAuthentication', '1',
      '--DataDirectory', torData,
      '--ClientOnly', '1',
      // Nothing outside this machine may use us as a proxy.
      '--SocksPolicy', 'accept 127.0.0.1',
      '--SocksPolicy', 'reject *',
      '--AvoidDiskWrites', '1',
      '--Log', 'notice stdout',
      // Tor exits by itself when this process does. It is only ever stopped
      // from the window-all-closed handler, so a browser that was killed,
      // crashed or lost its session left Tor running — holding the port, so
      // the next start failed with "port 9052 is already in use" until the
      // user found and killed it. Tor Browser starts its tor the same way.
      '__OwningControllerProcess', String(process.pid),
    ];
    if (geoip) args.push('--GeoIPFile', geoip);
    if (geoip6) args.push('--GeoIPv6File', geoip6);

    this.state = 'starting';
    this.bootstrapPercent = 0;
    this.lastError = null;
    this.exitIp = null;

    return new Promise((resolve) => {
      try {
        this.process = spawn(torPath, args, {
          cwd: path.dirname(torPath),
          stdio: ['ignore', 'pipe', 'pipe'],
          env: this._env(torPath),
        });
      } catch (err) {
        this.state = 'failed';
        this.lastError = err.message;
        this.process = null;
        return resolve({ ok: false, error: this.lastError });
      }

      let settled = false;
      let logTail = '';

      const finish = (result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(result);
      };

      const timer = setTimeout(() => {
        this.state = 'failed';
        this.lastError = `Tor did not finish bootstrapping in 120s (stalled at ${this.bootstrapPercent}%)`;
        finish({ ok: false, error: this.lastError });
      }, 120000);

      const readLine = (line) => {
        logTail = (logTail + line + '\n').slice(-1000);

        const m = line.match(/Bootstrapped (\d+)%(?:\s*\(([^)]*)\))?/);
        if (m) {
          this.bootstrapPercent = parseInt(m[1], 10);
          const summary = m[2] || '';
          if (typeof onProgress === 'function') {
            try { onProgress({ percent: this.bootstrapPercent, summary }); } catch (e) {}
          }
          if (this.bootstrapPercent >= 100) {
            this.state = 'ready';
            this.readyAt = Date.now();
            finish({ ok: true, socksPort: this.socksPort });
          }
        }

        if (/\[err\]/i.test(line)) {
          this.lastError = line.replace(/^.*\[err\]\s*/i, '').trim();
        }
      };

      const attach = (stream) => {
        let buffer = '';
        stream.on('data', (chunk) => {
          buffer += chunk.toString();
          const lines = buffer.split('\n');
          buffer = lines.pop();
          for (const l of lines) {
            const line = l.trim();
            if (!line) continue;
            console.log('[tor]', line);
            readLine(line);
          }
        });
      };

      attach(this.process.stdout);
      attach(this.process.stderr);

      this.process.on('error', (err) => {
        this.state = 'failed';
        this.lastError = err.message;
        this.process = null;
        finish({ ok: false, error: this.lastError });
      });

      this.process.on('close', (code) => {
        console.log('[tor] process exited, code', code);
        this.process = null;

        // A stop() we asked for is not a failure — without this the panel showed
        // "failed" right after the user pressed Disconnect.
        if (this._stopping) {
          this._stopping = false;
          this.state = 'stopped';
          this.bootstrapPercent = 0;
          // Stopped before it was up: the start waiting on it ends now, as a
          // start that did not happen, instead of hanging until the two-minute
          // timeout marked a Tor nobody was running any more as failed.
          finish({ ok: false, error: 'Tor was stopped before it finished connecting' });
          return;
        }

        if (this.state === 'ready') {
          // Died on its own after having worked.
          this.state = 'failed';
          this.exitIp = null;
          this.lastError = this.lastError || 'Tor exited unexpectedly';
          if (typeof this.onUnexpectedExit === 'function') {
            try { this.onUnexpectedExit(this.lastError); } catch (e) {}
          }
          return;
        }

        this.state = 'failed';
        if (!this.lastError) {
          this.lastError = logTail.trim().split('\n').pop() || `tor exited with code ${code}`;
        }
        finish({ ok: false, error: this.lastError });
      });
    });
  }

  // Sends one command over Tor's control port, authenticating with the cookie
  // file Tor writes into its data directory.
  _control(command) {
    return new Promise((resolve, reject) => {
      let cookie;
      try {
        cookie = fs.readFileSync(path.join(this.dataDir, 'control_auth_cookie')).toString('hex');
      } catch (e) {
        return reject(new Error('could not read the Tor control cookie'));
      }

      const socket = new net.Socket();
      let buffer = '';
      let step = 'auth';

      // A reply ends on a line whose status code is followed by a space.
      const replyComplete = () => {
        if (!buffer.endsWith('\r\n')) return false;
        const lines = buffer.split('\r\n').filter(Boolean);
        return /^\d{3} /.test(lines[lines.length - 1] || '');
      };

      socket.setTimeout(10000);
      socket.on('data', (chunk) => {
        buffer += chunk.toString();
        if (!replyComplete()) return;

        if (step === 'auth') {
          if (!buffer.startsWith('250')) {
            socket.destroy();
            return reject(new Error('control port authentication refused'));
          }
          step = 'cmd';
          buffer = '';
          socket.write(command + '\r\n');
          return;
        }

        const reply = buffer.trim();
        socket.destroy();
        reply.startsWith('250') ? resolve(reply) : reject(new Error(reply));
      });

      socket.on('timeout', () => { socket.destroy(); reject(new Error('control port timeout')); });
      socket.on('error', reject);
      socket.connect(this.controlPort, '127.0.0.1', () => socket.write(`AUTHENTICATE ${cookie}\r\n`));
    });
  }

  async newIdentity() {
    if (!this.isRunning()) return { ok: false, error: 'Tor is not connected' };
    try {
      await this._control('SIGNAL NEWNYM');
      this.exitIp = null;
      return { ok: true };
    } catch (e) {
      return { ok: false, error: e.message };
    }
  }

  async stop() {
    if (!this.process) {
      this.state = 'stopped';
      this.bootstrapPercent = 0;
      this.exitIp = null;
      return;
    }
    const proc = this.process;
    this._stopping = true;
    this.state = 'stopped';
    this.bootstrapPercent = 0;
    this.exitIp = null;

    // Wait for the port to actually be released, otherwise pressing Connect
    // right after Disconnect hits "port 9052 is already in use".
    await new Promise((resolve) => {
      let settled = false;
      const done = () => { if (!settled) { settled = true; resolve(); } };
      proc.once('close', done);
      try { proc.kill('SIGTERM'); } catch (e) { done(); }
      setTimeout(() => { try { proc.kill('SIGKILL'); } catch (e) {} done(); }, 5000);
    });
  }
}

module.exports = { TorManager, SOCKS_PORT };
