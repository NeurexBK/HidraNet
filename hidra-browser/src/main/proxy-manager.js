const { spawn } = require('child_process');
const net = require('net');
const http = require('http');
const path = require('path');

const NODE_API_PORT = 9051;
const SEVENNINE_PORT = 8084;

// Ports 8080/8081/8083 used to be probed here as "HidraMail/HidraChat/
// HidraSearch", the engine's "--apps" mode. Chat, mail, forum and search are
// served by the browser itself now, so probing them only produced false
// "connected" readings whenever the user happened to run something else on
// port 8080.

class ProxyManager {
  constructor(host, port) {
    this.host = host;
    this.port = port;
    this.connected = false;
    this.nodeConnected = false;
    this.hidraProcess = null;
    this.sevenNineProcess = null;
    this.relayCount = 0;
    this.latencyMs = 0;
    this.mode = 'disconnected';
    this.activeServices = [];
    this.lastError = null;
    this._probeCounter = 0;
    this._pollInterval = null;
    this._startPolling();
  }

  _startPolling() {
    this._pollInterval = setInterval(() => this._refreshStatus(), 5000);
    this._refreshStatus();
  }

  async _refreshStatus() {
    const proxyOk = await this._checkProxy();
    const nodeOk = proxyOk ? true : await this._checkNodeAPI();

    if (proxyOk) {
      this.activeServices = [{ name: 'SOCKS5', port: this.port }];
      this.connected = true;
      this.nodeConnected = true;
      this.mode = 'full';
    } else if (nodeOk) {
      this.activeServices = [{ name: 'Node API', port: NODE_API_PORT }];
      this.connected = true;
      this.nodeConnected = true;
      this.mode = 'local';
    } else {
      this.activeServices = [];
      this.connected = false;
      this.nodeConnected = false;
      this.mode = 'disconnected';
    }
  }

  async configure(electronSession) {
    const proxyOk = await this._checkProxy();

    if (proxyOk) {
      const proxyUrl = `socks5://${this.host}:${this.port}`;
      await electronSession.setProxy({
        proxyRules: proxyUrl,
        proxyBypassRules: '<local>',
      });
    } else {
      await electronSession.setProxy({
        mode: 'direct',
      });
    }

    electronSession.enableNetworkEmulation({ offline: false });

    this.connected = proxyOk || (await this._checkNodeAPI());
    return this.connected;
  }

  async startHidraNode(configFile) {
    if (this.hidraProcess) {
      return true;
    }

    const hidraPath = this._findHidraNode();
    if (!hidraPath) {
      console.warn('hidra-node binary not found — start it manually');
      return false;
    }

    // This used to pass "--apps", which starts HidraMail and HidraChat — not a
    // proxy — and which the older release build rejected outright, so Conectar
    // failed either way. "--proxy" is the browser gateway: it opens the SOCKS5
    // port that this manager then points every session at.
    const configPath = configFile || this._findConfig(hidraPath);
    const args = ['--proxy'];
    if (configPath) args.push('--config', configPath);

    // The engine resolves config.toml, keys/ and sites/ against its working
    // directory, and those live next to the config in both the packaged app and
    // the source tree.
    const cwd = configPath ? path.dirname(configPath) : path.dirname(hidraPath);

    this.lastError = null;

    return new Promise((resolve) => {
      try {
        this.hidraProcess = spawn(hidraPath, args, {
          cwd,
          stdio: ['ignore', 'pipe', 'pipe'],
        });
      } catch (err) {
        console.error('[hidra-node] spawn error:', err.message);
        this.lastError = err.message;
        resolve(false);
        return;
      }

      let settled = false;
      let stderrTail = '';

      let readyPoll = null;
      let readyTimeout = null;

      const finish = (ok, reason) => {
        if (settled) return;
        settled = true;
        clearInterval(readyPoll);
        clearTimeout(readyTimeout);
        if (ok) {
          this.connected = true;
          this.nodeConnected = true;
          this.mode = 'full';
        } else if (reason) {
          this.lastError = reason;
        }
        resolve(ok);
      };

      // Readiness used to be inferred from log text, but the engine prints
      // "local relay node started" about 75ms in — roughly a second before the
      // SOCKS5 listener is actually bound. connect() then configured every
      // session while the check still failed, leaving them on a direct
      // connection. The open port is the only signal that means anything here.
      // Must be the raw probe: _checkProxy short-circuits to true whenever a
      // spawned engine is alive, which here would report ready before the port
      // is actually bound — the exact bug this wait exists to prevent.
      readyPoll = setInterval(() => {
        this._probeSocks().then((proxyOk) => {
          if (proxyOk) finish(true);
        });
      }, 250);

      readyTimeout = setTimeout(() => {
        finish(false, 'o motor não abriu a porta SOCKS5 a tempo');
      }, 20000);

      this.hidraProcess.stdout.on('data', (data) => {
        const output = data.toString();
        console.log('[hidra-node]', output.trimEnd());

        const relayMatch = output.match(/"relay_count":(\d+)/);
        if (relayMatch) {
          this.relayCount = parseInt(relayMatch[1], 10);
        }
      });

      this.hidraProcess.stderr.on('data', (data) => {
        const output = data.toString();
        console.error('[hidra-node]', output.trimEnd());
        stderrTail = (stderrTail + output).slice(-500);
      });

      this.hidraProcess.on('error', (err) => {
        console.error('[hidra-node] process error:', err.message);
        this.hidraProcess = null;
        finish(false, err.message);
      });

      this.hidraProcess.on('close', (code) => {
        console.log(`hidra-node exited with code ${code}`);
        this.connected = false;
        this.nodeConnected = false;
        this.mode = 'disconnected';
        this.hidraProcess = null;

        // Exiting before the port ever opened means the launch itself failed.
        // Surface the engine's own message rather than waiting out the timeout
        // and answering with something generic.
        finish(false, this._explainExit(stderrTail, code));
      });
    });
  }

  isRunning() {
    return this.hidraProcess !== null;
  }

  sevenNineRunning() {
    return this.sevenNineProcess !== null;
  }

  // SevenNine is the engine's .hidra site builder. It is a separate mode from
  // the proxy — "--sevennine" serves it on 8084 and opens no SOCKS port — so it
  // gets its own process rather than riding on Conectar.
  async startSevenNine() {
    if (this.sevenNineProcess) return { ok: true, alreadyRunning: true };

    if (await this._httpPing('127.0.0.1', SEVENNINE_PORT, '/')) {
      return { ok: true, alreadyRunning: true, external: true };
    }

    const hidraPath = this._findHidraNode();
    if (!hidraPath) {
      return { ok: false, error: 'binário do hidra-node não encontrado' };
    }

    const configPath = this._findConfig(hidraPath);
    const args = ['--sevennine'];
    if (configPath) args.push('--config', configPath);
    const cwd = configPath ? path.dirname(configPath) : path.dirname(hidraPath);

    return new Promise((resolve) => {
      let proc;
      try {
        proc = spawn(hidraPath, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
      } catch (err) {
        return resolve({ ok: false, error: err.message });
      }
      this.sevenNineProcess = proc;

      let settled = false;
      let stderrTail = '';
      const finish = (result) => {
        if (settled) return;
        settled = true;
        clearInterval(readyPoll);
        clearTimeout(readyTimeout);
        resolve(result);
      };

      // Readiness is the open port, not a log line — the same lesson the proxy
      // start had to learn.
      const readyPoll = setInterval(() => {
        this._httpPing('127.0.0.1', SEVENNINE_PORT, '/').then((up) => {
          if (up) finish({ ok: true, port: SEVENNINE_PORT });
        });
      }, 300);

      const readyTimeout = setTimeout(() => {
        finish({ ok: false, error: `o SevenNine não abriu a porta ${SEVENNINE_PORT} a tempo` });
      }, 20000);

      proc.stdout.on('data', (d) => console.log('[sevennine]', d.toString().trimEnd()));
      proc.stderr.on('data', (d) => {
        stderrTail = (stderrTail + d.toString()).slice(-500);
        console.error('[sevennine]', d.toString().trimEnd());
      });

      proc.on('error', (err) => {
        this.sevenNineProcess = null;
        finish({ ok: false, error: err.message });
      });

      proc.on('close', (code) => {
        this.sevenNineProcess = null;
        finish({ ok: false, error: this._explainExit(stderrTail, code) });
      });
    });
  }

  async stopSevenNine() {
    const proc = this.sevenNineProcess;
    if (!proc) return { ok: true };
    this.sevenNineProcess = null;

    await new Promise((resolve) => {
      let settled = false;
      const done = () => { if (!settled) { settled = true; resolve(); } };
      proc.once('close', done);
      try { proc.kill('SIGTERM'); } catch (e) { done(); }
      setTimeout(() => { try { proc.kill('SIGKILL'); } catch (e) {} done(); }, 5000);
    });

    return { ok: true };
  }

  async shutdown(electronSession) {
    if (this.hidraProcess) {
      this.hidraProcess.kill('SIGTERM');
      this.hidraProcess = null;
    }
    this.connected = false;
    this.nodeConnected = false;
    this.mode = 'disconnected';
    this.activeServices = [];
    if (electronSession) {
      await electronSession.setProxy({ mode: 'direct' });
    }
  }

  shutdownFull() {
    if (this._pollInterval) {
      clearInterval(this._pollInterval);
      this._pollInterval = null;
    }
    if (this.hidraProcess) {
      this.hidraProcess.kill('SIGTERM');
      this.hidraProcess = null;
    }
    if (this.sevenNineProcess) {
      try { this.sevenNineProcess.kill('SIGTERM'); } catch (e) {}
      this.sevenNineProcess = null;
    }
    this.connected = false;
    this.nodeConnected = false;
    this.mode = 'disconnected';
  }

  getStatus() {
    return {
      connected: this.connected,
      nodeConnected: this.nodeConnected,
      mode: this.mode,
      host: this.host,
      port: this.port,
      relayCount: this.relayCount,
      latencyMs: this.latencyMs,
      activeServices: this.activeServices,
      lastError: this.lastError,
    };
  }


  // Any client that opens 9050 without completing a full CONNECT makes the
  // engine log "SOCKS5 session failed: unexpected end of file" — measured for
  // every probe shape, greeting or not, hard close or graceful. Since the status
  // panel refreshes every 5s, probing on each pass filled the engine log with
  // ~720 self-inflicted warnings an hour.
  //
  // When we started the engine ourselves and the process is still alive we
  // already know the port is up, because startHidraNode waits for it. Probe
  // occasionally anyway, so an engine that is running but wedged is still
  // noticed within a minute.
  async _checkProxy() {
    const ownsLiveEngine = this.hidraProcess !== null;
    if (ownsLiveEngine && (this._probeCounter++ % 12) !== 0) {
      return true;
    }
    return this._probeSocks();
  }

  _probeSocks() {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(2000);

      socket.on('connect', () => {
        const start = Date.now();
        socket.write(Buffer.from([0x05, 0x01, 0x00]));

        socket.once('data', (reply) => {
          this.latencyMs = Date.now() - start;
          socket.destroy();
          // 0x05 is the SOCKS5 method-selection reply: proves it speaks SOCKS5,
          // not merely that something holds the port.
          resolve(reply[0] === 0x05);
        });
      });

      socket.on('timeout', () => { socket.destroy(); resolve(false); });
      socket.on('error', () => { socket.destroy(); resolve(false); });

      socket.connect(this.port, this.host);
    });
  }

  async _checkNodeAPI() {
    return this._httpPing(this.host, NODE_API_PORT, '/api/status');
  }

  // The engine logs through `tracing`, so stderr carries ordinary INFO lines as
  // well as failures. Pick the line that actually explains the exit.
  _explainExit(stderrTail, code) {
    const lines = String(stderrTail)
      .replace(/\[[0-9;]*m/g, '')
      .split('\n')
      .map(l => l.trim())
      .filter(Boolean);

    const failure = lines.filter(l => /error|erro|panic|failed|unexpected/i.test(l)).pop();
    return failure || lines.pop() || `hidra-node saiu com código ${code}`;
  }

  // The engine defaults to "config.toml" in its working directory. In the
  // packaged app that sits next to the binary; in the source tree the binary is
  // under hidra-node/target/<profile>/ while the config stays at hidra-node/.
  _findConfig(hidraPath) {
    const fs = require('fs');
    const candidates = [
      path.join(path.dirname(hidraPath), 'config.toml'),
      path.join(__dirname, '..', '..', '..', 'hidra-node', 'config.toml'),
    ];
    for (const p of candidates) {
      if (fs.existsSync(p)) return p;
    }
    return null;
  }

  _httpPing(host, port, urlPath) {
    return new Promise((resolve) => {
      const req = http.get({ hostname: host, port, path: urlPath, timeout: 2000 }, (res) => {
        res.resume();
        resolve(res.statusCode >= 200 && res.statusCode < 500);
      });
      req.on('timeout', () => { req.destroy(); resolve(false); });
      req.on('error', () => resolve(false));
    });
  }

  _findHidraNode() {
    const fs = require('fs');
    const isWin = process.platform === 'win32';
    const bin = isWin ? 'hidra-node.exe' : 'hidra-node';

    // Packaged app: whatever was bundled is the one to run.
    if (process.resourcesPath) {
      const packaged = path.join(process.resourcesPath, 'bin', bin);
      if (fs.existsSync(packaged)) return packaged;
    }

    // Source tree: release and debug drift apart, and only the newer one
    // matches the current source. Picking a profile by position is how the
    // browser ended up launching a build that predated the flags it was
    // written against, which made every Conectar fail.
    const devRoot = path.join(__dirname, '..', '..', '..', 'hidra-node', 'target');
    const builds = ['release', 'debug']
      .map((profile) => path.join(devRoot, profile, bin))
      .filter((p) => fs.existsSync(p))
      .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);
    if (builds.length) return builds[0];

    const envPath = process.env.PATH || '';
    const sep = isWin ? ';' : ':';
    for (const dir of envPath.split(sep)) {
      if (dir && fs.existsSync(path.join(dir, bin))) return path.join(dir, bin);
    }
    return null;
  }
}

module.exports = { ProxyManager };
