const { spawn } = require('child_process');
const http = require('http');
const path = require('path');

// What goes around the proxy: this machine, and nothing else. Chromium's
// '<local>', used here before, also sends every hostname without a dot
// (http://intranet/, http://router/) straight out, DNS lookup included, to
// whatever resolver the local network hands out — past Tor and past the lock.
// *.localhost is listed too: it is where the apps live (app-origins.js).
const LOOPBACK_ONLY = 'localhost,*.localhost,127.0.0.1,[::1]';

const SEVENNINE_PORT = 8084;

// Ports 8080/8081/8083 used to be probed here as "HidraMail/HidraChat/
// HidraSearch", the engine's "--apps" mode. Chat, mail, forum and search are
// served by the browser itself now, so probing them only produced false
// "connected" readings whenever the user happened to run something else on
// port 8080.

// What is left of the engine launcher: SevenNine, the .hidra site builder,
// started when the user opens it. It used to also probe loopback port 9050
// every five seconds and hand the browser's sessions to whatever answered
// there as SOCKS5, or set them to 'direct' when nothing did. Any program on
// the machine can listen on 9050, and a tab opened while Tor was finishing
// its bootstrap kept that route after the kill switch opened. Sessions are
// routed by the network lock now (network-lock.js), always to Tor; nothing
// here touches a session or listens for a proxy.
class ProxyManager {
  constructor() {
    this.sevenNineProcess = null;
  }

  sevenNineRunning() {
    return this.sevenNineProcess !== null;
  }

  // SevenNine is the engine's .hidra site builder. It is a separate mode from
  // the proxy — "--sevennine" serves it on 8084 and opens no SOCKS port — so it
  // gets its own process rather than riding on Connect.
  async startSevenNine() {
    return this._startEngineApp('sevenNineProcess', '--sevennine', SEVENNINE_PORT, 'sevennine');
  }

  /// Readiness is always the port opening, never a log line — the lesson
  /// learned from starting the proxy.
  async _startEngineApp(field, flag, port, label) {
    if (this[field]) return { ok: true, alreadyRunning: true };

    if (await this._httpPing('127.0.0.1', port, '/')) {
      return { ok: true, alreadyRunning: true, external: true };
    }

    const hidraPath = this._findHidraNode();
    if (!hidraPath) {
      return { ok: false, error: 'hidra-node binary not found' };
    }

    const configPath = this._findConfig(hidraPath);
    const args = [flag];
    if (configPath) args.push('--config', configPath);
    const cwd = configPath ? path.dirname(configPath) : path.dirname(hidraPath);

    return new Promise((resolve) => {
      let proc;
      try {
        proc = spawn(hidraPath, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
      } catch (err) {
        return resolve({ ok: false, error: err.message });
      }
      this[field] = proc;

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
        this._httpPing('127.0.0.1', port, '/').then((up) => {
          if (up) finish({ ok: true, port: port });
        });
      }, 300);

      const readyTimeout = setTimeout(() => {
        finish({ ok: false, error: `SevenNine did not open port ${port} in time` });
      }, 20000);

      proc.stdout.on('data', (d) => console.log('[' + label + ']', d.toString().trimEnd()));
      proc.stderr.on('data', (d) => {
        stderrTail = (stderrTail + d.toString()).slice(-500);
        console.error('[' + label + ']', d.toString().trimEnd());
      });

      proc.on('error', (err) => {
        this[field] = null;
        finish({ ok: false, error: err.message });
      });

      proc.on('close', (code) => {
        this[field] = null;
        finish({ ok: false, error: this._explainExit(stderrTail, code) });
      });
    });
  }

  async stopSevenNine() {
    return this._stopEngineApp('sevenNineProcess');
  }

  async _stopEngineApp(field) {
    const proc = this[field];
    if (!proc) return { ok: true };
    this[field] = null;

    await new Promise((resolve) => {
      let settled = false;
      const done = () => { if (!settled) { settled = true; resolve(); } };
      proc.once('close', done);
      try { proc.kill('SIGTERM'); } catch (e) { done(); }
      setTimeout(() => { try { proc.kill('SIGKILL'); } catch (e) {} done(); }, 5000);
    });

    return { ok: true };
  }

  shutdownFull() {
    if (this.sevenNineProcess) {
      try { this.sevenNineProcess.kill('SIGTERM'); } catch (e) {}
      this.sevenNineProcess = null;
    }
  }

  // The engine logs through `tracing`, so stderr carries ordinary INFO lines as
  // well as failures. Pick the line that actually explains the exit.
  _explainExit(stderrTail, code) {
    const lines = String(stderrTail)
      .replace(/\[[0-9;]*m/g, '')
      .split('\n')
      .map(l => l.trim())
      .filter(Boolean);

    const failure = lines.filter(l => /error|panic|failed|unexpected/i.test(l)).pop();
    return failure || lines.pop() || `hidra-node exited with code ${code}`;
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
    // written against, which made every Connect fail.
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

module.exports = { ProxyManager, LOOPBACK_ONLY };
