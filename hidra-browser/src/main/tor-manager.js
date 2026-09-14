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
   */
  async start(dataDir, onProgress) {
    if (this.isRunning()) return { ok: true, alreadyRunning: true };

    const torPath = this.findBinary();
    if (!torPath) {
      this.state = 'failed';
      this.lastError = 'binário do Tor não encontrado — rode: node scripts/fetch-tor.js';
      return { ok: false, error: this.lastError };
    }

    if (!(await this._portFree())) {
      this.state = 'failed';
      this.lastError = `a porta ${this.socksPort} já está ocupada`;
      return { ok: false, error: this.lastError };
    }

    const torData = path.join(dataDir, 'tor-data');
    try {
      fs.mkdirSync(torData, { recursive: true });
    } catch (e) {
      this.state = 'failed';
      this.lastError = `não consegui criar ${torData}: ${e.message}`;
      return { ok: false, error: this.lastError };
    }

    const { geoip, geoip6 } = this._dataFiles(torPath);

    this.dataDir = torData;

    const args = [
      '--SocksPort', String(this.socksPort),
      // Needed for "nova identidade": SIGNAL NEWNYM tears down the current
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
        this.lastError = `o Tor não completou o bootstrap em 120s (parou em ${this.bootstrapPercent}%)`;
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
        console.log('[tor] processo terminou, código', code);
        this.process = null;

        // A stop() we asked for is not a failure — without this the panel showed
        // "failed" right after the user pressed Desconectar.
        if (this._stopping) {
          this._stopping = false;
          this.state = 'stopped';
          this.bootstrapPercent = 0;
          return;
        }

        if (this.state === 'ready') {
          // Died on its own after having worked.
          this.state = 'failed';
          this.lastError = this.lastError || 'o Tor encerrou inesperadamente';
          return;
        }

        this.state = 'failed';
        if (!this.lastError) {
          this.lastError = logTail.trim().split('\n').pop() || `tor saiu com código ${code}`;
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
        return reject(new Error('não consegui ler o cookie de controle do Tor'));
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
            return reject(new Error('autenticação no control port recusada'));
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

      socket.on('timeout', () => { socket.destroy(); reject(new Error('timeout no control port')); });
      socket.on('error', reject);
      socket.connect(this.controlPort, '127.0.0.1', () => socket.write(`AUTHENTICATE ${cookie}\r\n`));
    });
  }

  async newIdentity() {
    if (!this.isRunning()) return { ok: false, error: 'o Tor não está conectado' };
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

    // Wait for the port to actually be released, otherwise pressing Conectar
    // right after Desconectar hits "a porta 9052 já está ocupada".
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
