const { spawn } = require('child_process');
const net = require('net');
const http = require('http');
const path = require('path');

const NODE_API_PORT = 9051;
const LOCAL_SERVICES = [
  { name: 'HidraMail', port: 8080, path: '/api/identity' },
  { name: 'HidraChat', port: 8081, path: '/' },
  { name: 'HidraSearch', port: 8083, path: '/' },
];

class ProxyManager {
  constructor(host, port) {
    this.host = host;
    this.port = port;
    this.hopCount = 3;
    this.connected = false;
    this.nodeConnected = false;
    this.hidraProcess = null;
    this.relayCount = 0;
    this.latencyMs = 0;
    this.mode = 'disconnected';
    this.activeServices = [];
    this._pollInterval = null;
    this._startPolling();
  }

  _startPolling() {
    this._pollInterval = setInterval(() => this._refreshStatus(), 5000);
    this._refreshStatus();
  }

  async _refreshStatus() {
    const proxyOk = await this._checkProxy();
    const nodeOk = await this._checkNodeAPI();
    const services = await this._detectServices();

    this.activeServices = services;

    if (proxyOk) {
      this.connected = true;
      this.nodeConnected = true;
      this.mode = 'full';
    } else if (nodeOk || services.length > 0) {
      this.connected = true;
      this.nodeConnected = true;
      this.mode = 'local';
    } else {
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

    this.connected = proxyOk || (await this._checkNodeAPI()) || (await this._detectServices()).length > 0;
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

    const args = configFile
      ? ['--config', configFile]
      : ['--apps'];

    return new Promise((resolve) => {
      try {
        this.hidraProcess = spawn(hidraPath, args, {
          cwd: path.dirname(hidraPath),
          stdio: ['ignore', 'pipe', 'pipe'],
        });
      } catch (err) {
        console.error('[hidra-node] spawn error:', err.message);
        resolve(false);
        return;
      }

      let started = false;

      this.hidraProcess.stdout.on('data', (data) => {
        const output = data.toString();
        console.log('[hidra-node]', output.trimEnd());
        if ((output.includes('listening') || output.includes('started') || output.includes('HidraNet Apps')) && !started) {
          started = true;
          this.connected = true;
          this.nodeConnected = true;
          this.mode = 'local';
          resolve(true);
        }

        const relayMatch = output.match(/"relay_count":(\d+)/);
        if (relayMatch) {
          this.relayCount = parseInt(relayMatch[1], 10);
        }
      });

      this.hidraProcess.stderr.on('data', (data) => {
        const output = data.toString();
        console.error('[hidra-node]', output.trimEnd());
        if ((output.includes('listening') || output.includes('started') || output.includes('HidraNet Apps')) && !started) {
          started = true;
          this.connected = true;
          this.nodeConnected = true;
          this.mode = 'local';
          resolve(true);
        }
      });

      this.hidraProcess.on('error', (err) => {
        console.error('[hidra-node] process error:', err.message);
        this.hidraProcess = null;
        if (!started) resolve(false);
      });

      this.hidraProcess.on('close', (code) => {
        console.log(`hidra-node exited with code ${code}`);
        this.connected = false;
        this.nodeConnected = false;
        this.mode = 'disconnected';
        this.hidraProcess = null;
      });

      setTimeout(() => {
        if (!started) {
          this._detectServices().then(services => {
            if (services.length > 0) {
              started = true;
              this.connected = true;
              this.nodeConnected = true;
              this.mode = 'local';
              this.activeServices = services;
              resolve(true);
            } else {
              resolve(false);
            }
          });
        }
      }, 8000);
    });
  }

  isRunning() {
    return this.hidraProcess !== null;
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
      hopCount: this.hopCount,
      relayCount: this.relayCount,
      latencyMs: this.latencyMs,
      activeServices: this.activeServices,
    };
  }

  setHopCount(hops) {
    const valid = [3, 5, 7];
    if (valid.includes(hops)) {
      this.hopCount = hops;
      return true;
    }
    return false;
  }

  async _checkProxy() {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(2000);

      socket.on('connect', () => {
        const start = Date.now();
        socket.write(Buffer.from([0x05, 0x01, 0x00]));

        socket.once('data', () => {
          this.latencyMs = Date.now() - start;
          socket.destroy();
          resolve(true);
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

  async _detectServices() {
    const found = [];
    for (const svc of LOCAL_SERVICES) {
      const ok = await this._httpPing(this.host, svc.port, svc.path);
      if (ok) found.push({ name: svc.name, port: svc.port });
    }
    return found;
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

    const candidates = [];

    // Packaged app: binary bundled in resources
    if (process.resourcesPath) {
      candidates.push(path.join(process.resourcesPath, 'bin', bin));
    }

    // Development: relative to project root
    const devRoot = path.join(__dirname, '..', '..', '..', 'hidra-node', 'target');
    candidates.push(
      path.join(devRoot, 'release', bin),
      path.join(devRoot, 'debug', bin),
    );

    // System PATH fallback
    const envPath = process.env.PATH || '';
    const sep = isWin ? ';' : ':';
    for (const dir of envPath.split(sep)) {
      if (dir) candidates.push(path.join(dir, bin));
    }

    for (const p of candidates) {
      if (fs.existsSync(p)) return p;
    }
    return null;
  }
}

module.exports = { ProxyManager };
