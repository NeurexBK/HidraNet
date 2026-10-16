// Installing, updating and removing HidraVPN from inside the browser.
//
// The browser does not contain the VPN; it fetches it. The maintainers
// publish a release manifest — every file of a release, per platform, with
// its SHA-256 and size — and sign it offline with the release key
// (`hidravpn-sign sign manifest.json`). This module:
//
//   1. fetches the manifest and its .sig and checks the signature against the
//      release key built into this browser (release-verify.js) before a byte
//      of the manifest is parsed;
//   2. downloads the files for this platform into a fresh private folder and
//      checks each one's size and SHA-256 against the signed manifest;
//   3. asks for administrator rights once — UAC on Windows, pkexec on Linux —
//      and runs `hidravpn-service install` from that folder, which copies the
//      service into place, registers it, makes the machine's key and, on
//      Linux, puts this user in the hidravpn group.
//
// Nothing runs that the release key did not vouch for, and a manifest that
// fails the check is not read at all: it could say anything. An update is the
// same path with a newer manifest; the service stops, is replaced and starts.
//
// Uninstalling asks for administrator rights the same way and runs the
// installed service's own `uninstall` (with `--purge` to also remove the
// programs, the nodes and the machine's key).

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');

const releaseVerify = require('./release-verify');

const MANIFEST_MAX_BYTES = 64 * 1024;
const FILE_MAX_BYTES = 64 * 1024 * 1024;
const MAX_FILES = 8;
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const VERSION_RE = /^\d{1,4}\.\d{1,4}\.\d{1,4}$/;

// What this machine is, as the manifest names it.
function platformKey(platform = process.platform, arch = process.arch) {
  return `${platform}-${arch}`;
}

// Where an installed service lives (install/mod.rs installed_binary()).
function installedService(platform = process.platform, env = process.env) {
  if (platform === 'win32') {
    return path.join(env.ProgramFiles || 'C:\\Program Files', 'HidraVPN', 'hidravpn-service.exe');
  }
  return '/usr/local/bin/hidravpn-service';
}

// 0.4.10 > 0.4.9: numbers, not strings. Anything unparseable sorts lowest.
function compareVersions(a, b) {
  const pa = String(a || '').split('.').map((n) => parseInt(n, 10));
  const pb = String(b || '').split('.').map((n) => parseInt(n, 10));
  for (let i = 0; i < 3; i++) {
    const x = Number.isFinite(pa[i]) ? pa[i] : -1;
    const y = Number.isFinite(pb[i]) ? pb[i] : -1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

// The manifest, checked field by field. Throws with a reason a person can
// read; whatever passes is safe to act on (names cannot climb out of the
// folder, URLs are https, hashes are hashes).
function parseManifest(text) {
  let m;
  try {
    m = JSON.parse(text);
  } catch {
    throw new Error('the release manifest is not valid JSON');
  }
  if (!m || typeof m !== 'object') throw new Error('the release manifest is empty');
  if (m.product !== 'hidravpn') throw new Error('the manifest is not for HidraVPN');
  if (!VERSION_RE.test(String(m.version || ''))) throw new Error('the manifest has no version of the form X.Y.Z');
  if (!m.platforms || typeof m.platforms !== 'object') throw new Error('the manifest lists no platforms');
  const platforms = {};
  for (const [key, p] of Object.entries(m.platforms)) {
    if (!/^[a-z0-9]+-[a-z0-9_]+$/.test(key)) throw new Error(`the manifest names a platform oddly: ${key}`);
    if (!p || !Array.isArray(p.files) || !p.files.length || p.files.length > MAX_FILES) {
      throw new Error(`${key}: a platform lists between 1 and ${MAX_FILES} files`);
    }
    const files = p.files.map((f) => {
      if (!f || !NAME_RE.test(String(f.name || ''))) throw new Error(`${key}: a file has no plain name`);
      let u;
      try { u = new URL(String(f.url || '')); } catch { throw new Error(`${key}/${f.name}: the URL is not a URL`); }
      if (u.protocol !== 'https:') throw new Error(`${key}/${f.name}: only https downloads are accepted`);
      if (!/^[0-9a-f]{64}$/.test(String(f.sha256 || ''))) throw new Error(`${key}/${f.name}: the SHA-256 is not 64 hex digits`);
      const size = Number(f.size);
      if (!Number.isInteger(size) || size <= 0 || size > FILE_MAX_BYTES) throw new Error(`${key}/${f.name}: the size is not sensible`);
      return { name: f.name, url: u.href, sha256: f.sha256, size };
    });
    const names = new Set(files.map((f) => f.name));
    if (names.size !== files.length) throw new Error(`${key}: a file is listed twice`);
    if (!names.has(p.service)) throw new Error(`${key}: the service named is not among the files`);
    if (p.client !== undefined && !names.has(p.client)) throw new Error(`${key}: the client named is not among the files`);
    platforms[key] = { files, service: p.service, client: p.client };
  }
  return { version: m.version, generated: String(m.generated || ''), platforms };
}

class VpnInstaller {
  constructor(options = {}) {
    this.manifestUrl = options.manifestUrl;
    this.publicKey = options.publicKey !== undefined ? options.publicKey : releaseVerify.RELEASE_PUBLIC_KEY;
    this.platform = options.platform || process.platform;
    this.arch = options.arch || process.arch;
    this.env = options.env || process.env;
    // Injected: fetchText(url, maxBytes) -> string; fetchBuffer(url, maxBytes) -> Buffer;
    // run(file, args, env) -> { code, stdout, stderr }.
    this.fetchText = options.fetchText;
    this.fetchBuffer = options.fetchBuffer;
    this.run = options.run || runFile;
    this.tmpRoot = options.tmpRoot || os.tmpdir();
    this.user = options.user || safeUser();
  }

  // The newest signed release, or why there is none to trust.
  //   { ok: true, version, supported, generated } | { ok: false, error }
  async checkRelease() {
    let m;
    try {
      m = await this._manifest();
    } catch (e) {
      return { ok: false, error: e.message };
    }
    const supported = Boolean(m.platforms[platformKey(this.platform, this.arch)]);
    return { ok: true, version: m.version, generated: m.generated, supported };
  }

  async _manifest() {
    if (!this.publicKey) throw new Error('this browser carries no release key, so it cannot trust any release');
    if (!this.manifestUrl) throw new Error('no release address is configured');
    let text;
    let sig;
    try {
      [text, sig] = await Promise.all([
        this.fetchText(this.manifestUrl, MANIFEST_MAX_BYTES),
        this.fetchText(this.manifestUrl + '.sig', 4096),
      ]);
    } catch (e) {
      throw new Error(`could not fetch the release from ${this.manifestUrl}: ${(e && e.message) || e}`);
    }
    // Before anything is parsed: an unsigned manifest could say anything.
    if (!releaseVerify.verifyBytes(Buffer.from(text, 'utf8'), sig, this.publicKey)) {
      throw new Error('the release manifest is not signed by the HidraVPN release key; nothing was downloaded');
    }
    return parseManifest(text);
  }

  // Downloads, checks and installs (or updates). Resolves to
  //   { ok: true, version, note } | { ok: false, error, cancelled? }
  async install() {
    if (this.platform !== 'win32' && this.platform !== 'linux') {
      return { ok: false, error: 'HidraVPN installs on Windows and Linux; macOS is not supported yet' };
    }
    let m;
    try {
      m = await this._manifest();
    } catch (e) {
      return { ok: false, error: e.message };
    }
    const key = platformKey(this.platform, this.arch);
    const p = m.platforms[key];
    if (!p) return { ok: false, error: `release ${m.version} has no build for ${key}` };

    const dir = await fs.promises.mkdtemp(path.join(this.tmpRoot, 'hidravpn-install-'));
    try {
      await fs.promises.chmod(dir, 0o700).catch(() => {});
      for (const f of p.files) {
        let data;
        try {
          data = await this.fetchBuffer(f.url, f.size);
        } catch (e) {
          return { ok: false, error: `could not download ${f.name}: ${(e && e.message) || e}` };
        }
        if (data.length !== f.size) {
          return { ok: false, error: `${f.name} is ${data.length} bytes; the signed manifest says ${f.size}. Nothing was installed.` };
        }
        const got = crypto.createHash('sha256').update(data).digest('hex');
        if (got !== f.sha256) {
          return { ok: false, error: `${f.name} does not match the signed manifest (SHA-256 ${got}). Nothing was installed.` };
        }
        await fs.promises.writeFile(path.join(dir, f.name), data, { mode: 0o700 });
      }
      const service = path.join(dir, p.service);
      const args = ['install'];
      if (p.client) args.push('--client', path.join(dir, p.client));
      if (this.platform === 'linux' && this.user) args.push('--user', this.user);
      const r = await this._elevated(service, args);
      if (r.cancelled) return { ok: false, cancelled: true, error: 'administrator rights were not given; nothing was installed' };
      if (r.code !== 0) {
        return { ok: false, error: `the installer failed (exit ${r.code}): ${(r.stderr || r.stdout || '').trim().slice(0, 400)}` };
      }
      const note = this.platform === 'linux'
        ? `HidraVPN ${m.version} is installed and running. Log out and in once so this account can drive it.`
        : `HidraVPN ${m.version} is installed and running.`;
      return { ok: true, version: m.version, note };
    } finally {
      await fs.promises.rm(dir, { recursive: true, force: true }).catch(() => {});
    }
  }

  // Removes the service; with `purge`, also the programs, the nodes and the
  // machine's key.
  async uninstall(purge) {
    if (this.platform !== 'win32' && this.platform !== 'linux') {
      return { ok: false, error: 'nothing to uninstall on this system' };
    }
    const service = installedService(this.platform, this.env);
    const args = purge ? ['uninstall', '--purge'] : ['uninstall'];
    const r = await this._elevated(service, args);
    if (r.cancelled) return { ok: false, cancelled: true, error: 'administrator rights were not given; nothing was removed' };
    if (r.code !== 0) {
      return { ok: false, error: `uninstalling failed (exit ${r.code}): ${(r.stderr || r.stdout || '').trim().slice(0, 400)}` };
    }
    return {
      ok: true,
      note: purge
        ? 'HidraVPN is removed, with its programs, its nodes and this machine\'s key.'
        : 'HidraVPN is removed. This machine\'s key and nodes are kept for a later install.',
    };
  }

  // Runs `file args` with administrator rights, asking the person once.
  // The paths travel in environment variables, never inside a command
  // string, so no file name can become part of a command.
  async _elevated(file, args) {
    if (this.platform === 'win32') {
      const script =
        "$ErrorActionPreference='Stop';" +
        "$a=$env:HV_ARGS | ConvertFrom-Json;" +
        "try{$p=Start-Process -FilePath $env:HV_FILE -ArgumentList ($a | ForEach-Object { '\"' + $_ + '\"' }) -Verb RunAs -Wait -PassThru -WindowStyle Hidden}" +
        "catch{exit 1223};" +
        'exit $p.ExitCode';
      const r = await this.run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
        HV_FILE: file,
        HV_ARGS: JSON.stringify(args),
      });
      // 1223: ERROR_CANCELLED, the person said no to the UAC prompt.
      return { ...r, cancelled: r.code === 1223 };
    }
    const r = await this.run('pkexec', [file, ...args], {});
    // pkexec: 126 the dialog was dismissed, 127 not authorised.
    return { ...r, cancelled: r.code === 126 || r.code === 127 };
  }
}

function safeUser() {
  try {
    const u = os.userInfo().username;
    return /^[A-Za-z0-9._-]{1,32}$/.test(u) ? u : null;
  } catch {
    return null;
  }
}

function runFile(file, args, extraEnv) {
  return new Promise((resolve) => {
    execFile(file, args, { env: { ...process.env, ...extraEnv }, windowsHide: true, timeout: 10 * 60 * 1000 },
      (err, stdout, stderr) => {
        let code = 0;
        if (err) code = typeof err.code === 'number' ? err.code : 1;
        resolve({ code, stdout: String(stdout || ''), stderr: String(stderr || (err && err.code === 'ENOENT' ? `${file} was not found` : '')) });
      });
  });
}

module.exports = { VpnInstaller, parseManifest, compareVersions, platformKey, installedService, MANIFEST_MAX_BYTES, FILE_MAX_BYTES };
