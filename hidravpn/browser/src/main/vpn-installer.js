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
//      and, with those rights, copies the files into a folder only an
//      administrator can write, checks each copy's SHA-256 again there, and
//      only then runs `hidravpn-service install` from it. That copies the
//      service into place, registers it, makes the machine's key and, on
//      Linux, puts this user in the hidravpn group.
//
// Why the second check: the download folder belongs to this user, so any
// other program running as this user could swap a file in it between the
// first check and the moment it runs — and whatever was swapped in would run
// as root or Administrator. A copy in a folder this user cannot write, checked
// after the copy, cannot be swapped.
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
// The exit code the privileged step uses when a copy does not match.
const CHANGED_AFTER_CHECK = 65;

// Linux, run as root by pkexec. A fixed script: everything it is told comes
// in as positional arguments, never as part of the script, so no file name
// or path can become a command. It makes a root-only folder (mktemp -d is
// 0700), copies each file in, refuses anything that is not a plain file or
// whose SHA-256 is not the one from the signed manifest, and only then runs
// the service from there. The folder is removed whatever happens.
//   $1 base folder  $2 download folder  $3 service  $4 client or ''
//   $5 user or ''   then pairs of: name sha256
const LINUX_INSTALL_SCRIPT = [
  'set -eu',
  'base=$1; src=$2; service=$3; client=$4; user=$5; shift 5',
  'umask 077',
  'dst=$(mktemp -d "$base/hidravpn-install.XXXXXXXX")',
  'trap \'rm -rf -- "$dst"\' EXIT',
  'while [ $# -ge 2 ]; do',
  '  name=$1; want=$2; shift 2',
  '  case $name in ""|*/*|.*) exit ' + CHANGED_AFTER_CHECK + ';; esac',
  '  cp -- "$src/$name" "$dst/$name"',
  '  if [ -L "$dst/$name" ] || [ ! -f "$dst/$name" ]; then exit ' + CHANGED_AFTER_CHECK + '; fi',
  '  got=$(sha256sum -- "$dst/$name" | cut -d" " -f1)',
  '  if [ "$got" != "$want" ]; then echo "$name changed after it was checked" >&2; exit ' + CHANGED_AFTER_CHECK + '; fi',
  '  chmod 0700 -- "$dst/$name"',
  'done',
  'set -- install',
  'if [ -n "$client" ]; then set -- "$@" --client "$dst/$client"; fi',
  'if [ -n "$user" ]; then set -- "$@" --user "$user"; fi',
  '"$dst/$service" "$@"',
].join('\n');

// Windows, run as Administrator through UAC. The same steps in PowerShell.
// What it is told travels as base64 JSON inside a string literal (base64 has
// no quote), never as code. The folder is made under Program Files, found
// through the known-folder API rather than an environment variable this user
// could set, where an ordinary account cannot write.
const WINDOWS_INSTALL_SCRIPT = [
  "$ErrorActionPreference='Stop'",
  "$d=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@PAYLOAD@'))|ConvertFrom-Json",
  "$root=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) ('HidraVPN-install-'+[guid]::NewGuid().ToString('N'))",
  'New-Item -ItemType Directory -Path $root|Out-Null',
  'try{',
  ' foreach($f in $d.files){',
  '  $to=Join-Path $root $f.name',
  '  Copy-Item -LiteralPath (Join-Path $d.src $f.name) -Destination $to',
  '  $h=(Get-FileHash -Algorithm SHA256 -LiteralPath $to).Hash.ToLowerInvariant()',
  '  if($h -ne $f.sha256){exit ' + CHANGED_AFTER_CHECK + '}',
  ' }',
  " $a=@('install');if($d.client){$a+='--client';$a+=(Join-Path $root $d.client)}",
  " $p=Start-Process -FilePath (Join-Path $root $d.service) -ArgumentList ($a|ForEach-Object{'\"'+$_+'\"'}) -Wait -PassThru -WindowStyle Hidden",
  ' exit $p.ExitCode',
  '}finally{Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue}',
].join('\n');

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
    // Where the root-only copy is made on Linux (tests point it elsewhere).
    this.privRoot = options.privRoot || '/var/lib';
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
      const r = await this._elevatedInstall(dir, p);
      if (r.cancelled) return { ok: false, cancelled: true, error: 'administrator rights were not given; nothing was installed' };
      if (r.code === CHANGED_AFTER_CHECK) {
        return { ok: false, error: 'a downloaded file changed after it was checked, so nothing was run. Nothing was installed.' };
      }
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

  // With administrator rights, asking the person once: copy the checked files
  // out of this user's folder into one only an administrator can write, check
  // them again there, and run the installer from that copy.
  async _elevatedInstall(dir, p) {
    const files = p.files.map((f) => ({ name: f.name, sha256: f.sha256 }));
    if (this.platform === 'win32') {
      const payload = Buffer.from(JSON.stringify({ src: dir, files, service: p.service, client: p.client || null }), 'utf8').toString('base64');
      const inner = WINDOWS_INSTALL_SCRIPT.replace('@PAYLOAD@', payload);
      // The elevated program is Windows' own PowerShell by its full path,
      // never whatever "powershell.exe" this user's PATH finds first.
      const script =
        "$ErrorActionPreference='Stop';" +
        "$ps=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\\v1.0\\powershell.exe';" +
        "try{$p=Start-Process -FilePath $ps -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand',$env:HV_CMD -Verb RunAs -Wait -PassThru -WindowStyle Hidden}" +
        'catch{exit 1223};' +
        'exit $p.ExitCode';
      const r = await this.run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
        HV_CMD: Buffer.from(inner, 'utf16le').toString('base64'),
      });
      return { ...r, cancelled: r.code === 1223 };
    }
    const user = this.platform === 'linux' && this.user ? this.user : '';
    const pairs = files.flatMap((f) => [f.name, f.sha256]);
    const r = await this.run('pkexec', ['/bin/sh', '-c', LINUX_INSTALL_SCRIPT, 'hidravpn-install',
      this.privRoot, dir, p.service, p.client || '', user, ...pairs], {});
    return { ...r, cancelled: r.code === 126 || r.code === 127 };
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

module.exports = {
  VpnInstaller, parseManifest, compareVersions, platformKey, installedService, MANIFEST_MAX_BYTES, FILE_MAX_BYTES,
  LINUX_INSTALL_SCRIPT, WINDOWS_INSTALL_SCRIPT, CHANGED_AFTER_CHECK,
};
