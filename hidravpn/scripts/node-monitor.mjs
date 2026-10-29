#!/usr/bin/env node
// The hourly check of the network (.github/workflows/node-monitor.yml).
//
// It reads the official node list the way a client does, from hidranet.org:
// the signature against the list key the client embeds, then every check the
// client makes before it accepts a single node. It asks every node in it for
// its record (GET / on the admission port): a node that does not answer, or
// answers with a key other than the one the list names, is a node clients
// cannot use. It also checks what everyone depends on and nobody looks at: the
// release manifest's signature, that hidranet.org serves what main holds, that
// the pass issuer signs under the key clients ask with and has passes for
// sale, and the dates on which the list, the pass key, the release manifest
// and the browser's checksum record (SHA256SUMS.txt, once it is signed) stop
// being valid, two weeks ahead.
//
// Each problem is one GitHub issue, opened by the workflow and closed by it
// when the check passes again; GitHub sends the e-mail. A network check is
// tried three times, two minutes apart, and only a failure seen every time is
// reported, so a runner's bad minute is not an alert. When nothing at all
// answers, the runner is the likelier culprit: no issue is touched, and the
// run fails, which GitHub reports on its own.
//
// What it does not check: that WireGuard answers on the node's UDP port (only
// a client the node admitted gets an answer there), or that traffic flows
// through it. That takes a real connection: scripts/probe-nodes.sh.
//
// Nothing it prints or writes names an address: a node is its node_name.
//
//   node hidravpn/scripts/node-monitor.mjs [--dry-run] [--preview] [--landing DIR]
//
// --dry-run reports without touching issues. --preview checks the list in
// this checkout instead of the one on the site, as a pull request that
// publishes a list needs (implies --dry-run); it exits 1 when that list is
// not fit to publish. --landing compares the site with another copy of
// landing/ (a pull request's base) instead of this checkout's.

import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { appendFile, readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// The keys the client embeds (hidravpn-core/src/release.rs) and the port a
// node's admission service listens on unless its record says otherwise
// (hidravpn-core/src/admission.rs); the test checks these are the same.
export const LIST_PUBLIC_KEY_B64 = '0HfVyf5QtcUjBQSvRYQNeirD/I0432RnmlKQ+/gmNkk=';
export const RELEASE_PUBLIC_KEY_B64 = 'denZsjS2YtKOo4LRIGGTaKuHIWDFigChoLa71o0jBq8=';
export const DEFAULT_ADMISSION_PORT = 51821;
// Where the browser fetches them (hidra-browser/src/main/main.js).
export const LIST_URL = 'https://hidranet.org/vpn/nodes.json';
export const MANIFEST_URL = 'https://hidranet.org/vpn/release/manifest.json';
// Where the browser fetches its checksum record (hidra-browser/src/main/update-check.js).
export const SUMS_URL = 'https://hidranet.org/SHA256SUMS.txt';

const WARN_DAYS = 14;
const DAY = 24 * 60 * 60;
const NAME = /^[A-Za-z0-9._-]{1,32}$/;
// Canonical base64 of 32 and 64 bytes, as the client's decoder insists on.
const PUBLIC_KEY = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;
const SIGNATURE = /^[A-Za-z0-9+/]{85}[AQgw]==$/;
const LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const BOT = 'github-actions[bot]';
const MARKER = /<!-- node-monitor:([a-z0-9:._-]{1,80}) -->/i;
const TITLE_PREFIX = '[node monitor] ';
const PASS_KEY_ID_DOMAIN = Buffer.from('HidraVPN pass key id v1\0');
// The label the checksum table's signature is made over, before the file
// (hidra-browser/src/main/release-verify.js, browserSumsMessage).
const SUMS_CONTEXT = Buffer.from('hidranet-browser-sums-v1\0');

export const defaults = () => ({
  preview: false,
  listUrl: LIST_URL,
  manifestUrl: MANIFEST_URL,
  sumsUrl: SUMS_URL,
  listKey: LIST_PUBLIC_KEY_B64,
  releaseKey: RELEASE_PUBLIC_KEY_B64,
  defaultAdmissionPort: DEFAULT_ADMISSION_PORT,
  landingDir: join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'landing'),
  attempts: 3,
  retryDelayMs: 2 * 60 * 1000,
  timeoutMs: 10 * 1000,
  // Plain HTTP to the issuer only in the test, on loopback.
  allowHttp: false,
  now: () => new Date(),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  log: (line) => console.log(line),
});

// --- what the client accepts ---------------------------------------------------

// What `hidravpn-sign` writes and the client checks: Ed25519 over the file's
// bytes, the signature in base64 beside it, decoded strictly.
export function signatureMatches(publicKeyB64, data, sigText) {
  if (!PUBLIC_KEY.test(publicKeyB64)) throw new Error('not an Ed25519 public key');
  const sig = String(sigText).trim();
  if (!SIGNATURE.test(sig)) return false;
  const x = Buffer.from(publicKeyB64, 'base64').toString('base64url');
  const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x }, format: 'jwk' });
  try {
    return verifySignature(null, data, key, Buffer.from(sig, 'base64'));
  } catch {
    return false;
  }
}

// timefmt::rfc3339_to_unix: `YYYY-MM-DDTHH:MM:SS[.fff]Z` or `+00:00`, to
// seconds; null for anything else.
export function parseTime(s) {
  if (typeof s !== 'string') return null;
  const t = s.trim();
  const i = t.indexOf('T');
  if (i < 0) return null;
  const date = t.slice(0, i);
  let rest = t.slice(i + 1);
  if (rest.endsWith('Z')) rest = rest.slice(0, -1);
  else if (rest.endsWith('+00:00')) rest = rest.slice(0, -6);
  else return null;
  const dot = rest.indexOf('.');
  const time = dot < 0 ? rest : rest.slice(0, dot);
  if (dot >= 0 && !/^\d+$/.test(rest.slice(dot + 1))) return null;
  const fields = (text, sep, widths) => {
    const parts = text.split(sep);
    if (parts.length !== 3 || parts.some((p, k) => p.length !== widths[k] || !/^\d+$/.test(p))) return null;
    return parts.map(Number);
  };
  const d = fields(date, '-', [4, 2, 2]);
  const h = fields(time, ':', [2, 2, 2]);
  if (!d || !h) return null;
  const [y, m, day] = d;
  const [hh, mi, sec] = h;
  if (m < 1 || m > 12 || day < 1 || day > 31 || hh > 23 || mi > 59 || sec > 60) return null;
  // Howard Hinnant's days_from_civil, as the client computes it: a 31st of
  // February is a date there, so it is one here.
  const yy = m <= 2 ? y - 1 : y;
  const era = Math.floor(yy / 400);
  const yoe = yy - era * 400;
  const mp = (m + 9) % 12;
  const doy = Math.floor((153 * mp + 2) / 5) + day - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return (era * 146097 + doe - 719468) * DAY + hh * 3600 + mi * 60 + sec;
}

// http::Url::parse: https://, or http:// only to a private address.
function issuerUrlProblem(url) {
  const m = /^(https?):\/\/([^/]*)/.exec(url.trim());
  if (!m) return 'is not an http:// or https:// address';
  const authority = m[2];
  if (!authority || authority.includes('@')) return 'has no usable host';
  let host;
  let port;
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    if (close < 0) return 'has no usable host';
    host = authority.slice(1, close);
    port = authority.slice(close + 1).replace(/^:/, '') || null;
  } else {
    const c = authority.lastIndexOf(':');
    host = c < 0 ? authority : authority.slice(0, c);
    port = c < 0 ? null : authority.slice(c + 1);
  }
  if (port !== null && !(/^\d{1,5}$/.test(port) && Number(port) <= 65535)) return 'has a port that is not a number';
  if (!host || !/^[A-Za-z0-9.:-]+$/.test(host)) return 'has no usable host';
  if (m[1] === 'http') {
    const v4 = isIP(host) === 4 ? host.split('.').map(Number) : null;
    const local = host === 'localhost' || host === '::1'
      || (v4 && (v4[0] === 127 || v4[0] === 10 || (v4[0] === 172 && v4[1] >= 16 && v4[1] <= 31) || (v4[0] === 192 && v4[1] === 168) || (v4[0] === 100 && v4[1] >= 64 && v4[1] <= 127)));
    if (!local) return 'is plain HTTP to an address on the open internet';
  }
  return null;
}

// PassKeyRecord::validate: a 2048-bit RSA key whose id is its id.
function passKeyProblem(k) {
  if (!k || typeof k !== 'object' || typeof k.id !== 'string' || typeof k.key !== 'string' || typeof k.not_after !== 'string')
    return 'a pass key in it is not {id, key, not_after}';
  try {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(k.key.trim())) throw new Error();
    const spki = Buffer.from(k.key.trim(), 'base64');
    const pub = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    if (!['rsa', 'rsa-pss'].includes(pub.asymmetricKeyType) || pub.asymmetricKeyDetails?.modulusLength !== 2048) throw new Error();
    const id = createHash('sha256').update(PASS_KEY_ID_DOMAIN).update(spki).digest('hex').slice(0, 16);
    if (id !== k.id.trim()) return 'a pass key in it does not carry its own id';
  } catch {
    return 'a pass key in it is not a 2048-bit RSA key';
  }
  if (parseTime(k.not_after) === null) return "a pass key's not_after in it is not a date";
  return null;
}

// pass::newest_current: the key a client asks passes under.
export function newestCurrent(keys, now) {
  let best = null;
  for (const k of Array.isArray(keys) ? keys : []) {
    const t = parseTime(k?.not_after);
    if (t === null || now > t || passKeyProblem(k)) continue;
    if (!best || t > best.t) best = { key: k, t };
  }
  return best;
}

const optString = (v) => v === undefined || v === null || typeof v === 'string';
const chars = (s) => [...s].length;

// Directory::from_json_unchecked and NodeRecord::validate: why a client
// refuses this list, or null. A client refuses the whole list for one bad
// node. Nothing here names an endpoint.
export function clientRefusal(d) {
  if (!d || typeof d !== 'object' || Array.isArray(d)) return 'it is not a list';
  if (d.version !== 1) return 'it is not a version 1 list';
  if (d.sequence !== undefined && !(Number.isSafeInteger(d.sequence) && d.sequence >= 0)) return 'its sequence is not a number';
  if (d.generated !== undefined && typeof d.generated !== 'string') return 'its generated date is not text';
  if (!optString(d.note)) return 'its note is not text';
  if (!optString(d.expires) || (typeof d.expires === 'string' && parseTime(d.expires) === null)) return 'its expiry is not a date';
  const nodes = d.nodes ?? [];
  const removed = d.removed ?? [];
  if (!Array.isArray(nodes)) return 'its nodes are not a list';
  if (!Array.isArray(removed)) return 'its removed keys are not a list';
  if (nodes.length === 0 && removed.length === 0) return 'it names no nodes';
  for (const [i, n] of nodes.entries()) {
    const which = n && typeof n.node_name === 'string' && NAME.test(n.node_name.trim()) ? n.node_name.trim() : `node ${i + 1}`;
    if (!n || typeof n !== 'object' || Array.isArray(n)) return `${which} in it is not a record`;
    if (typeof n.node_name !== 'string' || !n.node_name.trim()) return `${which} in it has no name`;
    if (!NAME.test(n.node_name.trim())) return `${which} in it has a name that is not 1-32 letters, digits, '-', '_' or '.'`;
    if (!optString(n.operator) || (n.operator && chars(n.operator) > 64)) return `the operator of ${which} is not text of at most 64 characters`;
    if (!optString(n.contact) || (n.contact && chars(n.contact) > 128)) return `the contact of ${which} is not text of at most 128 characters`;
    if (typeof n.node_public_key !== 'string' || !PUBLIC_KEY.test(n.node_public_key.trim())) return `the key of ${which} is not a WireGuard key`;
    const ep = typeof n.endpoint === 'string' ? parseEndpoint(n.endpoint) : null;
    if (!ep) return `the endpoint of ${which} is not ip:port`;
    if (ep.family !== 4) return `the endpoint of ${which} is IPv6; a node is reached over IPv4 in this phase`;
    if (!optString(n.country) || (typeof n.country === 'string' && !/^[A-Za-z]{2}$/.test(n.country.trim()))) return `the country of ${which} is not two letters`;
    if (!optString(n.role) || (typeof n.role === 'string' && !['entry', 'exit', 'both'].includes(n.role.trim().toLowerCase()))) return `the role of ${which} is not entry, exit or both`;
    if (!optString(n.admission) || (typeof n.admission === 'string' && !['open', 'manual', 'pass'].includes(n.admission.trim().toLowerCase()))) return `the admission of ${which} is not open, manual or pass`;
    if (n.admission_port !== undefined && n.admission_port !== null && !(Number.isInteger(n.admission_port) && n.admission_port >= 0 && n.admission_port <= 65535)) return `the admission port of ${which} is not a port`;
    const f = n.features ?? [];
    if (!Array.isArray(f) || f.length > 16 || f.some((x) => typeof x !== 'string' || !/^[a-z-]{1,32}$/.test(x))) return `the features of ${which} are not at most 16 short lower-case words`;
  }
  if (removed.some((k) => typeof k !== 'string' || !PUBLIC_KEY.test(k.trim()))) return 'a removed key in it is not a WireGuard key';
  if (d.pass_issuer !== undefined && d.pass_issuer !== null) {
    const p = d.pass_issuer;
    if (typeof p !== 'object' || typeof p.url !== 'string') return 'its pass issuer has no address';
    const bad = issuerUrlProblem(p.url);
    if (bad) return `its pass issuer's address ${bad}`;
    if (!Array.isArray(p.keys) || p.keys.length === 0) return 'its pass issuer names no key';
    for (const k of p.keys) {
      const why = passKeyProblem(k);
      if (why) return why;
    }
  }
  return null;
}

export function readList(bytes, sigText, listKey) {
  if (!signatureMatches(listKey, bytes, sigText)) return { error: 'its signature does not match the list key' };
  let d;
  try {
    d = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    return { error: 'it is signed but is not UTF-8 JSON' };
  }
  const why = clientRefusal(d);
  return why ? { error: `clients refuse it: ${why}` } : { list: d };
}

export function readManifest(bytes, sigText, releaseKey) {
  if (!signatureMatches(releaseKey, bytes, sigText)) return { error: 'its signature does not match the release key' };
  try {
    const m = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!m || typeof m !== 'object' || typeof m.version !== 'string') return { error: 'it names no version' };
    // A manifest from before `expires` (0.1.0's) never expires.
    if (m.expires !== undefined && parseTime(m.expires) === null) return { error: 'browsers refuse it: its expiry is not a date' };
    return { manifest: m };
  } catch {
    return { error: 'it is signed but is not UTF-8 JSON' };
  }
}

// update-check.js, endOfDay: a valid-until day is believed through its end,
// UTC; null when it is not a real YYYY-MM-DD date.
function endOfDay(validUntil) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(validUntil ?? ''));
  const ms = m ? Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])) : NaN;
  if (!Number.isFinite(ms) || new Date(ms).toISOString().slice(0, 10) !== validUntil) return null;
  return ms / 1000 + DAY;
}

// The record's one `  valid-until:` line, as update-check.js reads it (field
// and parseRecord), or why a browser sets the record aside.
export function recordValidUntil(text) {
  const found = [...String(text).replace(/\r\n/g, '\n').matchAll(/^  valid-until:[ \t]+(\S+)[ \t]*$/gm)];
  if (found.length !== 1) return { error: found.length ? 'valid-until appears more than once' : 'it has no valid-until' };
  const end = endOfDay(found[0][1]);
  return end === null ? { error: 'its valid-until is not a date (YYYY-MM-DD)' } : { validUntil: found[0][1], end };
}

// The browser's checksum table: signed over the label and the file, with the
// release key.
export function readSums(bytes, sigText, releaseKey) {
  if (!signatureMatches(releaseKey, Buffer.concat([SUMS_CONTEXT, bytes]), sigText)) return { error: 'its signature does not match the release key' };
  const v = recordValidUntil(bytes.toString('utf8'));
  return v.error ? { error: `browsers set it aside: ${v.error}` } : { sums: v };
}

export function parseEndpoint(endpoint) {
  const m = /^\[([0-9A-Fa-f:.]+)\]:(\d{1,5})$/.exec(endpoint) || /^([0-9.]+):(\d{1,5})$/.exec(endpoint);
  if (!m) return null;
  const port = Number(m[2]);
  const family = isIP(m[1]);
  if (!family || port > 65535) return null;
  return { host: m[1], family, port };
}

// --- fetching ----------------------------------------------------------------

// Error text is ours, never the library's: its messages carry the address.
function describeFetchError(e) {
  if (e?.name === 'TimeoutError' || e?.name === 'AbortError') return 'does not answer (timed out)';
  const code = String(e?.cause?.code || e?.code || '');
  switch (code) {
    case 'ECONNREFUSED': return 'refuses the connection';
    case 'ECONNRESET': case 'EPIPE': case 'UND_ERR_SOCKET': return 'drops the connection';
    case 'ETIMEDOUT': case 'UND_ERR_CONNECT_TIMEOUT': case 'UND_ERR_HEADERS_TIMEOUT': case 'UND_ERR_BODY_TIMEOUT':
      return 'does not answer (timed out)';
    case 'EHOSTUNREACH': case 'ENETUNREACH': case 'EHOSTDOWN': case 'ENETDOWN': return 'cannot be reached';
    case 'ENOTFOUND': case 'EAI_AGAIN': return 'has a name that does not resolve';
  }
  if (/CERT|TLS|SSL/.test(code)) return 'has a TLS certificate problem';
  if (code.startsWith('HPE_')) return 'answers, but not in HTTP';
  return /^[A-Z][A-Z0-9_]{0,39}$/.test(code) ? `fails (${code})` : 'fails';
}

// GET, capped. `answered` is whether anything spoke HTTP back, which is what
// tells "the node is down" from "this runner reaches nothing".
export async function fetchBytes(url, { timeoutMs, maxBytes, follow = false }) {
  let res;
  try {
    res = await fetch(url, {
      redirect: follow ? 'follow' : 'manual',
      signal: AbortSignal.timeout(timeoutMs),
      headers: { 'user-agent': 'hidranet-node-monitor', 'cache-control': 'no-cache' },
    });
  } catch (e) {
    return { answered: false, error: describeFetchError(e) };
  }
  try {
    if (res.status !== 200) {
      await res.body?.cancel().catch(() => {});
      return { answered: true, status: res.status, error: `answers HTTP ${res.status}` };
    }
    const chunks = [];
    let total = 0;
    for await (const chunk of res.body ?? []) {
      total += chunk.length;
      if (total > maxBytes) return { answered: true, error: 'answers with far more than expected' };
      chunks.push(chunk);
    }
    return { answered: true, bytes: Buffer.concat(chunks) };
  } catch (e) {
    return { answered: true, error: describeFetchError(e) };
  }
}

async function readOptional(path) {
  try {
    return await readFile(path);
  } catch {
    return null;
  }
}

// A signed file and its .sig, fetched as the browser does (redirects
// followed, a megabyte at most).
async function fetchSigned(cfg, url) {
  const [file, sig] = await Promise.all([
    fetchBytes(url, { timeoutMs: cfg.timeoutMs, maxBytes: 1024 * 1024, follow: true }),
    fetchBytes(`${url}.sig`, { timeoutMs: cfg.timeoutMs, maxBytes: 4096, follow: true }),
  ]);
  return { file, sig, answered: file.answered || sig.answered };
}

function days(seconds) {
  const d = Math.floor(seconds / DAY);
  return d === 1 ? '1 day' : `${d} days`;
}
const isoDay = (seconds) => new Date(seconds * 1000).toISOString().slice(0, 10);
const isoTime = (seconds) => new Date(seconds * 1000).toISOString().replace('.000Z', 'Z');

// --- one round of checks ---------------------------------------------------------

// Problem keys: `list`, `manifest`, `sums`, `site`, `expiry`,
// `release-expiry`, `issuer`, `issuer-sales`, `node:<name>`. A transient problem is one a retry can
// change (anything fetched); a lasting one is in what was signed. `blocks` is
// for --preview: whether it makes the list in this checkout unfit to publish.
async function round(cfg) {
  const r = { problems: new Map(), passed: new Map(), rows: [], notes: [], listed: null, tried: 0, answered: 0 };
  const fail = (key, title, detail, { transient = true, blocks = false, operator } = {}) =>
    r.problems.set(key, { title, detail, transient, blocks, operator });
  const pass = (key, note) => r.passed.set(key, note);
  const now = Math.floor(cfg.now().getTime() / 1000);

  const repo = {
    list: await readOptional(join(cfg.landingDir, 'vpn', 'nodes.json')),
    listSig: await readOptional(join(cfg.landingDir, 'vpn', 'nodes.json.sig')),
    manifest: await readOptional(join(cfg.landingDir, 'vpn', 'release', 'manifest.json')),
    manifestSig: await readOptional(join(cfg.landingDir, 'vpn', 'release', 'manifest.json.sig')),
    sums: await readOptional(join(cfg.landingDir, 'SHA256SUMS.txt')),
    sumsSig: await readOptional(join(cfg.landingDir, 'SHA256SUMS.txt.sig')),
  };
  const [siteList, siteManifest, siteSums] = await Promise.all([
    fetchSigned(cfg, cfg.listUrl), fetchSigned(cfg, cfg.manifestUrl), fetchSigned(cfg, cfg.sumsUrl),
  ]);
  r.tried += 3;
  r.answered += Number(siteList.answered) + Number(siteManifest.answered) + Number(siteSums.answered);

  const fromSite = (f, url, read, key) => {
    const got = f.file.error ? { error: f.file.error }
      : f.sig.error ? { error: `its .sig ${f.sig.error}` }
        : read(f.file.bytes, f.sig.bytes.toString('utf8'), key);
    return got.error ? { error: `${shortUrl(url)}: ${got.error}` } : got;
  };
  const site = {
    list: fromSite(siteList, cfg.listUrl, readList, cfg.listKey),
    manifest: fromSite(siteManifest, cfg.manifestUrl, readManifest, cfg.releaseKey),
    // Until the first SHA256SUMS.txt.sig there is no record to watch. Once
    // main holds one, a site without it is a fault: browsers built after the
    // first signature, and any that has verified a record, then say they
    // cannot confirm they are up to date.
    sums: siteSums.sig.status === 404 && !repo.sumsSig ? null : fromSite(siteSums, cfg.sumsUrl, readSums, cfg.releaseKey),
  };
  const local = {
    list: repo.list && repo.listSig ? readList(repo.list, repo.listSig.toString('utf8'), cfg.listKey) : null,
    manifest: repo.manifest && repo.manifestSig ? readManifest(repo.manifest, repo.manifestSig.toString('utf8'), cfg.releaseKey) : null,
    sums: repo.sums && repo.sumsSig ? readSums(repo.sums, repo.sumsSig.toString('utf8'), cfg.releaseKey) : null,
  };
  const published = site.list.list ?? null;

  // The list and the manifest: in preview, the ones this checkout would
  // publish; otherwise the ones clients get.
  let list = null;
  if (cfg.preview) {
    if (!local.list) fail('list', 'This checkout has no signed node list', 'landing/vpn/nodes.json or its .sig is missing.', { transient: false, blocks: true });
    else if (local.list.error) fail('list', 'The node list in this checkout cannot be published', `landing/vpn/nodes.json: ${local.list.error}.`, { transient: false, blocks: true });
    else {
      list = local.list.list;
      // A client keeps the list it holds unless the new one's sequence is
      // higher (Directory::check_current, merge_into).
      const mine = list.sequence ?? 0;
      const theirs = published?.sequence ?? 0;
      if (published && mine < theirs)
        fail('list', 'The node list in this checkout cannot be published', `Its sequence ${mine} is lower than the published ${theirs}: every client that holds the published list refuses it.`, { transient: false, blocks: true });
      else if (published && mine === theirs && Buffer.compare(repo.list, siteList.file.bytes) !== 0)
        fail('list', 'The node list in this checkout cannot be published', `It changes the list but keeps the published sequence ${theirs}: clients that hold the published list keep what they have.`, { transient: false, blocks: true });
      else pass('list', published ? 'the list in this checkout is signed, clients accept it, and its sequence is not behind the published one' : 'the list in this checkout is signed and clients accept it');
    }
    if (local.manifest?.error) fail('manifest', 'The release manifest in this checkout cannot be published', `landing/vpn/release/manifest.json: ${local.manifest.error}.`, { transient: false, blocks: true });
    else if (local.manifest) pass('manifest', 'the manifest in this checkout is signed');
    if (local.sums?.error) fail('sums', "The browser's checksum record in this checkout cannot be published", `landing/SHA256SUMS.txt: ${local.sums.error}.`, { transient: false, blocks: true });
    else if (local.sums) pass('sums', 'the checksum record in this checkout is signed');
    if (site.list.error) r.notes.push(`the published list: ${site.list.error}`);
  } else {
    if (site.list.error) {
      fail('list', 'The node list on hidranet.org cannot be used', `${site.list.error}. A client that asks for the node list gets none.`);
      if (local.list?.list) {
        list = local.list.list;
        r.notes.push("checking the nodes in main's copy of the list instead");
      }
    } else {
      list = published;
      pass('list', 'hidranet.org serves a list signed with the list key, which clients accept');
    }
    if (site.manifest.error) fail('manifest', 'The release manifest on hidranet.org cannot be used', `${site.manifest.error}. Installs and updates refuse it.`);
    else pass('manifest', 'hidranet.org serves a manifest signed with the release key');
    if (site.sums?.error) fail('sums', "The browser's checksum record on hidranet.org cannot be used", `${site.sums.error}. Browsers set it aside and say they cannot confirm they are up to date.`);
    else if (site.sums) pass('sums', 'hidranet.org serves a checksum record signed with the release key');
    else pass('sums', 'neither hidranet.org nor main has a SHA256SUMS.txt.sig yet, so there is no record to check');

    // What main holds and what the site serves, byte for byte: a merge the
    // deployment never picked up, or a site serving something else.
    const differ = [];
    const same = (a, b) => a && b && Buffer.compare(a, b) === 0;
    if (repo.list && siteList.file.bytes && (!same(repo.list, siteList.file.bytes) || !same(repo.listSig, siteList.sig.bytes)))
      differ.push(`nodes.json (hidranet.org has sequence ${seq(published)}, main has ${seq(local.list?.list)})`);
    if (repo.manifest && siteManifest.file.bytes && (!same(repo.manifest, siteManifest.file.bytes) || !same(repo.manifestSig, siteManifest.sig.bytes)))
      differ.push(`release/manifest.json (hidranet.org has version ${ver(site.manifest.manifest)}, main has ${ver(local.manifest?.manifest)})`);
    if (differ.length) fail('site', 'hidranet.org does not serve what main holds', `Different files: ${differ.join('; ')}.`);
    else if (repo.list && siteList.file.bytes && siteList.sig.bytes && repo.manifest && siteManifest.file.bytes && siteManifest.sig.bytes)
      pass('site', 'hidranet.org serves what main holds');
  }

  // The release's dates, lasting problems in what was signed, as the list's
  // below. A browser refuses a manifest once now > expires, and then every
  // Install and Update fails; it sets the checksum record aside after its
  // valid-until day. A manifest with no expires (0.1.0's) never expires.
  const rel = cfg.preview ? local : site;
  const relExpiring = [];
  let relExpired = false;
  let relSoonest = Infinity;
  const mexp = rel.manifest?.manifest ? parseTime(rel.manifest.manifest.expires) : null;
  if (mexp !== null && mexp - now < WARN_DAYS * DAY) {
    const at = rel.manifest.manifest.expires;
    relExpiring.push(now > mexp ? `the release manifest expired on ${at}` : `the release manifest expires on ${at} (in ${days(mexp - now)})`);
    relExpired ||= now > mexp;
    relSoonest = Math.min(relSoonest, mexp);
  }
  const record = rel.sums?.sums ?? null;
  if (record && record.end - now < WARN_DAYS * DAY) {
    relExpiring.push(now >= record.end ? `the browser's checksum record ran out after ${record.validUntil}` : `the browser's checksum record is valid until ${record.validUntil} (in ${days(record.end - now)})`);
    relExpired ||= now >= record.end;
    relSoonest = Math.min(relSoonest, record.end);
  }
  if (relExpiring.length) {
    fail('release-expiry', relExpired ? "The release manifest or the browser's checksum record has expired" : `Renew before ${isoDay(relSoonest)}: the release manifest or the browser's checksum record runs out`,
      `${relExpiring.join('; ')}.`, { transient: false, blocks: relExpired });
  } else if ((!rel.manifest || rel.manifest.manifest) && (!rel.sums || record)) {
    pass('release-expiry', [
      !rel.manifest ? null : mexp === null ? 'the release manifest has no expiry' : 'the release manifest is good for more than two weeks',
      record ? "the browser's checksum record is good for more than two weeks" : 'no checksum record is signed yet',
    ].filter(Boolean).join('; '));
  }

  if (!list) return r;
  const nodes = list.nodes ?? [];

  // Dates: lasting problems, in what was signed. A client refuses a list
  // once now > expires, and asks passes under the current key that lasts
  // longest; when there is none, it gets no passes.
  const expiring = [];
  let expired = false;
  let soonest = Infinity;
  const lexp = parseTime(list.expires);
  if (lexp !== null && lexp - now < WARN_DAYS * DAY) {
    expiring.push(now > lexp ? `the node list expired on ${list.expires}` : `the node list expires on ${list.expires} (in ${days(lexp - now)})`);
    expired ||= now > lexp;
    soonest = Math.min(soonest, lexp);
  }
  const issuer = list.pass_issuer ?? null;
  const newest = issuer ? newestCurrent(issuer.keys, now) : null;
  if (issuer && !newest) {
    const last = Math.max(...issuer.keys.map((k) => parseTime(k.not_after) ?? 0));
    expiring.push(`every pass key the list names has expired, the last on ${isoTime(last)}`);
    expired = true;
    soonest = Math.min(soonest, last);
  } else if (newest && newest.t - now < WARN_DAYS * DAY) {
    expiring.push(`the pass key clients ask with (${newest.key.id.trim()}) stops on ${isoTime(newest.t)} (in ${days(newest.t - now)})`);
    soonest = Math.min(soonest, newest.t);
  }
  if (expiring.length) {
    fail('expiry', expired ? 'The node list or the pass key has expired' : `Renew before ${isoDay(soonest)}: the node list or the pass key runs out`,
      `${expiring.join('; ')}.`, { transient: false, blocks: expired });
  } else {
    pass('expiry', 'the list and the pass key clients ask with are good for more than two weeks');
  }

  // The pass issuer the list names.
  const takesPasses = nodes.filter((n) => String(n.admission ?? '').trim().toLowerCase() === 'pass').length;
  if (!issuer) {
    if (takesPasses) fail('issuer', 'The list names no pass issuer', `${takesPasses === 1 ? 'A node in it takes' : `${takesPasses} nodes in it take`} passes, and a client that imports it forgets where to get them.`, { transient: false, blocks: true });
    else pass('issuer', 'the list names no pass issuer, and no node in it takes passes');
    pass('issuer-sales', 'the list names no pass issuer');
  } else if (!issuer.url.trim().startsWith('https://') && !cfg.allowHttp) {
    fail('issuer', 'The pass issuer cannot be reached from the internet', 'The list names a pass issuer on plain HTTP to a private address, which no client on the internet reaches.', { transient: false, blocks: true });
    pass('issuer-sales', 'not checked: the issuer is on a private address');
  } else {
    const base = issuer.url.trim().replace(/\/+$/, '');
    const [k, p] = await Promise.all([
      fetchBytes(`${base}/keys`, { timeoutMs: cfg.timeoutMs, maxBytes: 256 * 1024 }),
      fetchBytes(`${base}/packs`, { timeoutMs: cfg.timeoutMs, maxBytes: 256 * 1024 }),
    ]);
    r.tried += 1;
    r.answered += Number(k.answered || p.answered);
    const host = issuerHost(base);
    const served = k.bytes ? jsonOr(k.bytes)?.keys : null;
    if (k.error) fail('issuer', 'The pass issuer is not answering', `${host}/keys ${k.error}. Clients cannot get passes.`);
    else if (!Array.isArray(served)) fail('issuer', 'The pass issuer is not answering', `${host}/keys answers, but not with a list of keys.`);
    else if (!newest) pass('issuer', 'the pass issuer answers; the list has no current key to ask with (see the expiry check)');
    else {
      // The issuer signs only under a key it holds as current
      // (hidravpn-issuer, POST /issue).
      const id = newest.key.id.trim().toLowerCase();
      const ok = served.some((s) => typeof s?.id === 'string' && s.id.trim().toLowerCase() === id && parseTime(s.not_after) !== null && now <= parseTime(s.not_after));
      if (ok) pass('issuer', 'the pass issuer signs under the key clients ask with');
      else fail('issuer', 'The pass issuer does not sign under the key clients ask with', `Clients ask for passes under ${id}, the newest current key in the list; ${host} does not hold it as current, so it refuses them.`);
    }
    const packs = p.bytes ? jsonOr(p.bytes)?.packs : null;
    if (p.error) fail('issuer-sales', 'Passes cannot be bought', `${host}/packs ${p.error}.`);
    else if (!Array.isArray(packs) || packs.length === 0)
      fail('issuer-sales', 'Passes cannot be bought', `${host}/packs lists nothing for sale. With packs priced in dollars, that usually means the HNET rate is stale.`);
    else pass('issuer-sales', 'the pass issuer has passes for sale');
  }

  // The nodes. A node changed by this checkout (new, or a new key, address
  // or admission port) has to answer before the list goes out.
  r.listed = new Set();
  const portOf = (n) => (Number.isInteger(n?.admission_port) ? n.admission_port : cfg.defaultAdmissionPort);
  const live = new Map((published?.nodes ?? []).map((n) => [n.node_name.trim(), `${n.node_public_key.trim()} ${n.endpoint} ${portOf(n)}`]));
  await Promise.all(nodes.map(async (n) => {
    const name = n.node_name.trim();
    const wgKey = n.node_public_key.trim();
    r.listed.add(name);
    const key = `node:${name}`;
    const label = [n.role?.trim().toLowerCase(), n.country?.trim().toUpperCase()].filter(Boolean).join(', ');
    const raw = typeof n.operator === 'string' ? n.operator.trim() : '';
    const operator = { ours: raw === 'HidraNet', shown: printable(raw) };
    const row = { name, label, status: '', ms: null };
    r.rows.push(row);
    const port = portOf(n);
    const blocks = cfg.preview && live.get(name) !== `${wgKey} ${n.endpoint} ${port}`;
    const ep = parseEndpoint(n.endpoint);
    const t0 = Date.now();
    const res = await fetchBytes(`http://${ep.host}:${port}/`, { timeoutMs: cfg.timeoutMs, maxBytes: 64 * 1024 });
    row.ms = Date.now() - t0;
    r.tried += 1;
    r.answered += Number(res.answered);
    if (res.error) { fail(key, `${name} is not answering`, `${name} ${res.error} on its admission port (TCP ${port}).`, { blocks, operator }); row.status = res.error; return; }
    const rec = jsonOr(res.bytes);
    const got = typeof rec?.node_public_key === 'string' ? rec.node_public_key.trim() : null;
    if (got === null) { fail(key, `${name} is not answering`, `${name} answers on TCP ${port}, but not with a node record.`, { blocks, operator }); row.status = 'not a node record'; return; }
    if (got !== wgKey) {
      const shown = PUBLIC_KEY.test(got) ? `\`${got}\`` : 'something that is not a key';
      fail(key, `${name} answers with a different key`, `The list names \`${wgKey}\`; the node answers with ${shown}. Clients will refuse it.`, { blocks, operator });
      row.status = 'different key';
      return;
    }
    row.status = 'ok';
    pass(key, `${name} answers with its key`);
  }));
  r.rows.sort((a, b) => a.name.localeCompare(b.name));
  return r;
}

function seq(list) {
  return Number.isSafeInteger(list?.sequence) ? String(list.sequence) : '(unreadable)';
}
function ver(m) {
  return typeof m?.version === 'string' && /^[0-9A-Za-z.+-]{1,32}$/.test(m.version) ? m.version : '(unreadable)';
}
function jsonOr(bytes) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    return null;
  }
}
// An operator's name as an issue shows it: these characters only, and inside
// a code span, so it cannot mention anyone or make a link.
function printable(s) {
  return typeof s === 'string' ? s.replace(/[^A-Za-z0-9 ._-]/g, '').trim().slice(0, 64) : '';
}
function shortUrl(url) {
  return url.replace(/^https?:\/\//, '');
}
// The issuer by its name; never by an address, should the list give one.
function issuerHost(base) {
  const host = shortUrl(base).split('/')[0].replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
  return isIP(host) ? 'the pass issuer' : shortUrl(base);
}

// --- three rounds, and what they agree on ---------------------------------------

export async function check(cfg) {
  const rounds = [];
  for (let i = 0; i < cfg.attempts; i++) {
    if (i > 0) {
      cfg.log(`trying what failed again in ${Math.round(cfg.retryDelayMs / 1000)} s`);
      await cfg.sleep(cfg.retryDelayMs);
    }
    const r = await round(cfg);
    r.blind = r.tried > 0 && r.answered === 0;
    rounds.push(r);
    if (!r.blind && ![...r.problems.values()].some((p) => p.transient)) break;
  }
  const last = rounds[rounds.length - 1];
  // Confirmed: failing in every round (a lasting problem: in the last).
  const confirmed = new Map();
  for (const [key, p] of last.problems) {
    if (!p.transient || rounds.every((r) => r.problems.has(key))) confirmed.set(key, p);
  }
  // Passed: what the latest round that looked at it said. A key that failed
  // last but not every time is neither: its issue stays as it is.
  const passed = new Map();
  const keys = new Set(rounds.flatMap((r) => [...r.passed.keys(), ...r.problems.keys()]));
  for (const key of keys) {
    const latest = [...rounds].reverse().find((r) => r.passed.has(key) || r.problems.has(key));
    if (latest.passed.has(key) && !confirmed.has(key)) passed.set(key, latest.passed.get(key));
  }
  return {
    confirmed,
    passed,
    rows: last.rows,
    notes: [...new Set(rounds.flatMap((r) => r.notes))],
    listed: [...rounds].reverse().find((r) => r.listed)?.listed ?? null,
    blind: rounds.every((r) => r.blind),
    rounds: rounds.length,
  };
}

// --- issues --------------------------------------------------------------------

export function github({ token, repo, api = 'https://api.github.com' }) {
  async function call(method, path, body) {
    const res = await fetch(`${api}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
        'user-agent': 'hidranet-node-monitor',
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(30 * 1000),
    });
    if (!res.ok) throw new Error(`GitHub answered ${res.status} to ${method} ${path.replace(/\?.*/, '')}`);
    return res.status === 204 ? null : res.json();
  }
  return {
    // The open issues this check opened, with the key each is about. Only
    // the workflow's own: anyone can open an issue carrying the marker.
    async openIssues() {
      const found = [];
      for (let page = 1; page <= 10; page++) {
        const batch = await call('GET', `/repos/${repo}/issues?state=open&per_page=100&page=${page}`);
        for (const i of batch) {
          const m = !i.pull_request && i.user?.login === BOT ? MARKER.exec(i.body ?? '') : null;
          if (m) found.push({ number: i.number, key: m[1], title: i.title });
        }
        if (batch.length < 100) break;
      }
      return found;
    },
    create: (title, body) => call('POST', `/repos/${repo}/issues`, { title, body }),
    comment: (number, body) => call('POST', `/repos/${repo}/issues/${number}/comments`, { body }),
    retitle: (number, title) => call('PATCH', `/repos/${repo}/issues/${number}`, { title }),
    close: (number) => call('PATCH', `/repos/${repo}/issues/${number}`, { state: 'closed', state_reason: 'completed' }),
  };
}

function advice(key, operator) {
  if (key.startsWith('node:')) {
    const theirs = operator && !operator.ours
      ? `This node is run by ${operator.shown ? `\`${operator.shown}\`` : 'an operator whose name cannot be shown here'}, not by us. Write to them at the address they gave us, as the operator guide promises.`
      : '';
    return [
      'On the server: `systemctl status hidravpn-node` and `journalctl -u hidravpn-node -n 50`; if it does not answer SSH, the provider\'s console. A node that was reinstalled has a new key: restore its `node.toml` from the backup, or publish a list with its new record.',
      theirs,
    ].filter(Boolean).join('\n\n');
  }
  return {
    list: 'Clients cannot import the list. Check the last change under `landing/vpn/` and the site\'s deployment.',
    manifest: 'Installs and updates through the browser refuse the manifest. Check the last change under `landing/vpn/release/` and the site\'s deployment.',
    site: 'A merge to main did not reach hidranet.org, or the site serves something else. Check the deployment of `landing/`.',
    sums: 'Browsers set the record aside and say they cannot confirm they are up to date. Check the last change to `landing/SHA256SUMS.txt` and its `.sig`, and the site\'s deployment.',
    'release-expiry': 'After its expiry browsers refuse the manifest, and every Install and Update of HidraVPN through the browser fails; after its valid-until they set the checksum record aside and say they cannot confirm they are up to date. Make the manifest again with `make-release-manifest.sh`, a higher `--sequence` and a later `--expires`, sign it offline and publish both (hidravpn/docs/code-signing.md); renew the record\'s `valid-until` and sign the table again (hidra-browser/docs/code-signing.md).',
    expiry: 'After that date clients refuse the list, and get no passes once no key in it is current. Make a new pass key, load it in the issuer, `hidravpn-node pass-key add` it on every node that takes passes, and sign and publish a list that names it, with a later expiry and a higher sequence.',
    issuer: 'Clients cannot get passes, and the nodes that take passes admit no one new. Check the issuer service on its server (`systemctl status hidravpn-issuer`) and the keys it was started with, against the list.',
    'issuer-sales': 'The issuer answers, but nobody can buy passes. Look at the issuer\'s log for the HNET rate feed, and at its payment settings.',
  }[key] ?? '';
}

export function issueBody(key, p, { at, rounds, runUrl, mention }) {
  const seen = p.transient && rounds > 1 ? `on ${rounds} tries, two minutes apart, ending ${at}` : `at ${at}`;
  return [
    `**What failed:** ${p.detail}`,
    `**Seen:** ${seen} (UTC).`,
    advice(key, p.operator),
    `Opened by the hourly node check${runUrl ? ` ([this run](${runUrl}))` : ''}. It closes itself when the check passes again; closing it by hand while the problem lasts brings a new one within the hour.`,
    mention.length ? `cc ${mention.map((m) => `@${m}`).join(' ')}` : '',
    `<!-- node-monitor:${key} -->`,
  ].filter(Boolean).join('\n\n');
}

export async function reconcile(result, gh, { at, runUrl, mention = [], log }) {
  const open = await gh.openIssues();
  const byKey = new Map();
  for (const i of open) if (!byKey.has(i.key)) byKey.set(i.key, i);
  for (const [key, p] of result.confirmed) {
    const title = TITLE_PREFIX + p.title;
    const already = byKey.get(key);
    if (!already) {
      await gh.create(title, issueBody(key, p, { at, rounds: result.rounds, runUrl, mention }));
      log(`opened: ${key}`);
    } else if (already.title !== title) {
      // The same thing, now worse or otherwise wrong (a reminder that became
      // an expiry, a node down that came back with another key): say so,
      // which e-mails whoever the issue mentions.
      await gh.comment(already.number, `**Now:** ${p.title}. ${p.detail}\n\n**Seen:** ${at} (UTC).`);
      await gh.retitle(already.number, title);
      log(`changed: ${key}`);
    } else {
      log(`still open: ${key}`);
    }
  }
  for (const issue of open) {
    if (result.confirmed.has(issue.key)) continue;
    let why = result.passed.get(issue.key);
    if (!why && issue.key.startsWith('node:') && result.listed && !result.listed.has(issue.key.slice(5))) why = 'the node is no longer in the list';
    if (!why) continue;
    await gh.comment(issue.number, `Passed at ${at} (UTC): ${why}.`);
    await gh.close(issue.number);
    log(`closed: ${issue.key}`);
  }
}

// --- the command -----------------------------------------------------------------

function summary(result, at) {
  const lines = [`## Node check, ${at} UTC`, '', '| node | | status | ms |', '|---|---|---|---|'];
  for (const r of result.rows) lines.push(`| ${r.name} | ${r.label} | ${r.status} | ${r.ms ?? ''} |`);
  lines.push('');
  for (const [key, p] of result.confirmed) lines.push(`- **${key}**: ${p.title}. ${p.detail}`);
  for (const [key, note] of result.passed) if (!key.startsWith('node:')) lines.push(`- ${key}: ${note}`);
  for (const n of result.notes) lines.push(`- ${n}`);
  return lines.join('\n') + '\n';
}

// `overrides` is for the test: addresses and keys of its own.
export async function main(argv = process.argv.slice(2), env = process.env, overrides = {}) {
  const flags = new Set();
  let landing = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--dry-run' || argv[i] === '--preview') flags.add(argv[i]);
    else if (argv[i] === '--landing' && argv[i + 1]) landing = resolve(argv[++i]);
    else { console.error(`unknown option ${argv[i]}`); return 2; }
  }
  const cfg = { ...defaults(), ...overrides, preview: flags.has('--preview') };
  if (landing) cfg.landingDir = landing;
  const dryRun = cfg.preview || flags.has('--dry-run');
  const result = await check(cfg);
  const at = cfg.now().toISOString().replace(/\.\d+Z$/, 'Z');

  for (const r of result.rows) cfg.log(`${r.status === 'ok' ? 'ok  ' : 'FAIL'} ${r.name}${r.label ? ` (${r.label})` : ''}: ${r.status}${r.ms !== null ? `, ${r.ms} ms` : ''}`);
  for (const [key, note] of result.passed) if (!key.startsWith('node:')) cfg.log(`ok   ${key}: ${note}`);
  for (const [key, p] of result.confirmed) cfg.log(`FAIL ${key}: ${p.title}. ${p.detail}`);
  for (const n of result.notes) cfg.log(`note ${n}`);
  if (env.GITHUB_STEP_SUMMARY) await appendFile(env.GITHUB_STEP_SUMMARY, summary(result, at)).catch(() => {});

  if (result.blind) {
    cfg.log('nothing answered, not even hidranet.org: this runner is the likelier culprit, so no issue was touched');
    return 1;
  }
  if (cfg.preview) {
    const blocking = [...result.confirmed.values()].filter((p) => p.blocks);
    if (blocking.length) cfg.log(`not fit to publish: ${blocking.map((p) => p.title).join('; ')}`);
    return blocking.length ? 1 : 0;
  }
  if (dryRun) {
    for (const [key, p] of result.confirmed) cfg.log(`would open, unless already open: ${key}: ${TITLE_PREFIX}${p.title}`);
    return 0;
  }
  if (!env.GITHUB_TOKEN || !env.GITHUB_REPOSITORY) {
    console.error('GITHUB_TOKEN and GITHUB_REPOSITORY are needed to open issues; use --dry-run to only report');
    return 2;
  }
  const mention = String(env.NODE_MONITOR_MENTION ?? '').split(/[\s,]+/).filter((m) => LOGIN.test(m));
  const runUrl = env.GITHUB_SERVER_URL && env.GITHUB_RUN_ID ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}` : '';
  await reconcile(result, github({ token: env.GITHUB_TOKEN, repo: env.GITHUB_REPOSITORY, api: env.GITHUB_API_URL || undefined }), { at, runUrl, mention, log: cfg.log });
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then((code) => { process.exitCode = code; }, (e) => { console.error(`node-monitor: ${e.message}`); process.exitCode = 1; });
}
