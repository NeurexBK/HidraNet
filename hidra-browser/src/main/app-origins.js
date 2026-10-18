// Where each of HidraNet's own apps lives: an origin of its own.
//
// The apps used to share one origin, http://127.0.0.1:8090, one path each.
// An origin is the browser's security boundary, so sharing one meant a
// script that got into any app — a stranger's post, mail or listing — had
// the storage, the cookies and the same-origin requests of all of them: it
// could read the mail page's state from the forum, or drive the site
// publisher. Now each app is served on a host of its own under .localhost,
// which Chromium resolves to this machine without asking any DNS server and
// treats as a secure context, so each one is a separate origin with storage
// of its own. The vault compartments keep their names, so nothing stored
// there moves.
//
// The old addresses still work: the server sends them to the new ones.

const APPS_PORT = 8090;

// name -> the vault compartment it may open (null: it keeps no identity).
// The name is also the host, and what the address bar shows as hidra://name.
const APPS = {
  chat: { vault: 'chat' },
  mail: { vault: 'mail' },
  forum: { vault: 'forum' },
  publish: { vault: 'publish' },
  site: { vault: null },        // the .hidra site viewer: other people's content
  search: { vault: null },
  reviews: { vault: null },
  donate: { vault: null },
};

function appOrigin(name) {
  if (!Object.prototype.hasOwnProperty.call(APPS, name)) throw new Error('no such app: ' + name);
  return `http://${name}.localhost:${APPS_PORT}`;
}

const ORIGINS = Object.keys(APPS).map(appOrigin);
const HOSTS = new Set(Object.keys(APPS).map((n) => `${n}.localhost:${APPS_PORT}`));

/** The app a URL belongs to, by exact origin, or null. */
function appOfUrl(rawUrl) {
  let u;
  try { u = new URL(rawUrl); } catch { return null; }
  if (u.protocol !== 'http:' || u.port !== String(APPS_PORT)) return null;
  const m = /^([a-z]+)\.localhost$/.exec(u.hostname);
  if (!m || !Object.prototype.hasOwnProperty.call(APPS, m[1])) return null;
  return m[1];
}

/** The app a Host header names, or null. */
function appOfHost(host) {
  const h = String(host || '').toLowerCase();
  if (!HOSTS.has(h)) return null;
  return h.split('.')[0];
}

// The paths the apps had on the shared origin, for the redirects.
const LEGACY_HOSTS = new Set([`127.0.0.1:${APPS_PORT}`, `localhost:${APPS_PORT}`]);
const LEGACY_PATHS = {
  '': 'chat',
  '/mail': 'mail',
  '/forum': 'forum',
  '/donate': 'donate',
  '/sites': 'publish',
  '/publish': 'publish',
  '/site': 'site',
  '/search': 'search',
  '/reviews': 'reviews',
};

/** Where an address on the old shared origin went, or null. */
function legacyTarget(host, pathAndQuery) {
  if (!LEGACY_HOSTS.has(String(host || '').toLowerCase())) return null;
  const qi = pathAndQuery.indexOf('?');
  const p = (qi >= 0 ? pathAndQuery.slice(0, qi) : pathAndQuery).replace(/\/+$/, '');
  const q = qi >= 0 ? pathAndQuery.slice(qi) : '';
  const name = LEGACY_PATHS[p];
  return name ? appOrigin(name) + '/' + q : null;
}

module.exports = { APPS, APPS_PORT, ORIGINS, appOrigin, appOfUrl, appOfHost, legacyTarget, LEGACY_HOSTS };
