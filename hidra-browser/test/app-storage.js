// HidraNet's own apps keep what they store; websites keep nothing.
//
// Every tab used to get a fresh in-memory partition, the apps included, so
// HidraMail handed out a new address in every tab and on every restart, and
// mail sent to the old one went to a mailbox that no longer existed. The fix
// puts the apps that hold an identity in one partition kept on disk. Both
// halves of that can regress quietly: an app falling back to a throwaway
// partition looks fine until someone loses their mail, and a website landing
// in the kept one looks fine while it stores cookies across restarts.
//
//   cd hidra-browser && node test/app-storage.js

require('./lib/no-electron');
const fs = require('fs');
const path = require('path');
const {
  TabManager,
  INTERNAL_BY_NAME,
  wantsAppStorage,
  APPS_PARTITION,
} = require('../src/main/tab-manager');

// Each app has an origin of its own (src/main/app-origins.js).
const A = (name) => `http://${name}.localhost:8090`;
const OLD = 'http://127.0.0.1:8090';
let failed = 0;
const check = (ok, label, detail) => {
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${label}${ok || !detail ? '' : `\n        ${detail}`}`);
};

// ── Which pages keep their storage ───────────────────────────────────────

const KEPT = [
  [`${A('mail')}/`, 'mail'],
  [`${A('mail')}/?x=1#y`, 'mail, with a query and fragment'],
  [`${A('chat')}/`, 'chat'],
  [`${A('chat')}`, 'chat, with no slash'],
  [`${A('chat')}/?room=x`, 'chat, with a query'],
  [`${A('forum')}/`, 'the forum'],
  [`${A('publish')}/`, 'the site publisher'],
];
for (const [url, label] of KEPT) {
  check(wantsAppStorage(url) === true, `kept: ${label}`, `${url} would get a throwaway partition`);
}

const THROWAWAY = [
  ['https://example.com/', 'a website'],
  ['http://example.com/mail', 'a website with an app-like path'],
  [`${OLD}/mail`, 'the old shared origin, which now only redirects'],
  ['http://localhost:8090/mail', 'the apps port under another name'],
  ['http://mail.localhost:8091/', 'an app host on another port'],
  ['https://mail.localhost:8090/', 'an app host over https (another origin)'],
  ['http://evil.localhost:8090/', 'a .localhost host that is not one of the apps'],
  ['http://mail.localhost.evil.com:8090/', 'a host that only starts like an app'],
  ['http://127.0.0.1:8084/', 'SevenNine, which serves sites people build'],
  [`${A('site')}/?addr=x.hidra`, 'the site viewer, which shows other people\'s content'],
  [`${A('search')}/?q=x`, 'search'],
  [`${A('reviews')}/`, 'reviews'],
  [`${A('donate')}/`, 'donate'],
  ['file:///tmp/download.html', 'a file on disk'],
  ['data:text/html,hi', 'a data URL'],
  ['not a url', 'something that is not a URL'],
];
for (const [url, label] of THROWAWAY) {
  check(wantsAppStorage(url) === false, `throwaway: ${label}`, `${url} would be kept on disk`);
}

check(/^persist:/.test(APPS_PARTITION), 'the apps partition is a persistent one', APPS_PARTITION);

// ── What a typed name opens ──────────────────────────────────────────────
//
// hidra://mail used to load the copy of the page on disk, a file:// origin
// with storage of its own, so typing it gave a different address from the
// new tab page's Mail card.

const resolve = (u) => TabManager.prototype._resolve.call(null, u);
const belongs = (u) => TabManager.prototype._belongsInApps.call(null, resolve(u));

for (const name of ['mail', 'chat', 'forum', 'publish']) {
  const r = resolve(`hidra://${name}`);
  check(r.kind === 'url' && r.url === A(name) + '/' && belongs(`hidra://${name}`),
    `hidra://${name} opens the app from the apps server, in the kept partition`,
    JSON.stringify(r));
}
for (const name of Object.keys(INTERNAL_BY_NAME)) {
  const r = resolve(`hidra://${name}`);
  // A page served from disk (the new tab page) resolves to a file; every
  // app resolves to the apps server.
  const ok = INTERNAL_BY_NAME[name].endsWith('.html') ? r.kind === 'file' : r.kind === 'url' && r.url.startsWith(A(name));
  check(ok, `hidra://${name} resolves`, JSON.stringify(r));
}
check(resolve('hidra://reviews?b=cafe').url === `${A('reviews')}/?b=cafe`,
  'a query on a typed name is carried through', resolve('hidra://reviews?b=cafe').url);
check(!belongs('hidra://search?q=hello'), 'a search stays out of the kept partition');
check(!belongs('example.com'), 'a typed website stays out of it');
check(resolve('example.com').url === 'https://example.com', 'a bare host becomes https');
check(resolve('some words').url.startsWith(`${A('search')}/?q=`), 'words become a search');

// ── Each app is an origin of its own ─────────────────────────────────────
//
// They used to share one, so a script that got into any app had the storage
// and same-origin requests of all of them.
const { appOrigin, legacyTarget, ORIGINS } = require('../src/main/app-origins');
check(new Set(ORIGINS).size === ORIGINS.length && ORIGINS.every((o) => new URL(o).origin === o),
  'every app has a distinct origin', JSON.stringify(ORIGINS));
check(new URL(appOrigin('mail')).origin !== new URL(appOrigin('forum')).origin, 'mail and the forum do not share one');
check(legacyTarget('127.0.0.1:8090', '/mail') === `${A('mail')}/` && legacyTarget('127.0.0.1:8090', '/') === `${A('chat')}/`
  && legacyTarget('127.0.0.1:8090', '/site?addr=x.hidra') === `${A('site')}/?addr=x.hidra`
  && legacyTarget('127.0.0.1:8090', '/reviews?b=cafe') === `${A('reviews')}/?b=cafe`,
  'an old address is sent on to its app\'s own origin');
check(legacyTarget('127.0.0.1:8090', '/vendor/mqtt.min.js') === null && legacyTarget('evil.com', '/mail') === null,
  'and only an old app address is');
check(resolve('shop.hidra').kind === 'domain', 'a .hidra name is looked up');
check(!belongs('shop.hidra'), 'and a .hidra name is never kept');

// ── Closing a tab never wipes the apps ───────────────────────────────────

function disposed(persistent) {
  let cleared = false;
  let closed = false;
  let flushed = false;
  TabManager.prototype._dispose.call(
    { window: { removeBrowserView() {} }, _flushApps() { flushed = true; } },
    {
      view: { webContents: { close() { closed = true; } } },
      session: { clearStorageData() { cleared = true; } },
      persistent,
    }
  );
  return { cleared, closed, flushed };
}
const keptTab = disposed(true);
const webTab = disposed(false);
check(keptTab.closed && !keptTab.cleared && keptTab.flushed, 'closing an app tab keeps the apps\' storage, and writes it out',
  'it would delete the mail address along with the tab, or leave it unwritten');
check(webTab.closed && webTab.cleared && !webTab.flushed, 'closing a website tab clears what the site stored');

// ── Every session follows the network route ──────────────────────────────

const fake = { tabs: new Map([[1, { session: 'web-1' }], [2, { session: 'web-1' }]]), appsSession: 'apps' };
const all = TabManager.prototype.getAllSessions.call(fake);
check(all.includes('apps') && all.length === 2,
  'the apps\' session gets the proxy even with no app tab open, once each',
  JSON.stringify(all));

// ── What the apps store reaches the disk before a crash can take it ──────
//
// Chromium commits DOM storage on a delay of several seconds. Killed inside
// it, the browser loses the change — and on first open that change is the
// mail address. Measured on the published build: a SIGKILL a few seconds
// after opening mail lost the address; the fix flushes pending changes.

const tabManagerSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'tab-manager.js'), 'utf8');
check(/flushStorageData\(\)/.test(tabManagerSrc) && /setInterval\([^;]*_flushApps/.test(tabManagerSrc),
  'the apps\' storage is flushed to disk on a cycle, not left to Chromium\'s delay');

// ── Two HidraMail tabs do not fight over one mailbox ─────────────────────
//
// With one address per person, two tabs share a broker client id and knock
// each other off every few seconds, and each saves its copy of the mailbox
// over the other's. Only the tab holding the lock may run it.

const mail = fs.readFileSync(path.join(__dirname, '..', 'src', 'ui', 'hidramail.html'), 'utf8');
check(/navigator\.locks\.request\(\s*'hidramail-mailbox'/.test(mail) && /runMailbox\(async function init/.test(mail),
  'HidraMail runs its mailbox in one tab at a time');

console.log(failed ? `\n${failed} check(s) failed` : '\napps keep their storage, websites keep none');
process.exit(failed ? 1 : 0);
