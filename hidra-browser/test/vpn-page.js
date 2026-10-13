// The VPN page and the wiring around it, as a lint.
//
// What it guards: that the page can reach nothing but the bridge (its policy
// has no exits, it loads nothing remote), that the bridge is offered to our
// own pages only and refused again in the main process, that the page is
// reachable by name, and that every sentence about what a mode hides is the
// same sentence the service itself prints — the page must never claim more
// than the command line does. And that no badge is fixed: the kill switch
// reads "Unknown" until the service has said otherwise.
//
//   node hidra-browser/test/vpn-page.js

'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(...p), 'utf8');

const page = read(ROOT, 'src', 'ui', 'hidravpn.html');
const newtab = read(ROOT, 'src', 'ui', 'newtab.html');
const preload = read(ROOT, 'src', 'renderer', 'tab-preload.js');
const main = read(ROOT, 'src', 'main', 'main.js');
const tabs = read(ROOT, 'src', 'main', 'tab-manager.js');
const ipcRs = read(ROOT, '..', 'hidravpn', 'crates', 'hidravpn-service', 'src', 'ipc.rs');

let failed = 0;
let passed = 0;
const ok = (n) => { passed++; console.log('ok    ' + n); };
const bad = (n, why) => { failed++; console.log('FAIL  ' + n + '\n      ' + why); };
const expect = (name, cond, why) => (cond ? ok(name) : bad(name, why));

// ── The page has no way out ──────────────────────────────────────────────
const csp = (page.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/) || [])[1] || '';
expect('the page carries a policy', csp.length > 0, 'no Content-Security-Policy meta');
for (const directive of ["connect-src 'none'", "object-src 'none'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'"]) {
  expect(`policy: ${directive}`, csp.includes(directive), `the policy is: ${csp}`);
}
expect('the page loads nothing remote', !/(src|href)=["']https?:|url\(\s*["']?https?:/.test(page), 'a remote src, href or url() in the page');
expect('the page has no external script', !/<script[^>]+src=/.test(page), 'a <script src> in the page; the logic is inline on purpose');

// ── The page says exactly what the service says ──────────────────────────
const rustSentence = (mode) => {
  const m = ipcRs.match(new RegExp(`"${mode}" => Some\\(\\s*"([^"]+)"`));
  return m ? m[1] : null;
};
for (const mode of ['privado', 'rapido']) {
  const s = rustSentence(mode);
  expect(`the service's ${mode} sentence is found in ipc.rs`, Boolean(s), 'could not read it; the test needs updating');
  if (s) expect(`the page repeats the ${mode} sentence word for word`, page.includes(s), `page lacks: ${s}`);
}
expect('the page never promises anonymity', !/anonymi[st]/i.test(page.replace(/not anonymity/g, '')), 'the word appears outside "not anonymity"');

// ── No badge is fixed ────────────────────────────────────────────────────
const ks = page.match(/<span class="badge" id="vpn-killswitch">([^<]*)<\/span>/);
expect('the kill switch badge exists', Boolean(ks), 'no id="vpn-killswitch"');
if (ks) expect('the kill switch badge starts as "Unknown", not "Armed"', ks[1].trim() === 'Unknown', `starts as "${ks[1]}"`);
expect('the kill switch badge is set from the report', /ks\.textContent = r\.killswitch \? 'Armed' : 'Off'/.test(page), 'nothing sets it from report.killswitch');
expect('the kill switch is "Unknown" when the service cannot be reached', /ks\.textContent = 'Unknown'/.test(page), 'no unreachable state');
const label = page.match(/<span class="label" id="state-label">([^<]*)<\/span>/);
expect('the state label does not start as connected', label && !/connected/i.test(label[1]), 'the label is fixed');

const vpnCard = newtab.match(/id="vpn-badge">([^<]*)</);
expect('the new tab card has a badge with an id', Boolean(vpnCard), 'no id="vpn-badge" in newtab.html');
if (vpnCard) expect('the new tab badge does not start as "On"', !/^on\b/i.test(vpnCard[1].trim()), `starts as "${vpnCard[1]}"`);
expect('the new tab badge is driven from the service', /window\.hidra\.vpn\.status\(\)/.test(newtab) && /'Not installed'/.test(newtab) && /'Off'/.test(newtab), 'detectVpn does not set the off and not-installed states');
expect('the new tab card opens the page from disk, beside it', /data-url="hidravpn\.html"/.test(newtab), 'the card points elsewhere');

// ── Reachable by name ────────────────────────────────────────────────────
expect('the page has an address-bar name', /'hidravpn\.html': 'vpn'/.test(tabs), 'INTERNAL_PAGES lacks hidravpn.html');
expect('hidra://vpn loads the page from disk', /vpn: 'hidravpn\.html'/.test(tabs), 'INTERNAL_BY_NAME lacks vpn');

// ── The bridge: our pages only, refused again in the main process ───────
const internalStart = preload.indexOf('if (isInternalPage) {');
const appsStart = preload.indexOf('if (isAppPage && !isInternalPage) {');
const vpnAt = preload.indexOf('vpn: {');
expect('the preload offers vpn inside the internal-page branch only', internalStart !== -1 && appsStart !== -1 && vpnAt > internalStart && vpnAt < appsStart, `positions: internal ${internalStart}, vpn ${vpnAt}, apps ${appsStart}`);
expect('the apps branch does not offer vpn', !preload.slice(appsStart).includes('vpn:'), 'vpn appears after the apps branch starts');
const handlers = [...main.matchAll(/ipcMain\.handle\('vpn:([a-z-]+)', (?:async )?\((event[^)]*)\) => \{\s*vpnOnlyOurs\(event\);/g)].map((m) => m[1]).sort();
expect('every vpn handler checks who asked before anything else', handlers.join() === ['connect', 'disconnect', 'fetch-list', 'import-nodes', 'join', 'new-identity', 'nodes', 'status', 'verify-file'].sort().join(), `gated handlers: ${handlers.join(', ') || 'none'}`);
const ungated = [...main.matchAll(/ipcMain\.handle\('vpn:[a-z-]+'/g)].length;
expect('no vpn handler is without the check', ungated === handlers.length, `${ungated} handlers, ${handlers.length} gated`);
expect('the check accepts only our own pages, by their path on disk', /function isInternalSender[\s\S]*?return url\.startsWith\(UI_ROOT_URL\);/.test(main), 'isInternalSender does not compare against UI_ROOT_URL alone');
expect('no scheme is trusted by either gate', !/startsWith\('hidra:\/\/'\)/.test(main.slice(main.indexOf('function isInternalSender'), main.indexOf('function isInternalSender') + 600)) && !/href\.startsWith\('hidra:\/\/'\)/.test(preload), 'a hidra:// URL would get the bridge');
expect('the check wants the main frame, not a frame inside a page', /frame !== event\.sender\.mainFrame\) return false/.test(main), 'a sub-frame could ask');

// ── The main process never hands the renderer a key ──────────────────────
const manager = read(ROOT, 'src', 'main', 'vpn-manager.js');
expect('the browser sends only the service\'s commands', ['status', 'connect', 'down', 'new_identity', 'nodes', 'import_nodes', 'join'].every((c) => manager.includes(`cmd: '${c}'`)) && !/cmd: 'up'/.test(manager), 'the browser sends an "up" with invites, or lacks a command');
expect('the fetched list is sent to the service unverified by the browser, with its .sig, from one fixed address', /VPN_LIST_URL \+ '\.sig'/.test(main) && /const VPN_LIST_URL = 'https:\/\//.test(main) && /importNodesFromTexts\(list, signature\)/.test(main), 'the fetch handler does not pass the signature through, or the URL is not fixed');
expect('the page says when one operator runs both hops', /One operator runs both hops/.test(page) && /same_operator === true/.test(page), 'no one-operator warning driven from status.same_operator');
expect('the page offers to join open nodes and to fetch the list', /id="btn-join-all"/.test(page) && /id="btn-fetch"/.test(page) && /api\.join\(/.test(page) && /api\.fetchList\(\)/.test(page), 'buttons or calls missing');
expect('the page never names a file path: the person chooses in a dialog', /dialog\.showOpenDialog/.test(main) && !/filePaths?\s*[:=]/.test(page), 'a path travels from the page');
expect('the browser does not verify the list itself; the service that writes the pocket does', !/releaseVerify\.verify(File|Bytes)\([^)]*list/.test(main), 'the browser verifies the node list, which would let a convinced browser feed an unconvinced service');
expect('the browser reads the token fresh on every request', /_readToken\(\)/.test(manager) && !/this\.token\s*=/.test(manager), 'the token is cached');

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
