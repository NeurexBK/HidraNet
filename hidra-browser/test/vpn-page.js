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
const guard = read(ROOT, 'src', 'main', 'ipc-guard.js');
const internalStart = preload.indexOf('if (isInternalPage) {');
const appsStart = preload.indexOf('if (isAppPage && !isInternalPage) {');
const bridgeAt = preload.indexOf('const vpnBridge = ');
const bridgeEnd = preload.indexOf(': null;', bridgeAt);
const bridge = preload.slice(bridgeAt, bridgeEnd);
expect('the full VPN bridge goes to hidravpn.html only, the new tab page gets the status alone',
  bridgeAt !== -1 && /^const vpnBridge = uiPage === 'hidravpn\.html' \? \{/.test(bridge)
    && /: uiPage === 'newtab\.html' \? \{\s*status: \(\) => ipcRenderer\.invoke\('vpn:status'\),\s*\}\s*$/.test(bridge),
  'vpnBridge is not keyed on the exact page names');
expect('the preload offers vpn inside the internal-page branch only', internalStart !== -1 && appsStart !== -1 && preload.indexOf('vpnBridge ? { vpn: vpnBridge }') > internalStart && preload.indexOf('vpnBridge ? { vpn: vpnBridge }') < appsStart, 'the bridge is offered outside the internal-page branch');
expect('the apps branch does not offer vpn', !preload.slice(appsStart).includes('vpn:'), 'vpn appears after the apps branch starts');
const handlers = [...main.matchAll(/ipcMain\.handle\('vpn:([a-z-]+)', (?:async )?\((event[^)]*)\) => \{\s*vpnOnlyOurs\(event\);/g)].map((m) => m[1]).sort();
expect('every vpn handler but the status checks for the VPN page before anything else', handlers.join() === ['check-release', 'connect', 'disconnect', 'fetch-list', 'get-passes', 'import-nodes', 'install', 'leak-test', 'new-identity', 'nodes', 'refill', 'set-pass-token', 'uninstall', 'verify-file'].sort().join(), `gated handlers: ${handlers.join(', ') || 'none'}`);
expect('the status is read by the VPN page or the new tab page, nothing else', /ipcMain\.handle\('vpn:status', \(event\) => \{\s*if \(!isVpnPage\(event\)\) requirePage\(event, UI_ROOT_URL, \['newtab\.html'\], 'the VPN status'\);/.test(main), 'vpn:status is not gated on the two pages');
const ungated = [...main.matchAll(/ipcMain\.handle\('vpn:[a-z-]+'/g)].length;
expect('no vpn handler is without the check', ungated === handlers.length + 1, `${ungated} handlers, ${handlers.length + 1} gated`);
expect('the VPN check wants hidravpn.html by its exact name', /function isVpnPage\(event\) \{\s*return senderPage\(event, UI_ROOT_URL\) === 'hidravpn\.html';/.test(main) && /const vpnOnlyOurs = \(event\) => \{\s*if \(!isVpnPage\(event\)\) throw/.test(main), 'isVpnPage or vpnOnlyOurs is not the exact-page check');
expect('no scheme is trusted by either gate', !/hidra:\/\//.test(guard.replace(/\/\/.*$/gm, '')) && !/href\.startsWith\('hidra:\/\/'\)/.test(preload), 'a hidra:// URL would get the bridge');
expect('the check wants the main frame, not a frame inside a page', /frame !== event\.sender\.mainFrame\) return null/.test(guard), 'a sub-frame could ask');

// ── The main process never hands the renderer a key ──────────────────────
const manager = read(ROOT, 'src', 'main', 'vpn-manager.js');
expect('the browser sends only the service\'s commands', ['status', 'connect', 'down', 'new_identity', 'nodes', 'import_nodes', 'get_passes', 'set_pass_token', 'refill'].every((c) => manager.includes(`cmd: '${c}'`)) && !/cmd: '(up|join)'/.test(manager), 'the browser sends an "up" with invites, or lacks a command');
expect('the fetched list is sent to the service unverified by the browser, with its .sig, from one fixed address', /VPN_LIST_URL \+ '\.sig'/.test(main) && /const VPN_LIST_URL = 'https:\/\//.test(main) && /importNodesFromTexts\(list, signature\)/.test(main), 'the fetch handler does not pass the signature through, or the URL is not fixed');
expect('the page says when one operator runs both hops', /One operator runs both hops/.test(page) && /same_operator === true/.test(page), 'no one-operator warning driven from status.same_operator');
expect('the page fetches the list and never joins a node: open nodes are asked for a fresh key on every connection', /id="btn-fetch"/.test(page) && /api\.fetchList\(\)/.test(page) && !/api\.join\(/.test(page) && !/btn-join/.test(page), 'the fetch button is missing, or the page still joins nodes (a lasting lease a node could recognise)');
expect('the page shows automatic passes as the service has them and switches them with one box', /id="auto-passes"/.test(page) && /api\.refill\(want\)/.test(page) && /api\.refill\(\)/.test(page) && /refill: \(enabled\) => ipcRenderer\.invoke\('vpn:refill', enabled\)/.test(fs.readFileSync(path.join(__dirname, '..', 'src', 'renderer', 'tab-preload.js'), 'utf8')), 'the box, its calls, or the bridge are missing');
expect('the page asks for passes, and leaves the token to an administrator: it has no token field, which the service would refuse from the person', /id="btn-passes"/.test(page) && /api\.getPasses\(/.test(page) && !/api\.setPassToken\(/.test(page) && !/id="pass-token"|id="btn-token"/.test(page) && /<code>sudo hidravpn passes token FILE<\/code>/.test(page), 'the passes card or its call is missing, or the page still offers a token field that cannot succeed, or does not say how an administrator keeps the token');
expect('the page asks for no passes while two hops are up or being built, whatever the service would do',
  /return Boolean\(r && r\.hops >= 2\);/.test(page)
    && /\$\('btn-passes'\)\.disabled = busy \|\| !reachable \|\| !hasPassNode \|\| twoHops\(s\);/.test(page)
    && /\$\('btn-passes'\)\.disabled = busy \|\| !hasPassNode \|\| twoHops\(lastStatus\);/.test(page)
    && /if \(!api \|\| busy \|\| twoHops\(lastStatus\)\) return;/.test(page),
  'Get passes stays on offer in privado, leaving the account token to the service alone');
{
  // A service older than this page tops passes up through two hops: the
  // page may say "never in privado" only of one whose status says so.
  const daemonRs = read(ROOT, '..', 'hidravpn', 'crates', 'hidravpn-service', 'src', 'daemon.rs');
  const old = (page.match(/var REFILL_ON_OLD = '((?:[^'\\]|\\.)+)';/) || [])[1] || '';
  expect('"never in privado" is said only of a service whose status says it keeps the token off two hops; an older one is said to top up through the exit, and to need updating',
    /pub account_one_hop_only: bool,/.test(ipcRs)
      && (daemonRs.match(/account_one_hop_only: true,/g) || []).length === 2
      && /return Boolean\(r && r\.account_one_hop_only !== true\);/.test(page)
      && /tokenThroughTwoHops\(lastStatus\) \? REFILL_ON_OLD : REFILL_ON/.test(page)
      && /if \(s\.state === 'outdated' \|\| tokenThroughTwoHops\(s\)\) outdated = true;/.test(page)
      && /privado too/.test(old) && /through the exit/.test(old) && /Update HidraVPN/.test(old),
    'the status field, the service setting it, or the page\'s use of it is missing');
}
expect('the token never comes back to the page: the module sends it and the service never echoes it', /cmd: 'set_pass_token', pass_token: t/.test(manager) && !/localStorage|sessionStorage/.test(page), 'the token is sent another way, or stored by the page');
expect('the page never names a file path: the person chooses in a dialog', /dialog\.showOpenDialog/.test(main) && !/filePaths?\s*[:=]/.test(page), 'a path travels from the page');
expect('the browser does not verify the list itself; the service that writes the pocket does', !/releaseVerify\.verify(File|Bytes)\([^)]*list/.test(main), 'the browser verifies the node list, which would let a convinced browser feed an unconvinced service');
expect('the browser reads the token fresh on every request', /_readToken\(\)/.test(manager) && !/this\.token\s*=/.test(manager), 'the token is cached');

// ── Phase 4 completion: install, leak test, local network, route ──────────
expect('the install card is hidden until the service says it is not installed', /id="install-card" style="display:none"/.test(page) && /notInstalled \? '' : 'none'/.test(page), 'the install card is not tied to the not-installed state');
const installer = read(ROOT, 'src', 'main', 'vpn-installer.js');
const notInstallable = (installer.match(/const NOT_INSTALLABLE = '([^']+)'/) || [])[1];
expect('where there is no installer (macOS) the page says so and offers no Install',
  Boolean(notInstallable) && page.includes(notInstallable)
    && /var noInstaller = notInstalled && s\.installable === false;/.test(page)
    && /\$\('btn-install'\)\.hidden = noInstaller;/.test(page)
    && /\$\('install-none'\)\.hidden = !noInstaller;/.test(page)
    && /\$\('install-why'\)\.hidden = noInstaller;/.test(page)
    && /\$\('install-steps'\)\.hidden = noInstaller;/.test(page)
    && /\$\('btn-install'\)\.disabled = busy \|\| noInstaller;/.test(page)
    && /installable: installable\(vpnInstaller\.platform\)/.test(main),
  'the status does not carry installable, or the page still offers Install where the installer refuses');
expect('installing goes through the bridge, never a link the page follows', /api\.install\(\)/.test(page) && !/href=["'][^"']*\.(exe|zip|msi)/.test(page), 'no api.install(), or a download link in the page');
expect('the bridge offers install, uninstall, leak test and release check', ['leakTest:', 'checkRelease:', 'install:', 'uninstall:'].every((k) => preload.includes(k)), 'tab-preload.js lacks one of them');
for (const ch of ["'vpn:leak-test'", "'vpn:install'", "'vpn:uninstall'", "'vpn:check-release'"]) {
  const block = main.slice(main.indexOf(ch), main.indexOf(ch) + 400);
  expect(`${ch} checks who asked`, block.includes('vpnOnlyOurs(event)'), 'the handler does not call vpnOnlyOurs');
}
expect('the local network is off unless the person ticks it', /<input type="checkbox" id="allow-lan">/.test(page), 'allow-lan is missing or pre-checked');
expect('only a strict true reaches the service as allow_lan', /options\.allowLan === true/.test(main), 'main.js does not insist on a boolean');
expect('two hops under one operator are off unless the person ticks it', /<input type="checkbox" id="allow-same-operator">/.test(page), 'allow-same-operator is missing or pre-checked');
expect('only a strict true reaches the service as allow_same_operator', /options\.allowSameOperator === true/.test(main) && /options\.allowSameOperator === true/.test(manager), 'main.js or vpn-manager.js does not insist on a boolean');
expect('the VPN page\'s own requests carry no browser name and no cookies', /credentials: 'omit'/.test(main) && /VPN_FETCH_UA = 'Mozilla\/5\.0'/.test(main) && /probe\.setUserAgent\(VPN_FETCH_UA\)/.test(main), 'a VPN fetch identifies the browser or sends cookies');
expect('the list and release fetches never go out while Tor is not ready', (main.match(/vpnFetchAllowed\(url\);/g) || []).length === 2, 'fetchText or fetchBuffer skips the network-lock check');
expect('the leak test asks without the Tor proxy, from its own session', /setProxy\(\{ mode: 'direct' \}\)/.test(main), 'no direct session for the leak test');
expect('a country reaches the page as text, never as markup', !/innerHTML/.test(page), 'the page uses innerHTML');
expect('uninstalling asks first', /window\.confirm\(question\)/.test(page), 'no confirmation before removing');

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
