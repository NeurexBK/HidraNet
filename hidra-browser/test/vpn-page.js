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
for (const directive of ["connect-src 'none'", "object-src 'none'", "base-uri 'none'", "form-action 'none'"]) {
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
expect('every vpn handler but the status checks for the VPN page before anything else', handlers.join() === ['check-release', 'checkout', 'connect', 'disconnect', 'fetch-list', 'get-passes', 'import-nodes', 'install', 'leak-test', 'new-identity', 'nodes', 'refill', 'set-pass-token', 'uninstall', 'verify-file'].sort().join(), `gated handlers: ${handlers.join(', ') || 'none'}`);
expect('the status is read by the VPN page or the new tab page, nothing else', /ipcMain\.handle\('vpn:status', \(event\) => \{\s*if \(!isVpnPage\(event\)\) requirePage\(event, UI_ROOT_URL, \['newtab\.html'\], 'the VPN status'\);/.test(main), 'vpn:status is not gated on the two pages');
const ungated = [...main.matchAll(/ipcMain\.handle\('vpn:[a-z-]+'/g)].length;
expect('no vpn handler is without the check', ungated === handlers.length + 1, `${ungated} handlers, ${handlers.length + 1} gated`);
expect('the VPN check wants hidravpn.html by its exact name', /function isVpnPage\(event\) \{\s*return senderPage\(event, UI_ROOT_URL\) === 'hidravpn\.html';/.test(main) && /const vpnOnlyOurs = \(event\) => \{\s*if \(!isVpnPage\(event\)\) throw/.test(main), 'isVpnPage or vpnOnlyOurs is not the exact-page check');
expect('no scheme is trusted by either gate', !/hidra:\/\//.test(guard.replace(/\/\/.*$/gm, '')) && !/href\.startsWith\('hidra:\/\/'\)/.test(preload), 'a hidra:// URL would get the bridge');
expect('the check wants the main frame, not a frame inside a page', /frame !== event\.sender\.mainFrame\) return null/.test(guard), 'a sub-frame could ask');

// ── The main process never hands the renderer a key ──────────────────────
const manager = read(ROOT, 'src', 'main', 'vpn-manager.js');
expect('the browser sends only the service\'s commands', ['status', 'connect', 'down', 'new_identity', 'nodes', 'import_nodes', 'get_passes', 'set_pass_token', 'refill', 'checkout'].every((c) => manager.includes(`cmd: '${c}'`)) && !/cmd: '(up|join)'/.test(manager), 'the browser sends an "up" with invites, or lacks a command');
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
  // Buying passes: the page names an action, a pack and a signature, never
  // where to pay, what in, how much, whom to ask or with which account.
  const asks = [...page.matchAll(/checkoutRequest\(\{([^}]*)\}/g)].map((m) => m[1]);
  const keys = asks.flatMap((a) => [...a.matchAll(/([a-z_]+):/g)].map((k) => k[1]));
  expect('the page asks checkout for an action, a pack, the person\'s word and a signature, and nothing else',
    asks.length >= 4 && keys.every((k) => ['action', 'passes', 'replace_unpaid', 'signature'].includes(k))
      && /checkoutRequest\(\{ action: 'buy', passes: n, replace_unpaid: replace \? String\(checkoutOrder\.amount_raw \|\| ''\) : '' \}/.test(page)
      && (page.match(/api\.checkout\(/g) || []).length === 1 && /r = await api\.checkout\(input\);/.test(page),
    `checkout is asked with: ${asks.join(' | ')}`);
  expect('the module sends checkout only what it builds itself, and the bridge only passes it on',
    /const cmd = \{ cmd: 'checkout', action \};/.test(manager)
      && /if \(typeof input\.replace_unpaid === 'string' && \/\^\[0-9\]\{1,20\}\$\/\.test\(input\.replace_unpaid\)\) \{\s*cmd\.replace_unpaid = input\.replace_unpaid;/.test(manager)
      && /checkout: \(input\) => ipcRenderer\.invoke\('vpn:checkout', input\),/.test(preload)
      && /ipcMain\.handle\('vpn:checkout', \(event, input\) => \{\s*vpnOnlyOurs\(event\);\s*return vpnManager\.checkout\(input\);/.test(main),
    'vpn-manager.js forwards the page\'s object, or the bridge or the handler is missing');
  expect('an order reads "Send exactly", the amount on its own with its own Copy, then the wallet with its own',
    /<div class="pay-label">Send exactly<\/div>\s*<div class="pay-row"><span class="pay-amount" id="checkout-amount"><\/span><span class="pay-unit" id="checkout-unit">HNET<\/span><button class="btn copy" id="checkout-copy-amount" type="button">Copy<\/button><\/div>/.test(page)
      && /id="checkout-wallet"><\/span><button class="btn copy" id="checkout-copy-wallet" type="button">Copy<\/button>/.test(page)
      && /copyField\('checkout-copy-amount', checkoutOrder\.amount\)/.test(page) && /copyField\('checkout-copy-wallet', checkoutOrder\.wallet\)/.test(page),
    'the amount, the wallet or their Copy buttons are not as they should be');
  const warn = (page.match(/\$\('checkout-warn'\)\.textContent = '([^;]+);/) || [])[1] || '';
  expect('the order says the amount must match to the last digit, to choose HNET and not dollars, and that dollars are only a reference never typed in',
    /must match to the last digit/.test(warn) && /as what you send, not dollars/.test(warn) && /only a reference: never type it into your wallet/.test(warn)
      && /Not the amount to send/.test(page),
    `the warning is: ${warn}`);
  expect('the dollars come after the amount, smaller',
    page.indexOf('id="checkout-ref"') > page.indexOf('id="checkout-amount"') && page.indexOf('id="checkout-ref"') > page.indexOf('id="checkout-warn"')
      && /\.pay-ref\{font-size:11px/.test(page) && /\.pay-amount\{[^}]*font-size:20px/.test(page),
    'the dollar line is before the amount, or not smaller');
  expect('an open order is replaced only on the person\'s word that it is unpaid',
    /var replace = Boolean\(checkoutOrder\) && \$\('checkout-unpaid'\)\.checked;/.test(page) && /if \(checkoutOrder && !replace\) \{/.test(page)
      && /<input type="checkbox" id="checkout-unpaid">/.test(page),
    'a package replaces an open order without the box, or the box starts ticked');
  expect('no order and no claim while two hops are up, whatever the service would do',
    /function buyPack\(n\) \{\s*if \(twoHops\(lastStatus\)\) \{/.test(page) && /\$\('checkout-claim'\)\.addEventListener\('click', function \(\) \{\s*if \(twoHops\(lastStatus\)\) \{/.test(page)
      && /\$\('checkout-claim'\)\.disabled = off \|\| privado/.test(page) && /b\.disabled = off \|\| privado;/.test(page),
    'the page would ask for an order or a claim in privado');
  expect('a service older than checkout: the page says to update HidraVPN from Settings and offers nothing',
    /var CHECKOUT_OLD = '[^']*Update HidraVPN: Settings, Service, Check for an update\./.test(page) && /\} else if \(r && \(r\.older === true \|\| r\.ok\)\) \{/.test(page)
      && /checkoutUnsupported = true;\s*message\('err', CHECKOUT_OLD, 'checkout-msg'\);/.test(page),
    'an older service would break the page, or the page does not say where to update');
  expect('the deadline is said, and an order past it is not shown to be paid',
    /return 'Pay before ' \+ hhmm\(d\.getHours\(\), d\.getMinutes\(\)\) \+ ' on ' \+ d\.getDate\(\)/.test(page) && /', your time \(' \+ hhmm\(d\.getUTCHours\(\), d\.getUTCMinutes\(\)\) \+ ' UTC\)/.test(page)
      && /\$\('checkout-pay'\)\.hidden = past;/.test(page) && /var past = !Number\.isFinite\(deadline\) \|\| Date\.now\(\) >= deadline \|\| !o\.amount;/.test(page),
    'no deadline, or an order past it still offered for payment');
}
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
      && /if \(tokenThroughTwoHops\(s\)\) outdated = true;/.test(page)
      && /privado too/.test(old) && /through the exit/.test(old) && /Update HidraVPN/.test(old),
    'the status field, the service setting it, or the page\'s use of it is missing');
}
expect('the token never comes back to the page: the module sends it and the service never echoes it', /cmd: 'set_pass_token', pass_token: t/.test(manager) && !/localStorage|sessionStorage/.test(page), 'the token is sent another way, or stored by the page');
expect('the page never names a file path: the person chooses in a dialog', /dialog\.showOpenDialog/.test(main) && !/filePaths?\s*[:=]/.test(page), 'a path travels from the page');
expect('the browser does not verify the list itself; the service that writes the pocket does', !/releaseVerify\.verify(File|Bytes)\([^)]*list/.test(main), 'the browser verifies the node list, which would let a convinced browser feed an unconvinced service');
expect('the browser reads the token fresh on every request', /_readToken\(\)/.test(manager) && !/this\.token\s*=/.test(manager), 'the token is cached');
const sealRs = read(ROOT, '..', 'hidravpn', 'crates', 'hidravpn-service', 'src', 'seal.rs');
const rsScheme = (sealRs.match(/pub const SCHEME: &str = "([^"]+)";/) || [])[1];
const rsInfo = (sealRs.match(/const INFO: &\[u8\] = b"([^"]+)";/) || [])[1];
expect('the browser seals with the scheme and the derivation the service opens with',
  Boolean(rsScheme) && Boolean(rsInfo) && manager.includes(`const SEAL = '${rsScheme}';`) && manager.includes(`const SEAL_INFO = Buffer.from('${rsInfo}');`),
  `seal.rs says ${rsScheme} / ${rsInfo}; vpn-manager.js does not match`);
expect('every request is sealed when the service has a key, and an answer that does not open is not believed',
  /sealed = sealRequest\(key, plain\);/.test(manager) && /if \(answer === null\) throw new VpnUnavailable\('unavailable', NOT_THE_SERVICE/.test(manager),
  'vpn-manager.js sends in the clear, or believes an answer that did not open');
expect('on Windows a service without a key is never asked in the clear',
  /\} else if \(this\.platform === 'win32'\) \{[\s\S]{0,300}throw new VpnUnavailable\('outdated'/.test(manager),
  'a keyless Windows service would be sent the token');
// A service that has not started since it was installed or updated wrote no
// key either, so the page does not call it older, and offers to start it.
expect('a Windows service with no key is shown as not running, or older, with starting it as the first step',
  page.includes("'outdated': 'Service not running, or older than this browser'")
    && /if \(s\.state === 'outdated'\) \{ text = 'Start the HidraVPN service, or, if it is running, update HidraVPN from Settings\.'/.test(page),
  'the page says only that the service is older');
// Nor does it remember one as older: once the service starts, its status is
// no longer "outdated", and nothing may still send the person to update it.
// Only an answer that shows the service is older is kept for the page's life.
expect('the page remembers a service as older only from an answer that shows it, not from "outdated" alone',
  /if \(a && a\.older === true && !outdated\) \{ outdated = true;/.test(page)
    && !/state === 'outdated'[^;\n]*\) outdated = true/.test(page)
    && !/a\.state === 'outdated' && !outdated/.test(page)
    && /updateKnown \|\| outdated \|\| \(lastStatus && lastStatus\.state === 'outdated'\)/.test(page)
    && /'Update HidraVPN: the installed service does not know the commands this page uses\.', \{ older: true \}\);/.test(manager)
    && /throw new VpnUnavailable\('outdated', 'the HidraVPN service on this machine is not running, or is older than this browser',\n\s+'[^']*'\);/.test(manager),
  'a status of "outdated" still marks the service as older for as long as the page is open, or the keyless answer claims to show it');

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
expect('installing goes through the bridge, never a link the page follows', /api\.install\(\{ version: release\.version, digest: release\.digest \}\)/.test(page) && !/href=["'][^"']*\.(exe|zip|msi)/.test(page), 'no api.install(), or a download link in the page');
expect('the bridge offers install, uninstall, leak test and release check', ['leakTest:', 'checkRelease:', 'install:', 'uninstall:'].every((k) => preload.includes(k)), 'tab-preload.js lacks one of them');
for (const ch of ["'vpn:leak-test'", "'vpn:install'", "'vpn:uninstall'", "'vpn:check-release'"]) {
  const block = main.slice(main.indexOf(ch), main.indexOf(ch) + 400);
  expect(`${ch} checks who asked`, block.includes('vpnOnlyOurs(event)'), 'the handler does not call vpnOnlyOurs');
}
expect('the local network is off unless the person ticks it', /<input type="checkbox" id="allow-lan">/.test(page), 'allow-lan is missing or pre-checked');
expect('only a strict true reaches the service as allow_lan', /options\.allowLan === true/.test(main), 'main.js does not insist on a boolean');
expect('two hops under one operator are off unless the person ticks it', /<input type="checkbox" id="allow-same-operator">/.test(page), 'allow-same-operator is missing or pre-checked');
expect('only a strict true reaches the service as allow_same_operator', /options\.allowSameOperator === true/.test(main) && /options\.allowSameOperator === true/.test(manager), 'main.js or vpn-manager.js does not insist on a boolean');
expect('the VPN page\'s own requests carry no browser name and no cookies', /credentials: 'omit'/.test(main) && /VPN_FETCH_UA = 'Mozilla\/5\.0'/.test(main) && /https\.get\(url, \{ headers: \{ 'User-Agent': VPN_FETCH_UA \}/.test(main), 'a VPN fetch identifies the browser or sends cookies');
expect('the list and release fetches never go out while Tor is not ready', (main.match(/vpnFetchAllowed\(url\);/g) || []).length === 2, 'fetchText or fetchBuffer skips the network-lock check');
// No Chromium session is ever direct, and Chromium resolves no names itself,
// so the leak test asks through Node, as any other program on the machine.
expect('the leak test asks outside the browser\'s Tor route, as any other program would', /function directProbe\(url\) \{\s*return new Promise\(\(resolve, reject\) => \{[\s\S]{0,400}?const request = https\.get\(url, \{[^}]*\}, agent: false/.test(main) && /runLeakTest\(await vpnManager\.status\(\), directProbe\)/.test(main), 'the leak test no longer asks through Node\'s https');
expect('the leak test gives up after ten seconds in all, not only after ten silent ones', /function directProbe[\s\S]{0,900}?deadline = setTimeout\(\(\) => request\.destroy\(new Error\('timeout'\)\), 10000\)[\s\S]{0,200}?clearTimeout\(deadline\)|function directProbe[\s\S]{0,300}?clearTimeout\(deadline\)[\s\S]{0,700}?deadline = setTimeout\(\(\) => request\.destroy\(new Error\('timeout'\)\), 10000\)/.test(main), 'directProbe has only a socket idle timeout, so a server sending a byte at a time holds the test open');
expect('a country reaches the page as text, never as markup', !/innerHTML/.test(page), 'the page uses innerHTML');
expect('uninstalling asks first', /window\.confirm\(question\)/.test(page), 'no confirmation before removing');

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
