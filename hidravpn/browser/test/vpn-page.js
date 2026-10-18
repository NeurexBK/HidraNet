// The VPN page, as a lint.
//
// What it guards: that the page can reach nothing but the bridge (its policy
// has no exits, it loads nothing remote), and that every sentence about what
// a mode hides is the same sentence the service itself prints — the page must
// never claim more than the command line does. And that no badge is fixed:
// the kill switch reads "Unknown" until the service has said otherwise.
//
// The page is parked here, out of the browser, until HidraVPN ships (see
// ../README.md). The checks on its wiring — the bridge offered to this page
// only, every handler refusing any other sender, the new tab card — went with
// the wiring, and come back with it.
//
//   node hidravpn/browser/test/vpn-page.js

'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(...p), 'utf8');

const page = read(ROOT, 'src', 'ui', 'hidravpn.html');
const ipcRs = read(ROOT, '..', 'crates', 'hidravpn-service', 'src', 'ipc.rs');

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

// ── The browser's module never hands the page a key ─────────────────────
const manager = read(ROOT, 'src', 'main', 'vpn-manager.js');
expect('the browser sends only the service\'s commands', ['status', 'connect', 'down', 'new_identity', 'nodes', 'import_nodes', 'get_passes', 'set_pass_token', 'refill'].every((c) => manager.includes(`cmd: '${c}'`)) && !/cmd: '(up|join)'/.test(manager), 'the browser sends an "up" with invites, or lacks a command');
expect('the page says when one operator runs both hops', /One operator runs both hops/.test(page) && /same_operator === true/.test(page), 'no one-operator warning driven from status.same_operator');
expect('the page fetches the list and never joins a node: open nodes are asked for a fresh key on every connection', /id="btn-fetch"/.test(page) && /api\.fetchList\(\)/.test(page) && !/api\.join\(/.test(page) && !/btn-join/.test(page), 'the fetch button is missing, or the page still joins nodes (a lasting lease a node could recognise)');
expect('the page shows automatic passes as the service has them and switches them with one box', /id="auto-passes"/.test(page) && /api\.refill\(want\)/.test(page) && /api\.refill\(\)/.test(page), 'the box or its calls are missing');
expect('the page asks for passes and hands the token to the service, emptying its field at once', /id="btn-passes"/.test(page) && /api\.getPasses\(/.test(page) && /api\.setPassToken\(token\)/.test(page) && /field\.value = '';[\s\S]{0,200}api\.setPassToken/.test(page) && /type="password"/.test(page), 'the passes card, its calls, or the emptied field are missing');
expect('the token never comes back to the page: the module sends it and the service never echoes it', /cmd: 'set_pass_token', pass_token: t/.test(manager) && !/localStorage|sessionStorage/.test(page), 'the token is sent another way, or stored by the page');
expect('the page never names a file path: the person chooses in a dialog', !/filePaths?\s*[:=]/.test(page), 'a path travels from the page');
expect('the browser reads the token fresh on every request', /_readToken\(\)/.test(manager) && !/this\.token\s*=/.test(manager), 'the token is cached');

// ── Phase 4 completion: install, leak test, local network, route ──────────
expect('the install card is hidden until the service says it is not installed', /id="install-card" style="display:none"/.test(page) && /notInstalled \? '' : 'none'/.test(page), 'the install card is not tied to the not-installed state');
expect('installing goes through the bridge, never a link the page follows', /api\.install\(\)/.test(page) && !/href=["'][^"']*\.(exe|zip|msi)/.test(page), 'no api.install(), or a download link in the page');
expect('the local network is off unless the person ticks it', /<input type="checkbox" id="allow-lan">/.test(page), 'allow-lan is missing or pre-checked');
expect('two hops under one operator are off unless the person ticks it', /<input type="checkbox" id="allow-same-operator">/.test(page), 'allow-same-operator is missing or pre-checked');
expect('only a strict true reaches the service as allow_same_operator', /options\.allowSameOperator === true/.test(manager), 'vpn-manager.js does not insist on a boolean');
expect('a country reaches the page as text, never as markup', !/innerHTML/.test(page), 'the page uses innerHTML');
expect('uninstalling asks first', /window\.confirm\(question\)/.test(page), 'no confirmation before removing');

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
