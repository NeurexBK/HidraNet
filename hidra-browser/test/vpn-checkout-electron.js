// The VPN page's checkout, as a person sees it: the real page with the
// real tab preload, and the main process's side answered by this test.
//
// It proves, on screen: an open order is shown again when the drawer
// opens; the packages list the price in HNET, with any dollar price after
// it as a reference; an order reads "Send exactly <amount> HNET" with the
// amount on its own, Copy copies only its digits and the wallet's Copy only
// the wallet; the deadline is said, and so is that the amount must match
// to the last digit, that the dollars are only a reference never typed
// into the wallet, and to choose HNET, not dollars; the dollars come after
// the amount and smaller; an open order is not replaced unless the person
// ticks that it is unpaid; a claim not final yet, or refused, keeps the
// order and the signature and says not to pay again; a confirmed one
// clears both; nothing is asked while two hops are up; and a service
// older than checkout makes the page say to update HidraVPN.
//
//   cd hidra-browser && xvfb-run -a ./node_modules/.bin/electron --no-sandbox test/vpn-checkout-electron.js

'use strict';

const { app, BrowserWindow, ipcMain } = require('electron');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');

const ROOT = path.join(__dirname, '..');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-checkout-'));
fs.cpSync(path.join(ROOT, 'src', 'ui'), dir, { recursive: true });
const UI_ROOT_URL = pathToFileURL(dir + path.sep).href;

const HNET = 'Aov3BtQvrGXM5V9oiHu8PKJWeV8a2rFnr24fwWcNpump';
const WALLET = 'So11111111111111111111111111111111111111112';
const SIG = '5VERv8NMvzbJMEkV8xnrLkEaWRtSz2CosKDYVCJjrRo'.padEnd(87, '1');
const report = (hops) => ({ connected: hops > 0, node_name: hops ? 'node-x' : null, endpoint: null, last_handshake_secs: null,
  tx_bytes: 0, rx_bytes: 0, killswitch: hops > 0, hops, mode: hops === 2 ? 'privado' : hops === 1 ? 'rapido' : '',
  entry_name: hops === 2 ? 'node-e' : null, hops_detail: [], version: '0.1.3', ipv6: false, account_one_hop_only: true });
let status = { state: 'disconnected', report: report(0) };
const order = (passes, amount) => ({ passes, amount, token: 'HNET', mint: HNET, wallet: WALLET,
  expires: new Date(Date.now() + 7200 * 1000).toISOString().replace(/\.\d+Z$/, 'Z'), usd: '5.99', rate: '0.00004005', payable: true });
const OPEN = order(150, '149563.032846');

const asked = [];
let answer = () => ({ ok: true, checkout: { state: 'idle', message: '' } });
ipcMain.handle('vpn:status', () => status);
ipcMain.handle('vpn:nodes', () => ({ ok: true, nodes: [{ slot: 'known', node_name: 'node-x', endpoint: '192.0.2.1:51820', admitted: false, role: 'exit', admission: 'pass' }] }));
ipcMain.handle('vpn:refill', () => ({ ok: true, refill: { enabled: true, low: 3, count: 10 } }));
ipcMain.handle('vpn:checkout', (_e, input) => { asked.push(input); return answer(input); });
for (const ch of ['connect', 'leak-test', 'check-release', 'install', 'uninstall', 'disconnect', 'new-identity',
  'import-nodes', 'fetch-list', 'get-passes', 'set-pass-token', 'verify-file']) {
  ipcMain.handle('vpn:' + ch, () => ({ ok: false, error: 'not in this test' }));
}

const failures = [];
const expect = (name, ok, detail) => {
  console.log((ok ? 'ok    ' : 'FAIL  ') + name + (ok || !detail ? '' : '\n      ' + detail));
  if (!ok) failures.push(name);
};

app.on('window-all-closed', () => {});
setTimeout(() => { console.log('FAIL  the page did not answer within 90 seconds'); app.exit(1); }, 90000).unref();

app.whenReady().then(async () => {
  const win = new BrowserWindow({
    show: true, width: 1200, height: 900,
    webPreferences: { preload: path.join(ROOT, 'src', 'renderer', 'tab-preload.js'), contextIsolation: true, nodeIntegration: false,
      sandbox: true, additionalArguments: [`--hidra-ui-root=${UI_ROOT_URL}`, '--hidra-app-origins='] },
  });
  await win.loadURL(pathToFileURL(path.join(dir, 'hidravpn.html')).href);
  const js = (code) => win.webContents.executeJavaScript(code, true);
  const until = async (code, ms = 8000) => {
    const end = Date.now() + ms;
    for (;;) {
      const v = await js(code);
      if (v) return v;
      if (Date.now() > end) return v;
      await new Promise((r) => setTimeout(r, 50));
    }
  };
  const text = (id) => js(`document.getElementById(${JSON.stringify(id)}).textContent`);
  const msg = () => js(`(function () { var m = document.getElementById('checkout-msg'); return { cls: m.className, text: m.textContent }; })()`);
  const click = (id) => js(`document.getElementById(${JSON.stringify(id)}).click()`);
  const shown = (id) => js(`(function () { var e = document.getElementById(${JSON.stringify(id)}); return Boolean(e.offsetParent) && !e.closest('[hidden]'); })()`);
  // Copy is caught at the page's own clipboard call: what it would write.
  await js(`window.__copied = []; navigator.clipboard.writeText = function (t) { window.__copied.push(t); return Promise.resolve(); }; true`);

  await until(`document.getElementById('version-line').textContent.indexOf('0.1.3') !== -1`);

  // ── An open order is shown again when the drawer opens ──────────────
  answer = () => ({ ok: true, checkout: { state: 'awaiting_payment', order: OPEN, message: 'An order is open on this computer. Pay it, or, if you already paid, check its transaction below. Do not pay it twice.' } });
  await click('btn-open-passes');
  await until(`!document.getElementById('checkout-order').hidden`);
  expect('opening the drawer asks only for the order kept', JSON.stringify(asked) === JSON.stringify([{ action: 'status' }]), JSON.stringify(asked));
  expect('the order kept is shown again, not replaced', (await text('checkout-amount')) === '149563.032846' && /Do not pay it twice/.test((await msg()).text), JSON.stringify(await msg()));

  // ── The order on screen ───────────────────────────────────────────────
  const pay = await js(`(function () {
    var g = function (id) { return document.getElementById(id); };
    var all = g('checkout-pay').textContent.replace(/\\s+/g, ' ');
    var amountAt = all.indexOf('149563.032846'), refAt = all.indexOf('5.99 USD');
    return { label: g('checkout-amount').previousElementSibling === null && g('checkout-amount').parentElement.previousElementSibling.textContent,
      amount: g('checkout-amount').textContent, unit: g('checkout-unit').textContent, wallet: g('checkout-wallet').textContent,
      expiry: g('checkout-expiry').textContent, warn: g('checkout-warn').textContent, ref: g('checkout-ref').textContent, refHidden: g('checkout-ref').hidden,
      amountAt: amountAt, refAt: refAt,
      amountPx: parseFloat(getComputedStyle(g('checkout-amount')).fontSize), refPx: parseFloat(getComputedStyle(g('checkout-ref')).fontSize),
      what: g('checkout-what').textContent };
  })()`);
  expect('the order reads "Send exactly <amount> HNET", the amount on its own', pay.label === 'Send exactly' && pay.amount === '149563.032846' && pay.unit === 'HNET', JSON.stringify(pay));
  expect('the receiving wallet is shown on its own', pay.wallet === WALLET, pay.wallet);
  expect('the deadline is said', /^Pay before .+ \(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ UTC\)\. After that, do not pay it\.$/.test(pay.expiry), pay.expiry);
  expect('the warning: every digit, choose HNET not dollars, the dollars only a reference never typed into the wallet',
    /must match to the last digit/.test(pay.warn) && /choose HNET as what you send, not dollars/.test(pay.warn)
      && /only a reference/.test(pay.warn) && /never type it into your wallet/.test(pay.warn), pay.warn);
  expect('the dollars come after the amount, smaller, and say they are not the amount to send',
    !pay.refHidden && pay.amountAt !== -1 && pay.refAt > pay.amountAt && pay.refPx < pay.amountPx && /For reference only: priced at 5\.99 USD/.test(pay.ref) && /Not the amount to send/.test(pay.ref),
    JSON.stringify(pay));
  expect('the amount and the dollars are never on one line', !/USD/.test(pay.amount) && !/149563/.test(pay.ref), JSON.stringify(pay));
  await click('checkout-copy-amount');
  await click('checkout-copy-wallet');
  const copied = await until(`window.__copied.length === 2 && window.__copied`);
  expect('Copy copies only the amount\'s digits, and the wallet\'s Copy only the wallet', JSON.stringify(copied) === JSON.stringify(['149563.032846', WALLET]), JSON.stringify(copied));

  // ── The packages, and an open order that is not replaced unasked ─────
  answer = () => ({ ok: true, checkout: { state: 'awaiting_payment', order: OPEN, message: 'An order is open on this computer. Pay it, or, if you already paid, check its transaction below. Do not pay it twice.',
    packs: [{ passes: 10, price: '50' }, { passes: 150, price: '149563', usd: '5.99' }], token: 'HNET', rate: '0.00004005' } });
  await click('checkout-load');
  await until(`document.querySelectorAll('#checkout-packs button').length === 2`);
  const packs = await js(`[].map.call(document.querySelectorAll('#checkout-packs button'), function (b) {
    return { main: b.querySelector('.pack-main').textContent, ref: b.querySelector('.pack-ref').textContent,
      mainPx: parseFloat(getComputedStyle(b.querySelector('.pack-main')).fontSize), refPx: parseFloat(getComputedStyle(b.querySelector('.pack-ref')).fontSize) }; })`);
  expect('the packages say their price in HNET first, the dollars after it, smaller, as a reference',
    packs[0].main === '10 passes for 50 HNET' && packs[1].main === '150 passes for 149563 HNET'
      && /^Priced at 5\.99 USD, a reference only\. The exact amount to send comes with the order\.$/.test(packs[1].ref)
      && packs[1].refPx < packs[1].mainPx && !/USD/.test(packs[0].ref), JSON.stringify(packs));
  let before = asked.length;
  await js(`document.querySelector('#checkout-packs button[data-passes="10"]').click()`);
  await new Promise((r) => setTimeout(r, 300));
  expect('with an order open and the box not ticked, a package asks for nothing and says why',
    asked.length === before && /An order is open below/.test((await msg()).text), JSON.stringify(asked.slice(before)) + ' ' + JSON.stringify(await msg()));
  const TEN = order(10, '50.004213');
  answer = () => ({ ok: true, checkout: { state: 'awaiting_payment', order: TEN, message: 'Order saved on this computer. Send exactly the amount shown, every decimal, to the wallet shown, before the deadline. Then paste the transaction\'s signature below and check the payment.' } });
  await click('checkout-unpaid');
  await js(`document.querySelector('#checkout-packs button[data-passes="10"]').click()`);
  await until(`document.getElementById('checkout-amount').textContent === '50.004213'`);
  expect('ticked as unpaid, a package replaces it, saying so to the service',
    JSON.stringify(asked[asked.length - 1]) === JSON.stringify({ action: 'buy', passes: 10, replace_unpaid: true }), JSON.stringify(asked[asked.length - 1]));
  expect('and the box is clear again for the new order', !(await js(`document.getElementById('checkout-unpaid').checked`)));

  // ── Claims ───────────────────────────────────────────────────────────
  await js(`document.getElementById('checkout-signature').value = ${JSON.stringify('  ' + SIG + ' ')}; true`);
  answer = () => ({ ok: true, checkout: { state: 'pending', order: TEN, message: 'The transaction is not on chain as finalized yet; that takes under a minute. Wait, then check the same signature again. Do not pay again.' } });
  await click('checkout-claim');
  await until(`/finalized yet/.test(document.getElementById('checkout-msg').textContent)`);
  expect('a claim sends the signature, trimmed, and nothing else', JSON.stringify(asked[asked.length - 1]) === JSON.stringify({ action: 'claim', signature: SIG }), JSON.stringify(asked[asked.length - 1]));
  let m = await msg();
  expect('not final yet: says to wait and check the same signature, not to pay again, and keeps the order and the signature',
    /note/.test(m.cls) && /Wait, then check the same signature again/.test(m.text) && /Do not pay again/.test(m.text)
      && (await shown('checkout-amount')) && (await js(`document.getElementById('checkout-signature').value.trim()`)) === SIG, JSON.stringify(m));
  answer = () => ({ ok: true, checkout: { state: 'rejected', order: TEN, message: 'The pass issuer did not take this transaction: it paid another amount than this order\'s. The amount must match exactly, every decimal: a dollar figure, or a rounded amount, does not pay the order. Your order is kept on this computer. Do not pay again before you have checked that transaction in your wallet: the amount, the token and the receiving wallet.' } });
  await click('checkout-claim');
  await until(`/another amount/.test(document.getElementById('checkout-msg').textContent)`);
  m = await msg();
  expect('refused: said as an error, the order and the signature kept, and not to pay again',
    /err/.test(m.cls) && /Do not pay again/.test(m.text) && (await shown('checkout-amount')) && (await js(`document.getElementById('checkout-signature').value.trim()`)) === SIG, JSON.stringify(m));
  answer = () => ({ ok: true, checkout: { state: 'confirmed', credited: 10, balance: 10, message: 'Payment confirmed: 10 passes are on this computer\'s pass account, 10 in all at this moment. Nothing more to pay. Get passes for the nodes now (Get 10 passes per node).' } });
  await click('checkout-claim');
  await until(`/Payment confirmed/.test(document.getElementById('checkout-msg').textContent)`);
  expect('confirmed: the order and the signature are cleared, and the next step said',
    (await js(`document.getElementById('checkout-order').hidden`)) && (await js(`document.getElementById('checkout-signature').value`)) === ''
      && /Get 10 passes per node/.test((await msg()).text), JSON.stringify(await msg()));

  // ── Two hops: nothing asked ──────────────────────────────────────────
  answer = () => ({ ok: true, checkout: { state: 'awaiting_payment', order: TEN, message: 'x' } });
  await click('checkout-load');
  await until(`!document.getElementById('checkout-order').hidden`);
  status = { state: 'connected', report: report(2) };
  await until(`document.querySelector('#checkout-packs button').disabled && document.getElementById('checkout-claim').disabled`, 6000);
  before = asked.length;
  await js(`document.querySelectorAll('#checkout-packs button').forEach(function (b) { b.click(); }); document.getElementById('checkout-claim').click(); true`);
  await new Promise((r) => setTimeout(r, 300));
  expect('connected in privado, the packages and Check payment are off, and nothing is asked',
    asked.length === before && (await js(`document.getElementById('checkout-claim').title`)).indexOf('Not while connected in privado') === 0,
    JSON.stringify(asked.slice(before)));
  status = { state: 'connected', report: report(1) };
  await until(`!document.querySelector('#checkout-packs button').disabled && !document.getElementById('checkout-claim').disabled`, 6000);
  expect('in rapido they are on again', !(await js(`document.getElementById('checkout-claim').disabled`)));

  // ── A service older than checkout ────────────────────────────────────
  status = { state: 'disconnected', report: Object.assign(report(0), { version: '0.1.2' }) };
  answer = () => ({ ok: false, state: 'outdated', older: true, error: 'the HidraVPN service on this machine is older than the browser',
    hint: 'Update HidraVPN: the installed service does not know the commands this page uses.' });
  await js(`document.getElementById('btn-settings-close').click(); true`);
  await click('btn-open-passes');
  await until(`/needs a newer HidraVPN/.test(document.getElementById('checkout-msg').textContent)`);
  await until(`/0\\.1\\.2/.test(document.getElementById('version-line').textContent)`, 6000);
  m = await msg();
  expect('an older service: the page says buying needs a newer HidraVPN, and where to update it',
    /err/.test(m.cls) && /Update HidraVPN: Settings, Service, Check for an update/.test(m.text) && /Nothing was paid/.test(m.text), JSON.stringify(m));
  expect('and offers nothing it cannot do, while the rest of the page still works',
    (await js(`document.getElementById('checkout-load').disabled && document.getElementById('checkout-claim').disabled`))
      && !(await js(`document.getElementById('settings-dot').hidden`)) && /0\.1\.2/.test(await text('version-line')),
    await text('version-line'));

  win.destroy();
  fs.rmSync(dir, { recursive: true, force: true });
  console.log(failures.length ? `\n${failures.length} case(s) wrong` : '\nall cases correct');
  app.exit(failures.length ? 1 : 0);
}).catch((e) => { console.error(e); app.exit(2); });
