// Does the address bar show a hidra:// name instead of the install path?
//
// Navigating to a built-in page used to put
// file:///home/.../resources/app/src/ui/newtab.html in the address bar — the
// browser's own install path, in the one field people read, copy and paste to
// share a page.
//
//   cd hidra-browser && node test/display-url.js

const path = require('path');
const { pathToFileURL } = require('url');
const { TabManager } = require('../src/main/tab-manager');

const UI = pathToFileURL(path.join(__dirname, '..', 'src', 'ui') + path.sep).href;
const APPS = 'http://127.0.0.1:8090';

// _displayUrl touches no instance state, so it can be exercised directly.
const show = TabManager.prototype._displayUrl;

const cases = [
  [`${UI}newtab.html`, 'hidra://newtab', 'the new tab page'],
  [`${UI}hidramail.html`, 'hidra://mail', 'mail, from disk'],
  [`${UI}hidrachat.html`, 'hidra://chat', 'chat, from disk'],
  [`${UI}hidrareview.html`, 'hidra://reviews', 'reviews, from disk'],
  [`${UI}hidramail.html?x=1#y`, 'hidra://mail', 'a query and fragment are dropped'],
  [`${APPS}/mail`, 'hidra://mail', 'mail, from the apps server'],
  [`${APPS}/reviews`, 'hidra://reviews', 'reviews, from the apps server'],
  [`${APPS}/`, 'hidra://chat', 'the apps root is chat'],
  [`${APPS}/search?q=hello`, 'hidra://search', 'a search keeps its name'],
  ['https://example.com/page', 'https://example.com/page', 'an ordinary site is untouched'],
  ['hidra://newtab', 'hidra://newtab', 'an already-internal name is untouched'],
];

let failed = 0;
for (const [input, expected, label] of cases) {
  const actual = show.call(null, input);
  const ok = actual === expected;
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${label}${ok ? '' : `\n        got ${actual}\n        want ${expected}`}`);
}

// Every name the bar shows has to open when typed back in. A browser that
// prints an address you cannot use is worse than one that prints the path.
const { INTERNAL_BY_NAME } = require('../src/main/tab-manager');
const shown = new Set(cases.map(([i]) => show.call(null, i))
  .filter((u) => u.startsWith('hidra://')));
for (const url of shown) {
  const name = url.replace('hidra://', '').split(/[/?#]/)[0];
  const ok = name === 'search' || Boolean(INTERNAL_BY_NAME[name]);
  if (!ok) { failed++; console.log(`FAIL  ${url} is shown but cannot be typed back in`); }
  else console.log(`ok    ${url} round-trips`);
}

// The install path must never reach the address bar.
const leaked = show.call(null, `${UI}newtab.html`).includes(__dirname);
if (leaked) { failed++; console.log('FAIL  the install path leaks into the address bar'); }
else console.log('ok    the install path never reaches the address bar');

console.log(failed ? `\n${failed} case(s) wrong` : '\nall cases correct');
process.exit(failed ? 1 : 0);
