// A query and a result must stay text, every character of them.
//
// Any website can open HidraSearch with ?q= of its choosing, and the page
// searches for it as it loads. When nothing was found, each suggestion was
// built with the query pasted into onclick="doSearch(...)": JSON.stringify
// escapes for a script string, not for an attribute, so a quote in the query
// ended the attribute and the rest of it became markup, and a handler in that
// markup ran in the search page, with no click. Results come from search
// engines, and from whoever runs a public SearXNG, so they are no safer.
//
// This serves the real page the way the browser does, with the search API on
// the same origin, opens it with hostile queries, answers with no results,
// hostile results and an error, presses every suggestion, and checks that
// nothing ran, that only the page's own elements are there, and that the
// suggestions still search for what they say.
//
//   cd hidra-browser && xvfb-run -a npx electron test/search-injection.js

const { app, BrowserWindow } = require('electron');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const PAGE = fs.readFileSync(path.join(__dirname, '..', 'src', 'ui', 'hidrasearch.html'));

const PWN = 'window.__pwned=(window.__pwned||0)+1';
const QUERIES = [
  `z"><img src=x onerror="${PWN}"> qx7`,
  `z",1);${PWN};doSearch("z qx7`,
  `z' onmouseover='${PWN}' qx7`,
  `</span><svg onload=${PWN}> qx7`,
  `&quot;><img src=x onerror=${PWN}> qx7`,
];
const HOSTILE = `<img src=x onerror="${PWN}">"'><b>x</b>`;
const RESULTS = [
  { title: HOSTILE, url: `javascript:${PWN}`, snippet: HOSTILE, engine: HOSTILE },
  { title: HOSTILE, url: `https://example.org/a"onmouseover="${PWN}`, snippet: HOSTILE, engine: HOSTILE },
  { title: 'Example', url: 'https://example.com/page', snippet: 'An ordinary result', engine: 'duckduckgo' },
];

let passed = 0;
let failed = 0;
const check = (name, cond, why) => {
  if (cond) { passed++; console.log('ok    ' + name); }
  else { failed++; console.log('FAIL  ' + name + (why ? '\n      ' + why : '')); }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// What the browser's local server answers for the search app, with the
// answer to a search chosen by the test.
let answer = 'empty';
const asked = [];
const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname === '/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(PAGE);
  }
  if (u.pathname === '/prefs') {
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ theme: 'teal', searchLang: 'all' }));
  }
  if (u.pathname === '/search/api') {
    asked.push(u.searchParams.get('q'));
    if (answer === 'error') { res.writeHead(502); return res.end(); }
    const results = answer === 'hostile' ? RESULTS : [];
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ results, total: results.length, query: u.searchParams.get('q'), elapsed_ms: 12 }));
  }
  res.writeHead(404);
  res.end();
});

app.setPath('userData', fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-search-inj-')));
app.on('window-all-closed', () => {});

app.whenReady().then(async () => {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}/`;
  const win = new BrowserWindow({
    show: false,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  const run = (js) => win.webContents.executeJavaScript(js);
  const settle = async () => {
    for (let i = 0; i < 50 && (await run('isLoading || !document.getElementById("resultsList").childElementCount')); i++) await sleep(50);
    // Long enough for a planted <img src=x> to fail and fire its handler.
    await sleep(300);
  };
  // Every element under the results is one the page makes, with no
  // attribute but its own, and every link goes to a web address.
  const SHAPE = `(() => {
    const ok = { DIV: ['class', 'style'], H3: [], P: [], BR: [], SPAN: ['class', 'style'], STRONG: [], A: ['class', 'href', 'style'] };
    const bad = [];
    document.querySelectorAll('#resultsMeta *, #resultsList *').forEach((e) => {
      const allowed = ok[e.tagName];
      if (!allowed) { bad.push('<' + e.tagName + '>'); return; }
      for (const a of e.attributes) if (!allowed.includes(a.name)) bad.push(e.tagName + ' ' + a.name + '=' + a.value);
      if (e.tagName === 'A' && !/^(https?:\\/\\/[^\\s"<>]+|#)$/.test(e.getAttribute('href'))) bad.push('href=' + e.getAttribute('href'));
    });
    return bad;
  })()`;

  // Opened from a link, as another website would, with nothing found.
  for (const q of QUERIES) {
    answer = 'empty';
    await win.loadURL(base + '?q=' + encodeURIComponent(q));
    await settle();
    const seen = await run(`({
      pwned: window.__pwned || 0,
      bad: ${SHAPE},
      inline: document.querySelectorAll('[onclick], [onerror], [onload], [onmouseover]').length,
      strong: (document.querySelector('#resultsMeta strong') || {}).textContent,
      tags: [...document.querySelectorAll('#resultsList .tag')].map((t) => t.textContent),
      want: suggestionsFor(${JSON.stringify(q)}),
    })`);
    check(`no script ran: ${q}`, seen.pwned === 0, `window.__pwned = ${seen.pwned}`);
    check(`only the page's own elements: ${q}`, seen.bad.length === 0 && seen.inline === 0,
      seen.bad.concat(seen.inline ? [`${seen.inline} inline handlers`] : []).join(' | '));
    check(`the query and the suggestions are shown as written: ${q}`,
      seen.strong === q && JSON.stringify(seen.tags) === JSON.stringify(seen.want), JSON.stringify(seen));

    // Press every suggestion, each on a fresh page: each searches for what
    // it says.
    const pressed = [];
    let pwned = 0;
    for (let i = 0; i < seen.want.length; i++) {
      await win.loadURL(base + '?q=' + encodeURIComponent(q));
      await settle();
      asked.length = 0;
      await run(`document.querySelectorAll('#resultsList .tag')[${i}].click(); 1`);
      await settle();
      pressed.push(asked[0]);
      pwned += await run('window.__pwned || 0');
    }
    check(`each suggestion searches for its own text: ${q}`,
      JSON.stringify(pressed) === JSON.stringify(seen.want) && pwned === 0, JSON.stringify(pressed));
  }

  // Hostile results.
  answer = 'hostile';
  await win.loadURL(base + '?q=' + encodeURIComponent('ordinary words'));
  await settle();
  const res = await run(`({
    pwned: window.__pwned || 0,
    bad: ${SHAPE},
    titles: [...document.querySelectorAll('.result-title')].map((a) => [a.textContent, a.getAttribute('href')]),
    snippets: [...document.querySelectorAll('.result-snippet')].map((s) => s.textContent),
    engines: [...document.querySelectorAll('.result-engine')].map((s) => s.textContent),
    meta: document.getElementById('resultsMeta').textContent,
  })`);
  check('no script from a result ran', res.pwned === 0, `window.__pwned = ${res.pwned}`);
  check('a result brings no element or attribute of its own', res.bad.length === 0, res.bad.join(' | '));
  check('a result that is not a web address links nowhere', res.titles[0] && res.titles[0][1] === '#', JSON.stringify(res.titles));
  check('a result\'s title, snippet and engine are shown as text',
    res.titles[1] && res.titles[1][0] === HOSTILE && res.snippets[0] === HOSTILE && res.engines[0] === HOSTILE, JSON.stringify(res));
  check('an ordinary result still shows, with its link',
    res.titles[2] && res.titles[2][0] === 'Example' && res.titles[2][1] === 'https://example.com/page'
    && res.snippets.includes('An ordinary result') && /^3 results in 12ms/.test(res.meta), JSON.stringify(res));

  // The search failed: the other engines are offered, with the query encoded.
  answer = 'error';
  const q = QUERIES[0];
  await win.loadURL(base + '?q=' + encodeURIComponent(q));
  await settle();
  const err = await run(`({
    pwned: window.__pwned || 0,
    bad: ${SHAPE},
    links: [...document.querySelectorAll('#resultsList a')].map((a) => a.getAttribute('href')),
  })`);
  check('no script ran when the search failed', err.pwned === 0, `window.__pwned = ${err.pwned}`);
  check('only the page\'s own elements when the search failed', err.bad.length === 0, err.bad.join(' | '));
  check('the other engines are offered the query as written',
    err.links.length === 3 && err.links[0] === 'https://duckduckgo.com/?q=' + encodeURIComponent(q), JSON.stringify(err.links));

  win.destroy();
  server.close();
  console.log(`\n${passed} passed, ${failed} failed`);
  app.exit(failed ? 1 : 0);
}).catch((e) => { console.error(e); app.exit(2); });
