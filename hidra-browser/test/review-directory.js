// Does the directory let someone judge a .hidra site before opening it?
//
// HidraReview started as a directory of restaurants and shops. It is now
// mostly for the sites and forums people build inside HidraNet, where the
// address is 26 random characters and tells you nothing about what is behind
// it — so the stars and the review count have to be on the card, before the
// click, and a bad or unreviewed site has to say so.
//
//   cd hidra-browser && xvfb-run -a npx electron test/review-directory.js
//
// Exits non-zero if any case comes out wrong.

const { app, BrowserWindow } = require('electron');
const path = require('path');
const { pathToFileURL } = require('url');

const UI = path.join(__dirname, '..', 'src', 'ui');
const PRELOAD = path.join(__dirname, '..', 'src', 'renderer', 'tab-preload.js');

const out = [];
const say = (ok, msg) => out.push((ok ? 'ok    ' : 'FAIL  ') + msg);

// A real sitepub address: 16 random bytes, base32, 26 characters.
const MAKE_ADDR = `(function(){
  function b32(b){var A='abcdefghijklmnopqrstuvwxyz234567',o='',bits=0,v=0;
    for(var i=0;i<b.length;i++){v=(v<<8)|b[i];bits+=8;
    while(bits>=5){o+=A[(v>>>(bits-5))&31];bits-=5;}}if(bits>0)o+=A[(v<<(5-bits))&31];return o;}
  return b32(crypto.getRandomValues(new Uint8Array(16))) + '.hidra';
})()`;

app.on('window-all-closed', () => {});

app.whenReady().then(async () => {
  const problems = [];
  const win = new BrowserWindow({
    show: false,
    width: 1280,
    height: 1000,
    webPreferences: {
      preload: PRELOAD,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      additionalArguments: [`--hidra-ui-root=${pathToFileURL(UI + path.sep).href}`],
    },
  });
  win.webContents.on('console-message', (_e, level, message) => {
    if (/Content Security Policy|Refused to/i.test(message)) problems.push('CSP: ' + message.slice(0, 140));
    else if (level >= 3) problems.push('ERR: ' + message.slice(0, 140));
  });
  await win.loadFile(path.join(UI, 'hidrareview.html'));
  await new Promise((r) => setTimeout(r, 1500));
  const js = (code) => win.webContents.executeJavaScript(code);

  // ── the address validator ────────────────────────────────────────────
  const addr = await js(`(function(){
    var real = ${MAKE_ADDR};
    return {
      'a real sitepub address is accepted': normHidra(real) === real,
      'the .hidra suffix is optional': normHidra(real.replace('.hidra','')) === real,
      'a hidra:// scheme is stripped': normHidra('hidra://' + real) === real,
      'a path after the address is stripped': normHidra('hidra://' + real + '/thread/4') === real,
      'case does not matter': normHidra(real.toUpperCase()) === real,
      'a label the browser cannot resolve is refused': normHidra('abc.hidra') === '',
      'characters outside base32 are refused': normHidra('abcdefghijklmnopqrstuvwxyz01789.hidra') === '',
      'empty input is refused': normHidra('') === '',
      'prose is refused': normHidra('not an address') === '',
      'the open link points at the site route': hidraUrl(real).indexOf('127.0.0.1:8090/site?addr=') > 0,
      'a legacy record with a city reads as a place': kindOf({ city: 'Lisboa' }) === 'place',
      'a record with an address reads as a site': kindOf({ hidra: real }) === 'site',
      'an explicit kind wins over the guess': kindOf({ kind: 'site', city: 'x' }) === 'site'
    };
  })()`);
  for (const [name, ok] of Object.entries(addr)) say(ok, name);

  // ── the form follows what is being listed ────────────────────────────
  await js('showList(true)');
  await new Promise((r) => setTimeout(r, 300));
  const siteForm = await js(`({
    hidraShown: getComputedStyle(document.querySelector('.only-site')).display !== 'none',
    cityShown: getComputedStyle(document.querySelector('.only-place')).display !== 'none',
    firstCat: document.getElementById('n-cat').options[0].text
  })`);
  say(siteForm.hidraShown, 'listing a site asks for the .hidra address');
  say(!siteForm.cityShown, 'listing a site does not ask for a city or a street');
  say(siteForm.firstCat === 'Forum', 'listing a site offers site categories');

  await js("setKind('place')");
  await new Promise((r) => setTimeout(r, 200));
  const placeForm = await js(`({
    hidraShown: getComputedStyle(document.querySelector('.only-site')).display !== 'none',
    cityShown: getComputedStyle(document.querySelector('.only-place')).display !== 'none',
    firstCat: document.getElementById('n-cat').options[0].text
  })`);
  say(!placeForm.hidraShown, 'listing a place does not ask for a .hidra address');
  say(placeForm.cityShown, 'listing a place asks for a city');
  say(placeForm.firstCat === 'Restaurant', 'listing a place offers place categories');

  // ── the directory, with listings that arrived from the network ───────
  const cards = await js(`(function(){
    state.biz['good'] = { name:'The Lantern Board', kind:'site', hidra:${MAKE_ADDR},
      cat:'Forum', desc:'Slow board, long posts', at: Date.now() };
    state.biz['bad'] = { name:'Fast Exit', kind:'site', hidra:${MAKE_ADDR},
      cat:'Marketplace', desc:'Sells things', at: Date.now() };
    state.biz['unrated'] = { name:'Quiet Wiki', kind:'site', hidra:${MAKE_ADDR},
      cat:'Wiki', desc:'Nobody has been here', at: Date.now() };
    state.biz['cafe'] = { name:'Corner Cafe', cat:'Cafe', city:'Lisboa',
      desc:'Pastries', at: Date.now() };
    // state.revs is flat, keyed by review id, each carrying its _slug.
    state.revs['r1'] = { _slug:'good', stars:5, txt:'Worth reading', at:Date.now() };
    state.revs['r2'] = { _slug:'good', stars:4, txt:'Good', at:Date.now() };
    state.revs['r3'] = { _slug:'bad', stars:1, txt:'Scam', at:Date.now() };
    state.revs['r4'] = { _slug:'bad', stars:2, txt:'Avoid', at:Date.now() };
    state.sort = 'best';
    showList(false);
    return [].map.call(document.querySelectorAll('.biz'), function (el) {
      return { slug: el.getAttribute('data-slug'), text: el.textContent };
    });
  })()`);
  const card = (slug) => cards.find((c) => c.slug === slug);
  say(cards.length === 4, 'every listing renders');
  say(/4\.5/.test(card('good').text), 'the rating is on the card, before any click');
  say(/\.hidra/.test(card('good').text), 'the address is on the card');
  say(/no reviews yet/.test(card('unrated').text), 'an unrated site says so on the card');
  say(/place/.test(card('cafe').text), 'a legacy record is tagged as a place');
  say(cards[0].slug === 'good', 'top rated puts the well-reviewed site first');

  // ── filtering ────────────────────────────────────────────────────────
  const sites = await js(`(function(){ document.getElementById('f-kind').value='site'; render();
    return [].map.call(document.querySelectorAll('.biz'), function(e){ return e.getAttribute('data-slug'); }); })()`);
  say(sites.length === 3 && !sites.includes('cafe'), 'the .hidra filter drops places');
  const places = await js(`(function(){ document.getElementById('f-kind').value='place'; render();
    return [].map.call(document.querySelectorAll('.biz'), function(e){ return e.getAttribute('data-slug'); }); })()`);
  say(places.length === 1 && places[0] === 'cafe', 'the places filter keeps only places');
  await js("document.getElementById('f-kind').value=''; render();");

  // ── the decision, on the page itself ─────────────────────────────────
  const good = await js(`(function(){ openBiz('good'); return {
    visit: document.getElementById('b-visit').innerHTML,
    caution: document.getElementById('b-caution').textContent,
    owner: document.getElementById('b-addr-box').textContent }; })()`);
  say(/site\?addr=/.test(good.visit), 'a site offers an Open button pointing at the site route');
  say(good.caution.trim() === '', 'a well-reviewed site shows no warning');
  say(/share outside HidraNet/.test(good.owner), 'the owner block speaks to a site owner');

  const bad = await js("(function(){ openBiz('bad'); return document.getElementById('b-caution').textContent; })()");
  say(/1\.5 out of 5/.test(bad), 'a badly-reviewed site warns before you open it');

  const unrated = await js("(function(){ openBiz('unrated'); return document.getElementById('b-caution').textContent; })()");
  say(/Nobody has reviewed/.test(unrated), 'an unreviewed site says nothing has been checked');

  const place = await js(`(function(){ openBiz('cafe'); return {
    visit: document.getElementById('b-visit').innerHTML,
    acts: document.getElementById('b-acts').innerHTML,
    owner: document.getElementById('b-addr-box').textContent }; })()`);
  say(place.visit === '', 'a place offers no .hidra Open button');
  say(/openstreetmap/.test(place.acts), 'a place still offers directions');
  say(/NFC card/.test(place.owner), 'the owner block still speaks to a place owner');

  say(problems.length === 0, 'no console errors and no CSP violations' +
    (problems.length ? ' (' + problems[0] + ')' : ''));

  console.log(out.join('\n'));
  const failed = out.filter((l) => l.startsWith('FAIL')).length;
  console.log(failed ? `\n${failed} case(s) wrong` : '\nall cases correct');
  app.exit(failed ? 1 : 0);
});
