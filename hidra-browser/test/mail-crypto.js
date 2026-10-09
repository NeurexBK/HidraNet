// Can a HidraMail message lie about who sent it?
//
// Until the signing work, yes: the app encrypted to the recipient and stopped
// there. `from` was a string the sender chose, and nothing on the receiving
// side checked it, so anyone who looked up your published key could send you
// mail that arrived as anyone. These cases pin that shut.
//
//   cd hidra-browser && xvfb-run -a npx electron test/mail-crypto.js
//
// The crypto is lifted out of src/ui/hidramail.html at run time rather than
// copied here, so the test cannot drift away from the code it is testing.
// Exits non-zero if any case comes out wrong.

const { app, BrowserWindow } = require('electron');
const fs = require('fs');
const os = require('os');
const path = require('path');

const PAGE = path.join(__dirname, '..', 'src', 'ui', 'hidramail.html');

function cryptoSectionOf(html) {
  const script = /<script>([\s\S]*?)<\/script>/.exec(html);
  if (!script) throw new Error('no script block in hidramail.html');
  const body = script[1];
  const from = body.indexOf('// ───────── crypto ─────────');
  const to = body.indexOf('// ───────── storage ─────────');
  if (from < 0 || to < 0) throw new Error('crypto section markers moved');
  return body.slice(from, to);
}

const CASES = `
  var a = await genId(), b = await genId(), evil = await genId(), c = await genId();

  var payload = { v:MAIL_VERSION, mid:'m1', from:a.addr, to:b.addr,
                  subject:'hello', body:'secret body', date:1700000000000,
                  sp:a.pubRaw, ss:a.sigPubRaw };
  payload.sig = await signMail(a, payload);
  var ct = await encryptTo(b64d(b.pubRaw), JSON.stringify(payload));
  var got = JSON.parse(await decryptFor(b, ct));

  say(got.body === 'secret body', 'a genuine message decrypts');
  say(await verifyMail(got) === a.addr, 'a genuine message proves its sender');

  // The attack the old version could not see: write someone else's address
  // into from, sign with your own key.
  var forged = { v:MAIL_VERSION, mid:'m2', from:a.addr, to:b.addr,
                 subject:'urgent: send funds', body:'to this address',
                 date:Date.now(), sp:evil.pubRaw, ss:evil.sigPubRaw };
  forged.sig = await signMail(evil, forged);
  say(await verifyMail(forged) === null, 'a forged From is rejected');

  // Copy the real sender's published keys in. Still cannot produce the signature.
  var stolen = { v:MAIL_VERSION, mid:'m3', from:a.addr, to:b.addr,
                 subject:'x', body:'y', date:Date.now(),
                 sp:a.pubRaw, ss:a.sigPubRaw };
  stolen.sig = await signMail(evil, stolen);
  say(await verifyMail(stolen) === null, 'a signature from the wrong key is rejected');

  var tampered = JSON.parse(JSON.stringify(got));
  tampered.body = 'send it to me instead';
  say(await verifyMail(tampered) === null, 'an edited body breaks the signature');

  var replay = JSON.parse(JSON.stringify(got));
  replay.to = c.addr;
  say(await verifyMail(replay) === null, 'retargeting to another mailbox breaks it');

  var threw = false;
  try { await decryptFor(b, ct.slice(0, ct.length - 6) + 'AAAAAA'); } catch (e) { threw = true; }
  say(threw, 'a tampered ciphertext does not decrypt');

  // The ephemeral key is authenticated, not merely prepended.
  var raw = b64d(ct); raw[5] ^= 1;
  var threw2 = false;
  try { await decryptFor(b, b64e(raw)); } catch (e) { threw2 = true; }
  say(threw2, 'a swapped ephemeral key does not decrypt');

  say(await addrFrom(b64d(a.pubRaw), b64d(a.sigPubRaw)) === a.addr,
      'the address is reproduced from the two published keys');
  say(await addrFrom(b64d(a.pubRaw), b64d(evil.sigPubRaw)) !== a.addr,
      'substituting the signing key changes the address');

  var threw3 = false;
  try { await decryptFor(c, ct); } catch (e) { threw3 = true; }
  say(threw3, 'a third party cannot decrypt it');
`;

app.on('window-all-closed', () => {});

app.whenReady().then(async () => {
  const page = `<!doctype html><html><head><meta charset="utf-8"></head><body><pre id="out"></pre>
<script>
var subtle = crypto.subtle, te = new TextEncoder(), td = new TextDecoder(), log = [];
function say(ok, msg){ log.push((ok ? 'ok    ' : 'FAIL  ') + msg); }
</script>
<script>${cryptoSectionOf(fs.readFileSync(PAGE, 'utf8'))}</script>
<script>
(async function(){
  try { ${CASES} } catch (e) { say(false, 'harness error: ' + e.message); }
  document.getElementById('out').textContent = log.join('\\n');
  document.title = log.some(function(l){ return l.indexOf('FAIL') === 0; }) ? 'FAILED' : 'PASSED';
})();
</script></body></html>`;

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-mail-'));
  const file = path.join(tmp, 'cases.html');
  fs.writeFileSync(file, page);

  const w = new BrowserWindow({ show: false, webPreferences: { contextIsolation: true, sandbox: true } });
  await w.loadFile(file);
  const title = await w.webContents.executeJavaScript(
    'new Promise(function(r){ var t = setInterval(function(){' +
    ' if (document.title === "PASSED" || document.title === "FAILED") { clearInterval(t); r(document.title); } }, 100);' +
    ' setTimeout(function(){ r("TIMEOUT"); }, 30000); })'
  );
  console.log(await w.webContents.executeJavaScript('document.getElementById("out").textContent'));
  console.log('\n=> ' + title);

  fs.rmSync(tmp, { recursive: true, force: true });
  app.exit(title === 'PASSED' ? 0 : 1);
});
