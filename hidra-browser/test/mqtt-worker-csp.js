// Every page that loads the bundled MQTT client needs worker-src blob: in its
// policy. The client runs its keepalive timers in a Worker created from a blob
// URL; without the directive the policy falls back to script-src, the Worker is
// refused, and the rejection takes down the 'connect' handler before it
// subscribes. The page still publishes, so sending looks fine and nothing ever
// arrives — a failure that is invisible from the sending side, which is why it
// is worth a test rather than a comment.
const fs = require('fs');
const path = require('path');

const UI = path.join(__dirname, '..', 'src', 'ui');
let bad = 0;

for (const file of fs.readdirSync(UI).filter((f) => f.endsWith('.html'))) {
  const html = fs.readFileSync(path.join(UI, file), 'utf8');
  if (!html.includes('vendor/mqtt.min.js')) continue;

  const meta = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)"/);
  if (!meta) {
    console.log('FAIL  ' + file + ': loads the MQTT client with no policy at all');
    bad++;
    continue;
  }
  const worker = meta[1].split(';').map((d) => d.trim()).find((d) => d.startsWith('worker-src'));
  if (!worker || !/\bblob:/.test(worker)) {
    console.log('FAIL  ' + file + ': ' + (worker || 'no worker-src') + ' — the blob Worker is refused, so nothing is received');
    bad++;
    continue;
  }
  console.log('ok    ' + file + ': ' + worker);
}

if (bad) { console.log('\n' + bad + ' page(s) would connect and never receive'); process.exit(1); }
console.log('\nevery MQTT page can start its Worker');
