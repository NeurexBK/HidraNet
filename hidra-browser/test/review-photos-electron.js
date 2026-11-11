// Adds photos to a HidraReview listing through the real form, under main.js's
// own Chromium switches (no canvas readback, lib/main-switches.js): each is
// taken or refused, never left waiting, and goes out without the metadata a
// camera writes into it. MQTT is a stand-in, so nothing reaches a broker.
//
//   cd hidra-browser && xvfb-run -a ./node_modules/.bin/electron --no-sandbox test/review-photos-electron.js
//
// Exits non-zero if any case comes out wrong.

const { app, BrowserWindow, nativeImage } = require('electron');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { pathToFileURL } = require('url');
const { mainSwitches } = require('./lib/main-switches');

const ROOT = path.join(__dirname, '..');
const switches = mainSwitches();
for (const [name, value] of switches) {
  if (value === undefined) app.commandLine.appendSwitch(name);
  else app.commandLine.appendSwitch(name, value);
}

const STUB = `window.mqtt = { connect: function () {
  var c = { connected: false, on: function () { return c; }, subscribe: function () {}, unsubscribe: function () {},
    publish: function () {}, end: function () {} };
  return c; } };`;
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hidra-photos-'));
fs.cpSync(path.join(ROOT, 'src', 'ui'), dir, { recursive: true });
fs.writeFileSync(path.join(dir, 'vendor', 'mqtt.min.js'), STUB);

// An RGB PNG whose pixels come from `pixels` (w * h * 3 bytes).
function png(w, h, pixels) {
  const raw = Buffer.alloc((w * 3 + 1) * h);
  for (let y = 0; y < h; y++) pixels.copy(raw, y * (w * 3 + 1) + 1, y * w * 3, (y + 1) * w * 3);
  const chunk = (type, data) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
    const body = Buffer.concat([Buffer.from(type), data]);
    const crc = Buffer.alloc(4); crc.writeUInt32BE(zlib.crc32(body));
    return Buffer.concat([len, body, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 2;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}
const SMALL = png(8, 8, Buffer.alloc(8 * 8 * 3, 0x7f));
// A JPEG segment: marker, length, payload.
const segment = (marker, payload) => {
  const head = Buffer.from([0xff, marker, 0, 0]);
  head.writeUInt16BE(payload.length + 2, 2);
  return Buffer.concat([head, Buffer.from(payload)]);
};
// A PNG chunk with a CRC nothing checks here.
const pngChunk = (type, data) => {
  const body = Buffer.from(data, 'latin1');
  const len = Buffer.alloc(4); len.writeUInt32BE(body.length);
  return Buffer.concat([len, Buffer.from(type), body, Buffer.alloc(4)]);
};
const LARGE = png(240, 240, crypto.randomBytes(240 * 240 * 3));   // noise does not compress

const failures = [];
const expect = (name, ok, detail) => {
  console.log((ok ? 'ok    ' : 'FAIL  ') + name + (ok || !detail ? '' : '\n      ' + detail));
  if (!ok) failures.push(name);
};

app.on('window-all-closed', () => {});
setTimeout(() => { console.log('FAIL  the page did not answer within 60 seconds'); app.exit(1); }, 60000).unref();

app.whenReady().then(async () => {
  expect('main.js\'s switches are applied', switches.length > 0 && switches.some(([n]) => n === 'host-resolver-rules'), JSON.stringify(switches));

  const win = new BrowserWindow({
    show: false,
    webPreferences: {
      preload: path.join(ROOT, 'src', 'renderer', 'tab-preload.js'),
      contextIsolation: true, nodeIntegration: false, sandbox: true,
      additionalArguments: [`--hidra-ui-root=${pathToFileURL(dir + path.sep).href}`],
    },
  });
  await win.loadFile(path.join(dir, 'hidrareview.html'));
  const js = (code) => win.webContents.executeJavaScript(code);

  // Adds one file through the form and waits for the form to say how it went.
  const add = (bytes, name, type) => js(`(async () => {
    const b = Uint8Array.from(atob(${JSON.stringify(bytes.toString('base64'))}), (c) => c.charCodeAt(0));
    const dt = new DataTransfer();
    dt.items.add(new File([b], ${JSON.stringify(name)}, { type: ${JSON.stringify(type)} }));
    const input = document.getElementById('n-files');
    const msg = document.getElementById('n-msg');
    const before = state.draft.length;
    msg.className = '';
    input.files = dt.files;
    input.dispatchEvent(new Event('change'));
    for (let i = 0; i < 50 && (msg.className === '' || msg.className === 'msg work'); i++) {
      await new Promise((r) => setTimeout(r, 100));
    }
    return { added: state.draft.length - before, cls: msg.className, text: msg.textContent,
             thumbs: document.querySelectorAll('#n-thumbs img').length,
             pic: state.draft.length > before && PIC_RE.test(state.draft[state.draft.length - 1]) };
  })()`);

  const small = await add(SMALL, 'small.png', 'image/png');
  expect('a small image is added as it is', small.added === 1 && small.pic && small.thumbs === 1 && small.cls !== 'msg work', JSON.stringify(small));

  const large = await add(LARGE, 'large.png', 'image/png');
  expect('an image over the limit is refused, with its size and the limit', large.added === 0 && large.cls === 'msg err' &&
    /large\.png: \d+ KB is too large; the limit is 124 KB/.test(large.text), JSON.stringify(large));

  const fake = await add(Buffer.from('not an image at all'), 'notes.png', 'image/png');
  expect('a file that is not an image is refused', fake.added === 0 && fake.cls === 'msg err' && /not a valid image/.test(fake.text), JSON.stringify(fake));

  const heic = await add(Buffer.from('ftypheic'), 'photo.heic', 'image/heic');
  expect('a format the listing cannot carry is refused by name', heic.added === 0 && heic.cls === 'msg err' && /JPEG or PNG/.test(heic.text), JSON.stringify(heic));

  // What the last photo added publishes, as bytes.
  const lastPhoto = async () => Buffer.from((await js('state.draft[state.draft.length - 1]')).split(',')[1], 'base64');
  const SECRETS = ['GPSLatitude 52.37N', 'taken at home', 'ICC_PROFILE', 'MotionPhoto', 'SECRET'];
  // Exif, little-endian: orientation 6 (turn right) and a GPS pointer, then text.
  const exif = Buffer.concat([Buffer.from('Exif\0\0II'), Buffer.from([0x2a, 0, 8, 0, 0, 0, 2, 0,
    0x12, 0x01, 3, 0, 1, 0, 0, 0, 6, 0, 0, 0, 0x25, 0x88, 4, 0, 1, 0, 0, 0, 0x26, 0, 0, 0, 0, 0, 0, 0]),
  Buffer.from('GPSLatitude 52.37N')]);
  const ORIENTED = Buffer.from([0xff, 0xe1, 0, 34, 0x45, 0x78, 0x69, 0x66, 0, 0, 0x4d, 0x4d, 0, 0x2a, 0, 0, 0, 8,
    0, 1, 0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, 6, 0, 0, 0, 0, 0, 0]);
  const leaks = (b) => SECRETS.filter((x) => b.includes(Buffer.from(x)));

  const camera = nativeImage.createFromBuffer(SMALL).toJPEG(90);
  const tagged = Buffer.concat([camera.subarray(0, 2),
    segment(0xe1, exif),
    segment(0xe2, Buffer.from('ICC_PROFILE\0')), segment(0xfe, Buffer.from('taken at home')),
    camera.subarray(2), Buffer.from('MotionPhoto video follows')]);
  const jpeg = await add(tagged, 'camera.jpg', 'image/jpeg');
  const jpegOut = jpeg.added === 1 ? await lastPhoto() : Buffer.alloc(0);
  expect('a JPEG goes out with its orientation and without its Exif, profile, comment or what follows the image',
    jpeg.added === 1 && jpeg.pic && jpegOut.length > 0 && leaks(jpegOut).length === 0 && jpegOut.includes(ORIENTED) &&
    jpegOut.subarray(-2).equals(Buffer.from([0xff, 0xd9])), JSON.stringify({ jpeg, leaks: leaks(jpegOut) }));

  const textPng = Buffer.concat([SMALL.subarray(0, 33), pngChunk('tEXt', 'Comment\0taken at home'),
    pngChunk('eXIf', 'GPSLatitude 52.37N'), pngChunk('tIME', '\x07\xea\x0b\x01\x0c\x00\x00'),
    SMALL.subarray(33), Buffer.from('MotionPhoto')]);
  const pngAdd = await add(textPng, 'screen.png', 'image/png');
  expect('a PNG goes out as its image chunks alone', pngAdd.added === 1 && (await lastPhoto()).equals(SMALL), JSON.stringify(pngAdd));

  const misnamed = await add(textPng, 'saved.jpg', 'image/jpeg');
  expect('a PNG named .jpg is read as the PNG it is', misnamed.added === 1 && (await lastPhoto()).equals(SMALL) &&
    (await js('state.draft[state.draft.length - 1].startsWith("data:image/png;")')), JSON.stringify(misnamed));

  // The scan is copied whole: stuffed bytes and restarts, with or without fill
  // bytes before them, are not markers, and a second scan after new tables is
  // kept too.
  const SOI = [0xff, 0xd8], EOI = [0xff, 0xd9];
  const scan = [0x12, 0xff, 0x00, 0x34, 0xff, 0xd3, 0x56, 0xff, 0xff, 0xd4, 0x78];
  const sos = segment(0xda, [1, 1, 0, 0, 63, 0]), dht = segment(0xc4, [0, 1, 2, 3]);
  const parts = [segment(0xdb, [0, 1, 2]), segment(0xc0, [8, 0, 1, 0, 1, 1, 1, 0x11, 0]), dht, sos, Buffer.from(scan), dht, sos, Buffer.from(scan)];
  const adobe = Buffer.concat([Buffer.from('Adobe'), Buffer.from([0, 100, 0, 0, 0, 0, 1])]);
  const synthetic = Buffer.concat([Buffer.from(SOI), segment(0xe0, Buffer.from('JFIF\0')), segment(0xe1, exif),
    segment(0xee, Buffer.concat([adobe, Buffer.from('SECRET')])), ...parts, Buffer.from(EOI), Buffer.from('tail')]);
  const want = Buffer.concat([Buffer.from(SOI), ORIENTED, segment(0xee, adobe), ...parts, Buffer.from(EOI)]);
  const got = Buffer.from(await js(`Array.from(cleanJpeg(new Uint8Array(${JSON.stringify([...synthetic])})))`));
  expect('the JPEG cleaner keeps every scan byte, the orientation and the Adobe colour bytes, and nothing else', got.equals(want), got.toString('hex'));

  const cut = await add(camera.subarray(0, camera.length - 2), 'cut.jpg', 'image/jpeg');
  expect('a JPEG that never ends is refused', cut.added === 0 && cut.cls === 'msg err' && /not a valid image/.test(cut.text), JSON.stringify(cut));

  win.destroy();
  fs.rmSync(dir, { recursive: true, force: true });
  console.log(failures.length ? `\n${failures.length} case(s) wrong` : '\nall cases correct');
  app.exit(failures.length ? 1 : 0);
}).catch((e) => { console.error(e); app.exit(2); });
