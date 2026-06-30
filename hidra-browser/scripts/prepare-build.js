#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const BUILD = path.join(ROOT, 'build');
const BIN_DIR = path.join(BUILD, 'bin');
const ICONS_DIR = path.join(BUILD, 'icons');
const NODE_ROOT = path.join(ROOT, '..', 'hidra-node');

console.log('=== HidraNet Browser — Build Preparation ===\n');

// ── 1. Create directories ──
for (const dir of [BUILD, BIN_DIR, ICONS_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}

// ── 2. Generate PNG icon from embedded data ──
// 512x512 PNG with HidraNet logo (generated inline, no external deps)
function generateIcon() {
  const iconPath = path.join(BUILD, 'icon.png');
  if (fs.existsSync(iconPath) && fs.statSync(iconPath).size > 1000) {
    console.log('[ok] icon.png already exists');
    return;
  }

  // Create a minimal 256x256 PNG with the H logo
  // Using raw PNG construction (no dependencies)
  const size = 256;
  const channels = 4; // RGBA
  const raw = Buffer.alloc(size * size * channels, 0);

  // Background: dark (#0a0e17)
  for (let i = 0; i < size * size; i++) {
    raw[i * 4] = 10;      // R
    raw[i * 4 + 1] = 14;  // G
    raw[i * 4 + 2] = 23;  // B
    raw[i * 4 + 3] = 255; // A
  }

  const cx = size / 2, cy = size / 2;

  // Draw circles
  function drawCircle(r, cr, cg, cb, alpha) {
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        const dist = Math.sqrt((x - cx) ** 2 + (y - cy) ** 2);
        if (Math.abs(dist - r) < 1.5) {
          const idx = (y * size + x) * 4;
          const blend = alpha / 255;
          raw[idx] = Math.round(raw[idx] * (1 - blend) + cr * blend);
          raw[idx + 1] = Math.round(raw[idx + 1] * (1 - blend) + cg * blend);
          raw[idx + 2] = Math.round(raw[idx + 2] * (1 - blend) + cb * blend);
        }
      }
    }
  }

  // Draw filled circle
  function fillCircle(r, cr, cg, cb, alpha) {
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        const dist = Math.sqrt((x - cx) ** 2 + (y - cy) ** 2);
        if (dist <= r) {
          const idx = (y * size + x) * 4;
          const blend = alpha / 255;
          raw[idx] = Math.round(raw[idx] * (1 - blend) + cr * blend);
          raw[idx + 1] = Math.round(raw[idx + 1] * (1 - blend) + cg * blend);
          raw[idx + 2] = Math.round(raw[idx + 2] * (1 - blend) + cb * blend);
        }
      }
    }
  }

  // Draw letter H
  function drawH() {
    const accent = [0, 212, 170];
    const hLeft = 88, hRight = 168, hTop = 72, hBottom = 184;
    const barTop = 120, barBottom = 136;
    const thickness = 16;

    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        let inH = false;
        // Left vertical
        if (x >= hLeft && x < hLeft + thickness && y >= hTop && y <= hBottom) inH = true;
        // Right vertical
        if (x >= hRight && x < hRight + thickness && y >= hTop && y <= hBottom) inH = true;
        // Horizontal bar
        if (x >= hLeft && x < hRight + thickness && y >= barTop && y <= barBottom) inH = true;

        if (inH) {
          const idx = (y * size + x) * 4;
          raw[idx] = accent[0];
          raw[idx + 1] = accent[1];
          raw[idx + 2] = accent[2];
          raw[idx + 3] = 255;
        }
      }
    }
  }

  // Concentric rings (HidraNet signature)
  fillCircle(110, 0, 212, 170, 12);
  drawCircle(100, 0, 212, 170, 40);
  drawCircle(75, 0, 212, 170, 65);
  drawCircle(50, 0, 212, 170, 100);
  fillCircle(12, 0, 212, 170, 200);

  // H letter on top
  drawH();

  // Encode as PNG (minimal valid PNG)
  const png = encodePNG(raw, size, size);
  fs.writeFileSync(iconPath, png);
  console.log('[ok] icon.png generated (256x256)');

  // Copy to Linux icon sizes
  for (const s of [16, 32, 48, 64, 128, 256, 512]) {
    const dest = path.join(ICONS_DIR, s + 'x' + s + '.png');
    fs.copyFileSync(iconPath, dest);
  }
  console.log('[ok] Linux icon sizes created');
}

function encodePNG(rawRGBA, w, h) {
  const { deflateSync } = require('zlib');

  // PNG signature
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  // IHDR
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // color type: RGBA
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace

  // IDAT: filter each row with filter byte 0 (None)
  const rowLen = w * 4 + 1;
  const filtered = Buffer.alloc(h * rowLen);
  for (let y = 0; y < h; y++) {
    filtered[y * rowLen] = 0; // filter: None
    rawRGBA.copy(filtered, y * rowLen + 1, y * w * 4, (y + 1) * w * 4);
  }
  const compressed = deflateSync(filtered, { level: 6 });

  // Build chunks
  function chunk(type, data) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const typeB = Buffer.from(type, 'ascii');
    const crcData = Buffer.concat([typeB, data]);
    const crc = crc32(crcData);
    const crcB = Buffer.alloc(4);
    crcB.writeUInt32BE(crc >>> 0);
    return Buffer.concat([len, typeB, data, crcB]);
  }

  return Buffer.concat([
    sig,
    chunk('IHDR', ihdr),
    chunk('IDAT', compressed),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

function crc32(buf) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
    }
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

// ── 3. Copy hidra-node binary ──
function copyBinary() {
  const isWin = process.platform === 'win32';
  const binName = isWin ? 'hidra-node.exe' : 'hidra-node';
  const dest = path.join(BIN_DIR, binName);

  const candidates = [
    path.join(NODE_ROOT, 'target', 'release', binName),
    path.join(NODE_ROOT, 'target', 'debug', binName),
  ];

  for (const src of candidates) {
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, dest);
      // Make executable on unix
      if (!isWin) {
        fs.chmodSync(dest, 0o755);
      }
      const mb = (fs.statSync(dest).size / 1024 / 1024).toFixed(1);
      console.log(`[ok] ${binName} copied (${mb} MB) from ${path.basename(path.dirname(src))}`);
      return true;
    }
  }

  console.warn(`[!!] ${binName} NOT FOUND — build hidra-node first:`);
  console.warn('     cd ../hidra-node && cargo build --release');
  console.warn('     The browser will still build, but without the node binary.');

  // Create placeholder so electron-builder doesn't fail
  fs.writeFileSync(dest, '');
  return false;
}

// ── Run ──
generateIcon();
const hasBinary = copyBinary();

console.log('\n=== Preparation complete ===');
if (hasBinary) {
  console.log('Ready to build! Run: npm run build:win');
} else {
  console.log('WARNING: hidra-node binary missing. Build will proceed without it.');
}
