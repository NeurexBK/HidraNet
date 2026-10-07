'use strict';
/**
 * Minimal ZIP reader/writer shared by the packaging scripts.
 *
 * Entries keep their raw (still-compressed) bytes, their Unix mode in
 * `extAttr` and their `versionMadeBy`, so an entry read from one archive and
 * written to another comes out byte-identical — permissions, symlinks and all.
 * That is what lets a release package be patched in place without unpacking
 * it: anything not replaced is copied through untouched.
 *
 * No ZIP64: sizes and offsets are 32-bit, so an archive must stay under 4 GB.
 */
const { deflateRawSync } = require('zlib');

// ── CRC-32 ───────────────────────────────────────────────────────────────────
const CRC_TBL = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[i] = c;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) c = CRC_TBL[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

// ── ZIP Reader ────────────────────────────────────────────────────────────────
function readZip(buf) {
  // find End-of-Central-Directory record
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65558); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('EOCD not found — not a valid ZIP');

  const cdCount  = buf.readUInt16LE(eocd + 10);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  const entries  = [];
  let pos = cdOffset;

  for (let i = 0; i < cdCount; i++) {
    if (buf.readUInt32LE(pos) !== 0x02014b50) throw new Error('Bad CD signature at ' + pos);
    const versionMadeBy = buf.readUInt16LE(pos + 4);
    const method        = buf.readUInt16LE(pos + 10);
    const crc           = buf.readUInt32LE(pos + 16);
    const compSz        = buf.readUInt32LE(pos + 20);
    const uncompSz      = buf.readUInt32LE(pos + 24);
    const fnLen         = buf.readUInt16LE(pos + 28);
    const exLen         = buf.readUInt16LE(pos + 30);
    const cmLen         = buf.readUInt16LE(pos + 32);
    const extAttr       = buf.readUInt32LE(pos + 38);
    const lhOffset      = buf.readUInt32LE(pos + 42);
    const filename      = buf.slice(pos + 46, pos + 46 + fnLen).toString('utf8');

    // read compressed data from local header (use local header's own field lengths)
    const lhFnLen  = buf.readUInt16LE(lhOffset + 26);
    const lhExLen  = buf.readUInt16LE(lhOffset + 28);
    const dataStart = lhOffset + 30 + lhFnLen + lhExLen;
    const rawData  = Buffer.from(buf.slice(dataStart, dataStart + compSz));

    entries.push({ filename, method, crc, compSz, uncompSz, extAttr, versionMadeBy, rawData });
    pos += 46 + fnLen + exLen + cmLen;
  }
  return entries;
}

// ── ZIP Writer ────────────────────────────────────────────────────────────────
function writeZip(entries) {
  const lhParts = [];
  const cdParts = [];
  let offset = 0;

  for (const e of entries) {
    const nameBuf = Buffer.from(e.filename, 'utf8');

    // local file header
    const lh = Buffer.alloc(30 + nameBuf.length);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0, 6);
    lh.writeUInt16LE(e.method, 8);
    lh.writeUInt32LE(0, 10);       // mod time/date (zero)
    lh.writeUInt32LE(e.crc, 14);
    lh.writeUInt32LE(e.compSz, 18);
    lh.writeUInt32LE(e.uncompSz, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);
    nameBuf.copy(lh, 30);

    // central directory entry
    // versionMadeBy upper byte = 3 (Unix) → macOS unzip respects extAttr as Unix st_mode
    const cd = Buffer.alloc(46 + nameBuf.length);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(e.versionMadeBy || 0x0314, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(0, 8);
    cd.writeUInt16LE(e.method, 10);
    cd.writeUInt32LE(0, 12);
    cd.writeUInt32LE(e.crc, 16);
    cd.writeUInt32LE(e.compSz, 20);
    cd.writeUInt32LE(e.uncompSz, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt16LE(0, 30);
    cd.writeUInt16LE(0, 32);
    cd.writeUInt16LE(0, 34);
    cd.writeUInt16LE(0, 36);
    cd.writeUInt32LE(e.extAttr, 38); // Unix permissions in upper 2 bytes
    cd.writeUInt32LE(offset, 42);
    nameBuf.copy(cd, 46);

    lhParts.push(lh, e.rawData);
    cdParts.push(cd);
    offset += lh.length + e.rawData.length;
  }

  const cdBuf = Buffer.concat(cdParts);
  const eocd  = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...lhParts, cdBuf, eocd]);
}

// ── Entry helpers ─────────────────────────────────────────────────────────────
const UNIX_VER = 0x0314; // version made by: Unix 2.0

function mkFile(filename, data, mode) {
  mode = mode || 0o644;
  const comp    = deflateRawSync(data, { level: 6 });
  const useComp = comp.length < data.length;
  return {
    filename,
    method:        useComp ? 8 : 0,
    crc:           crc32(data),
    compSz:        useComp ? comp.length : data.length,
    uncompSz:      data.length,
    extAttr:       ((0o100000 | mode) << 16) >>> 0,
    versionMadeBy: UNIX_VER,
    rawData:       useComp ? comp : data
  };
}

function mkDir(filename) {
  if (!filename.endsWith('/')) filename += '/';
  return {
    filename,
    method: 0, crc: 0, compSz: 0, uncompSz: 0,
    extAttr:       (0o040755 << 16) >>> 0,
    versionMadeBy: UNIX_VER,
    rawData:       Buffer.alloc(0)
  };
}

function patchEntry(e, newFilename, newData) {
  if (newData === undefined) return Object.assign({}, e, { filename: newFilename });
  const comp    = deflateRawSync(newData, { level: 6 });
  const useComp = comp.length < newData.length;
  return Object.assign({}, e, {
    filename:  newFilename,
    method:    useComp ? 8 : 0,
    crc:       crc32(newData),
    compSz:    useComp ? comp.length : newData.length,
    uncompSz:  newData.length,
    rawData:   useComp ? comp : newData
  });
}

module.exports = { crc32, readZip, writeZip, mkFile, mkDir, patchEntry, UNIX_VER };
