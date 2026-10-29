'use strict';
/**
 * Where a builder writes its package: the folder after --out, or the
 * Desktop as before.
 *
 * The builders used to write to ~/Desktop and nowhere else, and never made
 * the folder. A machine with no folder by that name (a Linux build box, a
 * Linux desktop in Portuguese, where it is "Área de Trabalho", a Windows
 * account whose Desktop OneDrive moved) built the whole package and then
 * failed writing it. And a Desktop that still holds the 1.0.0 packages is the
 * wrong folder to give update-sums.js, check-engine.js and release-notes.js,
 * which read every package in it: --out <folder> keeps the four new ones on
 * their own. The folder is made if it is not there.
 */
const fs   = require('fs');
const os   = require('os');
const path = require('path');

/**
 * Splits --out <dir> from the other arguments. Returns the output folder
 * (absolute) and what is left, in order, for the builder's own arguments.
 */
function outArgs(argv) {
  const rest = [];
  let out = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--out') {
      out = argv[i + 1];
      if (!out || out.startsWith('--')) throw new Error('--out needs a folder');
      i++;
      continue;
    }
    rest.push(argv[i]);
  }
  return { out: path.resolve(out || path.join(os.homedir(), 'Desktop')), rest };
}

/** Writes one package into `dir`, making the folder first. Returns its path. */
function writePackage(dir, name, buf) {
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, name);
  fs.writeFileSync(file, buf);
  return file;
}

module.exports = { outArgs, writePackage };
