'use strict';
/**
 * Which build a package is: the commit it was made from and the day. The new
 * tab page shows it in its footer (main.js, buildInfo, which reads
 * app/build.json), so whoever tests a package can tell it from an older copy
 * still on their machine. A tree with uncommitted changes says so: "-dirty" is
 * not something to publish.
 *
 * Shared by the three builders; refresh-release.js writes the same shape.
 */
const path = require('path');
const { execFileSync } = require('child_process');

function buildStamp() {
  let build = 'unknown';
  try {
    build = execFileSync('git', ['describe', '--always', '--dirty', '--abbrev=7', '--exclude', '*'],
      { cwd: path.join(__dirname, '..', '..'), encoding: 'utf8' }).trim();
  } catch (e) { /* not a checkout */ }
  return { build, date: new Date().toISOString().slice(0, 10) };
}

// The file as it goes into a package.
function buildJson() {
  return Buffer.from(JSON.stringify(buildStamp()) + '\n', 'utf8');
}

module.exports = { buildStamp, buildJson };
