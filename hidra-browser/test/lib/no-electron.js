// tab-manager.js requires electron for BrowserView and session, which the
// checks that load it never touch: they exercise its pure functions. The
// release job runs without node_modules, and installing Electron to read a
// few functions would be the slowest step in it, so these tests get a
// stand-in instead.
const Module = require('module');

const resolve = Module._resolveFilename;
Module._resolveFilename = function (request, ...rest) {
  if (request === 'electron') return require.resolve('./electron-stub');
  return resolve.call(this, request, ...rest);
};
