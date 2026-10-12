// See no-electron.js. Empty on purpose: tab-manager.js destructures it at
// load, which is fine, and a test that actually calls into Electron fails
// loudly ("BrowserView is not a constructor") rather than passing.
module.exports = {};
