// Where an app keeps what identifies you.
//
// Inside HidraNet the browser hands each app a compartment in its vault
// (src/main/vault.js), protected by the system keychain where there is one.
// The same pages also run where there is no browser around them — the tests
// drive them in plain Chromium — and there they fall back to localStorage, as
// they always did.
//
// load() rejects when something is stored but cannot be read, such as a
// locked keyring. An app must then stop and say so, not start over with a new
// identity: its next save would write over the one it could not read.
(function () {
  'use strict';
  // The new tab page's bridge has a vault with status() only; a compartment
  // is one that can be read and written.
  var bridge = window.hidra && window.hidra.vault;
  var vault = bridge && typeof bridge.get === 'function' && typeof bridge.set === 'function' ? bridge : null;
  var chain = Promise.resolve();

  function reason(e) {
    // An IPC rejection arrives as "Error invoking remote method 'x': Error: why".
    var m = String(e && e.message || e).replace(/^.*?: Error: /, '');
    return m;
  }

  async function load(legacyKey) {
    if (!vault) {
      try { return localStorage.getItem(legacyKey); } catch (e) { return null; }
    }
    var v;
    try { v = await vault.get(); } catch (e) { throw new Error(reason(e)); }
    if (v === null && legacyKey) {
      // Data from before the vault, written by an earlier version into
      // localStorage: move it in, then take it off the disk.
      var old = null;
      try { old = localStorage.getItem(legacyKey); } catch (e) {}
      if (old !== null) {
        await vault.set(old);
        try { localStorage.removeItem(legacyKey); } catch (e) {}
        v = old;
      }
    }
    return v;
  }

  // Writes are queued in order; the returned promise settles when this one
  // is on disk. Callers that do not care may ignore it.
  function save(legacyKey, value) {
    if (!vault) {
      try { localStorage.setItem(legacyKey, value); } catch (e) {}
      return Promise.resolve();
    }
    chain = chain.catch(function () {}).then(function () { return vault.set(value); });
    return chain;
  }

  async function status() {
    if (vault) {
      try { return await vault.status(); } catch (e) {}
    }
    return { encrypted: false, backend: 'none' };
  }

  window.hidraStore = { load: load, save: save, status: status, inVault: Boolean(vault) };
})();
