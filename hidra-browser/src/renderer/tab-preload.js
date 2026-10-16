// Tab preload — exposes limited HidraNet API to internal pages only.
// Fingerprint injection happens via executeJavaScript from the main process,
// not through the preload, to ensure it runs before any page scripts.

const { contextBridge, ipcRenderer } = require('electron');

// Only our own shipped pages get this API. The test used to be
// `url.startsWith('file://')`, which is every file on the disk: any .html the
// user downloaded and opened in a tab was handed proxy.disconnect(), which
// turns Tor off, along with tor.newIdentity(), prefs.save() and
// sevennine.start(). A page cannot be trusted for living on this machine —
// only for being one of ours.
//
// The root comes in through additionalArguments because this preload runs
// sandboxed, where require() reaches only electron, events, timers and url —
// no path, no fs. A plain string prefix is enough: the URL constructor
// resolves ../ before we compare, so a page cannot walk out of the directory
// by spelling its way out.
const UI_ROOT_FLAG = '--hidra-ui-root=';
const uiRoot = (process.argv.find((a) => a.startsWith(UI_ROOT_FLAG)) || '')
  .slice(UI_ROOT_FLAG.length);

const isInternalPage = (() => {
  try {
    // Only a page shipped under src/ui. Not hidra:// — nothing serves that
    // scheme to a frame today, and the day something does (published sites
    // are the obvious candidate) it must not inherit this.
    const href = new URL(window.location.href).href;
    return Boolean(uiRoot) && href.startsWith(uiRoot);
  } catch {
    return false;
  }
})();

if (isInternalPage) {
  contextBridge.exposeInMainWorld('hidra', {
    proxy: {
      status: () => ipcRenderer.invoke('proxy:status'),
      connect: () => ipcRenderer.invoke('proxy:connect'),
      disconnect: () => ipcRenderer.invoke('proxy:disconnect'),
    },
    prefs: {
      get: () => ipcRenderer.invoke('prefs:get'),
      save: (p) => ipcRenderer.invoke('prefs:save', p),
    },
    apps: {
      status: () => ipcRenderer.invoke('apps:status'),
    },
    tor: {
      newIdentity: () => ipcRenderer.invoke('tor:new-identity'),
    },
    sevennine: {
      start: () => ipcRenderer.invoke('sevennine:start'),
      stop: () => ipcRenderer.invoke('sevennine:stop'),
    },
    vault: {
      status: () => ipcRenderer.invoke('vault:status'),
    },
    // HidraVPN: the browser drives the service installed on this machine
    // (src/main/vpn-manager.js). Connecting routes the whole machine, so this
    // is offered to our own pages only, and the main process checks the
    // caller again before it does anything.
    vpn: {
      status: () => ipcRenderer.invoke('vpn:status'),
      connect: (mode, options) => ipcRenderer.invoke('vpn:connect', mode, options),
      leakTest: () => ipcRenderer.invoke('vpn:leak-test'),
      checkRelease: () => ipcRenderer.invoke('vpn:check-release'),
      install: () => ipcRenderer.invoke('vpn:install'),
      uninstall: (purge) => ipcRenderer.invoke('vpn:uninstall', purge === true),
      disconnect: () => ipcRenderer.invoke('vpn:disconnect'),
      newIdentity: () => ipcRenderer.invoke('vpn:new-identity'),
      nodes: () => ipcRenderer.invoke('vpn:nodes'),
      importNodes: () => ipcRenderer.invoke('vpn:import-nodes'),
      fetchList: () => ipcRenderer.invoke('vpn:fetch-list'),
      getPasses: (count) => ipcRenderer.invoke('vpn:get-passes', count),
      setPassToken: (token) => ipcRenderer.invoke('vpn:set-pass-token', token),
      refill: (enabled) => ipcRenderer.invoke('vpn:refill', enabled),
      verifyFile: () => ipcRenderer.invoke('vpn:verify-file'),
    },
  });
}

// HidraNet's own apps — mail, chat, forum, the site publisher — are served by
// the browser on a loopback origin, and they hold an identity. They get one
// thing and one thing only: a compartment in the vault (src/main/vault.js),
// where that identity is kept under the system keychain instead of in
// localStorage. Nothing here can touch Tor, the proxy or the preferences.
//
// This decides whether the bridge is offered; it is not what protects the
// vault. The main process checks the sender of every call against the
// frame's own URL, so a page that is not one of these gets a refusal even if
// it somehow had the bridge.
const APPS_FLAG = '--hidra-apps-origin=';
const appsOrigin = (process.argv.find((a) => a.startsWith(APPS_FLAG)) || '')
  .slice(APPS_FLAG.length);
// Keep in step with APP_NAMESPACES in tab-manager.js.
const APP_PATHS = new Set(['/', '/mail', '/forum', '/publish', '/sites']);

const isAppPage = (() => {
  try {
    const u = new URL(window.location.href);
    return Boolean(appsOrigin) && u.origin === appsOrigin
      && APP_PATHS.has(u.pathname.replace(/\/+$/, '') || '/');
  } catch {
    return false;
  }
})();

if (isAppPage && !isInternalPage) {
  contextBridge.exposeInMainWorld('hidra', {
    vault: {
      get: () => ipcRenderer.invoke('vault:get'),
      set: (value) => ipcRenderer.invoke('vault:set', value),
      status: () => ipcRenderer.invoke('vault:status'),
    },
  });
}
