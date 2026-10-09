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
    const href = new URL(window.location.href).href;
    if (href.startsWith('hidra://')) return true;
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
  });
}
