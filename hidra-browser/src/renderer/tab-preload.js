// Tab preload — exposes limited HidraNet API to internal pages only.
// Fingerprint injection happens via executeJavaScript from the main process,
// not through the preload, to ensure it runs before any page scripts.

const { contextBridge, ipcRenderer } = require('electron');

// Only expose the proxy status API to internal hidra:// pages
// and file:// pages (newtab). External web pages get nothing.
const isInternalPage = (() => {
  try {
    const url = window.location.href;
    return url.startsWith('file://') || url.startsWith('hidra://');
  } catch {
    return false;
  }
})();

if (isInternalPage) {
  contextBridge.exposeInMainWorld('hidra', {
    proxy: {
      status: () => ipcRenderer.invoke('proxy:status'),
      setHops: (hops) => ipcRenderer.invoke('proxy:set-hops', hops),
      connect: () => ipcRenderer.invoke('proxy:connect'),
      disconnect: () => ipcRenderer.invoke('proxy:disconnect'),
    },
  });
}
