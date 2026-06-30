const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('hidra', {
  tab: {
    create: (url) => ipcRenderer.invoke('tab:create', url),
    close: (tabId) => ipcRenderer.invoke('tab:close', tabId),
    navigate: (tabId, url) => ipcRenderer.invoke('tab:navigate', tabId, url),
    goBack: (tabId) => ipcRenderer.invoke('tab:go-back', tabId),
    goForward: (tabId) => ipcRenderer.invoke('tab:go-forward', tabId),
    reload: (tabId) => ipcRenderer.invoke('tab:reload', tabId),
    activate: (tabId) => ipcRenderer.invoke('tab:activate', tabId),
    list: () => ipcRenderer.invoke('tab:list'),
  },
  proxy: {
    status: () => ipcRenderer.invoke('proxy:status'),
    setHops: (hops) => ipcRenderer.invoke('proxy:set-hops', hops),
    connect: () => ipcRenderer.invoke('proxy:connect'),
    disconnect: () => ipcRenderer.invoke('proxy:disconnect'),
  },
  window: {
    minimize: () => ipcRenderer.invoke('window:minimize'),
    maximize: () => ipcRenderer.invoke('window:maximize'),
    close: () => ipcRenderer.invoke('window:close'),
  },
  on: (channel, callback) => {
    const validChannels = [
      'tab:created', 'tab:closed', 'tab:activated',
      'tab:title', 'tab:navigated', 'tab:loading',
    ];
    if (validChannels.includes(channel)) {
      ipcRenderer.on(channel, (_event, data) => callback(data));
    }
  },
});
