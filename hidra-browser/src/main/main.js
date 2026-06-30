const { app, BrowserWindow, session, ipcMain, protocol } = require('electron');
const path = require('path');
const http = require('http');
const fs = require('fs');
const { TabManager } = require('./tab-manager');
const { ProxyManager } = require('./proxy-manager');
const { FingerprintEngine } = require('../fingerprint/engine');

const PROXY_ADDR = '127.0.0.1';
const PROXY_PORT = 9050;
const CHAT_PORT = 8090;

let mainWindow = null;
let tabManager = null;
let proxyManager = null;
let chatServer = null;

// Serve HidraChat from the trusted browser process (localhost = secure context
// for Web Crypto). The chat is fully client-side (MQTT relay + E2E in browser),
// so it does NOT depend on the hidra-node engine — works even if Smart App
// Control blocks the engine.
function startChatServer() {
  const load = (f) => {
    try { return fs.readFileSync(path.join(__dirname, '..', 'ui', f), 'utf8'); }
    catch (e) { console.error('[srv] failed to load', f, e.message); return '<h1>' + f + ' não encontrado</h1>'; }
  };
  const pages = { chat: load('hidrachat.html'), publish: load('sitepub.html'), site: load('siteload.html'), mail: load('hidramail.html'), forum: load('forum.html'), donate: load('donate.html') };
  chatServer = http.createServer((req, res) => {
    const p = (req.url || '/').split('?')[0];
    let html = pages.chat;
    if (p.indexOf('/mail') === 0) html = pages.mail;
    else if (p.indexOf('/forum') === 0) html = pages.forum;
    else if (p.indexOf('/donate') === 0) html = pages.donate;
    else if (p === '/sites' || p.indexOf('/publish') === 0) html = pages.publish;
    else if (p.indexOf('/site') === 0) html = pages.site;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    res.end(html);
  });
  chatServer.on('error', (e) => console.error('[srv] server error:', e.message));
  chatServer.listen(CHAT_PORT, '127.0.0.1', () => {
    console.log('[srv] HidraNet apps at http://127.0.0.1:' + CHAT_PORT + ' (chat, /publish, /site)');
  });
}

app.commandLine.appendSwitch('disable-features', 'WebRTC');
app.commandLine.appendSwitch('disable-webrtc');
app.commandLine.appendSwitch('disable-reading-from-canvas');
app.commandLine.appendSwitch('disable-gl-extensions');
app.commandLine.appendSwitch('disable-accelerated-2d-canvas');

protocol.registerSchemesAsPrivileged([{
  scheme: 'hidra',
  privileges: { standard: true, secure: true, supportFetchAPI: true }
}]);

app.whenReady().then(async () => {
  startChatServer();
  proxyManager = new ProxyManager(PROXY_ADDR, PROXY_PORT);

  const proxyReady = await proxyManager.configure(session.defaultSession);
  if (proxyReady) {
    console.log('SOCKS5 proxy detected — connected');
  } else {
    console.log('Waiting for user to click Conectar');
  }

  mainWindow = createMainWindow();
  tabManager = new TabManager(mainWindow, proxyManager);

  setupIPC(tabManager, proxyManager);

  mainWindow.once('ready-to-show', async () => {
    mainWindow.show();
    await tabManager.createTab('hidra://newtab');
  });
});

app.on('window-all-closed', () => {
  if (proxyManager) {
    proxyManager.shutdownFull();
  }
  app.quit();
});

function createMainWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    title: 'HidraNet Browser',
    backgroundColor: '#0a0a0f',
    frame: false,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, '..', 'renderer', 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  win.loadFile(path.join(__dirname, '..', 'ui', 'browser.html'));
  return win;
}

function setupIPC(tabs, proxy) {
  ipcMain.handle('tab:create', async (_event, url) => {
    return await tabs.createTab(url || 'hidra://newtab');
  });

  ipcMain.handle('tab:close', (_event, tabId) => {
    tabs.closeTab(tabId);
  });

  ipcMain.handle('tab:navigate', (_event, tabId, url) => {
    tabs.navigate(tabId, url);
  });

  ipcMain.handle('tab:go-back', (_event, tabId) => {
    tabs.goBack(tabId);
  });

  ipcMain.handle('tab:go-forward', (_event, tabId) => {
    tabs.goForward(tabId);
  });

  ipcMain.handle('tab:reload', (_event, tabId) => {
    tabs.reload(tabId);
  });

  ipcMain.handle('tab:activate', (_event, tabId) => {
    tabs.activateTab(tabId);
  });

  ipcMain.handle('tab:list', () => {
    return tabs.listTabs();
  });

  ipcMain.handle('proxy:status', () => {
    return proxy.getStatus();
  });

  ipcMain.handle('proxy:set-hops', (_event, hops) => {
    return proxy.setHopCount(hops);
  });

  ipcMain.handle('proxy:connect', async () => {
    if (proxy.isRunning()) {
      await proxy.configure(session.defaultSession);
      for (const s of tabs.getAllSessions()) {
        await proxy.configure(s);
      }
      return { ok: true, msg: 'already running' };
    }
    const ok = await proxy.startHidraNode();
    if (ok) {
      await proxy.configure(session.defaultSession);
      for (const s of tabs.getAllSessions()) {
        await proxy.configure(s);
      }
      return { ok: true, msg: 'connected' };
    }
    return { ok: false, msg: 'failed to start hidra-node' };
  });

  ipcMain.handle('proxy:disconnect', async () => {
    await proxy.shutdown(session.defaultSession);
    for (const s of tabs.getAllSessions()) {
      await s.setProxy({ mode: 'direct' });
    }
    return { ok: true, msg: 'disconnected' };
  });

  ipcMain.handle('window:minimize', () => {
    if (mainWindow) mainWindow.minimize();
  });

  ipcMain.handle('window:maximize', () => {
    if (mainWindow) {
      if (mainWindow.isMaximized()) {
        mainWindow.unmaximize();
      } else {
        mainWindow.maximize();
      }
    }
  });

  ipcMain.handle('window:close', () => {
    if (mainWindow) mainWindow.close();
  });
}
