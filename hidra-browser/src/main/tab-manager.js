const { BrowserView, session } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { FingerprintEngine } = require('../fingerprint/engine');

class TabManager {
  constructor(parentWindow, proxyManager) {
    this.window = parentWindow;
    this.proxyManager = proxyManager;
    this.tabs = new Map();
    this.activeTabId = null;
    this.nextId = 1;
  }

  async createTab(url) {
    const tabId = this.nextId++;
    const tabSession = this._createIsolatedSession(tabId);
    const fingerprint = FingerprintEngine.generate();

    const view = new BrowserView({
      webPreferences: {
        preload: path.join(__dirname, '..', 'renderer', 'tab-preload.js'),
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        session: tabSession,
        webSecurity: true,
        allowRunningInsecureContent: false,
      },
    });

    await this.proxyManager.configure(tabSession);

    this._injectFingerprint(view, fingerprint);

    // Inject the "Publicar na rede" feature into the SevenNine page (no engine rebuild)
    view.webContents.on('did-finish-load', () => {
      try {
        const u = view.webContents.getURL();
        if (u.includes('127.0.0.1:8084')) this._injectSevenNinePublish(view);
      } catch (e) {}
    });

    const tabInfo = {
      id: tabId,
      view,
      session: tabSession,
      fingerprint,
      title: 'New Tab',
      url: url || 'hidra://newtab',
      loading: false,
    };

    view.webContents.on('did-start-loading', () => {
      tabInfo.loading = true;
      this._notifyUI('tab:loading', { tabId, loading: true });
    });

    view.webContents.on('did-stop-loading', () => {
      tabInfo.loading = false;
      this._notifyUI('tab:loading', { tabId, loading: false });
    });

    view.webContents.on('page-title-updated', (_event, title) => {
      tabInfo.title = title;
      this._notifyUI('tab:title', { tabId, title });
    });

    view.webContents.on('did-navigate', (_event, navUrl) => {
      tabInfo.url = navUrl;
      this._notifyUI('tab:navigated', {
        tabId,
        url: navUrl,
        canGoBack: view.webContents.navigationHistory.canGoBack(),
        canGoForward: view.webContents.navigationHistory.canGoForward(),
      });
    });

    view.webContents.on('did-navigate-in-page', (_event, navUrl) => {
      tabInfo.url = navUrl;
      this._notifyUI('tab:navigated', {
        tabId,
        url: navUrl,
        canGoBack: view.webContents.navigationHistory.canGoBack(),
        canGoForward: view.webContents.navigationHistory.canGoForward(),
      });
    });

    view.webContents.setWindowOpenHandler(({ url: openUrl }) => {
      this.createTab(openUrl);
      return { action: 'deny' };
    });

    this.tabs.set(tabId, tabInfo);
    this.activateTab(tabId);
    this.navigate(tabId, url || 'hidra://newtab');


    this._notifyUI('tab:created', { tabId, title: tabInfo.title, url: tabInfo.url });
    return tabId;
  }

  closeTab(tabId) {
    const tab = this.tabs.get(tabId);
    if (!tab) return;

    this.window.removeBrowserView(tab.view);
    tab.view.webContents.close();
    tab.session.clearStorageData();
    this.tabs.delete(tabId);

    if (this.activeTabId === tabId) {
      const remaining = [...this.tabs.keys()];
      if (remaining.length > 0) {
        this.activateTab(remaining[remaining.length - 1]);
      } else {
        this.activeTabId = null;
        this.createTab('hidra://newtab');
      }
    }

    this._notifyUI('tab:closed', { tabId });
  }

  activateTab(tabId) {
    const tab = this.tabs.get(tabId);
    if (!tab) return;

    if (this.activeTabId !== null) {
      const prev = this.tabs.get(this.activeTabId);
      if (prev) {
        this.window.removeBrowserView(prev.view);
      }
    }

    this.activeTabId = tabId;
    this.window.addBrowserView(tab.view);
    this._resizeView(tab.view);
    tab.view.setAutoResize({ width: true, height: true });

    this._notifyUI('tab:activated', {
      tabId,
      url: tab.url,
      title: tab.title,
      canGoBack: tab.view.webContents.navigationHistory.canGoBack(),
      canGoForward: tab.view.webContents.navigationHistory.canGoForward(),
    });
  }

  navigate(tabId, url) {
    const tab = this.tabs.get(tabId);
    if (!tab) return;

    let finalUrl = url;
    if (!url.includes('://') && !url.startsWith('hidra://')) {
      if (url.endsWith('.hidra') || url.includes('.hidra/')) {
        finalUrl = 'hidra://' + url;
      } else if (url.includes('.') && !url.includes(' ')) {
        finalUrl = 'https://' + url;
      } else {
        finalUrl = 'http://127.0.0.1:8083/?q=' + encodeURIComponent(url);
      }
    }

    if (finalUrl.startsWith('hidra://newtab')) {
      tab.view.webContents.loadFile(
        path.join(__dirname, '..', 'ui', 'newtab.html')
      );
    } else if (finalUrl.startsWith('hidra://search')) {
      const searchQuery = finalUrl.includes('?q=')
        ? finalUrl.split('?q=')[1]
        : '';
      const searchUrl = searchQuery
        ? 'http://127.0.0.1:8083/?q=' + searchQuery
        : 'http://127.0.0.1:8083/';
      tab.view.webContents.loadURL(searchUrl);
    } else if (finalUrl.startsWith('hidra://')) {
      this._resolveHidraDomain(tab, finalUrl);
    } else {
      tab.view.webContents.loadURL(finalUrl);
    }

    tab.url = finalUrl;
  }

  goBack(tabId) {
    const tab = this.tabs.get(tabId);
    if (tab && tab.view.webContents.navigationHistory.canGoBack()) {
      tab.view.webContents.navigationHistory.goBack();
    }
  }

  goForward(tabId) {
    const tab = this.tabs.get(tabId);
    if (tab && tab.view.webContents.navigationHistory.canGoForward()) {
      tab.view.webContents.navigationHistory.goForward();
    }
  }

  reload(tabId) {
    const tab = this.tabs.get(tabId);
    if (tab) {
      tab.view.webContents.reload();
    }
  }

  getAllSessions() {
    return [...this.tabs.values()].map(t => t.session).filter(Boolean);
  }

  listTabs() {
    return [...this.tabs.values()].map(t => ({
      id: t.id,
      title: t.title,
      url: t.url,
      active: t.id === this.activeTabId,
      loading: t.loading,
    }));
  }

  _createIsolatedSession(tabId) {
    const partition = `tab-${tabId}-${crypto.randomBytes(8).toString('hex')}`;
    const tabSession = session.fromPartition(partition, { cache: false });

    tabSession.webRequest.onBeforeSendHeaders((details, callback) => {
      const headers = { ...details.requestHeaders };
      delete headers['X-Client-Data'];
      delete headers['Sec-CH-UA'];
      delete headers['Sec-CH-UA-Platform'];
      delete headers['Sec-CH-UA-Mobile'];
      delete headers['Sec-CH-UA-Full-Version'];
      delete headers['Sec-CH-UA-Full-Version-List'];
      delete headers['Sec-CH-UA-Arch'];
      delete headers['Sec-CH-UA-Bitness'];
      delete headers['Sec-CH-UA-Model'];
      callback({ requestHeaders: headers });
    });

    tabSession.setPermissionRequestHandler((_wc, permission, callback) => {
      const blocked = ['geolocation', 'media', 'notifications', 'midi', 'pointerLock'];
      callback(!blocked.includes(permission));
    });

    return tabSession;
  }

  _injectFingerprint(view, fingerprint) {
    view.webContents.on('dom-ready', () => {
      const script = FingerprintEngine.buildInjectionScript(fingerprint);
      view.webContents.executeJavaScript(script).catch(() => {});
    });
  }

  _injectSevenNinePublish(view) {
    try {
      const code = fs.readFileSync(
        path.join(__dirname, '..', 'renderer', 'sevennine-publish.js'), 'utf8'
      );
      view.webContents.executeJavaScript(code).catch(() => {});
    } catch (e) {}
  }

  async _resolveHidraDomain(tab, hidraUrl) {
    const hostname = hidraUrl.replace('hidra://', '').split('/')[0];
    const pathPart = hidraUrl.replace('hidra://', '').substring(hostname.length);

    // Network .hidra address (encrypted site on the relay): long base32 label.
    const label = hostname.replace('.hidra', '');
    if (label.length >= 24 && /^[a-z2-7]+$/.test(label)) {
      tab.view.webContents.loadURL('http://127.0.0.1:8090/site?addr=' + encodeURIComponent(hostname));
      return;
    }

    tab.view.webContents.loadURL('data:text/html,' + encodeURIComponent(
      `<!DOCTYPE html><html><head><style>
        body { background: #06060b; color: #e0e0e8; font-family: -apple-system, sans-serif;
               display: flex; align-items: center; justify-content: center; height: 100vh; }
        .resolving { text-align: center; }
        .resolving h2 { color: #00d4aa; font-weight: 300; letter-spacing: 2px; margin-bottom: 12px; }
        .resolving p { color: #555570; font-size: 13px; }
        .spinner { width: 32px; height: 32px; border: 2px solid #1a1a2e; border-top-color: #00d4aa;
                   border-radius: 50%; animation: spin 0.8s linear infinite; margin: 0 auto 16px; }
        @keyframes spin { to { transform: rotate(360deg); } }
      </style></head><body><div class="resolving">
        <div class="spinner"></div>
        <h2>Resolving ${hostname}</h2>
        <p>Querying HidraNet DHT...</p>
      </div></body></html>`
    ));

    const siteName = hostname.replace('.hidra', '');
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);

      // Try DHT resolver first
      const response = await fetch(
        `http://127.0.0.1:9051/api/resolve?name=${encodeURIComponent(siteName)}`,
        { signal: controller.signal }
      ).catch(() => null);

      clearTimeout(timeout);

      if (response && response.ok) {
        const data = await response.json();
        if (data.address) {
          tab.view.webContents.loadURL(`http://${data.address}${pathPart}`);
          return;
        }
      }
    } catch {
      // DHT resolver not available
    }

    // Fallback: check if SevenNine hosts this site locally
    try {
      const snRes = await fetch(
        `http://127.0.0.1:8084/api/resolve?name=${encodeURIComponent(siteName)}`,
        { signal: AbortSignal.timeout(3000) }
      ).catch(() => null);

      if (snRes && snRes.ok) {
        const snData = await snRes.json();
        if (snData.found) {
          tab.view.webContents.loadURL(`http://${snData.address}${snData.path}`);
          return;
        }
      }
    } catch {
      // SevenNine not available
    }

    tab.view.webContents.loadURL('data:text/html,' + encodeURIComponent(
      `<!DOCTYPE html><html><head><style>
        body { background: #06060b; color: #e0e0e8; font-family: -apple-system, sans-serif;
               display: flex; align-items: center; justify-content: center; height: 100vh; }
        .error { text-align: center; max-width: 400px; }
        .error h2 { color: #ff4466; font-weight: 400; margin-bottom: 12px; }
        .error p { color: #555570; font-size: 13px; line-height: 1.6; }
        .error code { color: #00d4aa; background: #10101c; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
      </style></head><body><div class="error">
        <h2>Cannot resolve ${hostname}</h2>
        <p>The .hidra domain could not be found in the DHT network.
        Make sure the HidraNet client is running and the service is registered.</p>
        <p style="margin-top: 16px;">Tried: <code>http://127.0.0.1:9051/api/resolve</code></p>
      </div></body></html>`
    ));
  }

  _resizeView(view) {
    const bounds = this.window.getBounds();
    const TAB_BAR_HEIGHT = 104;
    view.setBounds({
      x: 0,
      y: TAB_BAR_HEIGHT,
      width: bounds.width,
      height: bounds.height - TAB_BAR_HEIGHT,
    });
  }

  _notifyUI(channel, data) {
    if (this.window && !this.window.isDestroyed()) {
      this.window.webContents.send(channel, data);
    }
  }
}

module.exports = { TabManager };
