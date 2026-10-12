const { BrowserView, session } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { pathToFileURL } = require('url');
const { FingerprintEngine } = require('../fingerprint/engine');

// HidraNet apps (chat, mail, forum, search, sites) are served by main.js on this
// port — not by the hidra-node engine, so they work even when the engine is not
// running. Keep in sync with CHAT_PORT in main.js.
const APPS_PORT = 8090;

// Trailing slash matters: without it, a sibling directory whose name merely
// starts with "ui" would match the prefix too.
const UI_ROOT_URL = pathToFileURL(path.join(__dirname, '..', 'ui') + path.sep).href;

// The built-in pages, by the name the address bar should show for each.
const INTERNAL_PAGES = {
  'newtab.html': 'newtab',
  'hidramail.html': 'mail',
  'hidrachat.html': 'chat',
  'forum.html': 'forum',
  'hidrasearch.html': 'search',
  'hidrareview.html': 'reviews',
  'sitepub.html': 'publish',
  'siteload.html': 'site',
  'donate.html': 'donate',
};

// What to load when someone types the name. Only the new tab page comes from
// disk; every app comes from the apps server, so it has one origin — and one
// store — however it was opened. Typing hidra://mail used to load the copy on
// disk, a file:// page with storage of its own, and so a different mail
// address from the one behind the new tab page's Mail card.
const INTERNAL_BY_NAME = {
  newtab: 'newtab.html',
  mail: '/mail',
  chat: '/',
  forum: '/forum',
  reviews: '/reviews',
  publish: '/publish',
  donate: '/donate',
};

// The same, for the pages the apps server hands out on the loopback port.
const APPS_ROUTES = {
  '': 'chat',
  '/mail': 'mail',
  '/forum': 'forum',
  '/donate': 'donate',
  '/sites': 'publish',
  '/publish': 'publish',
  '/site': 'site',
  '/search': 'search',
  '/reviews': 'reviews',
};
const APPS_ORIGIN = `http://127.0.0.1:${APPS_PORT}`;
const SEARCH_URL = `${APPS_ORIGIN}/search`;

// HidraNet's own apps keep what they store. Websites do not.
//
// Every tab used to get a fresh, random, in-memory partition. That is right
// for websites, which should forget you when the tab closes, and it was wrong
// for the apps, which hold an identity: the mail address and its keys, the
// mail received, the forum name, the list of sites you published. Opening
// HidraMail in a second tab gave you a second address, and every restart gave
// you another, so anything sent to the first one went to a mailbox that no
// longer existed. The forum forgot who you were the same way.
//
// So those pages, and only those, share one partition kept on disk. It is
// chosen by path and not just by origin: search, reviews and donate store
// nothing, and the site viewer renders other people's content, so they stay
// in a throwaway partition like any website.
const APPS_PARTITION = 'persist:hidra-apps';

// Each app that holds an identity, by the path it is served on. The name is
// also the app's compartment in the vault (main.js, vault.js), so the forum
// cannot read the mail keys, and a page on any other path reads nothing.
const APP_NAMESPACES = {
  '/': 'chat',
  '/mail': 'mail',
  '/forum': 'forum',
  '/publish': 'publish',
  '/sites': 'publish',
};

function appNamespace(rawUrl) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return null;
  }
  if (u.origin !== APPS_ORIGIN) return null;
  return APP_NAMESPACES[u.pathname.replace(/\/+$/, '') || '/'] || null;
}

function wantsAppStorage(rawUrl) {
  return appNamespace(rawUrl) !== null;
}

// The compartment an IPC call may open: the one belonging to the URL of the
// top frame that sent it, or none. A subframe gets nothing, whatever it says.
function vaultNamespaceOf(event) {
  const frame = event && event.senderFrame;
  if (!frame || !event.sender || frame !== event.sender.mainFrame) return null;
  return appNamespace(frame.url);
}

class TabManager {
  constructor(parentWindow, proxyManager, networkLock) {
    this.window = parentWindow;
    this.proxyManager = proxyManager;
    this.networkLock = networkLock;
    this.tabs = new Map();
    this.activeTabId = null;
    this.nextId = 1;
    // Set while connected, so tabs opened after connecting inherit the same
    // network route instead of quietly going out direct.
    this.proxyRules = null;
    // The apps' shared partition, made on first use, and the one fingerprint
    // every tab in it presents: a session has one user agent, so tabs sharing
    // it cannot each claim a different one.
    this.appsSession = null;
    this.appsFingerprint = null;

    // A BrowserView keeps whatever bounds it was given, so without this the
    // page stays at the size the window had when the tab opened: resize the
    // window and the content is either clipped or leaves a strip of empty
    // chrome. Every one of these events changes the content area.
    for (const ev of ['resize', 'maximize', 'unmaximize', 'enter-full-screen', 'leave-full-screen']) {
      this.window.on(ev, () => this._resizeActiveView());
    }
  }

  _resizeActiveView() {
    if (!this.window || this.window.isDestroyed()) return;
    const tab = this.tabs.get(this.activeTabId);
    if (tab && tab.view) this._resizeView(tab.view);
  }

  setProxyRules(rules) {
    this.proxyRules = rules || null;
  }

  async _applyProxy(tabSession) {
    if (this.proxyRules) {
      await tabSession.setProxy({ proxyRules: this.proxyRules, proxyBypassRules: '<local>' });
      return;
    }
    await this.proxyManager.configure(tabSession);
  }

  async createTab(url) {
    const tabId = this.nextId++;
    const first = url || 'hidra://newtab';

    const tabInfo = {
      id: tabId,
      view: null,
      session: null,
      fingerprint: null,
      // Whether the view sits in the apps' partition, the one kept on disk.
      persistent: false,
      // Pages left behind when the tab moved between partitions. A view
      // cannot change partition, so the tab gets a new view instead, and the
      // old view's history goes with it; this is the way back.
      backStack: [],
      // Bumped by every navigation, so one that finishes late can tell it
      // has been overtaken and not load over the newer one.
      navSeq: 0,
      closed: false,
      title: 'New Tab',
      url: first,
      loading: false,
    };

    await this._attach(tabInfo, this._belongsInApps(this._resolve(first)));

    this.tabs.set(tabId, tabInfo);

    // The UI creates the tab strip element on 'tab:created', so it has to arrive
    // before 'tab:activated' — otherwise activateTab marks a tab that is not in
    // the DOM yet and the new tab never gets the active highlight.
    this._notifyUI('tab:created', { tabId, title: tabInfo.title, url: tabInfo.url });
    this.activateTab(tabId);
    this.navigate(tabId, first);

    return tabId;
  }

  // Gives the tab a view in the right partition: the apps' persistent one, or
  // a fresh throwaway one. Replaces the tab's current view if it has one.
  async _attach(tab, persistent) {
    const fingerprint = persistent ? this._appsFingerprint() : FingerprintEngine.generate();
    const tabSession = persistent
      ? this._appsSession()
      : this._createIsolatedSession(tab.id, fingerprint);

    // Routed before anything is created that could load, so nothing in this
    // view ever goes out on a route other than the one every tab is on.
    await this._applyProxy(tabSession);

    if (tab.closed) {
      if (!persistent) tabSession.clearStorageData();
      return false;
    }

    const view = this._buildView(tab, tabSession, fingerprint);
    const old = { view: tab.view, session: tab.session, persistent: tab.persistent };

    tab.view = view;
    tab.session = tabSession;
    tab.fingerprint = fingerprint;
    tab.persistent = persistent;

    if (old.view) {
      if (this.activeTabId === tab.id && this.tabs.get(tab.id) === tab) {
        this.window.addBrowserView(view);
        this._resizeView(view);
        view.setAutoResize({ width: true, height: true });
      }
      this._dispose(old);
    }
    return true;
  }

  _dispose({ view, session: tabSession, persistent }) {
    try {
      this.window.removeBrowserView(view);
    } catch (e) {}
    view.webContents.close();
    // The apps' partition is shared and kept on purpose: clearing it here
    // would delete the mail address along with the tab. What the tab wrote
    // goes to disk now instead.
    if (persistent) this._flushApps();
    else tabSession.clearStorageData();
  }

  _buildView(tab, tabSession, fingerprint) {
    const tabId = tab.id;
    const view = new BrowserView({
      webPreferences: {
        preload: path.join(__dirname, '..', 'renderer', 'tab-preload.js'),
        // Tells the preload which file:// URLs are our own shipped pages, and
        // which origin the apps are served from. It runs sandboxed and cannot
        // work either out for itself.
        additionalArguments: [
          `--hidra-ui-root=${UI_ROOT_URL}`,
          `--hidra-apps-origin=${APPS_ORIGIN}`,
        ],
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        session: tabSession,
        webSecurity: true,
        allowRunningInsecureContent: false,
      },
    });

    // A replaced view can still fire an event or two while it closes. Only
    // the view the tab currently shows gets to speak for it.
    const live = () => tab.view === view;

    // WebRTC can reveal the real IP through ICE candidates, going around the
    // proxy. The injected page deletes window.RTCPeerConnection, but that runs
    // late, and a fresh iframe hands back a clean window — protection written
    // in JavaScript is bypassable. This policy acts in the Chromium network
    // stack, where it is not. The switches 'disable-features=WebRTC' and
    // '--disable-webrtc' in main.js correspond to nothing real in Chromium;
    // this is the measure that works.
    try {
      view.webContents.setWebRTCIPHandlingPolicy('disable_non_proxied_udp');
    } catch (e) {
      console.error('[tab] WebRTC IP handling policy:', e.message);
    }

    this._injectFingerprint(view, fingerprint);
    this._bindShortcuts(view, tabId);

    // Inject the "Publish to the network" feature into the SevenNine page (no engine rebuild)
    view.webContents.on('did-finish-load', () => {
      try {
        const u = view.webContents.getURL();
        if (u.includes('127.0.0.1:8084')) this._injectSevenNinePublish(view);
      } catch (e) {}
      // An app writes its identity right after it loads (HidraMail generates
      // the address on first open). Get that to disk sooner than the cycle
      // above would, so the window in which a crash loses it is as small as
      // it can be made.
      if (tab.persistent) setTimeout(() => this._flushApps(), 1500);
    });

    // A page can take the tab across the line between the apps and the web
    // itself — a link out of an app, the new tab page's Mail card, a site
    // redirecting to the apps server. The view it is in cannot change
    // partition, so the navigation is stopped here and repeated in a view
    // that is in the right one. Without this, a website opened from inside an
    // app would run in the partition kept on disk and could keep cookies
    // across restarts, and the Mail card would open a mailbox that is gone
    // when the tab closes.
    const crossing = (target) => live() && this._belongsInApps({ kind: 'url', url: target }) !== tab.persistent;
    view.webContents.on('will-navigate', (event, legacyUrl) => {
      const target = event.url || legacyUrl;
      if (!crossing(target)) return;
      event.preventDefault();
      this.navigate(tabId, target);
    });
    view.webContents.on('will-redirect', (event, legacyUrl, _inPlace, legacyMainFrame) => {
      const mainFrame = event.isMainFrame !== undefined ? event.isMainFrame : legacyMainFrame;
      const target = event.url || legacyUrl;
      if (!mainFrame || !crossing(target)) return;
      event.preventDefault();
      this.navigate(tabId, target);
    });

    view.webContents.on('did-start-loading', () => {
      if (!live()) return;
      tab.loading = true;
      this._notifyUI('tab:loading', { tabId, loading: true });
    });

    view.webContents.on('did-stop-loading', () => {
      if (!live()) return;
      tab.loading = false;
      this._notifyUI('tab:loading', { tabId, loading: false });
    });

    view.webContents.on('page-title-updated', (_event, title) => {
      if (!live()) return;
      tab.title = title;
      this._notifyUI('tab:title', { tabId, title });
    });

    const navigated = (_event, navUrl) => {
      if (!live()) return;
      tab.url = this._displayUrl(navUrl);
      this._notifyUI('tab:navigated', {
        tabId,
        url: tab.url,
        canGoBack: this._canGoBack(tab),
        canGoForward: view.webContents.navigationHistory.canGoForward(),
      });
    };
    view.webContents.on('did-navigate', navigated);
    view.webContents.on('did-navigate-in-page', navigated);

    // Cancelling in onBeforeRequest returns ERR_BLOCKED_BY_CLIENT (-20) and the
    // user saw a Chromium error screen with no explanation. Tell them why.
    view.webContents.on('did-fail-load', (_e, errorCode, _desc, failedUrl, isMainFrame) => {
      if (!isMainFrame || errorCode !== -20) return;
      if (!this.networkLock || !this.networkLock.engaged) return;
      const reason = this.networkLock.reason || 'the anonymous connection is not ready';
      view.webContents.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(
        `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><style>
          body{background:#06070d;color:#e9ecf5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
               display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:24px}
          .box{max-width:460px}
          h1{font-size:19px;font-weight:700;color:#00d4aa;margin:0 0 12px}
          p{font-size:14px;line-height:1.6;color:#9aa3bd;margin:0 0 10px}
          code{font-family:'SF Mono',Consolas,monospace;font-size:12px;color:#e9ecf5;
               background:#10131f;border:1px solid #1c2133;border-radius:6px;padding:2px 6px}
        </style></head><body><div class="box">
          <h1>Request blocked — you are not anonymous yet</h1>
          <p>Nothing left this computer. HidraNet blocks all traffic until Tor
             is carrying it, so no request goes out with your real IP address.</p>
          <p>Reason: ${reason}.</p>
          <p>Once the panel shows a confirmed exit IP, reload with
             <code>Ctrl+R</code>.</p>
        </div></body></html>`
      )).catch(() => {});
    });

    view.webContents.setWindowOpenHandler(({ url: openUrl }) => {
      this.createTab(openUrl);
      return { action: 'deny' };
    });

    return view;
  }

  closeTab(tabId) {
    const tab = this.tabs.get(tabId);
    if (!tab) return;

    tab.closed = true;
    this._dispose(tab);
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
      canGoBack: this._canGoBack(tab),
      canGoForward: tab.view.webContents.navigationHistory.canGoForward(),
    });
  }

  /**
   * What the address bar should say.
   *
   * The built-in pages live on disk and on a loopback port, so navigating to
   * one put `file:///home/.../resources/app/src/ui/newtab.html` in the address
   * bar — the install path of the browser, on screen, in the one field people
   * read and copy. It is also the field they would paste to share a page,
   * which for an internal page is a path that means nothing on anyone else's
   * machine. Internal destinations report the hidra:// name the user typed, or
   * would have typed; everything else is untouched.
   */
  _displayUrl(rawUrl) {
    if (typeof rawUrl !== 'string') return rawUrl;

    if (rawUrl.startsWith(UI_ROOT_URL)) {
      const page = rawUrl.slice(UI_ROOT_URL.length).split(/[?#]/)[0];
      const name = INTERNAL_PAGES[page];
      return name ? `hidra://${name}` : 'hidra://newtab';
    }

    if (rawUrl.startsWith(APPS_ORIGIN)) {
      const rest = rawUrl.slice(APPS_ORIGIN.length);
      const path = rest.split(/[?#]/)[0].replace(/\/+$/, '');
      const name = APPS_ROUTES[path] || APPS_ROUTES[''] || null;
      return name ? `hidra://${name}` : rawUrl;
    }

    return rawUrl;
  }

  // Turns what was typed or clicked into what to load: a page on disk, a URL,
  // or a .hidra name that still has to be looked up.
  _resolve(url) {
    let finalUrl = url;
    if (!url.includes('://') && !url.startsWith('hidra://')) {
      if (url.endsWith('.hidra') || url.includes('.hidra/')) {
        finalUrl = 'hidra://' + url;
      } else if (url.includes('.') && !url.includes(' ')) {
        finalUrl = 'https://' + url;
      } else {
        finalUrl = SEARCH_URL + '?q=' + encodeURIComponent(url);
      }
    }

    if (!finalUrl.startsWith('hidra://')) return { kind: 'url', url: finalUrl, finalUrl };

    const rest = finalUrl.slice('hidra://'.length);
    const name = rest.split(/[/?#]/)[0];

    if (name === 'search') {
      const searchQuery = finalUrl.includes('?q=') ? finalUrl.split('?q=')[1] : '';
      const url = searchQuery ? SEARCH_URL + '?q=' + searchQuery : SEARCH_URL;
      return { kind: 'url', url, finalUrl };
    }

    // The built-in apps, by name. The address bar reports these names when
    // you are on one of these pages, so they have to work typed back in —
    // showing a user an address they cannot use is worse than showing them
    // the raw path.
    const route = INTERNAL_BY_NAME[name];
    if (route && route.endsWith('.html')) return { kind: 'file', file: route, finalUrl };
    if (route) {
      const tail = rest.slice(name.length);
      const query = /^[?#]/.test(tail) ? tail : '';
      return { kind: 'url', url: APPS_ORIGIN + route + query, finalUrl };
    }

    return { kind: 'domain', url: finalUrl, finalUrl };
  }

  // Only a URL can be one of the apps; a page on disk and a .hidra name are
  // not (a .hidra name resolves to a website, the site viewer or reviews).
  _belongsInApps(target) {
    return target.kind === 'url' && wantsAppStorage(target.url);
  }

  _canGoBack(tab) {
    return tab.view.webContents.navigationHistory.canGoBack() || tab.backStack.length > 0;
  }

  async navigate(tabId, url, { returning = false } = {}) {
    const tab = this.tabs.get(tabId);
    if (!tab) return;

    const seq = ++tab.navSeq;
    const target = this._resolve(url);
    tab.url = target.finalUrl;

    const persistent = this._belongsInApps(target);
    if (persistent !== tab.persistent) {
      // Moving partition replaces the view, and its history with it. Keep the
      // page being left, so Back still goes somewhere.
      const leaving = tab.view.webContents.getURL();
      if (!returning && leaving && !leaving.startsWith('data:')) tab.backStack.push(leaving);
      if (!(await this._attach(tab, persistent))) return;
      if (tab.navSeq !== seq) return;
    }

    const wc = tab.view.webContents;
    if (target.kind === 'file') {
      wc.loadFile(path.join(__dirname, '..', 'ui', target.file)).catch(() => {});
    } else if (target.kind === 'domain') {
      this._resolveHidraDomain(tab, target.url, seq);
    } else {
      wc.loadURL(target.url).catch(() => {});
    }
  }

  goBack(tabId) {
    const tab = this.tabs.get(tabId);
    if (!tab) return;
    if (tab.view.webContents.navigationHistory.canGoBack()) {
      tab.view.webContents.navigationHistory.goBack();
      return;
    }
    const previous = tab.backStack.pop();
    if (previous) this.navigate(tabId, previous, { returning: true });
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

  // Every session that has to follow the network route. The apps' one is in
  // here even with no app open, so an app opened later is already routed.
  getAllSessions() {
    const all = new Set([...this.tabs.values()].map(t => t.session).filter(Boolean));
    if (this.appsSession) all.add(this.appsSession);
    return [...all];
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

  _createIsolatedSession(tabId, fingerprint) {
    const partition = `tab-${tabId}-${crypto.randomBytes(8).toString('hex')}`;
    const tabSession = session.fromPartition(partition, { cache: false });
    this._secureSession(tabSession, fingerprint);
    return tabSession;
  }

  // The apps' partition: on disk, so what the apps store survives the tab and
  // the restart. No HTTP cache is kept even so — the only thing worth keeping
  // is what the apps put in their own storage.
  _appsSession() {
    if (!this.appsSession) {
      this.appsSession = session.fromPartition(APPS_PARTITION, { cache: false });
      this._secureSession(this.appsSession, this._appsFingerprint());
      // Chromium writes DOM storage to disk on a delay of several seconds,
      // batching changes. A browser that is killed inside that window —
      // crash, force quit, power loss — loses them, and for HidraMail the
      // change in that window is the address itself: open mail for the first
      // time, lose power, come back to a different address. Measured on the
      // published build: a SIGKILL a few seconds after opening mail lost the
      // address every time; thirty seconds later it was safe. So pending
      // changes are flushed on a short cycle, which costs nothing when there
      // are none.
      this._appsFlushTimer = setInterval(() => this._flushApps(), 3000);
    }
    return this.appsSession;
  }

  _flushApps() {
    if (!this.appsSession) return;
    try {
      this.appsSession.flushStorageData();
    } catch (e) {}
  }

  _appsFingerprint() {
    if (!this.appsFingerprint) this.appsFingerprint = FingerprintEngine.generate();
    return this.appsFingerprint;
  }

  // What every session gets, throwaway or kept: the kill switch, the spoofed
  // user agent, the header stripping and the permission lockdown.
  _secureSession(tabSession, fingerprint) {
    // Every session needs the filter: a session without it is a way straight
    // around the kill switch.
    if (this.networkLock) this.networkLock.protect(tabSession);

    // Without this every request advertises the real Electron user agent
    // ("HidraNet Browser/1.0.0 ... Electron/33"), which both identifies the
    // browser to every server and contradicts the spoofed navigator.userAgent.
    tabSession.setUserAgent(fingerprint.userAgent, fingerprint.languages.join(','));

    tabSession.webRequest.onBeforeSendHeaders((details, callback) => {
      const headers = { ...details.requestHeaders };

      // Chromium hands these over lowercase ("sec-ch-ua"), and delete is
      // case-sensitive — the old fixed-case deletes never matched a single
      // header, so the client hints went out on every request while the UI
      // claimed they were stripped.
      const drop = (name) => {
        const target = name.toLowerCase();
        for (const key of Object.keys(headers)) {
          if (key.toLowerCase() === target) delete headers[key];
        }
      };

      [
        'X-Client-Data',
        'Sec-CH-UA', 'Sec-CH-UA-Platform', 'Sec-CH-UA-Mobile',
        'Sec-CH-UA-Full-Version', 'Sec-CH-UA-Full-Version-List',
        'Sec-CH-UA-Arch', 'Sec-CH-UA-Bitness', 'Sec-CH-UA-Model',
        'Sec-CH-UA-Platform-Version', 'Sec-CH-UA-WoW64',
      ].forEach(drop);

      // Cross-site referrers are the tracking vector; same-origin ones are load
      // bearing (CSRF checks, hotlink protection) so they stay.
      const refKey = Object.keys(headers).find((k) => k.toLowerCase() === 'referer');
      if (refKey) {
        let sameOrigin = false;
        try {
          sameOrigin = new URL(headers[refKey]).origin === new URL(details.url).origin;
        } catch (e) {
          sameOrigin = false;
        }
        if (!sameOrigin) delete headers[refKey];
      }

      callback({ requestHeaders: headers });
    });

    // Allowlist, not denylist. The previous blocklist let through everything that
    // was not in it — including the permissions Chromium added after it was
    // written (serial, hid, usb, idle-detection, clipboard-read). In a privacy
    // tool the default has to be to deny.
    const ALLOWED = new Set(['fullscreen', 'clipboard-sanitized-write']);

    tabSession.setPermissionRequestHandler((_wc, permission, callback) => {
      callback(ALLOWED.has(permission));
    });

    // The synchronous check path does not go through the handler above;
    // without this, some permissions were granted without ever being asked for.
    tabSession.setPermissionCheckHandler((_wc, permission) => ALLOWED.has(permission));

    // WebUSB, WebHID and Web Serial: no device, under any circumstances.
    tabSession.setDevicePermissionHandler(() => false);

    return tabSession;
  }

  // While the user is browsing, keyboard focus lives in the BrowserView, so the
  // keydown listener in browser.js never fires. Mirror the shortcuts here.
  _bindShortcuts(view, tabId) {
    view.webContents.on('before-input-event', (event, input) => {
      if (input.type !== 'keyDown') return;

      const mod = input.control || input.meta;
      const key = (input.key || '').toLowerCase();

      let action = null;
      if (mod && key === 't') action = () => this.createTab('hidra://newtab');
      else if (mod && key === 'w') action = () => this.closeTab(tabId);
      else if (mod && key === 'l') action = () => this._focusAddressBar();
      else if ((mod && key === 'r') || key === 'f5') action = () => this.reload(tabId);
      if (!action) return;

      // preventDefault has to come first: closing the tab destroys the
      // webContents this very event belongs to.
      event.preventDefault();
      action();
    });
  }

  _focusAddressBar() {
    if (this.window && !this.window.isDestroyed()) {
      this.window.webContents.focus();
      this._notifyUI('ui:focus-url', {});
    }
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

  // A load decided after the navigation started, once a lookup came back. It
  // is dropped if the user has gone somewhere else in the meantime, and goes
  // through navigate() if it lands on the other side of the line between the
  // apps and the web.
  _loadLater(tab, seq, url) {
    if (tab.closed || tab.navSeq !== seq) return;
    if (wantsAppStorage(url) !== tab.persistent) {
      this.navigate(tab.id, url);
      return;
    }
    tab.view.webContents.loadURL(url).catch(() => {});
  }

  async _resolveHidraDomain(tab, hidraUrl, seq = tab.navSeq) {
    const hostname = hidraUrl.replace('hidra://', '').split('/')[0];
    const pathPart = hidraUrl.replace('hidra://', '').substring(hostname.length);

    // Network .hidra address (encrypted site on the relay): long base32 label.
    const label = hostname.replace('.hidra', '');
    if (label.length >= 24 && /^[a-z2-7]+$/.test(label)) {
      this._loadLater(tab, seq, APPS_ORIGIN + '/site?addr=' + encodeURIComponent(hostname));
      return;
    }

    this._loadLater(tab, seq, 'data:text/html,' + encodeURIComponent(
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
          this._loadLater(tab, seq, `http://${data.address}${pathPart}`);
          return;
        }
      }
    } catch {
      // DHT resolver not available
    }

    // Fallback: ask SevenNine, which hosts .hidra sites locally.
    for (const port of [8084]) {
      try {
        const res = await fetch(
          `http://127.0.0.1:${port}/api/resolve?name=${encodeURIComponent(siteName)}`,
          { signal: AbortSignal.timeout(2000) }
        ).catch(() => null);

        if (res && res.ok) {
          const data = await res.json();
          if (data.found) {
            this._loadLater(tab, seq, `http://${data.address}${data.path || ''}`);
            return;
          }
        }
      } catch {
        // service unavailable — try the next one
      }
    }

    // Last resort: HidraReview. Every business has a
    // <slug>.hidra address to write onto NFC cards, and the page resolves it
    // against the network — if it does not exist, it says so with a way back
    // to the directory, instead of a dead end.
    this._loadLater(tab, seq, 
      `${APPS_ORIGIN}/reviews?b=${encodeURIComponent(siteName)}`
    );
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

module.exports = {
  TabManager,
  INTERNAL_BY_NAME,
  wantsAppStorage,
  appNamespace,
  vaultNamespaceOf,
  APPS_PARTITION,
  APPS_ORIGIN,
  UI_ROOT_URL,
};
