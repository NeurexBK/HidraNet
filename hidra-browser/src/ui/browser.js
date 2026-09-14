const tabsContainer = document.getElementById('tabs-container');
const urlInput = document.getElementById('url-input');
const btnBack = document.getElementById('btn-back');
const btnForward = document.getElementById('btn-forward');
const btnReload = document.getElementById('btn-reload');
const btnNewTab = document.getElementById('btn-new-tab');
const btnHidraPanel = document.getElementById('btn-hidra-panel');
const hidraPanel = document.getElementById('hidra-panel');
const proxyDot = document.getElementById('proxy-dot');
const proxyLabel = document.getElementById('proxy-label');

let activeTabId = null;

// === TAB MANAGEMENT ===

function createTabElement(tabId, title) {
  const tab = document.createElement('div');
  tab.className = 'tab';
  tab.dataset.tabId = tabId;

  const titleSpan = document.createElement('span');
  titleSpan.className = 'tab-title';
  titleSpan.textContent = title || 'New Tab';

  const closeBtn = document.createElement('button');
  closeBtn.className = 'tab-close';
  closeBtn.textContent = '✕';
  closeBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    window.hidra.tab.close(tabId);
  });

  tab.appendChild(titleSpan);
  tab.appendChild(closeBtn);

  tab.addEventListener('click', () => {
    window.hidra.tab.activate(tabId);
  });

  tabsContainer.appendChild(tab);
  return tab;
}

function setActiveTab(tabId) {
  activeTabId = tabId;
  document.querySelectorAll('.tab').forEach(t => {
    t.classList.toggle('active', parseInt(t.dataset.tabId) === tabId);
  });
}

function removeTabElement(tabId) {
  const el = tabsContainer.querySelector(`[data-tab-id="${tabId}"]`);
  if (el) el.remove();
}

function updateTabTitle(tabId, title) {
  const el = tabsContainer.querySelector(`[data-tab-id="${tabId}"] .tab-title`);
  if (el) el.textContent = title;
}

function setTabLoading(tabId, loading) {
  const tab = tabsContainer.querySelector(`[data-tab-id="${tabId}"]`);
  if (!tab) return;

  const existing = tab.querySelector('.tab-loading');
  if (loading && !existing) {
    const spinner = document.createElement('div');
    spinner.className = 'tab-loading';
    tab.insertBefore(spinner, tab.firstChild);
  } else if (!loading && existing) {
    existing.remove();
  }
}

// === NAVIGATION ===

urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && activeTabId !== null) {
    const value = urlInput.value.trim();
    if (value) {
      window.hidra.tab.navigate(activeTabId, value);
      urlInput.blur();
    }
  }
});

urlInput.addEventListener('focus', () => {
  urlInput.select();
});

btnBack.addEventListener('click', () => {
  if (activeTabId !== null) window.hidra.tab.goBack(activeTabId);
});

btnForward.addEventListener('click', () => {
  if (activeTabId !== null) window.hidra.tab.goForward(activeTabId);
});

btnReload.addEventListener('click', () => {
  if (activeTabId !== null) window.hidra.tab.reload(activeTabId);
});

btnNewTab.addEventListener('click', () => {
  window.hidra.tab.create();
});

// === HIDRA PANEL ===

btnHidraPanel.addEventListener('click', () => {
  hidraPanel.classList.toggle('hidden');
  if (!hidraPanel.classList.contains('hidden')) {
    refreshProxyStatus();
  }
});

document.addEventListener('click', (e) => {
  if (!hidraPanel.contains(e.target) && e.target !== btnHidraPanel && !btnHidraPanel.contains(e.target)) {
    hidraPanel.classList.add('hidden');
  }
});

document.getElementById('panel-new-identity').addEventListener('click', async (e) => {
  const btn = e.currentTarget;
  const label = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Trocando…';
  try {
    const r = await window.hidra.tor.newIdentity();
    if (r && r.ok) {
      btn.textContent = r.changed ? r.exitIp : 'Mesmo nó — repita';
    } else {
      btn.textContent = 'Falhou';
    }
  } catch (err) {
    btn.textContent = 'Falhou';
  }
  setTimeout(() => { btn.textContent = label; btn.disabled = false; }, 4000);
  refreshProxyStatus();
});

async function refreshProxyStatus() {
  const status = await window.hidra.proxy.status();

  const panelStatus = document.getElementById('panel-status');
  if (status.connected && (status.mode === 'tor' || status.mode === 'full')) {
    const exit = status.tor && status.tor.exitIp;
    panelStatus.textContent = exit ? `Anônimo — ${exit}` : 'Anônimo (Tor)';
    panelStatus.style.color = '#00d4aa';
    proxyDot.className = 'connected';
    proxyLabel.textContent = 'Anônimo';
  } else if (status.connected) {
    panelStatus.textContent = 'Conectado — Local';
    panelStatus.style.color = '#00d4aa';
    proxyDot.className = 'connected';
    proxyLabel.textContent = 'Modo Local';
  } else {
    panelStatus.textContent = 'Desconectado';
    panelStatus.style.color = '#ff4466';
    proxyDot.className = 'disconnected';
    proxyLabel.textContent = 'Desconectado';
  }

  document.getElementById('panel-proxy').textContent =
    `${status.host}:${status.port}`;
  document.getElementById('panel-relays').textContent =
    status.relayCount || '—';
  document.getElementById('panel-latency').textContent =
    status.latencyMs ? `${status.latencyMs}ms` : '—';
}

// === WINDOW CONTROLS ===

document.getElementById('btn-minimize').addEventListener('click', () => {
  window.hidra.window.minimize();
});

document.getElementById('btn-maximize').addEventListener('click', () => {
  window.hidra.window.maximize();
});

document.getElementById('btn-close').addEventListener('click', () => {
  window.hidra.window.close();
});

// === KEYBOARD SHORTCUTS ===

document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.key === 't') {
    e.preventDefault();
    window.hidra.tab.create();
  }
  if (e.ctrlKey && e.key === 'w') {
    e.preventDefault();
    if (activeTabId !== null) window.hidra.tab.close(activeTabId);
  }
  if (e.ctrlKey && e.key === 'l') {
    e.preventDefault();
    urlInput.focus();
    urlInput.select();
  }
  if (e.ctrlKey && e.key === 'r') {
    e.preventDefault();
    if (activeTabId !== null) window.hidra.tab.reload(activeTabId);
  }
  if (e.key === 'F5') {
    e.preventDefault();
    if (activeTabId !== null) window.hidra.tab.reload(activeTabId);
  }
});

// === IPC EVENT HANDLERS ===

window.hidra.on('tab:created', (data) => {
  createTabElement(data.tabId, data.title);
});

window.hidra.on('tab:closed', (data) => {
  removeTabElement(data.tabId);
});

window.hidra.on('tab:activated', (data) => {
  setActiveTab(data.tabId);
  urlInput.value = data.url || '';
  btnBack.disabled = !data.canGoBack;
  btnForward.disabled = !data.canGoForward;
});

window.hidra.on('tab:title', (data) => {
  updateTabTitle(data.tabId, data.title);
});

window.hidra.on('tab:navigated', (data) => {
  if (data.tabId === activeTabId) {
    urlInput.value = data.url || '';
    btnBack.disabled = !data.canGoBack;
    btnForward.disabled = !data.canGoForward;
  }
});

window.hidra.on('tab:loading', (data) => {
  setTabLoading(data.tabId, data.loading);
});

// Ctrl+L pressed while the page had focus — the main process hands focus back
// to the chrome so the address bar can take it.
window.hidra.on('ui:focus-url', () => {
  urlInput.focus();
  urlInput.select();
});

// === INIT ===

setInterval(refreshProxyStatus, 5000);
refreshProxyStatus();
