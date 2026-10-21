'use strict';
/**
 * Puts a tab's fingerprint in place before any of a page's own code runs, in
 * every frame and every worker the page starts.
 *
 * It used to be injected on dom-ready, with executeJavaScript, into the main
 * frame only. Measured on Electron 44, with a Windows profile on a Linux
 * machine, a page could read the real values four ways:
 *   - any script in its <head> runs before dom-ready, and saw the real
 *     navigator.platform, time zone and screen;
 *   - navigator.userAgentData was never touched, and said Linux throughout;
 *   - a fresh iframe has its own, untouched navigator;
 *   - a worker runs outside the page, and saw the real platform and cores.
 *
 * Now each tab drives its own page through the DevTools protocol, which acts
 * inside Chromium rather than beside the page: the user agent with
 * navigator.platform and userAgentData to match, the time zone and the core
 * count are overridden for the target, the page script is registered to run
 * at the start of every document, and frames on other sites (their own
 * targets) and dedicated workers are held at their start until the same is
 * in place for them. Shared and service workers start outside the tab; the
 * page script switches them off (see engine.js).
 */
const { FingerprintEngine } = require('../fingerprint/engine');

/**
 * Applies the fingerprint to a freshly built tab, before it loads anything.
 * Resolves true when the protocol is in place, false when it could not be
 * (another debugger attached, say): the caller then falls back to injecting
 * the page script on dom-ready, which is weaker and the best left.
 */
async function guardFingerprint(webContents, fp) {
  const dbg = webContents.debugger;
  const page = FingerprintEngine.buildInjectionScript(fp);
  const worker = FingerprintEngine.buildWorkerScript(fp);
  const ua = FingerprintEngine.userAgentOverride(fp);

  // A target with no document yet takes no commands: they wait for one that
  // never comes. So the view first holds a blank page, which leaves the
  // history once the first real page is shown.
  try {
    await webContents.loadURL('about:blank');
    dbg.attach('1.3');
  } catch (e) {
    console.error('[fingerprint] could not attach to the tab:', e.message);
    return false;
  }

  const send = (method, params, sessionId) =>
    sessionId ? dbg.sendCommand(method, params || {}, sessionId) : dbg.sendCommand(method, params || {});

  const frame = async (sessionId) => {
    await send('Page.enable', {}, sessionId);
    await send('Page.addScriptToEvaluateOnNewDocument', { source: page }, sessionId);
    await send('Emulation.setUserAgentOverride', ua, sessionId);
    await send('Emulation.setTimezoneOverride', { timezoneId: fp.timezone }, sessionId);
    await send('Emulation.setHardwareConcurrencyOverride', { hardwareConcurrency: fp.hardwareConcurrency }, sessionId);
    await send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, sessionId);
  };
  const dedicatedWorker = async (sessionId) => {
    await send('Runtime.evaluate', { expression: worker }, sessionId);
  };

  dbg.on('message', (_event, method, params) => {
    if (method !== 'Target.attachedToTarget') return;
    const child = params.sessionId;
    const type = params.targetInfo && params.targetInfo.type;
    const setup = type === 'iframe' ? frame(child)
      : type === 'worker' ? dedicatedWorker(child)
      : Promise.resolve();
    // Whatever happened, the frame or worker is let go: held at its start,
    // it would hang the page.
    setup
      .catch((e) => console.error('[fingerprint] could not set up a ' + type + ':', e.message))
      .finally(() => send('Runtime.runIfWaitingForDebugger', {}, child).catch(() => {}));
  });

  try {
    await frame();
  } catch (e) {
    console.error('[fingerprint] could not set up the tab:', e.message);
    try { dbg.detach(); } catch (_) {}
    return false;
  }

  // Ahead of the tab's own did-navigate handler, which tells the toolbar
  // whether Back is possible: by then the blank page has to be gone.
  webContents.prependOnceListener('did-navigate', () => {
    const history = webContents.navigationHistory;
    try {
      if (history.length() > 1 && history.getEntryAtIndex(0).url === 'about:blank') history.removeEntryAtIndex(0);
    } catch (e) { /* an older Electron without these: Back shows a blank page once */ }
  });
  return true;
}

module.exports = { guardFingerprint };
