// Who is asking? Every ipcMain handler in main.js answers one question
// before it does anything: which of our pages sent this, and is it one of
// the pages that call it? The answer comes from the frame that sent the
// message (Electron fills event.senderFrame in), never from anything the
// page passed along.
//
// A page counts as ours only when it is the main frame of its tab or window
// and its address is one of the files shipped under src/ui, by exact name.
// "Any page under src/ui" is not narrow enough: a script that got into one of
// them (the chat once ran a stranger's script through a member's colour)
// would then hold everything every other page holds. So each handler names
// the pages that use it, and only those.

'use strict';

// The file name of the page that sent the event ("newtab.html"), or null
// when the sender is a subframe, a website, an app on the loopback origin,
// or anything that is not one of our files. The query and the fragment are
// dropped before comparing: neither changes which file was loaded.
function senderPage(event, uiRootUrl) {
  const frame = event && event.senderFrame;
  if (!frame || !event.sender || frame !== event.sender.mainFrame) return null;
  if (typeof uiRootUrl !== 'string' || !uiRootUrl.startsWith('file:')) return null;
  let url;
  try { url = new URL(frame.url || ''); } catch { return null; }
  if (url.protocol !== 'file:') return null;
  url.search = '';
  url.hash = '';
  // The URL parser has already resolved ../ and %2e%2e, so a page cannot
  // spell its way out of the folder or into another file's name.
  const href = url.href;
  if (!href.startsWith(uiRootUrl)) return null;
  const name = href.slice(uiRootUrl.length);
  return /^[a-z0-9-]+\.html$/.test(name) ? name : null;
}

// Throws unless the sender is one of `pages`. The message names the page
// that was refused, which helps whoever wires up a new caller.
function requirePage(event, uiRootUrl, pages, what) {
  const page = senderPage(event, uiRootUrl);
  if (!page || !pages.includes(page)) {
    throw new Error(`refused: ${what || 'this call'} is not offered to ${page || 'this page'}`);
  }
  return page;
}

module.exports = { senderPage, requirePage };
