// HidraNet's icon, wherever the operating system shows one.
//
// The packages ship Electron's own executable, renamed and untouched: on
// Windows, editing it to carry another icon would change its hash, and Smart
// App Control and SmartScreen would then treat it as an unknown program and
// block it (see scripts/pack-portable.js). So the icon is given everywhere it
// can be without touching the binary:
//
//   - the window, which is what the taskbar and the window switcher show on
//     Windows and Linux;
//   - the Dock on macOS (the bundle's own icon is replaced when the package
//     is built: scripts/patch-zip.js);
//   - on Windows, shortcuts in the Start menu and on the desktop that carry
//     the icon, made once, on the first start;
//   - on Linux, an entry in the applications menu.
//
// Nothing here runs from a development checkout (`npm start`): only a
// packaged browser puts shortcuts on someone's machine.

const fs = require('fs');
const path = require('path');

const IMG = path.join(__dirname, '..', 'ui', 'img');
const ICON_PNG = path.join(IMG, 'hidranet-icon.png');
const ICON_ICO = path.join(IMG, 'hidranet.ico');
const APP_ID = 'net.hidra.browser';
const SHORTCUT_NAME = 'HidraNet.lnk';

/** The icon for a BrowserWindow, or undefined if it cannot be read. */
function windowIcon(nativeImage) {
  try {
    const img = nativeImage.createFromPath(ICON_PNG);
    return img.isEmpty() ? undefined : img;
  } catch (e) {
    return undefined;
  }
}

// The icon files are copied out of the app before a shortcut or a menu entry
// points at them: inside an asar archive the system could not read them, and
// a copy in the profile keeps working whatever happens to the package.
function stableCopy(app, file) {
  const dest = path.join(app.getPath('userData'), path.basename(file));
  try {
    const want = fs.readFileSync(file);
    let have = null;
    try { have = fs.readFileSync(dest); } catch (e) { /* not there yet */ }
    if (!have || !have.equals(want)) fs.writeFileSync(dest, want);
    return dest;
  } catch (e) {
    return null;
  }
}

function windowsShortcuts(app, shell) {
  const ico = stableCopy(app, ICON_ICO);
  if (!ico) return;
  const marker = path.join(app.getPath('userData'), 'shortcuts-made');
  const options = {
    target: process.execPath,
    cwd: path.dirname(process.execPath),
    icon: ico,
    iconIndex: 0,
    appUserModelId: APP_ID,
    description: 'HidraNet Browser',
  };
  const places = [
    path.join(app.getPath('appData'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', SHORTCUT_NAME),
    path.join(app.getPath('desktop'), SHORTCUT_NAME),
  ];
  const firstStart = !fs.existsSync(marker);
  for (const lnk of places) {
    try {
      if (fs.existsSync(lnk)) {
        // Kept pointing at this copy if the folder was moved; left alone if
        // it is someone else's shortcut with the same name.
        const cur = shell.readShortcutLink(lnk);
        if (cur.appUserModelId === APP_ID && cur.target !== options.target) shell.writeShortcutLink(lnk, 'update', options);
      } else if (firstStart) {
        // Only on the first start: a shortcut the user deleted stays deleted.
        shell.writeShortcutLink(lnk, 'create', options);
      }
    } catch (e) {
      console.error('[icon] shortcut', lnk, e.message);
    }
  }
  try { fs.writeFileSync(marker, new Date().toISOString()); } catch (e) { /* next start tries again */ }
}

// A .desktop file is a key=value text format; a path with a newline in it
// would add keys of its own, so such a path is not written at all.
function desktopEntry(execPath, iconPath) {
  if (/[\r\n]/.test(execPath + iconPath)) return null;
  const quoted = '"' + execPath.replace(/(["`$\\])/g, '\\$1') + '"';
  return [
    '[Desktop Entry]',
    'Type=Application',
    'Name=HidraNet',
    'GenericName=Private Browser',
    'Comment=Browse through Tor and the HidraNet network',
    'Exec=' + quoted + ' %U',
    'Icon=' + iconPath,
    'Terminal=false',
    'Categories=Network;WebBrowser;',
    // Electron names the window after the package (resources/app/package.json).
    'StartupWMClass=hidra-browser',
    '',
  ].join('\n');
}

function linuxMenuEntry(app) {
  const png = stableCopy(app, ICON_PNG);
  if (!png) return;
  const dir = path.join(app.getPath('home'), '.local', 'share', 'applications');
  const file = path.join(dir, 'hidranet.desktop');
  const body = desktopEntry(process.execPath, png);
  if (!body) return;
  try {
    let cur = null;
    try { cur = fs.readFileSync(file, 'utf8'); } catch (e) { /* not there yet */ }
    if (cur === body) return;
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(file, body, { mode: 0o644 });
  } catch (e) {
    console.error('[icon] menu entry', e.message);
  }
}

/** Call once the app is ready. */
function applyAppIcon({ app, nativeImage, shell }) {
  if (process.platform === 'darwin' && app.dock) {
    const img = windowIcon(nativeImage);
    if (img) app.dock.setIcon(img);
  }
  if (process.platform === 'win32') app.setAppUserModelId(APP_ID);
  if (!app.isPackaged) return;
  if (process.platform === 'win32') windowsShortcuts(app, shell);
  if (process.platform === 'linux') linuxMenuEntry(app);
}

module.exports = { applyAppIcon, windowIcon, desktopEntry, ICON_PNG, ICON_ICO, APP_ID };
