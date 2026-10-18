# HidraNet brand files

`logo/hidranet-logo-black.jpg` is the master: the three-headed hydra, green on
black. Everything else in `logo/` is made from it by `make_brand.py`:

```bash
python3 brand/make_brand.py brand/logo/hidranet-logo-black.jpg brand/logo
```

It needs Pillow. The transparent versions take their alpha from how far each
pixel is from black, so the logo's soft edges stay soft on any background.

Where the files are used:

- the browser: `hidra-browser/src/ui/img/` (title bar, tabs, new tab page,
  apps), the window and Dock icon and the Windows shortcuts
  (`src/main/app-icon.js`), and the macOS bundle icon, swapped in when the
  release packages are built (`scripts/refresh-release.js`);
- the engine's chat page: `hidra-node/assets/img/`, the same files byte for
  byte (a test checks);
- the website: `landing/assets/hidranet-logo.png`, `landing/icons/`,
  `landing/favicon.ico` and the link preview `landing/assets/hidranet-social.png`;
- the presence monitor: `hidra-monitor/img/`.

After changing the master, run the script and copy the files to those places.
