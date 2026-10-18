# HidraVPN in the browser (parked)

HidraVPN is not ready for the public, so the HidraNet Browser ships without
it. Its half of the browser is kept here, out of the browser, so nothing of
it is in the packages, and so it keeps being tested while the VPN is built.
The layout mirrors `hidra-browser/`:

| File | What it is |
| --- | --- |
| `src/main/vpn-manager.js` | Talks to the service on this machine over its control channel |
| `src/main/vpn-installer.js` | Installs, updates and removes the service from a signed release |
| `src/main/vpn-leaktest.js` | The one-click leak test |
| `src/main/release-verify.js` | Checks release files against the release key (Ed25519, same as `hidravpn-sign`) |
| `src/ui/hidravpn.html` | The VPN page |
| `test/*.js` | Their tests; `vpn-live.js` is driven by `scripts/test-browser-netns.sh` |

Run the tests with node, from the top of the repository:

    for t in vpn-manager vpn-installer vpn-leaktest release-verify vpn-page; do
      node hidravpn/browser/test/$t.js || break
    done

`scripts/test-browser-netns.sh`, `test-client-installer.sh`,
`test-passes-netns.sh` and `embed-release-key.sh` use these files from here.

## Bringing it back

The wiring that connected these files to the browser was taken out in the
commit "Remove HidraVPN from the browser for now". Reverting that commit
moves everything back into `hidra-browser/` and restores the wiring with it:

- `hidra-browser/src/main/main.js`: the `vpn:*` IPC handlers, each refusing
  any sender but the VPN page (`isVpnPage`); the fetches of the signed node
  list and release files, refused while Tor is not ready; the leak test's
  direct session;
- `hidra-browser/src/renderer/tab-preload.js`: the `vpn` bridge, offered to
  `hidravpn.html` only, and its status alone to the new tab page;
- `hidra-browser/src/main/tab-manager.js`: the `hidra://vpn` address;
- `hidra-browser/src/ui/newtab.html`: the HidraVPN card and its badge;
- the browser's tests that cover them (`ipc-senders.js`,
  `preload-boundary.js`) and the wiring checks of `test/vpn-page.js`;
- the VPN tests in `.github/workflows/browser-tests.yml`.

The website lost its HidraVPN pages in the same commit (the technical
whitepaper's VPN section, the token paper's VPN passes, the terms); they
come back with the revert too.
