# HidraNet Browser 1.0.0

A browser for private browsing, with Tor built in and HidraNet's own apps alongside it: encrypted mail, chat, a forum and `.hidra` site publishing. For Windows, macOS (Apple Silicon and Intel) and Linux.

These packages are refreshed in place. The files on this page are rebuilt from the current source and replace the previous ones under the same names, and the table at the bottom is generated from the files that were actually uploaded. If a hash does not match your download, do not run it.

## What is in this build

- The whole product in English, the apps included.
- Tor starts with the browser. Nothing leaves the machine until Tor is carrying the traffic, and the panel shows a verified exit address once it is. Tor exits when the browser does, even after a crash.
- Websites are isolated per tab: separate cookies, storage and fingerprint, cleared when the tab closes. Client hints and cross-site referrers are stripped; WebRTC cannot reveal the real address.
- HidraNet's own apps keep your identity across tabs and restarts: the mail address and its keys, the forum name, the chat's recent rooms and the sites you published. They are kept in a vault under the system keychain — the macOS Keychain, Windows DPAPI, GNOME Keyring or KWallet. Where a system has no keychain, HidraMail and the privacy panel say so.
- HidraMail is end-to-end encrypted and every message is signed by its sender. Mail sent while you were away is delivered when you come back. Several addresses can be kept and switched between.
- HidraChat: the same password is the same room, end-to-end encrypted. Leaving the password empty opens a new private room with a strong password to pass on.
- The forum and `.hidra` sites work between people on different networks.
- Support the project in $HNET from the Donate page.
- Linux: the browser's sandbox stays on. On Ubuntu 23.10 and later, `start.sh` sets up the helper the sandbox needs and asks once for your password to do it.

## Running it

| System | Open |
|---|---|
| Windows | Extract the ZIP and run `Start HidraNet.bat` (or `HidraNet.exe`). SmartScreen may warn that the publisher is unknown: the build is not signed. Check the hash below instead. |
| macOS | Extract the ZIP and run `Start HidraNet.command`. The app is not notarised, and on Apple Silicon macOS reports an unsigned app as "damaged"; the command clears that. `README-macOS.txt` in the package explains it and the manual steps. |
| Linux | Extract the ZIP and run `bash start.sh`. |

The first start takes 20 to 40 seconds while Tor connects; the panel shows the progress.

## Verifying your download

```
sha256sum HidraNet-Browser-1.0.0-Linux-x64.zip            # Linux
shasum -a 256 HidraNet-Browser-1.0.0-macOS-arm64.zip      # macOS
Get-FileHash .\HidraNet-Browser-1.0.0-Windows-x64.zip -Algorithm SHA256   # Windows PowerShell
```

Compare the result with the table below. The same table is kept in the repository at `landing/SHA256SUMS.txt`, written by the run that uploaded the files.

None of these builds are signed or notarised. `SECURITY.md` in the repository says what this browser defends against and what it does not; read it before relying on it for anything that matters.
