HidraVPN for Windows
====================

What is in this folder
----------------------
  hidravpn.exe           the client command line
  hidravpn-service.exe   the background service (holds the tunnel, arms the kill switch)
  hidravpn-sign.exe      verifies a download against the project's release signature
  wintun.dll             the Wintun driver, signed by WireGuard LLC (not built by us)
  SHA256SUMS.txt         SHA-256 of the four files above, made after signing
  LICENSE-wintun.txt     Wintun's licence

The three .exe files are code-signed (Authenticode) through SignPath.io under
the SignPath Foundation open-source programme, from the public source at
github.com/NeurexBK/HidraNet. They run under Smart App Control and SmartScreen
without turning any protection off.

Verify before you run anything (recommended)
--------------------------------------------
In PowerShell, in this folder:

  Get-FileHash *.exe, wintun.dll -Algorithm SHA256      # compare with SHA256SUMS.txt
  Get-AuthenticodeSignature *.exe, wintun.dll           # Status must be Valid

If the release page carries SHA256SUMS-<version>.txt.sig, also check the
project's own signature with the project public key published on the
HidraNet site:

  .\hidravpn-sign.exe verify --pubkey <project public key> SHA256SUMS-<version>.txt

Install
-------
1. Put this whole folder somewhere permanent, for example C:\HidraVPN
   (wintun.dll must stay beside the executables).
2. Open PowerShell "as Administrator" in that folder and run:

     .\hidravpn-service.exe install     # registers and starts the service
     .\hidravpn.exe keygen              # once; this machine's master key

3. Every node is shown a different key derived from the master key. Ask the
   node's administrator for the node's public key (hidravpn-node pubkey), run
   .\hidravpn.exe pubkey --node <that key>, and send the administrator what
   it prints; they admit it and send you an invite file (invite.json).

Use
---
  .\hidravpn.exe up invite.json        # connect: routes everything, arms the kill switch
  .\hidravpn.exe status                # connected? kill switch on?
  .\hidravpn.exe down                  # disconnect and restore the network

With the kill switch armed, nothing leaves the machine outside the tunnel; if
the tunnel drops, traffic stops instead of leaking. Remove everything with:

  .\hidravpn-service.exe uninstall

Privacy
-------
HidraVPN gives strong privacy: the exit node sees your traffic leave, your
network sees only encrypted packets to the node. Nothing here logs an address,
a name looked up or a byte of traffic. It is not a promise of anonymity.
