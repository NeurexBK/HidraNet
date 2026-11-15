# HidraNet

Open-source privacy tools that work together:

- **HidraNet Browser**, a desktop browser with Tor built in and HidraNet's own
  apps beside it: encrypted mail and chat, a forum and `.hidra` site
  publishing;
- **HidraVPN**, a VPN with no sign-up, paid with passes bought in **HNET**,
  the project's token on Solana.

Download them from **https://hidranet.org**. Every release is also on the
[releases page](https://github.com/NeurexBK/HidraNet/releases).

## HidraNet Browser

For Windows, macOS (Apple Silicon and Intel) and Linux.

- Tor starts with the browser, and nothing leaves the machine until Tor is
  carrying the traffic.
- Each website tab is isolated: its own cookies, storage and fingerprint,
  cleared when the tab closes. HidraNet's own apps share one profile kept on
  disk, so your mail address and its keys survive a restart.
- HidraNet's own apps: HidraMail (end-to-end encrypted, with `@hidra`
  addresses), HidraChat (end-to-end encrypted, no phone number), a forum, and
  `.hidra` sites you publish yourself.
- Its VPN page installs, updates and drives HidraVPN, and buys its passes.

Source: [`hidra-browser/`](hidra-browser/), with the engine in
[`hidra-node/`](hidra-node/).

## HidraVPN

For Windows x64 and Linux x64.

- **Two modes.** Fast (one hop): the node sees your address and your traffic,
  and hides them from your own network. Private (two hops): the entry sees
  your address, the exit sees your traffic, and no node sees both.
- **Kill switch** on by default. DNS goes through the tunnel; IPv6 goes
  through it when the exit carries IPv6, and is blocked when it does not.
- **No sign-up.** The account is anonymous and prepaid: the pass issuer knows
  it only by the SHA-256 of a random token kept on your machine, with no
  name, e-mail or card.
- **Paid in HNET.** A connection through a node that takes passes spends one
  pass. Passes come in packs, paid in HNET from your own Solana wallet to the
  wallet the signed node list names. Pack prices are set in dollars and turned
  into HNET at the going rate when the order is made. The browser's VPN page
  (Settings, Passes, Buy passes with HNET, Show packages) or
  `sudo hidravpn passes buy` (from an administrator prompt on Windows) lists
  the packs on sale. The HNET mint is
  `Aov3BtQvrGXM5V9oiHu8PKJWeV8a2rFnr24fwWcNpump`.
- **Passes signed blind.** The issuer never learns which node a pass is for,
  and a node never learns from a pass which account it came from. Against the
  maintainers this is not unlinkability: they run the issuer and every node,
  the issuer sees the address you fetch or buy passes from, and someone who
  watches both can compare times.

Source and documentation: [`hidravpn/`](hidravpn/README.md).

## Checking what you download

- **The browser:** compare each package with
  [`SHA256SUMS.txt`](https://hidranet.org/SHA256SUMS.txt)
  ([`landing/SHA256SUMS.txt`](landing/SHA256SUMS.txt) here). Its signature,
  `SHA256SUMS.txt.sig`, is made offline with the release key, and the browser
  checks it before it tells you of a new version.
- **HidraVPN:** the browser installs it only from the release manifest
  ([`landing/vpn/release/manifest.json`](landing/vpn/release/manifest.json)),
  signed with the same key, and refuses any file whose SHA-256 or size
  differs. From HidraVPN 0.1.2 on, the Windows executables are built by GitHub
  Actions (`hidravpn-build.yml`) on a push to `main` and carry a build
  attestation:
  `gh attestation verify hidravpn.exe --repo NeurexBK/HidraNet --signer-workflow NeurexBK/HidraNet/.github/workflows/hidravpn-build.yml --source-ref refs/heads/main`.
- **The release key** (Ed25519, base64):
  `denZsjS2YtKOo4LRIGGTaKuHIWDFigChoLa71o0jBq8=`. It and the key that signs
  the node list are also listed on https://hidranet.org/vpn/.

## What it is not

- HidraVPN is not Tor, and it does not make you anonymous: it changes who sees
  what, and with two hops it splits that.
- Today the maintainers run every node and the pass issuer, so two hops are
  refused unless you allow one operator on both (a box on the VPN page, or
  `--allow-same-operator`). Once allowed, they put your address and your
  traffic on different machines, but not with different people, and the VPN
  page says so.
- When you buy or fetch passes, the issuer sees the payment and, for now, the
  address the request comes from: yours when you are not connected, since
  these requests go from the HidraVPN service and not through Tor. Buying
  through Tor is planned. Payments on Solana are public.
- None of the builds are Authenticode-signed or notarised yet.
- Nothing here has had an independent security audit. [`SECURITY.md`](SECURITY.md)
  says what HidraNet defends against and what it does not.

## In this repository

| Folder | What |
|---|---|
| [`hidra-browser/`](hidra-browser/) | HidraNet Browser (Electron) |
| [`hidra-node/`](hidra-node/) | the HidraNet engine (Rust) |
| [`hidravpn/`](hidravpn/) | HidraVPN: the client, the service, the node and the pass issuer (Rust) |
| [`hidra-monitor/`](hidra-monitor/) | a panel that counts the clients sending a presence signal |
| [`landing/`](landing/) | the site at https://hidranet.org |
| [`brand/`](brand/) | the HidraNet logo files and the script that makes them |
| [`docs/`](docs/) | technical, business, corporate, legal, security, brand and community documents |

## License

MIT: see [`LICENSE`](LICENSE).
