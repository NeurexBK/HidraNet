# HidraVPN — code signing (Windows)

Windows 11 with Smart App Control refuses to run an unsigned binary, and even
without it an unsigned download shows a SmartScreen warning. So the HidraVPN
Windows executables — `hidravpn.exe` (the client), `hidravpn-service.exe` (the
service) and `hidravpn-sign.exe` (the download verifier) — are signed with an
Authenticode certificate. Signed, they run cleanly without the user having to
weaken any security setting on their machine.

We never ask a user to turn Smart App Control off. The only correct fix is a
signature, and that is what this sets up.

## How it works

Signing is done by **SignPath.io** through the **SignPath Foundation** free
programme for open-source projects. The private key lives in SignPath's HSM
and never touches this repository, a developer's machine, or a build runner.

The binaries that get signed are built **only** by GitHub Actions, from the
checked-in source, in the workflow `.github/workflows/hidravpn-build.yml`. That
workflow builds the three executables, uploads them, and — once signing is
turned on — hands that exact build to SignPath to sign. SignPath verifies the
build came from this repository before it signs, so a signed HidraVPN binary can
only have come from the public source. On a release tag the same workflow then
packages the signed files with the Wintun driver and publishes the release.

## Code signing policy (for the project page)

Published in full at <https://hidranet.org/code-signing/> (`landing/code-signing/index.html`), linked from the site's footer. Keep the two in step. In short:

> HidraVPN's Windows executables are code-signed through SignPath.io under the
> SignPath Foundation's free open-source programme. The signing certificate's
> private key is held in SignPath's HSM and is never exported. Only the project
> maintainers can start a signing request, and only binaries built by the
> project's GitHub Actions workflow from the public source at
> github.com/NeurexBK/HidraNet are signed. No telemetry is added during the
> build or signing process.

## The day SignPath approves: turning it on

Everything below is already in place and switched off. Turning it on is
configuration only — no code changes.

1. **In SignPath** (they email you when the project is approved): open the
   project, create a *release signing* policy if the application did not, and
   in *Artifact configurations* make one that signs the three `.exe` files in
   the uploaded folder (Authenticode, RSA). Note the values SignPath shows:
   organization id, project slug, signing policy slug, artifact configuration
   slug, and create an **API token** (CI user).
2. **In GitHub** → repository *Settings → Secrets and variables → Actions*:
   - *Secrets*: `SIGNPATH_API_TOKEN` = the API token.
   - *Variables*: `SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG`,
     `SIGNPATH_POLICY_SLUG`, `SIGNPATH_ARTIFACT_SLUG` = the values from step 1.
   - *Variables*: `SIGNPATH_ENABLED` = `true`. This is the switch.
3. **Prove it signs**: *Actions → HidraVPN build → Run workflow* (on
   `main`; only `main` and `hidravpn-v*` tags are ever signed, never a pull
   request or another branch). The `sign with SignPath` job must now run (it
   was skipped before) and leave a `hidravpn-windows-signed` artifact. Download
   it on a Windows machine and check one file:
   `Get-AuthenticodeSignature .\hidravpn.exe` → *Status: Valid*, signer
   SignPath Foundation / HidraNet.
4. If SignPath's project page shows a different `uses:` version or input
   names for their GitHub action, paste theirs over the `sign-windows` job's;
   the one in the workflow is the standard template.

Until step 2 is done the build and the checks run and both the signing and
the release jobs are skipped, so nothing breaks in the meantime.

## Cutting a Windows release

A release is made by a **git tag** of the form `hidravpn-vX.Y.Z`; nothing else
publishes anything, and an unsigned build is never released (the release job
only runs when `SIGNPATH_ENABLED` is `true`, and only after the checks, every
namespace suite, the Windows unit tests and signing have succeeded).

The one exception so far is **0.1.0, a preview for testers**: published by
hand as a GitHub pre-release, without Authenticode, so the browser's Install
button could be tried before SignPath is set up. Its files are listed in
`landing/vpn/release/manifest.json`, signed offline with the release key, and
the browser refuses any file that differs from it. On Windows 11 with Smart App
Control on it does not run. Every earlier test build also calls itself 0.1.0,
so on a machine that runs one, "Check for an update" says it is up to date:
press Uninstall there (without removing the data, which keeps the key and the
nodes), then Install. The first release for everyone goes through this
workflow, signed.

```
git checkout main && git pull
git tag -a hidravpn-v0.3.0 -m "HidraVPN 0.3.0"
git push origin hidravpn-v0.3.0
```

The workflow then: builds → signs through SignPath → downloads the official
`wintun-0.14.1.zip` from wintun.net and **checks its SHA-256 against the pin in
the workflow** (a mismatch fails the release rather than ship a wrong driver;
the repository variable `WINTUN_SHA256` overrides the pin if Wintun's download
ever changes) → packs `hidravpn.exe`, `hidravpn-service.exe`,
`hidravpn-sign.exe`, `wintun.dll`, `README.txt` and a post-signing
`SHA256SUMS.txt` into `hidravpn-windows-<tag>.zip` → publishes a GitHub
Release on the tag with the zip and `SHA256SUMS-<tag>.txt` attached.

To confirm the Wintun pin on your own PC before the first release (the phase
scripts already downloaded that zip while testing):
`Get-FileHash C:\HidraVPN\logs\wintun.zip -Algorithm SHA256`.

## The project's own signature (Ed25519) — the one manual step

The Authenticode signature proves *who built it*; the project's Ed25519
signature proves *the maintainer released it*. Its secret key lives **offline**
and never enters CI, so this step is by hand, after the release appears:

```
hidravpn-sign verify ...              # (optional) check the zip's hashes first
hidravpn-sign sign --key hidravpn-release.key SHA256SUMS-hidravpn-v0.3.0.txt
```

Attach the resulting `SHA256SUMS-hidravpn-v0.3.0.txt.sig` to the GitHub
Release. Users then verify the download with the project's public key (the one
`hidravpn-sign keygen` printed; it is published on the site and embedded in
the client and the browser — `RELEASE_PUBLIC_KEY_B64` in
`crates/hidravpn-core/src/release.rs` and `RELEASE_PUBLIC_KEY` in
`hidra-browser/src/main/release-verify.js`, which a test keeps identical):

```
hidravpn-sign verify --pubkey <project public key> SHA256SUMS-hidravpn-v0.3.0.txt
```

The browser installs from a manifest signed with the same key
(`landing/vpn/release/manifest.json` and its `.sig`). Make it with a sequence
higher than the published one's, sign it, and publish both:

```
hidravpn/scripts/make-release-manifest.sh --version 0.3.0 --sequence 2026110101 \
    --base https://hidranet.org/vpn/release/0.3.0 \
    --linux-x64 dist/linux --win32-x64 dist/windows > manifest.json
hidravpn-sign sign --key hidravpn-release.key manifest.json
```

The manifest expires (90 days by default; `--expires` sets another date), and
after that the browser refuses it, so that a site serving an old manifest
forever cannot hold back later releases. Before it runs out, make and sign it
again with a higher sequence, even when nothing else changed.

The sequence only protects a browser that has already seen a later manifest.
A new profile, a reinstalled browser, or one whose service was installed with
the CLI starts at sequence 0, and 0.1.0 is signed, never expires and carries
neither the version mark nor the service's own downgrade check. What keeps
such a browser from being served an old release is `MIN_VERSION` in
`hidra-browser/src/main/vpn-installer.js`, the oldest release it installs
whatever is signed. Raise it in a browser release:

- once 0.1.1 (the first release whose service carries its version mark) is
  published with a manifest of sequence above 0: set `MIN_VERSION` to
  `0.1.1`;
- with every HidraVPN release that fixes a security problem in the service:
  set it to that release.

Raise it only after that release's manifest is live, or the browser has
nothing it may install. Browsers already shipped keep the value they were
built with; only an update of the browser itself moves them on.

There are **two keys**, and they are made the same way:

```
hidravpn-sign keygen --out hidravpn-release.key   # signs release files
hidravpn-sign keygen --out hidravpn-list.key      # signs the node list (scripts/make-node-list.sh)
hidravpn/scripts/embed-release-key.sh --release <release public key> --list <list public key>
```

`embed-release-key.sh` pastes the public halves into the Rust constants
(`RELEASE_PUBLIC_KEY_B64`, `LIST_PUBLIC_KEY_B64` in `release.rs`) and the
JavaScript ones (`release-verify.js`) together, and the tests keep each pair
identical. Both keys exist and their public halves are embedded; a build
with an empty constant verifies nothing and refuses everything, on purpose.
The secret halves were made offline and are backed up in two places; the
same script embeds a replacement when a key is rotated.

Know what each key is worth. The release key says "the maintainers built
this"; whoever held it could ship a client. The list key says "the
maintainers vouch for these nodes"; whoever held it could publish a list
naming nodes of their own, and every client that imported it would know
them — and, with open admission, could join them. The list key is used far
more often (every list, not every release), which is why it is a separate
key: losing it means a new list key and a client release, not a new
identity for the project.

## What SignPath checks (so the application goes through)

- An OSI-approved open-source licence (HidraVPN is MIT) and a public repository.
- No closed-source components except system libraries (`wintun.dll` is the
  Microsoft/WireGuard-signed driver, loaded at run time, not built by us).
- A fully automated build from the checked-in source — this workflow.
- The policy above published on the project's home or download page.
- The project actively maintained, with its function described for users.

One thing to raise with SignPath in the application: HidraVPN's source is open
(MIT) but the VPN service itself is paid. Selling a service on top of
open-source code is normally fine for them, but say it plainly so there is no
surprise.

## Certificate choice

RSA, not ECC — Smart App Control does not accept ECC signatures. A certificate
from a CA in the Microsoft Trusted Root Program (which SignPath's is) lets the
binary run under Smart App Control before it has built cloud reputation;
SmartScreen's "unknown publisher" notice may still appear at first and fades as
reputation builds, which happens by signing every release.
