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
   `feature/hidravpn`). The `sign with SignPath` job must now run (it was
   skipped before) and leave a `hidravpn-windows-signed` artifact. Download
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
only runs when `SIGNPATH_ENABLED` is `true` and only after signing succeeded).

```
git checkout feature/hidravpn && git pull
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
`hidravpn-sign keygen` printed; it is published on the site and, in phase 4,
embedded in the browser):

```
hidravpn-sign verify --pubkey <project public key> SHA256SUMS-hidravpn-v0.3.0.txt
```

If the key does not exist yet, make it now, offline, and keep it backed up in
two places: `hidravpn-sign keygen --out hidravpn-release.key`.

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
