# HidraVPN — code signing (Windows)

Windows 11 with Smart App Control refuses to run an unsigned binary, and even
without it an unsigned download shows a SmartScreen warning. So the HidraVPN
Windows executables — `hidravpn.exe` (the client) and `hidravpn-service.exe`
(the service) — are signed with an Authenticode certificate. Signed, they run
cleanly without the user having to weaken any security setting on their machine.

We never ask a user to turn Smart App Control off. The only correct fix is a
signature, and that is what this sets up.

## How it works

Signing is done by **SignPath.io** through the **SignPath Foundation** free
programme for open-source projects. The private key lives in SignPath's HSM
and never touches this repository, a developer's machine, or a build runner.

The binaries that get signed are built **only** by GitHub Actions, from the
checked-in source, in the workflow `.github/workflows/hidravpn-build.yml`. That
workflow builds the two executables, uploads them, and — once signing is turned
on — hands that exact build to SignPath to sign. SignPath verifies the build
came from this repository before it signs, so a signed HidraVPN binary can only
have come from the public source.

## Code signing policy (for the project page)

> HidraVPN's Windows executables are code-signed through SignPath.io under the
> SignPath Foundation's free open-source programme. The signing certificate's
> private key is held in SignPath's HSM and is never exported. Only the project
> maintainers can start a signing request, and only binaries built by the
> project's GitHub Actions workflow from the public source at
> github.com/NeurexBK/HidraNet are signed. No telemetry is added during the
> build or signing process.

## Turning it on (after SignPath approves the project)

1. Register the project on SignPath and create a signing policy for release
   signing. SignPath gives you an organization id, a project slug, a signing
   policy slug and an artifact configuration slug, plus an API token.
2. In the GitHub repository settings add:
   - a secret `SIGNPATH_API_TOKEN` (the API token);
   - variables `SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG`,
     `SIGNPATH_POLICY_SLUG`, `SIGNPATH_ARTIFACT_SLUG`;
   - a variable `SIGNPATH_ENABLED` set to `true`.
3. Paste the exact `uses:` line and inputs SignPath shows for your project into
   the `sign-windows` job (the one already in the workflow is the template).
4. Push to `feature/hidravpn`. The `sign-windows` job now runs and produces a
   `hidravpn-windows-signed` artifact.

Until step 2 is done, the build and the checks run and the signing job is
skipped, so nothing breaks in the meantime.

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
