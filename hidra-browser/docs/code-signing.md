# Signing and notarizing the HidraNet Browser

The published packages are **not code-signed or notarized** on any platform.
On macOS that means Gatekeeper calls the app "damaged" and the user must run a
`codesign`/`xattr` dance from the launcher; on Windows SmartScreen warns that
the publisher is unknown. For a security product this is a real gap: nobody
can verify the binary is genuinely ours and unmodified.

Closing it needs things only the maintainer can obtain — a paid Apple Developer
account and a SignPath Foundation project — so this is a **turn-on guide**, not
something a commit can finish. Two pieces are already in the repo and inert
until you finish the steps below:

- `scripts/entitlements.mac.plist` — the hardened-runtime entitlements Electron
  needs to notarize.
- `scripts/sign-mac.sh` — signs + notarizes + staples an extracted
  `HidraNet.app`. It **does nothing and exits 0 when the `APPLE_*` secrets are
  unset**, so unsigned/local builds are unaffected until you turn signing on.

Nothing else in the build or release scripts was changed, because the
remaining edits (below) can only be tested on a Mac with a real certificate,
and getting them wrong blind would break the working unsigned build.

Until then, the one thing that does not come from the same accounts as the
files is the release key: the checksum table can be signed offline with it
(below). That does not help someone downloading for the first time, who reads
the key from the same site, but it lets every installed browser from 1.1.0 on
tell a genuine update notice from one the site's controller made up.

---

## The checksum table — Ed25519, offline, with the release key

`landing/SHA256SUMS.txt` lists the packages' hashes and, near its top, a
small record the browser reads (`src/main/update-check.js`): the latest
version, the minimum safe version and the day the record stops being valid.
The browser fetches the table and `SHA256SUMS.txt.sig` through Tor once the
network lock opens, checks the signature with the release key it embeds
(`release-verify.js`, `verifyBrowserSums`), and shows a notice on the new tab
page when a newer build is out or this one is below the minimum. It never
downloads or installs anything.

What the signature does and does not stop: whoever controls the site cannot
make a browser believe a record the maintainers did not sign. They can still
take the `.sig` away, serve one that does not verify, or serve an older
signed record again. So the browser keeps the highest versions and the latest
`valid-until` it has verified in its data folder and sets aside a record with
lower versions; the last record it verified holds until that record's own
`valid-until`, and after that, with nothing it can believe, the new tab page
says it could not confirm the browser is up to date and to check the site. A
build made before the first signature, that has never verified a record,
shows nothing for a missing `.sig`: that is how things stand until the
table is signed. `SUMS_SIGNED` in `update-check.js` marks the builds made
after it, which show that notice for a missing `.sig` too.

The signature is over the label `hidranet-browser-sums-v1`, a zero byte, then
the file, never over the bare file: the same key signs HidraVPN's manifest
and its `SHA256SUMS-hidravpn-*.txt` over their bare bytes, and the label keeps
a signature made for one from passing as the other.

### Signing it (on the PC that holds the release key)

Every time the table changes — a new build, a new minimum, a renewed
`valid-until` — sign it again, in PowerShell, from the repository root.
The first time only, also set `SUMS_SIGNED = true` in
`hidra-browser\src\main\update-check.js` and commit it with the signature:
`verify-sums.js` refuses a signed table while it says false.

```
git pull
node hidra-browser\scripts\update-sums.js <folder with the four zips> <commit> --minimum 1.1.0   # only when the packages change
.\hidra-browser\scripts\sign-sums.ps1 -Key E:\hidravpn-release.key -Sign C:\HidraVPN\hidravpn-sign.exe
node hidra-browser\scripts\verify-sums.js
git add landing\SHA256SUMS.txt landing\SHA256SUMS.txt.sig
git commit -m "landing: sign SHA256SUMS.txt"
```

`sign-sums.ps1` shows the file's SHA-256 and the three record lines and asks
before signing; it refuses a key inside the repository, CRLF line endings
(`.gitattributes` keeps the file LF) and a `valid-until` that has passed or is
more than 400 days away. Any `hidravpn-sign` will do: the script adds the
label itself, signs, checks the result against the public key in
`release-verify.js`, writes `landing/SHA256SUMS.txt.sig` and deletes its
temporary copy. The key file is only read by `hidravpn-sign`.

Before signing, read the whole table, not only the record: `update-sums.js`
rewrites the title, the record and the rows, and refuses packages that do not
run the pinned Electron, Chromium and Tor, but it leaves the prose alone. It
warns when a `KNOWN PROBLEMS WITH THE <version> PACKAGES` section is about
another version than the one listed; change or remove that section first.

Choose `valid-until` so it is renewed well before it passes (180 days is the
default `update-sums.js` writes): once it passes, browsers say they cannot
confirm they are up to date. It is also how long anyone who can change the
site can keep serving the last signed record, hiding a newer one, so do not
make it longer than you need. Raise `minimum-safe-version` whenever a
release fixes a security problem: every build below it then shows a warning
instead of a plain update notice.

### What CI does with it

The `release-sums` job in `browser-tests.yml` runs `scripts/verify-sums.js`
on every change: the record must parse, `package.json` must not be behind
it, and once a `.sig` exists, the table must verify against it with the
embedded release key, and `SUMS_SIGNED` must say true. A change that
removes a `.sig` the previous commit had is refused too. An expired record is
only a warning there.

---

## macOS — Developer ID + notarization

### What you need (one time)

1. A paid **Apple Developer** account (US$99/yr).
2. A **Developer ID Application** certificate. Create it in the Apple Developer
   portal, download it, and in Keychain Access export it (with its private key)
   as a `.p12` with an export password.
3. An **app-specific password** for your Apple ID (appleid.apple.com → Sign-In
   and Security → App-Specific Passwords) — notarytool uses it.
4. Your 10-character **Team ID** (Apple Developer → Membership).

Base64 the `.p12` (`base64 -i cert.p12 | pbcopy`) and set these as environment
variables locally, or as GitHub **secrets** for CI:

| name | value |
|---|---|
| `APPLE_CERT_P12` | base64 of the `.p12` |
| `APPLE_CERT_PASSWORD` | the `.p12` export password |
| `APPLE_ID` | the developer account email |
| `APPLE_TEAM_ID` | the 10-char team id |
| `APPLE_APP_SPECIFIC_PASSWORD` | the app-specific password |

### Building a signed package (on a Mac)

```
cd hidra-browser
node scripts/fetch-tor.js --platform darwin --arch arm64
node scripts/build-mac.js                 # writes the zip to ~/Desktop
# unzip that package so you have HidraNet.app, then:
bash scripts/sign-mac.sh /path/to/HidraNet.app
# re-zip the signed+stapled bundle for upload
```

`sign-mac.sh` signs the bundled Tor on its own first (`--deep` does not reach
`Contents/Resources/`), then Electron's frameworks and helpers, then the outer
bundle with the entitlements, then notarizes and staples.

### Three edits to make when you turn this on

These change files that only run on a Mac, so make and test them there with a
real certificate — they are intentionally **not** applied blind in this change:

1. **`scripts/release-mac.sh` verifier.** It currently *fails* on any
   `_CodeSignature` entry ("stale Apple signature"). A real Developer ID
   signature legitimately adds one, so a correctly signed bundle would be
   rejected and could never ship. Change that check to accept **either** the
   current unsigned/ad-hoc package **or** a bundle that passes
   `codesign --verify --deep --strict`, `spctl -a -t exec -vv` and
   `xcrun stapler validate`. Also make the launcher-content asserts conditional
   on the unsigned path.
2. **`scripts/lib/mac-extras.js` launcher.** The `Start HidraNet.command`
   launcher runs `codesign --force --deep --sign -` (ad-hoc) and `xattr -cr`.
   On a signed + stapled build that **destroys** the real signature and strips
   the ticket. Gate the ad-hoc dance so it only runs when the app is not
   already validly signed, and branch the `README-macOS.txt` text to the
   "signed & notarised" wording for signed builds.
3. **`scripts/refresh-release.js`.** The CI publish job byte-patches the
   macOS zips on Ubuntu; patching a signed bundle strips the signature and
   stapling. Once macOS is signed, exclude the macOS packages from that repack
   and build + sign them on a macOS runner instead.

### CI: a gated macOS signing job

macOS signing **cannot run on the Ubuntu publish runner** — `codesign`,
`notarytool` and `stapler` are macOS-only. Add a job on a `macos-14` runner,
gated on the secrets being present, that builds, signs and uploads the signed
zips as an artifact the publish job consumes (and have the publish job skip the
macOS repack). Sketch:

```yaml
  sign-mac:
    runs-on: macos-14
    if: ${{ secrets.APPLE_CERT_P12 != '' }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - working-directory: hidra-browser
        run: |
          node scripts/fetch-tor.js --platform darwin --arch arm64
          node scripts/fetch-tor.js --platform darwin --arch x64
          node scripts/build-mac.js
          # unzip each package, run scripts/sign-mac.sh on the .app, re-zip
        env:
          APPLE_CERT_P12: ${{ secrets.APPLE_CERT_P12 }}
          APPLE_CERT_PASSWORD: ${{ secrets.APPLE_CERT_PASSWORD }}
          APPLE_ID: ${{ secrets.APPLE_ID }}
          APPLE_TEAM_ID: ${{ secrets.APPLE_TEAM_ID }}
          APPLE_APP_SPECIFIC_PASSWORD: ${{ secrets.APPLE_APP_SPECIFIC_PASSWORD }}
      - uses: actions/upload-artifact@v4
        with: { name: hidranet-macos-signed, path: hidra-browser/dist/signed/ }
```

---

## Windows — Authenticode via SignPath

HidraVPN already uses the SignPath Foundation (free for OSS) — reuse that
project. The pattern is in `.github/workflows/hidravpn-build.yml` (`sign-windows`
job) and `hidravpn/docs/code-signing.md`.

### What you need

- A SignPath Foundation project for this repo, with an
  **artifact-configuration** for the browser's Windows package — which is a
  **zip containing PEs** (`HidraNet.exe`, the Electron `*.dll`s, and
  `resources/bin/hidra-node.exe`). SignPath recurses into the zip, Authenticode-
  signs the inner PEs and re-zips. This is a *different* artifact configuration
  from hidravpn's (which signs a flat three-exe folder), so it needs its own
  slug.
- Set repo **variables** `SIGNPATH_ENABLED=true`, `SIGNPATH_ORGANIZATION_ID`,
  `SIGNPATH_PROJECT_SLUG`, `SIGNPATH_POLICY_SLUG`, `SIGNPATH_ARTIFACT_SLUG`, and
  the **secret** `SIGNPATH_API_TOKEN`. SignPath prints the exact values when you
  register the project.

### CI: a gated Windows signing job

Add to `.github/workflows/publish-release.yml`, between building the packages
and `gh release upload`, so the Windows zip is signed before it is published.
Gated off until `SIGNPATH_ENABLED` is set, exactly like hidravpn:

```yaml
  sign-windows:
    needs: publish            # or restructure so signing happens pre-upload
    if: ${{ vars.SIGNPATH_ENABLED == 'true' && github.event_name != 'pull_request' }}
    runs-on: ubuntu-latest
    permissions: { contents: read, id-token: write }
    steps:
      - uses: signpath/github-action-submit-signing-request@v1
        with:
          api-token: ${{ secrets.SIGNPATH_API_TOKEN }}
          organization-id: ${{ vars.SIGNPATH_ORGANIZATION_ID }}
          project-slug: ${{ vars.SIGNPATH_PROJECT_SLUG }}
          signing-policy-slug: ${{ vars.SIGNPATH_POLICY_SLUG }}
          artifact-configuration-slug: ${{ vars.SIGNPATH_ARTIFACT_SLUG }}
          github-artifact-id: <the Windows zip artifact id>
          wait-for-completion: true
          output-artifact-directory: signed
```

**Honest limit:** Authenticode proves "signed by us", not "built from our
source" — the renamed Electron PEs are not compiled in CI (the publish job only
swaps in a freshly built `hidra-node.exe`). The strongest provenance win is to
sign at least that freshly-built `hidra-node.exe`; signing the whole package is
still worth it to clear the SmartScreen "unknown publisher" warning.

---

## While this is off

`sign-mac.sh` no-ops without the `APPLE_*` secrets and nothing else changed, so
builds stay exactly as they are — unsigned, with the ad-hoc launcher — until you
obtain the credentials and make the edits above. When a signed release does
ship, update the "not signed/notarised" wording in `landing/SHA256SUMS.txt`,
`landing/index.html`, and the macOS "damaged" workaround in the installation
docs and FAQ.
