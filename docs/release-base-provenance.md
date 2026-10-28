# Browser release input baseline

The v1.0.0 input pins describe the four existing public ZIPs built from
`423f0ce1ed25e56dbd03efe23cb1f6dd8b27ee0e` on 2026-10-22. This change does
not publish or replace those files.

## Why the previous table differed

[Actions run 39805862641](https://github.com/NeurexBK/HidraNet/actions/runs/39805862641)
ran on `hidravpn-v0.1.0`. Its job steps report successful build, asset upload,
checksum generation and release-description update, followed by failure of
`Commit the table`. The repository retained the older 562121c table while
the release description and assets recorded 423f0ce.

## Evidence checked before changing the pins

- Downloaded all four public ZIPs without executing their contents.
- Computed each SHA-256 and size locally; all matched GitHub's asset metadata
  and the hashes in the release description.
- Checked every ZIP member's CRC successfully.
- Read each embedded `app/build.json`: build `423f0ce`, date `2026-10-22`.
- Compared all 41 files under `app/src/` in each archive byte-for-byte with
  `hidra-browser/src/` exported from that commit with `core.autocrlf=false`.
  All matched.

The exact accepted hashes are in `hidra-browser/scripts/lib/release-base.js`.
The public checksum table is intentionally unchanged in this scoped change;
its discrepancy remains a separate follow-up. The verifier rejects other bytes, including
cached files, before compiling or parsing an archive. A later replacement
must be investigated and reviewed again, never accepted automatically.

These checks establish consistency with the recorded release, not independent
publisher authentication or a reproducible build of Electron, Tor or the Rust
engine. They also say nothing about what runs inside: the Linux package was
later found to carry Electron 33.4.11 (Chromium 130) and Tor 15.0.22, not the
pinned 44.9.3 and 15.0.26. `refresh-release.js` now checks every Electron
file, every Tor file and the engine version of a base package against the
pins (`scripts/lib/package-runtime.js`) and refuses these four, so
`verify-browser-release.yml` fails on them by design. The next packages come
from the from-scratch builders under a new version, and these pins are then
replaced by that release's, after the same review. The legacy packages remain unsigned/not notarised. Runtime VPN,
installation and anonymity verification are separate from this release
containment change.

## Scope of containment

The new workflows (`verify-browser-release.yml` and
`preview-browser-release-notes.yml`) are manual, read-only and restricted to
main. They produce review artifacts and cannot replace public release assets.
They use new paths so the legacy workflow IDs can remain disabled globally.

Deployment must also disable the legacy `publish-release.yml` (ID 380890791)
and `release-notes.yml` (ID 381747046) through GitHub Actions. Historical
branches retain those files, so removing them from main alone is insufficient.
Check for running legacy jobs separately; disabling a workflow does not cancel
already running jobs. Do not re-enable the legacy IDs for a review build.
