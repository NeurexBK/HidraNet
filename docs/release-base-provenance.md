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
engine. The legacy packages remain unsigned/not notarised. Runtime VPN,
installation and anonymity verification are separate from this release
containment change.

## Scope of containment

The changed workflows are manual, read-only and restricted to main. They
produce review artifacts and cannot replace public release assets. Historical
branches still contain their old workflow versions; merging this change alone
does not revoke those versions or disable already running jobs. Repository
administrators should account for that when managing historical branches.
