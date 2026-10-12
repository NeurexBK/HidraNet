Touch this file to publish the release packages.

The workflow that watches it is .github/workflows/publish-release.yml. It
rebuilds the four v1.0.0 download packages from whatever branch the push
landed on, replaces the assets on the release page, and commits the checksum
table it generated from the bytes it uploaded.

Why a file rather than the Run workflow button: workflow_dispatch only offers
workflows that exist on the default branch, and this one was written on a
feature branch.

run 1 — 2026-10-10 — the September packages were still being served, with a
partly Portuguese interface and without any of the security work from 7-10
October.

run 2 — 2026-10-11 — support moved from a Bitcoin address to an $HNET wallet on
Solana, ExYv4idyqxmuodpoZtxyGxeTGi6oYrqFAshAgCsRissc. The packages published in
run 1 still show the Bitcoin donate page.

run 3 — 2026-10-12 — the Linux package did not open on Ubuntu 23.10 and later:
Chromium aborted for want of a sandbox. start.sh now sets one up.
run 4: 2026-10-12T01:39Z — apps keep their identity; chat, forum and site fixes
run 5: 2026-10-12T01:41Z — run 4 stopped at the new storage test (no Electron in CI); fixed
run 6: 2026-10-12T01:55Z — Tor no longer outlives a crashed browser
