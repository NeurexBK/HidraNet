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
