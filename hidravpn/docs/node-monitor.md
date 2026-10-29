# The hourly node check

Every hour, at 41 minutes past, a GitHub Actions run
(`.github/workflows/node-monitor.yml`) checks the network the way a client
sees it, and opens an issue when something is wrong. It runs on GitHub, not on
any of our servers, so it still runs when a server is down. It uses no secret
and costs nothing.

## What it checks

| Check | Fails when | Issue key |
|---|---|---|
| The node list on hidranet.org | it does not load, its signature does not hold under the list key the client embeds, or a client would refuse it for any other reason (a bad node record, an operator name over 64 characters, an expiry that is not a date) | `list` |
| The release manifest on hidranet.org | the same, under the release key, or its `expires` is not a date | `manifest` |
| The browser's checksum record on hidranet.org | once `SHA256SUMS.txt.sig` is on hidranet.org or in `landing/` on main: the table or the `.sig` does not load (a site without the `.sig` main holds included), the signature does not hold under the release key (with the browser's label), or the record has no single `valid-until` day | `sums` |
| hidranet.org against main | the site serves different bytes from `landing/vpn/` on main: a merge the deployment never picked up | `site` |
| Every node in the list | it does not answer `GET /` on its admission port (TCP 51821 unless the list says otherwise), or answers with a key other than the one the list names | `node:<name>` |
| The pass issuer the list names | `/keys` does not answer, or does not hold as current the key clients ask passes under (the newest current key in the list); or the list names no issuer while nodes in it take passes | `issuer` |
| Passes for sale | `/packs` does not answer, or lists nothing (with packs priced in dollars, usually a stale HNET rate) | `issuer-sales` |
| Dates | the list's `expires`, or the `not_after` of the key clients ask passes under, is less than 14 days away, or past | `expiry` |
| Release dates | the release manifest's `expires`, or the signed checksum record's `valid-until`, is less than 14 days away, or past. A manifest with no `expires` (0.1.0's) never expires, and before the first `SHA256SUMS.txt.sig` there is no record to run out | `release-expiry` |

What it does **not** check: that WireGuard answers on the node's UDP port, or
that traffic flows through a node. Only a client the node admitted gets an
answer there, so that takes a real connection: `scripts/probe-nodes.sh`, on a
machine of ours, connects through every exit. A node whose service answers
but whose tunnel is broken passes this check.

## How it alerts

- Anything fetched is tried three times, two minutes apart. Only a failure seen
  all three times is reported, so a runner's bad minute is not an alert. A date
  is not retried: it does not change. An issue closes only when the latest try
  passed.
- Each problem is one issue titled `[node monitor] ...`. It mentions the logins
  in `NODE_MONITOR_MENTION` in the workflow, and GitHub e-mails them. The issue
  says what failed and what to look at first.
- An issue already open is not opened again. When what is wrong changes (a
  reminder becomes an expiry, a node that was down answers with another key),
  the run says so in a comment, which e-mails again, and renames the issue.
  When the check passes, the run comments and closes it. A node taken out of
  the list has its issue closed. An issue whose check could not run (no usable
  list anywhere) stays as it is.
- Closing an issue by hand while the problem lasts brings a new one within the
  hour. To stop an alert, fix the cause.
- When nothing at all answers (the site, the issuer and every node), the runner
  is the likelier culprit. No issue is touched, and the run fails. A red run
  always means the check broke, never that a node is down; GitHub e-mails the
  person who last changed the schedule about it.
- Only issues the workflow opened count: anyone can open an issue, and one
  that carries the check's marker is not mistaken for its own.
- Nothing it prints, writes in an issue or puts in the run summary names an
  address. A node is its `node_name`, and nothing a node answers is copied into
  an issue except a key, and only when it is shaped like one.

When the issue is about a node someone else runs, it says so, and it is ours
to write to that operator at the address they gave us, as
[the operator guide](operators/running-an-entry.md) promises.

## Getting the e-mail where you want it

GitHub sends the notification to the mentioned account's notification address.
To receive it at a shared address such as contact@hidranet.pro: add that address
under GitHub **Settings → Emails** and verify it, then choose it under
**Settings → Notifications → Default notifications email**. GitHub lets one
address belong to one account only: if it is already on another account,
put that account's login in `NODE_MONITOR_MENTION` instead. Or keep the
account's address and forward, from your mail, what `notifications@github.com`
sends with `[node monitor]` in the subject.

## On a pull request

A pull request that changes the check, anything under `landing/vpn/`,
`landing/SHA256SUMS.txt` or its `.sig`, or the client code the check copies
its rules from runs the tests
(`scripts/test-node-monitor.mjs`) and two checks that write nothing:

- `--preview`: the list in the branch, as it would be published. It fails when
  that list's or the manifest's signature does not hold, when a client would
  refuse the list, when the list or the manifest has expired, when a signed
  checksum record in the branch does not verify or is past its `valid-until`, when its sequence is lower than
  the published one (or the same, with the list changed: clients would keep
  what they have), when nodes in it take passes and it names no issuer, or
  when a node it adds or changes (a new key, address or admission port) does
  not answer with its key. A node already published, unchanged and down does
  not fail it; that is the hourly check's to report.
- `--dry-run --landing base/landing`: everything the hourly check would report
  now, with the site compared with the base branch.

## Running it by hand

From the Actions tab, **node monitor → Run workflow**. Or anywhere with Node 20
or later:

```
node hidravpn/scripts/node-monitor.mjs --dry-run
```

GitHub turns off scheduled runs in a public repository after 60 days with no
activity in it. If the repository goes quiet that long, turn the workflow back
on in the Actions tab.

## Starting it from outside

GitHub starts scheduled runs late, by hours when it is busy, and may skip
them. For a check that really runs every hour, have an outside scheduler
start it as well. Any cron service that can send an HTTPS request will do.
Each hour at 41 minutes past it sends:

```
POST https://api.github.com/repos/NeurexBK/HidraNet/actions/workflows/node-monitor.yml/dispatches
Authorization: Bearer <token>
Accept: application/vnd.github+json
X-GitHub-Api-Version: 2022-11-28

{"ref":"main"}
```

GitHub answers `204` when the run is queued.

The token is a fine-grained personal access token of the repository's owner,
for this repository only, with one permission: **Actions**, read and write. It
reaches this repository's Actions and nothing else (no code, no issues, no
settings), and it is kept by the scheduler alone, never in this repository. When it expires the outside runs
stop; GitHub's own schedule still runs, late.

A dispatched run and a scheduled run in the same hour do no harm: the
`node-monitor` concurrency group runs them one after the other, and the second
finds the issues the first opened and does not open them again.
