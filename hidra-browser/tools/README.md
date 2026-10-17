# Operator tools

## forum-registrar.js

The forum keeps its accounts on an MQTT relay. A public relay enforces
nothing: anyone can overwrite the claim on a username. The registrar is the
one party whose word on names the forum page takes over the relay's. It
watches the claims, records the first key seen for each name, and publishes
the whole list signed under `hforum/registry`. The page ships the public
half of the registrar's key and trusts nothing else for names in that list.
With `hidra-relay` (below) the relay itself refuses what the page would,
and the registrar stays the authority the pages and the relay follow.

It needs Node 22 or newer and nothing else: it loads the same MQTT bundle
the browser ships.

### What it sees

Only what every client of the relay sees: usernames, public keys and the
time of each claim. No address reaches it, and it logs counts and key
fingerprints, never names.

What it adds is authority, not visibility: whoever holds the key decides
which key owns a name. Keep the key accordingly.

### Setting it up, once

1. On the machine that will run it, make the key pair:

   ```
   node hidra-browser/tools/forum-registrar.js keygen /path/to/registrar
   ```

   This writes `/path/to/registrar/registry.secret` and prints the public
   key. On Linux and macOS the file is made readable by its owner only; on
   Windows it is not, so keep the directory under your own user profile.
   Back the file up; never commit it (`*.secret` is in `.gitignore`).

2. Paste the printed public key into `REGISTRY_PUBKEY` in
   `hidra-browser/src/ui/forum.html`, and ship the browser.

3. Name the moderator. Moderation is not taken from the relay, where anyone
   could have written first; the operator sets it, from the public key the
   moderator's account shows (the forum page prints an account's key
   fingerprint; ask the moderator for the full key, which their page can
   copy from the account dialog, or take it from their claim on the relay):

   ```
   node hidra-browser/tools/forum-registrar.js set-admin /path/to/registrar <public key>
   ```

   Until this is done, pages fall back to the first moderation claim they
   saw on the relay.

4. Run it, and keep it running:

   ```
   node hidra-browser/tools/forum-registrar.js run /path/to/registrar
   ```

   Options: `--broker <url>` (default `wss://broker.emqx.io:8084/mqtt`),
   `--interval <seconds>` (republish at least this often, default 1800),
   `--adopt-existing` (see below).

### Starting out

On its first run the registrar cannot tell a name claimed by its rightful
owner last month from one an attacker overwrote last night: both are just
retained messages. So by default it records nothing that is already on the
relay when it first connects; it counts those claims, logs the count, and
records only names claimed from then on, live, where an attacker would have
to beat the owner to the relay in real time. People who registered before
the registrar existed keep working under the first-seen rule and can
register a fresh name to be listed.

If you know the relay is clean (a new forum, or one you have watched), pass
`--adopt-existing` on the first run to record what is there.

### How it behaves

- On connecting it collects the retained claims for five seconds, then
  publishes the list, and again on every change (coalesced to one list per
  fifteen seconds) and on the interval. A list wiped from or replaced on
  the relay is republished, at most once a minute. After a reconnection,
  a relay that hands over no list (one that restarted without its data,
  or a new relay) is given the list straight away.
- `registry-state.json` beside the key holds what has been recorded and the
  sequence number. The sequence only grows; the page refuses a list with a
  sequence below the one it holds, so an old list cannot be replayed. Back
  this file up with the key: if it is lost, the registrar adopts the last
  list it finds on the relay under its own key, and logs that it did.
- Run exactly one copy per key. A second copy on the same key publishes
  competing sequence numbers; the log says when it sees one.
- The list is capped at 3000 names and 512 KB, below what a public relay
  carries. New names are refused beyond the cap, and a burst of more than
  200 new names in ten minutes is refused while it lasts: names are free to
  make, so a burst is a flood, not a crowd. Both are logged.
- A name recorded here stays with its key. There is no command to reassign
  one; editing `registry-state.json` by hand and restarting is the only way,
  and that is deliberate.
- `show <dir>` prints the sequence, the number of names and the moderator.

### Limits

- A few thousand names is where this design ends and the forum needs the
  hub on HidraNet's own infrastructure.
- Pages that never received a list, because the registrar was down and the
  relay's copy was wiped, fall back to first-seen until the next list.
- The registrar's own machine talks to the relay directly: the relay sees
  that machine's address. It is the operator's, not any user's.

## hidra-relay

The project's own relay for the chat and the forum, in place of the public
MQTT brokers the pages ship with. It is a Rust binary in `hidra-node`
(`src/apps/hidrarelay.rs`, `src/bin/hidra-relay.rs`): MQTT 3.1.1 over
WebSocket, the subset the pages use, and nothing else.

What it does that a public broker does not:

- Carries only the two trees the pages use, `hidra/` (rooms, ciphertext
  only, topics of a fixed shape) and `hforum/`. Everything else is dropped.
- Keeps retained messages on disk (`--data`), so the forum survives a
  restart, under caps on count and size.
- Limits every client: handshake and CONNECT within ten seconds of being
  accepted, payloads of 128 KiB (640 KiB for the registry), 12
  subscriptions and 256 SUBSCRIBE packets in a connection's life, 10
  packets a second with a burst of 60 (a subscription costs five per
  filter, since it is a pass over everything kept; a WebSocket frame with
  no packet in it costs one), a keep-alive of at most ten minutes, and an
  outbound queue of 256 frames or 1 MiB; a client that exceeds them, or
  stops reading, is disconnected, as is one whose publish above 128 KiB
  was refused (only the registrar's list is that large, and the
  registrar's never is). 4096 clients in all. A message is held
  once however many clients it goes to, and a new subscriber's backlog is
  sent between the packets it keeps sending, so a slow load never stops
  its pings from being answered. What is kept is capped at 50 000
  messages and 32 MiB, which is also the most a new page is ever asked to
  load; the top 4 MiB are for moderation and the registrar's list only,
  the 4 MiB below that also for names, and one signing key may hold at
  most 4 MiB, so a store filled with posts still takes a hide, a list and
  a registration. With `--data`, a write is queued for the disk before
  memory changes; when the disk cannot keep up the publish is refused and
  the log says so, so memory and disk never disagree; a disk that keeps
  failing stops the relay from taking retained publishes at all. On
  SIGTERM or Ctrl-C the relay stops accepting, writes out what it had
  acknowledged, and exits. A refused list is logged at warn level, since
  the registrar is the operator's own.
- With the registrar's key (`--registrar-key`), enforces the forum's rules
  before keeping anything: a claim only on a free name or from the key
  that holds it, where the registrar's list is the authority on names (a
  relay that starts empty knows every registered name as soon as the list
  arrives); a post only signed, only under a name its key holds, with an
  id of its own, and replaced or deleted only by that key; a hide only
  from the moderator, whom the relay takes from the list (`set-admin`);
  the registry only from the registrar and only with a higher sequence
  number (a list left by another key, say after a key change, does not
  hold it back); no name, post, hide, moderation claim or list is ever
  wiped by an empty message (a report, which is unsigned, can be withdrawn
  by anyone, as on the page); the same bytes published again go nowhere;
  nothing retained in the chat tree, and nothing live-only in the forum
  tree. Each kind has a cap (10 000 names, 30 000 posts, 5 000 hides,
  5 000 reports) past which new ones are refused. The page's own checks
  stay and agree with these; signatures are verified off the relay's
  lock, and under it the relay reads what it remembered beside each
  message instead of parsing it, so a flood slows only its sender.
- Logs counts and reasons. No topic, payload, name, key or address is
  written.

What it sees is what any relay sees: the address of each client, when it
connects, how much it sends and to which topic. Room traffic is ciphertext
to it; the forum is public anyway.

### Running it

Build and install:

```
cd hidra-node && cargo build --release --bin hidra-relay
install -m 755 target/release/hidra-relay /usr/local/bin/
```

Run it on loopback and put TLS in front of it. `deploy/hidra-relay/`
holds a systemd unit and a Caddyfile; fill in the host name and the
registrar's public key (the `REGISTRY_PUBKEY` in `forum.html`).

```
hidra-relay --listen 127.0.0.1:1884 --data /var/lib/hidra-relay \
            --registrar-key <REGISTRY_PUBKEY>
```

Flags: `--listen` (default `127.0.0.1:1884`), `--data` (omit to keep
retained messages in memory only), `--registrar-key` (required, unless
`--no-forum-rules` asks for a plain relay that keeps whatever is
published, which is for testing the pages' own checks), `--log-level`.
There is no flag for the moderator: `set-admin` at the registrar names
the moderator for the pages and the relay alike.

Point the pages at it: `MQTT_BROKERS` and the `connect-src` of the content
security policy in `hidra-browser/src/ui/hidrachat.html` and
`forum.html`, and the copy of the chat page in `hidra-node/assets/`. Run
the registrar against the same URL (`--broker wss://<host>/mqtt`).

### Checking it

```
cd hidra-node && cargo test hidrarelay
```

covers the packet parser, the limits, the store across a restart, delivery
through real WebSocket clients, and every forum rule against signatures
made by the browser's own module (`src/apps/hidrarelay/forum_vectors.json`).
