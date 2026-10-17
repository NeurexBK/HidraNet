# Operator tools

## forum-registrar.js

The forum keeps its accounts on a public MQTT relay, and the relay enforces
nothing: anyone can overwrite the claim on a username. The registrar is the
one party whose word on names the forum page takes over the relay's. It
watches the claims, records the first key seen for each name, and publishes
the whole list signed under `hforum/registry`. The page ships the public
half of the registrar's key and trusts nothing else for names in that list.

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
  the relay is republished, at most once a minute.
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
